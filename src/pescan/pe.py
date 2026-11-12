"""A Portable Executable parser written from the format's specification: the headers, the section table, imports, exports and the few data
directories the analysis needs. Nothing is executed and nothing is loaded: the file is bytes.

Where the format leaves room for interpretation (which section an address falls in, how a raw pointer is rounded), the rules
are the Windows loader's as pefile documents them, so the two parsers can be compared value by value (see `reference.py`).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

import numpy as np

MAX_SECTIONS = 0x800
MAX_IMPORT_DLLS = 0x1000
MAX_IMPORT_SYMBOLS = 0x2000
MAX_NAME = 0x200

DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_EXCEPTION, DIR_SECURITY, DIR_BASERELOC = 0, 1, 2, 3, 4, 5
DIR_DEBUG, DIR_TLS, DIR_LOAD_CONFIG, DIR_IAT, DIR_DELAY_IMPORT, DIR_CLR = 6, 9, 10, 12, 13, 14

SCN_CODE = 0x00000020
SCN_EXECUTE = 0x20000000
SCN_READ = 0x40000000
SCN_WRITE = 0x80000000

FILE_DLL = 0x2000
DLLCHAR_HIGH_ENTROPY_VA = 0x0020
DLLCHAR_DYNAMIC_BASE = 0x0040
DLLCHAR_NX_COMPAT = 0x0100
DLLCHAR_GUARD_CF = 0x4000

MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x1C4: "arm", 0xA641: "arm64ec", 0x200: "ia64"}
SUBSYSTEMS = {
    0: "unknown",
    1: "native",
    2: "windows gui",
    3: "windows console",
    9: "windows ce",
    10: "efi application",
    11: "efi boot driver",
    12: "efi runtime driver",
    13: "efi rom",
    14: "xbox",
    16: "boot application",
}


class PEError(ValueError):
    """The bytes are not a PE file this parser can read; the message says why."""


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & SCN_EXECUTE)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & SCN_WRITE)


@dataclass(frozen=True)
class Import:
    dll: str
    name: str | None  # None when imported by ordinal
    ordinal: int | None


@dataclass
class PE:
    size: int
    machine: int
    sections_declared: int
    timestamp: int
    characteristics: int
    pe32plus: bool
    entry_point: int
    image_base: int
    section_alignment: int
    file_alignment: int
    size_of_image: int
    size_of_headers: int
    checksum: int
    checksum_offset: int
    subsystem: int
    dll_characteristics: int
    directories: tuple[tuple[int, int], ...]
    sections: tuple[Section, ...]
    imports: tuple[Import, ...] = ()
    import_dlls: tuple[str, ...] = ()
    export_name: str | None = None
    export_names: int = 0
    export_functions: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def is_dll(self) -> bool:
        return bool(self.characteristics & FILE_DLL)

    def directory(self, index: int) -> tuple[int, int]:
        return self.directories[index] if index < len(self.directories) else (0, 0)

    @property
    def is_dotnet(self) -> bool:
        return self.directory(DIR_CLR)[0] != 0

    @property
    def has_tls(self) -> bool:
        return self.directory(DIR_TLS)[0] != 0

    @property
    def security_size(self) -> int:
        """Size of the Authenticode blob the header points at (0: no embedded signature)."""
        return self.directory(DIR_SECURITY)[1]


def _u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 2], "little")


def _u32(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 4], "little")


def _need(data: bytes, off: int, n: int, what: str) -> None:
    if off < 0 or off + n > len(data):
        raise PEError(f"{what} is outside the file (offset {off:#x}, {n} bytes, file of {len(data)} bytes)")


def section_name(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("latin-1")


class _Map:
    """Addresses (RVA) to file offsets, with the loader's rounding of pointers and section starts."""

    def __init__(self, data: bytes, sections: tuple[Section, ...], section_alignment: int, file_alignment: int) -> None:
        self.size = len(data)
        align = file_alignment if section_alignment < 0x1000 else section_alignment
        spans = []
        by_va = sorted(sections, key=lambda s: s.virtual_address)
        for i, s in enumerate(by_va):
            va = align * (s.virtual_address // align) if align and s.virtual_address % align else s.virtual_address
            ptr = s.raw_offset & ~0x1FF
            if section_alignment < 0x1000 and s.raw_offset == s.virtual_address:
                ptr = s.virtual_address
            # a raw size that runs past the end of the file is not believed: the virtual size is used instead
            size = s.virtual_size if self.size - ptr < s.raw_size else max(s.raw_size, s.virtual_size)
            nxt = by_va[i + 1].virtual_address if i + 1 < len(by_va) else None
            if nxt is not None and nxt > s.virtual_address and va + size > nxt:
                size = nxt - va
            spans.append((va, va + size, ptr, s.raw_offset + s.raw_size))
        self.spans = spans

    def find(self, rva: int) -> tuple[int, int, int, int] | None:
        for span in self.spans:
            if span[0] <= rva < span[1]:
                return span
        return None

    def offset(self, rva: int) -> int | None:
        span = self.find(rva)
        if span is None:
            return rva if rva < self.size else None
        return rva - span[0] + span[2]

    def window(self, rva: int, length: int) -> tuple[int, int] | None:
        """(start, end) of the bytes at `rva`, at most `length`, within the section's raw data (or the file)."""
        span = self.find(rva)
        if span is None:
            if rva >= self.size:
                return None
            return rva, min(self.size, rva + length)
        start = rva - span[0] + span[2]
        end = min(start + length, span[3], self.size)
        return (start, end) if start < end else None


def _string(data: bytes, amap: _Map, rva: int, limit: int = MAX_NAME) -> str | None:
    w = amap.window(rva, limit)
    if w is None:
        return None
    raw = data[w[0] : w[1]]
    return raw.split(b"\0", 1)[0].decode("latin-1")


def parse_headers(data: bytes) -> PE:
    """The DOS, COFF and optional headers and the section table; raises PEError if they are not there."""
    if len(data) < 64 or data[:2] != b"MZ":
        raise PEError("no MZ signature: not a PE file")
    e_lfanew = _u32(data, 0x3C)
    _need(data, e_lfanew, 24, "the PE header")
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise PEError(f"no PE signature at {e_lfanew:#x}")
    coff = e_lfanew + 4
    machine, nsections, timestamp, _sym, _nsym, opt_size, characteristics = struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    _need(data, opt, 2, "the optional header")
    magic = _u16(data, opt)
    if magic == 0x10B:
        pe32plus, fixed = False, 96
    elif magic == 0x20B:
        pe32plus, fixed = True, 112
    else:
        raise PEError(f"unknown optional header magic {magic:#x}")
    _need(data, opt, fixed, "the optional header")
    entry_point = _u32(data, opt + 16)
    image_base = struct.unpack_from("<Q", data, opt + 24)[0] if pe32plus else _u32(data, opt + 28)
    section_alignment, file_alignment = struct.unpack_from("<II", data, opt + 32)
    size_of_image, size_of_headers, checksum = struct.unpack_from("<III", data, opt + 56)
    subsystem, dll_characteristics = struct.unpack_from("<HH", data, opt + 68)
    n_dirs = _u32(data, opt + fixed - 4)
    dirs = []
    for i in range(min(n_dirs, 16)):
        off = opt + fixed + 8 * i
        if off + 8 > len(data):
            break
        dirs.append(struct.unpack_from("<II", data, off))
    sections = []
    warnings = []
    table = opt + opt_size
    va_align = file_alignment if section_alignment < 0x1000 else section_alignment
    for i in range(min(nsections, MAX_SECTIONS)):
        off = table + 40 * i
        raw = data[off : off + 40]
        if len(raw) < 40 or raw.count(0) == 40:
            break
        name = section_name(raw[:8])
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", raw, 8)
        ch = struct.unpack_from("<I", raw, 36)[0]
        # a header with three or more impossible values ends the table (where pefile stops reading too)
        problems = [
            rptr + rsize > len(data),
            (rptr & ~0x1FF) > len(data),
            vsize > 0x10000000,
            (va_align * (va // va_align) if va_align else va) > 0x10000000,
            bool(file_alignment) and rptr % file_alignment != 0,
        ]
        if sum(problems) >= 3:
            warnings.append(f"section header {i} has {sum(problems)} impossible values: the table ends there")
            break
        sections.append(Section(name, va, vsize, rptr, rsize, ch))
    return PE(
        size=len(data),
        machine=machine,
        sections_declared=nsections,
        timestamp=timestamp,
        characteristics=characteristics,
        pe32plus=pe32plus,
        entry_point=entry_point,
        image_base=image_base,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        checksum=checksum,
        checksum_offset=opt + 64,
        subsystem=subsystem,
        dll_characteristics=dll_characteristics,
        directories=tuple((int(a), int(b)) for a, b in dirs),
        sections=tuple(sections),
        warnings=warnings,
    )


def _imports(data: bytes, pe: PE, amap: _Map) -> None:
    rva, _size = pe.directory(DIR_IMPORT)
    if not rva:
        return
    width, flag = (8, 1 << 63) if pe.pe32plus else (4, 1 << 31)
    imports: list[Import] = []
    dlls: list[str] = []
    for _ in range(MAX_IMPORT_DLLS):
        w = amap.window(rva, 20)
        if w is None or w[1] - w[0] < 20:
            if w is not None:
                pe.warnings.append(f"import descriptor at {rva:#x} is cut short")
            break
        oft, _ts, _fwd, name_rva, ft = struct.unpack_from("<IIIII", data, w[0])
        if not (oft or _ts or _fwd or name_rva or ft):
            break
        rva += 20
        dll = _string(data, amap, name_rva) if name_rva else None
        if not dll:
            pe.warnings.append(f"import descriptor without a DLL name at {rva - 20:#x}")
            continue
        dlls.append(dll)
        thunk = oft or ft
        for _ in range(MAX_IMPORT_SYMBOLS):
            tw = amap.window(thunk, width)
            if tw is None or tw[1] - tw[0] < width:
                pe.warnings.append(f"thunk table of {dll} is cut short")
                break
            value = int.from_bytes(data[tw[0] : tw[1]], "little")
            if value == 0:
                break
            thunk += width
            if value & flag:
                imports.append(Import(dll, None, value & 0xFFFF))
            else:
                name = _string(data, amap, (value & 0x7FFFFFFF) + 2, MAX_NAME)
                imports.append(Import(dll, name or None, None if name else 0))
        else:
            pe.warnings.append(f"more than {MAX_IMPORT_SYMBOLS} imports from {dll}")
    pe.imports = tuple(imports)
    pe.import_dlls = tuple(dlls)


def _exports(data: bytes, pe: PE, amap: _Map) -> None:
    rva, _size = pe.directory(DIR_EXPORT)
    if not rva:
        return
    w = amap.window(rva, 40)
    if w is None or w[1] - w[0] < 40:
        pe.warnings.append("export directory is cut short")
        return
    name_rva, _base, n_functions, n_names = struct.unpack_from("<IIII", data, w[0] + 12)
    pe.export_name = _string(data, amap, name_rva) if name_rva else None
    pe.export_functions, pe.export_names = n_functions, n_names


def parse(data: bytes) -> PE:
    """Parse a whole PE file held in memory."""
    pe = parse_headers(data)
    amap = _Map(data, pe.sections, pe.section_alignment, pe.file_alignment)
    _imports(data, pe, amap)
    _exports(data, pe, amap)
    return pe


def rva_section(pe: PE, rva: int) -> Section | None:
    """The section whose virtual range holds `rva` (the larger of the virtual and raw size), in table order."""
    for s in pe.sections:
        if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
            return s
    return None


def section_bytes(data: bytes, pe: PE, s: Section) -> bytes:
    """The raw bytes of a section as the loader reads them (pointer rounded down to 512, never past the raw end)."""
    start = s.raw_offset & ~0x1FF
    if pe.section_alignment < 0x1000 and s.raw_offset == s.virtual_address:
        start = s.virtual_address
    end = min(start + s.raw_size, s.raw_offset + s.raw_size)
    return data[start:end]


def overlay_offset(pe: PE) -> int:
    """Where the data appended after the last section begins (the file size when there is none)."""
    ends = [s.raw_offset + s.raw_size for s in pe.sections if s.raw_size]
    if not ends:
        return pe.size
    return min(max(pe.size_of_headers, *ends), pe.size)


def checksum(data: bytes, checksum_offset: int) -> int:
    """The PE checksum (what the header's CheckSum field should hold): the 32-bit words of the file, skipping the
    field itself, added with end-around carry, folded to 16 bits, plus the file size."""
    whole = len(data) // 4 * 4
    words = np.frombuffer(data, dtype="<u4", count=whole // 4)
    total = int(words.sum(dtype=np.uint64))
    if len(data) > whole:
        total += int.from_bytes(data[whole:], "little")
    skip = checksum_offset // 4
    if skip < len(words):
        total -= int(words[skip])
    elif skip == len(words) and len(data) > whole:
        total -= int.from_bytes(data[whole:], "little")
    while total >> 32:
        total = (total & 0xFFFFFFFF) + (total >> 32)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total + (total >> 16)) & 0xFFFF
    return total + len(data)
