"""A small PE writer for tests and synthetic corpora: the files are well formed, never meant to run (the code sections hold
filler bytes, not instructions), and every property the analysis looks for is set from the specification, so the truth of
each file is known without parsing it.

It shares no code with the parser: offsets, tables and the checksum are computed here in their own way.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
IMAGE_BASE_32 = 0x400000
IMAGE_BASE_64 = 0x140000000

CODE = 0x60000020  # code, execute, read
DATA = 0xC0000040  # initialised data, read, write
RDATA = 0x40000040  # initialised data, read


@dataclass
class SectionSpec:
    name: str
    data: bytes
    characteristics: int = DATA
    virtual_size: int | None = None


@dataclass
class Spec:
    pe32plus: bool = True
    timestamp: int = 0x60000000
    dll: bool = False
    subsystem: int = 3
    dll_characteristics: int = 0x8160  # high-entropy VA, dynamic base, NX, terminal-server aware
    sections: list[SectionSpec] = field(default_factory=list)
    imports: list[tuple[str, list[str | int]]] = field(default_factory=list)
    export: tuple[str, list[str]] | None = None
    entry: tuple[int, int] | None = (0, 0)  # (section index, offset in it); None: entry point 0
    tls_callbacks: int = 0
    dotnet: bool = False
    signature: int = 0  # bytes of an (unverifiable) Authenticode blob at the end of the file
    overlay: bytes = b""  # data appended after the sections, before the signature
    checksum: str = "good"  # good, zero or bad
    machine: int | None = None


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def _tables(spec: Spec, base_rva: int, code_rva: int, image_base: int) -> tuple[bytes, dict[int, tuple[int, int]]]:
    """The generated table section (imports, exports, TLS, CLR header) laid out at `base_rva`, and the data directories."""
    out = bytearray()
    dirs: dict[int, tuple[int, int]] = {}
    w = 8 if spec.pe32plus else 4
    ordinal_flag = 1 << (63 if spec.pe32plus else 31)

    def here() -> int:
        return base_rva + len(out)

    def put(b: bytes) -> int:
        rva = here()
        out.extend(b)
        return rva

    def pad(n: int = 8) -> None:
        out.extend(b"\0" * ((-len(out)) % n))

    if spec.imports:
        n = len(spec.imports)
        desc_at = len(out)
        out.extend(b"\0" * (20 * (n + 1)))
        dirs[1] = (base_rva + desc_at, 20 * (n + 1))
        for i, (dll, names) in enumerate(spec.imports):
            pad()
            hint_rvas: list[int] = []
            for item in names:
                if isinstance(item, int):
                    hint_rvas.append(-1)
                else:
                    pad(2)
                    hint_rvas.append(put(struct.pack("<H", 0) + item.encode() + b"\0"))
            pad()
            thunks = (
                b"".join(
                    (ordinal_flag | item).to_bytes(w, "little")
                    if isinstance(item, int)
                    else hint_rvas[k].to_bytes(w, "little")
                    for k, item in enumerate(names)
                )
                + b"\0" * w
            )
            ilt = put(thunks)
            iat = put(thunks)
            name = put(dll.encode() + b"\0")
            struct.pack_into("<IIIII", out, desc_at + 20 * i, ilt, 0, 0, name, iat)
    if spec.export:
        pad()
        exp_dll, exp_names = spec.export
        at = len(out)
        out.extend(b"\0" * 40)
        funcs = put(b"".join(struct.pack("<I", code_rva) for _ in exp_names))
        name_rvas = [put(n.encode() + b"\0") for n in sorted(exp_names)]
        pad(4)
        names_at = put(b"".join(struct.pack("<I", r) for r in name_rvas))
        ords = put(b"".join(struct.pack("<H", i) for i in range(len(exp_names))))
        dll_name = put(exp_dll.encode() + b"\0")
        struct.pack_into(
            "<IIHHIIIIIII", out, at, 0, 0, 0, 0, dll_name, 1, len(exp_names), len(exp_names), funcs, names_at, ords
        )
        dirs[0] = (base_rva + at, len(out) - at)
    if spec.tls_callbacks:
        pad()
        index = put(b"\0" * 4)
        pad()
        callbacks = put(
            b"".join((image_base + code_rva).to_bytes(w, "little") for _ in range(spec.tls_callbacks)) + b"\0" * w
        )
        fmt = "<QQQQII" if spec.pe32plus else "<IIIIII"
        tls = put(struct.pack(fmt, 0, 0, image_base + index, image_base + callbacks, 0, 0))
        dirs[9] = (tls, struct.calcsize(fmt))
    if spec.dotnet:
        pad()
        clr = put(struct.pack("<IHH", 72, 2, 5) + b"\0" * 64)
        dirs[14] = (clr, 72)
    if not out:
        out.extend(b"\0" * 16)
    return bytes(out), dirs


def checksum_of(data: bytes, checksum_offset: int) -> int:
    """The PE checksum computed one word at a time, as the format describes it."""
    total = 0
    padded = data + b"\0" * ((-len(data)) % 4)
    for i in range(0, len(padded), 4):
        if i == checksum_offset:
            continue
        total += int.from_bytes(padded[i : i + 4], "little")
        total = (total & 0xFFFFFFFF) + (total >> 32)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total + (total >> 16)) & 0xFFFF
    return total + len(data)


def build(spec: Spec) -> bytes:
    """The bytes of the PE file `spec` describes."""
    sections = list(spec.sections)
    needs_tables = bool(spec.imports or spec.export or spec.tls_callbacks or spec.dotnet)
    n_sections = len(sections) + (1 if needs_tables else 0)
    opt_size = 240 if spec.pe32plus else 224
    e_lfanew = 0x80
    headers = _align(e_lfanew + 4 + 20 + opt_size + 40 * n_sections, FILE_ALIGN)
    image_base = IMAGE_BASE_64 if spec.pe32plus else IMAGE_BASE_32

    layout: list[tuple[str, bytes, int, int, int]] = []  # (name, data, characteristics, rva, virtual size)
    rva = SECT_ALIGN
    for s in sections:
        vsize = s.virtual_size if s.virtual_size is not None else max(len(s.data), 1)
        layout.append((s.name, s.data, s.characteristics, rva, vsize))
        rva = _align(rva + max(vsize, len(s.data), 1), SECT_ALIGN)
    code_rva = next((row[3] for row in layout if row[2] & 0x20000000), layout[0][3] if layout else SECT_ALIGN)
    dirs: dict[int, tuple[int, int]] = {}
    if needs_tables:
        table, dirs = _tables(spec, rva, code_rva, image_base)
        layout.append((".idata", table, DATA, rva, len(table)))
        rva = _align(rva + len(table), SECT_ALIGN)
    size_of_image = rva

    body = bytearray()
    raw = headers
    table_rows: list[bytes] = []
    for name, data, ch, va, vsize in layout:
        rsize = _align(len(data), FILE_ALIGN) if data else 0
        ptr = raw if data else 0
        table_rows.append(struct.pack("<8sIIIIIIHHI", name.encode()[:8], vsize, va, rsize, ptr, 0, 0, 0, 0, ch))
        if data:
            body.extend(data + b"\0" * (rsize - len(data)))
            raw += rsize

    entry = 0
    if spec.entry is not None and layout:
        idx, off = spec.entry
        entry = layout[idx][3] + off
    code_size = sum(_align(len(r[1]), FILE_ALIGN) for r in layout if r[2] & 0x20)
    data_size = sum(_align(len(r[1]), FILE_ALIGN) for r in layout if not r[2] & 0x20)
    characteristics = 0x0022 | (0x2000 if spec.dll else 0) | (0 if spec.pe32plus else 0x0100)
    machine = spec.machine if spec.machine is not None else (0x8664 if spec.pe32plus else 0x14C)

    head = bytearray(headers)
    head[0:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, e_lfanew)
    stub = b"This program is a test file and cannot be run.\r\n$"
    head[0x40 : 0x40 + len(stub)] = stub
    head[e_lfanew : e_lfanew + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH", head, e_lfanew + 4, machine, n_sections, spec.timestamp, 0, 0, opt_size, characteristics
    )
    opt = e_lfanew + 24
    base_of_code = code_rva
    if spec.pe32plus:
        struct.pack_into("<HBBIIIII", head, opt, 0x20B, 14, 30, code_size, data_size, 0, entry, base_of_code)
        struct.pack_into("<Q", head, opt + 24, image_base)
        rest = opt + 32
    else:
        struct.pack_into("<HBBIIIIII", head, opt, 0x10B, 14, 30, code_size, data_size, 0, entry, base_of_code, 0)
        struct.pack_into("<I", head, opt + 28, image_base)
        rest = opt + 32
    struct.pack_into(
        "<IIHHHHHHIIII", head, rest, SECT_ALIGN, FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0, size_of_image, headers, 0
    )
    struct.pack_into("<HH", head, opt + 68, spec.subsystem, spec.dll_characteristics)
    if spec.pe32plus:
        struct.pack_into("<QQQQII", head, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        dir_at = opt + 112
    else:
        struct.pack_into("<IIIIII", head, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        dir_at = opt + 96
    for index, (d_rva, d_size) in dirs.items():
        struct.pack_into("<II", head, dir_at + 8 * index, d_rva, d_size)
    table_at = opt + opt_size
    for i, row in enumerate(table_rows):
        head[table_at + 40 * i : table_at + 40 * (i + 1)] = row

    out = bytearray(head) + body + spec.overlay
    if spec.signature:
        out.extend(b"\0" * ((-len(out)) % 8))
        sig_at = len(out)
        blob = struct.pack("<IHH", spec.signature, 0x200, 2) + bytes(
            (i * 37 + 11) % 256 for i in range(spec.signature - 8)
        )
        out.extend(blob)
        struct.pack_into("<II", out, dir_at + 8 * 4, sig_at, spec.signature)
    checksum_offset = opt + 64
    if spec.checksum == "good":
        struct.pack_into("<I", out, checksum_offset, checksum_of(bytes(out), checksum_offset))
    elif spec.checksum == "bad":
        good = checksum_of(bytes(out), checksum_offset)
        struct.pack_into("<I", out, checksum_offset, (good ^ 0x5A5A) or 1)
    return bytes(out)
