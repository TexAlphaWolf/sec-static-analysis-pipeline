"""The same fields read by pefile, the reference parser, and by this package's parser, in one comparable shape."""

from __future__ import annotations

from typing import Any

import pefile

from . import features as F
from . import pe as P

DIRS = [
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
]
CHECKSUM_MAX = 4 << 20  # pefile's checksum is one Python loop per word: compared only on files up to 4 MiB

FIELDS = (
    "machine",
    "timestamp",
    "characteristics",
    "pe32plus",
    "entry_point",
    "image_base",
    "section_alignment",
    "file_alignment",
    "size_of_image",
    "size_of_headers",
    "checksum",
    "subsystem",
    "dll_characteristics",
    "directories",
    "sections",
    "entropy",
    "imports",
    "export",
    "imphash",
    "checksum_computed",
)


def _str(b: bytes | str | None) -> str | None:
    if b is None:
        return None
    return b.decode("latin-1") if isinstance(b, bytes) else b


def view_reference(data: bytes) -> dict[str, Any]:
    """What pefile reads; raises pefile.PEFormatError where pefile refuses the file."""
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=DIRS)
    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    secs = sorted(pe.sections, key=lambda s: s.VirtualAddress)
    imports: list[tuple[str, str | None, int | None]] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = _str(entry.dll) or ""
        for imp in entry.imports:
            if imp.import_by_ordinal:
                imports.append((dll, None, imp.ordinal))
            else:
                imports.append((dll, _str(imp.name), None))
    export = None
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        st = pe.DIRECTORY_ENTRY_EXPORT.struct
        export = (_str(pe.DIRECTORY_ENTRY_EXPORT.name), st.NumberOfNames, st.NumberOfFunctions)
    return {
        "machine": fh.Machine,
        "timestamp": fh.TimeDateStamp,
        "characteristics": fh.Characteristics,
        "pe32plus": oh.Magic == 0x20B,
        "entry_point": oh.AddressOfEntryPoint,
        "image_base": oh.ImageBase,
        "section_alignment": oh.SectionAlignment,
        "file_alignment": oh.FileAlignment,
        "size_of_image": oh.SizeOfImage,
        "size_of_headers": oh.SizeOfHeaders,
        "checksum": oh.CheckSum,
        "subsystem": oh.Subsystem,
        "dll_characteristics": oh.DllCharacteristics,
        "directories": [(d.VirtualAddress, d.Size) for d in oh.DATA_DIRECTORY],
        "sections": [
            (
                s.Name.split(b"\0", 1)[0].decode("latin-1"),
                s.VirtualAddress,
                s.Misc_VirtualSize,
                s.PointerToRawData,
                s.SizeOfRawData,
                s.Characteristics,
            )
            for s in secs
        ],
        "entropy": [s.get_entropy() for s in secs],
        "imports": imports,
        "export": export,
        "imphash": pe.get_imphash(),
        "checksum_computed": pe.generate_checksum() if len(data) <= CHECKSUM_MAX else None,
    }


def view_own(data: bytes) -> dict[str, Any]:
    """The same fields from this package's parser; raises P.PEError where it refuses the file."""
    pe = P.parse(data)
    order = sorted(range(len(pe.sections)), key=lambda i: pe.sections[i].virtual_address)
    secs = [pe.sections[i] for i in order]
    ent = F.section_entropies(data, pe)
    export = (
        (pe.export_name, pe.export_names, pe.export_functions)
        if pe.directory(P.DIR_EXPORT)[0] and (pe.export_name is not None or pe.export_names or pe.export_functions)
        else None
    )
    return {
        "machine": pe.machine,
        "timestamp": pe.timestamp,
        "characteristics": pe.characteristics,
        "pe32plus": pe.pe32plus,
        "entry_point": pe.entry_point,
        "image_base": pe.image_base,
        "section_alignment": pe.section_alignment,
        "file_alignment": pe.file_alignment,
        "size_of_image": pe.size_of_image,
        "size_of_headers": pe.size_of_headers,
        "checksum": pe.checksum,
        "subsystem": pe.subsystem,
        "dll_characteristics": pe.dll_characteristics,
        "directories": list(pe.directories),
        "sections": [
            (s.name, s.virtual_address, s.virtual_size, s.raw_offset, s.raw_size, s.characteristics) for s in secs
        ],
        "entropy": [ent[i] for i in order],
        "imports": [(i.dll, i.name, i.ordinal) for i in pe.imports],
        "export": export,
        "imphash": F.imphash(pe),
        "checksum_computed": P.checksum(data, pe.checksum_offset) if len(data) <= CHECKSUM_MAX else None,
    }


def differences(own: dict[str, Any], ref: dict[str, Any], tol: float = 1e-9) -> list[str]:
    """The fields that differ (floats within `tol` are equal)."""
    out = []
    for key in FIELDS:
        a, b = own.get(key), ref.get(key)
        if key == "entropy" and isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
            if all(abs(x - y) <= tol for x, y in zip(a, b, strict=True)):
                continue
        elif a == b:
            continue
        out.append(key)
    return out
