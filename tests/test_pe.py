"""The parser on files whose every value is known, worked out by hand from the builder's layout."""

from __future__ import annotations

import struct
from collections.abc import Callable

import pytest

from pescan import build as B
from pescan import pe as P

from .conftest import NOW


def test_headers_of_a_64_bit_executable(make: Callable[..., bytes]) -> None:
    data = make()
    pe = P.parse(data)
    assert (pe.machine, pe.pe32plus, pe.is_dll, pe.subsystem) == (0x8664, True, False, 3)
    assert pe.timestamp == NOW - 1000 and pe.image_base == 0x140000000
    assert (pe.section_alignment, pe.file_alignment, pe.size_of_headers) == (0x1000, 0x200, 0x200)
    # headers: 0x80 + 4 + 20 + 240 + 3 x 40 = 0x200 bytes exactly; then .text (2,048 bytes), .rdata (900 bytes, 1,024
    # raw) and the generated .idata, each at the next page in memory and the next 512 bytes in the file
    assert [(s.name, s.virtual_address, s.raw_offset, s.raw_size) for s in pe.sections] == [
        (".text", 0x1000, 0x200, 0x800),
        (".rdata", 0x2000, 0xA00, 0x400),
        (".idata", 0x3000, 0xE00, 0x200),
    ]
    assert pe.entry_point == 0x1000 and pe.sections[0].executable and not pe.sections[0].writable
    assert pe.size_of_image == 0x4000
    assert pe.checksum_offset == 0x80 + 24 + 64
    assert pe.security_size == 512 and pe.directory(P.DIR_SECURITY)[0] == 0x1000  # right after the last section
    assert len(data) == 0x1000 + 512
    assert pe.directory(99) == (0, 0) and pe.warnings == []


def test_headers_of_a_32_bit_dll(make: Callable[..., bytes]) -> None:
    pe = P.parse(make(pe32plus=False, dll=True, subsystem=2, export=("x.dll", ["One", "Two", "Three"])))
    assert (pe.machine, pe.pe32plus, pe.is_dll, pe.subsystem, pe.image_base) == (0x14C, False, True, 2, 0x400000)
    assert pe.export_name == "x.dll" and (pe.export_names, pe.export_functions) == (3, 3)
    assert len(pe.directories) == 16


def test_imports_by_name_and_by_ordinal(make: Callable[..., bytes]) -> None:
    for plus in (True, False):
        pe = P.parse(
            make(
                pe32plus=plus, imports=[("KERNEL32.dll", ["Sleep", "ExitProcess"]), ("WS2_32.dll", [3, 115, "connect"])]
            )
        )
        assert [(i.dll, i.name, i.ordinal) for i in pe.imports] == [
            ("KERNEL32.dll", "Sleep", None),
            ("KERNEL32.dll", "ExitProcess", None),
            ("WS2_32.dll", None, 3),
            ("WS2_32.dll", None, 115),
            ("WS2_32.dll", "connect", None),
        ]
        assert pe.import_dlls == ("KERNEL32.dll", "WS2_32.dll")


def test_no_imports_no_exports(make: Callable[..., bytes]) -> None:
    pe = P.parse(make(imports=[]))
    assert pe.imports == () and pe.import_dlls == () and pe.export_name is None
    assert [s.name for s in pe.sections] == [".text", ".rdata"]  # nothing to generate: no .idata


def test_flags_tls_and_dotnet(make: Callable[..., bytes]) -> None:
    pe = P.parse(make(tls_callbacks=2, dotnet=True))
    assert pe.has_tls and pe.is_dotnet
    pe = P.parse(make())
    assert not pe.has_tls and not pe.is_dotnet


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "no MZ"),
        (b"MZ" + b"\0" * 10, "no MZ"),
        (b"ZM" + b"\0" * 100, "no MZ"),
        (b"MZ" + b"\0" * 58 + struct.pack("<I", 0x1000) + b"\0" * 100, "outside the file"),
        (b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40) + b"NE\0\0" + b"\0" * 100, "no PE signature"),
    ],
)
def test_not_a_pe(data: bytes, message: str) -> None:
    with pytest.raises(P.PEError, match=message):
        P.parse(data)


def test_bad_optional_header(make: Callable[..., bytes]) -> None:
    data = bytearray(make())
    struct.pack_into("<H", data, 0x80 + 24, 0x107)  # a ROM image magic
    with pytest.raises(P.PEError, match="magic 0x107"):
        P.parse(bytes(data))
    with pytest.raises(P.PEError, match="optional header"):
        P.parse(bytes(make()[: 0x80 + 24 + 50]))


def test_section_table_stops_at_an_empty_header_or_an_impossible_one(make: Callable[..., bytes]) -> None:
    data = bytearray(make())
    struct.pack_into("<H", data, 0x80 + 6, 40)  # 40 sections declared, 3 present, then zeros
    pe = P.parse(bytes(data))
    assert len(pe.sections) == 3 and pe.sections_declared == 40
    table = 0x80 + 24 + 240
    struct.pack_into("<IIII", data, table + 40 + 8, 0x20000000, 0x20000000, 0x400, 0x7FFFFFF1)  # three problems
    pe = P.parse(bytes(data))
    assert [s.name for s in pe.sections] == [".text"] and "impossible" in pe.warnings[0]
    struct.pack_into("<IIII", data, table + 40 + 8, 0x20000000, 0x2000, 0x400, 0xC00)  # one problem only: kept
    assert len(P.parse(bytes(data)).sections) == 3


def test_address_map_follows_the_loader_rules(make: Callable[..., bytes]) -> None:
    data = make()
    pe = P.parse(data)
    amap = P._Map(data, pe.sections, pe.section_alignment, pe.file_alignment)
    assert amap.offset(0x1010) == 0x210  # inside .text
    assert amap.offset(0x2384) == 0xD84  # inside .rdata's raw data
    assert amap.offset(0x10) == 0x10  # in the headers: the address is the offset
    assert amap.offset(0x9000) is None  # beyond everything
    assert amap.window(0x2380, 0x1000) == (0xD80, 0xE00)  # cut at the end of .rdata's raw data
    assert amap.window(0x2400, 8) is None  # .rdata's virtual tail has no bytes in the file
    s = P.Section(".odd", 0x1000, 0x100, 0x203, 0x200, P.SCN_READ)  # unaligned pointer: rounded down to 512
    m = P._Map(b"\0" * 0x1000, (s,), 0x1000, 0x200)
    assert m.offset(0x1004) == 0x204
    s = P.Section(".big", 0x1000, 0x80, 0x400, 0x10000, P.SCN_READ)  # raw size past the end: the virtual size counts
    m = P._Map(b"\0" * 0x1000, (s,), 0x1000, 0x200)
    assert m.find(0x1080) is None and m.find(0x107F) is not None
    s = P.Section(".low", 0x200, 0x200, 0x200, 0x200, P.SCN_READ)  # section alignment below a page: raw = virtual
    m = P._Map(b"\0" * 0x1000, (s,), 0x200, 0x200)
    assert m.offset(0x210) == 0x210
    a = P.Section(".a", 0x1000, 0x3000, 0x400, 0x200, P.SCN_READ)  # overlaps the next section: cut at its start
    b = P.Section(".b", 0x2000, 0x100, 0x600, 0x200, P.SCN_READ)
    m = P._Map(b"\0" * 0x1000, (b, a), 0x1000, 0x200)
    assert m.find(0x1FFF) is not None and m.find(0x2000) == (
        0x2000,
        0x2200,
        0x600,
        0x800,
    )  # the larger of 0x100 and 0x200


def test_checksum_against_the_word_by_word_definition() -> None:
    for n in (64, 65, 66, 67, 4096, 4099):
        data = bytes((i * 31 + 7) % 256 for i in range(n))
        for off in (0, 8, 60):
            assert P.checksum(data, off) == B.checksum_of(data, off)
    data = b"\xff" * 64  # every word all ones: the end-around carry decides
    assert P.checksum(data, 0) == B.checksum_of(data, 0)
    assert P.checksum(b"\x01\x02\x03", 0) == 3  # the only (partial) word is the checksum field itself
    assert P.checksum(b"\x01\x02\x03", 8) == B.checksum_of(b"\x01\x02\x03", 8) == 0x0201 + 0x03 + 3


def test_section_bytes_and_overlay(make: Callable[..., bytes]) -> None:
    data = make(overlay=b"O" * 700)
    pe = P.parse(data)
    assert P.section_bytes(data, pe, pe.sections[0]) == data[0x200:0xA00]
    assert P.overlay_offset(pe) == 0x1000
    empty = P.PE(0x100, 0, 0, 0, 0, True, 0, 0, 0x1000, 0x200, 0, 0x400, 0, 0, 0, 0, (), ())
    assert P.overlay_offset(empty) == 0x100
    s = P.Section(".low", 0x200, 0x10, 0x200, 0x10, P.SCN_READ)
    low = P.PE(0x400, 0, 0, 0, 0, True, 0, 0, 0x200, 0x200, 0, 0x200, 0, 0, 0, 0, (), (s,))
    assert P.section_bytes(b"x" * 0x400, low, s) == b"x" * 0x10
