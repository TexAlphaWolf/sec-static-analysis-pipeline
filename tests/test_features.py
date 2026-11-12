"""Hashes, entropy, strings and every trait on hand-made files, each trait through Python and through YARA."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable
from typing import Any

import pytest

from pescan import build as B
from pescan import features as F
from pescan import pe as P
from pescan import yarascan

from .conftest import NOW, text


def both(data: bytes, now: int = NOW) -> list[str]:
    """The traits by Python, after checking YARA finds exactly the same."""
    py = F.traits(data, P.parse(data), now)
    assert yarascan.match(data, now) == py
    return py


def test_entropy_known_values() -> None:
    assert F.entropy(b"") == F.entropy_literal(b"") == 0.0
    assert F.entropy(b"\0" * 100) == 0.0
    assert F.entropy(b"ab" * 50) == pytest.approx(1.0)
    assert F.entropy(bytes(range(256))) == pytest.approx(8.0)
    assert F.entropy(b"aaab") == pytest.approx(-(0.75 * math.log2(0.75) + 0.25 * math.log2(0.25)))
    data = bytes((i * i + 3 * i) % 251 for i in range(5000))
    assert F.entropy(data) == pytest.approx(F.entropy_literal(data), abs=1e-12)


def test_hashes() -> None:
    h = F.hashes(b"abc")
    assert h["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert h["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert h["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_import_hash_rules(make: Callable[..., bytes]) -> None:
    data = make(
        imports=[
            ("KERNEL32.dll", ["GetProcAddress"]),
            ("WS2_32.dll", [3, "connect"]),
            ("odd.exe", [5]),
            ("x.OCX", ["F"]),
        ]
    )
    expected = "kernel32.getprocaddress,ws2_32.closesocket,ws2_32.connect,odd.exe.ord5,x.f"
    assert F.imphash(P.parse(data)) == hashlib.md5(expected.encode()).hexdigest()
    assert F.imphash(P.parse(make(imports=[]))) == ""


def test_strings() -> None:
    blob = (
        b"\0\0see https://example.org/path?q=1 and http://10.0.0.1:8080/x\0"
        b"server 192.168.1.20 not 999.1.1.1 nor 1.2.3.4.5\0"
        b"HKEY_LOCAL_MACHINE\\Software\\X\0hklm\\run\0short\0"
        + "wide http://wide.example.net/w".encode("utf-16-le")
        + b"\0\0"
    )
    s = F.strings(blob)
    assert s.urls == ("https://example.org/path?q=1", "http://10.0.0.1:8080/x", "http://wide.example.net/w")
    assert s.ipv4 == ("10.0.0.1", "192.168.1.20")
    assert s.registry == 2 and s.utf16 == 1 and s.ascii == 4  # "short" is too short to count
    many = b" ".join(b"https://h%d.example/" % i for i in range(50)) + b" " + b"https://h0.example/"
    assert F.strings(many, keep=3).urls == ("https://h0.example/", "https://h1.example/", "https://h2.example/")


def test_a_plain_file_has_no_trait(make: Callable[..., bytes]) -> None:
    assert both(make()) == []


CASES: list[tuple[str, dict[str, Any]]] = [
    ("packer_section", {"sections": [B.SectionSpec("UPX1", text(), B.CODE)]}),
    ("high_entropy_code", {"sections": [B.SectionSpec(".text", bytes(range(256)) * 8, B.CODE)]}),
    ("writable_code", {"sections": [B.SectionSpec(".text", text(), B.CODE | 0x80000000)]}),
    (
        "entry_outside_code",
        {
            "sections": [B.SectionSpec(".text", text(), B.CODE), B.SectionSpec(".rdata", text(), B.RDATA)],
            "entry": (1, 16),
        },
    ),
    (
        "injection_imports",
        {"imports": [("KERNEL32.dll", ["Sleep", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThreadEx"])]},
    ),
    (
        "debugger_check",
        {"imports": [("KERNEL32.dll", ["Sleep", "ExitProcess", "ReadFile", "CheckRemoteDebuggerPresent"])]},
    ),
    ("few_imports", {"imports": [("KERNEL32.dll", ["Sleep", "ExitProcess", "ReadFile"])]}),
    ("checksum_mismatch", {"checksum": "bad"}),
    ("future_timestamp", {"timestamp": NOW + 1}),
    ("overlay", {"overlay": b"x" * 512}),
    ("tls", {"tls_callbacks": 1}),
    ("no_aslr", {"dll_characteristics": 0x4120}),
    ("no_dep", {"dll_characteristics": 0x4060}),
    ("no_cfg", {"dll_characteristics": 0x0160}),
    ("no_high_entropy_va", {"dll_characteristics": 0x4140}),
    ("no_embedded_signature", {"signature": 0}),
]


@pytest.mark.parametrize(("trait", "kw"), CASES, ids=[c[0] for c in CASES])
def test_each_trait_alone(make: Callable[..., bytes], trait: str, kw: dict[str, Any]) -> None:
    assert both(make(**kw)) == [trait]


NEAR_MISSES: list[tuple[str, dict[str, Any]]] = [
    (
        "compressed data that is not code",
        {"sections": [B.SectionSpec(".text", text(), B.CODE), B.SectionSpec(".rsrc", bytes(range(256)) * 8, B.RDATA)]},
    ),
    ("entropy just under the line", {"sections": [B.SectionSpec(".text", bytes(range(128)) * 16, B.CODE)]}),  # 7 bits
    ("a DLL without an entry point", {"dll": True, "entry": None, "imports": [("KERNEL32.dll", ["Sleep"])]}),
    (
        "two of the three injection imports",
        {"imports": [("KERNEL32.dll", ["Sleep", "VirtualAllocEx", "WriteProcessMemory", "ReadFile"])]},
    ),
    ("a .NET file with one import", {"dotnet": True, "imports": [("mscoree.dll", ["_CorExeMain"])]}),
    ("a checksum of zero", {"checksum": "zero"}),
    ("a time stamp of now", {"timestamp": NOW}),
    ("511 bytes of overlay", {"overlay": b"x" * 511, "signature": 0, "dll_characteristics": 0x4160}),
    ("a large signature and a small overlay", {"overlay": b"x" * 100, "signature": 4096}),
    ("32-bit without high-entropy VA", {"pe32plus": False, "dll_characteristics": 0x4140}),
    ("a packer's name as a substring", {"sections": [B.SectionSpec(".UPX0x", text(), B.CODE)]}),
]


@pytest.mark.parametrize(("why", "kw"), NEAR_MISSES, ids=[c[0] for c in NEAR_MISSES])
def test_near_misses_have_no_trait(make: Callable[..., bytes], why: str, kw: dict[str, Any]) -> None:
    got = both(make(**kw))
    assert got in ([], ["no_embedded_signature"]), why


def test_overlay_counts_the_signature_out(make: Callable[..., bytes]) -> None:
    pe = P.parse(make(overlay=b"x" * 600, signature=1024))
    assert F.overlay_extra(pe) == 600  # 600 is a multiple of 8: no padding before the signature
    pe = P.parse(make(overlay=b"", signature=1024))
    assert F.overlay_extra(pe) == 0
    data = bytearray(make(overlay=b"x" * 2000, signature=0))
    pe = P.parse(bytes(data))
    assert F.overlay_extra(pe) == 2000


def test_several_traits_in_order(make: Callable[..., bytes]) -> None:
    data = make(
        sections=[B.SectionSpec("UPX0", bytes(range(256)) * 16, B.CODE | 0x80000000)],
        imports=[("KERNEL32.dll", ["IsDebuggerPresent"])],
        tls_callbacks=1,
        checksum="bad",
        dll_characteristics=0,
        signature=0,
        timestamp=NOW + 3600,
    )
    assert both(data) == [
        "packer_section",
        "high_entropy_code",
        "writable_code",
        "debugger_check",
        "few_imports",
        "checksum_mismatch",
        "future_timestamp",
        "tls",
        "no_aslr",
        "no_dep",
        "no_cfg",
        "no_high_entropy_va",
        "no_embedded_signature",
    ]


def test_describe_record(make: Callable[..., bytes]) -> None:
    data = make(
        imports=[("KERNEL32.dll", ["Sleep", "Sleep", "ReadFile", "WriteFile"])], export=("me.dll", ["A"]), dll=True
    )
    rec = F.describe(data, P.parse(data), NOW)
    assert rec["machine"] == "x64" and rec["bits"] == 64 and rec["dll"] and rec["subsystem"] == "windows console"
    assert rec["imports"] == 4 and rec["imported"] == ["ReadFile", "Sleep", "WriteFile"]
    assert rec["export_name"] == "me.dll" and rec["exports"] == 1
    assert rec["checksum"] == rec["checksum_computed"] and rec["signature_size"] == 512
    assert [s["name"] for s in rec["sections"]] == [".text", ".rdata", ".idata"]
    assert rec["sections"][1]["entropy"] == pytest.approx(F.entropy((b"abc" * 300).ljust(1024, b"\0")))
    assert rec["traits"] == [] and rec["warnings"] == []


def test_urls_in_certificates_do_not_take_the_next_byte() -> None:
    blob = b"\x86\x1ehttp://www.microsoft.com/pki/crl0\x06http://crl.example.com0Z\0http://10.1.2.3:80/a\0http://x.y\0"
    assert F.strings(blob).urls == (
        "http://www.microsoft.com/pki/crl0",
        "http://crl.example.com",
        "http://10.1.2.3:80/a",
    )


def test_a_timed_out_yara_scan_is_run_again(make: Callable[..., bytes], monkeypatch: pytest.MonkeyPatch) -> None:
    import yara

    real = yarascan.compiled()
    calls: list[int] = []

    class Flaky:
        def match(self, **kw: Any) -> Any:
            calls.append(1)
            if len(calls) == 1:
                raise yara.TimeoutError("scanning timed out")
            return real.match(**kw)

    monkeypatch.setattr(yarascan, "compiled", lambda: Flaky())
    before = len(yarascan.RETRIES)
    assert yarascan.match(make(tls_callbacks=1), NOW) == ["tls"]
    assert len(calls) == 2 and len(yarascan.RETRIES) == before + 1
