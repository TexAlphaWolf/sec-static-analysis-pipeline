"""What is computed for one file: hashes, the import hash, section entropies, strings worth a look and the traits.

The traits are written twice: here in Python, and as YARA rules in `rules/traits.yar`; `verify` checks they agree.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from dataclasses import dataclass
from typing import Any

import numpy as np
import ordlookup  # the ordinal-to-name tables pefile ships, so that the import hash means what it means elsewhere

from . import pe as P

ENTROPY_HIGH = 7.2
FEW_IMPORTS = 4
OVERLAY_MIN = 512

PACKER_SECTIONS = (
    "UPX0",
    "UPX1",
    "UPX2",
    ".aspack",
    ".adata",
    ".packed",
    "MPRESS1",
    "MPRESS2",
    ".MPRESS1",
    ".MPRESS2",
    ".petite",
    ".nsp0",
    ".nsp1",
    ".nsp2",
    ".vmp0",
    ".vmp1",
    ".vmp2",
    ".themida",
    ".enigma1",
    ".enigma2",
    "PEC2",
    ".perplex",
    ".yP",
    ".kkrunch",
)
DEBUGGER_CHECKS = ("IsDebuggerPresent", "CheckRemoteDebuggerPresent")
INJECTION = ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")

INDICATORS = (
    "packer_section",
    "high_entropy_code",
    "writable_code",
    "entry_outside_code",
    "injection_imports",
    "debugger_check",
    "few_imports",
    "checksum_mismatch",
    "future_timestamp",
    "overlay",
    "tls",
)
HARDENING = ("no_aslr", "no_dep", "no_cfg", "no_high_entropy_va", "no_embedded_signature")
TRAITS = INDICATORS + HARDENING

DESCRIPTIONS = {
    "packer_section": "a section named like a packer's (UPX0, .aspack, .themida ...)",
    "high_entropy_code": f"an executable section with entropy of {ENTROPY_HIGH} bits a byte or more (compressed or encrypted)",
    "writable_code": "a section that is both writable and executable",
    "entry_outside_code": "an entry point that is not inside an executable section",
    "injection_imports": "imports VirtualAllocEx, WriteProcessMemory and CreateRemoteThread together",
    "debugger_check": "imports IsDebuggerPresent or CheckRemoteDebuggerPresent",
    "few_imports": f"native code with an entry point and fewer than {FEW_IMPORTS} imported functions",
    "checksum_mismatch": "a header checksum that is set but wrong",
    "future_timestamp": "a link time stamp later than the time of the scan",
    "overlay": f"at least {OVERLAY_MIN} bytes after the last section that are not the signature",
    "tls": "a TLS directory (code that can run before the entry point)",
    "no_aslr": "not built for address space randomisation (no DYNAMIC_BASE)",
    "no_dep": "not marked compatible with data execution prevention (no NX_COMPAT)",
    "no_cfg": "not built with Control Flow Guard (no GUARD_CF)",
    "no_high_entropy_va": "64-bit without high-entropy ASLR (no HIGH_ENTROPY_VA)",
    "no_embedded_signature": "no Authenticode signature in the file (it may still be signed in a catalog)",
}

# the host ends with a name of letters (or is an IPv4 address): in certificates the next byte is often a printable ASN.1 tag
# ("0"), which would otherwise be read as part of the host ("www.microsoft.com0")
URL = re.compile(
    rb"https?://(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})"
    rb"(?::\d{1,5})?(?:/[\x21-\x7e]*)?"
)
IPV4 = re.compile(rb"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
REGISTRY = re.compile(rb"(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU)\\", re.I)
ASCII = re.compile(rb"[\x20-\x7e]{6,}")
UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


def entropy(data: bytes) -> float:
    """Shannon entropy in bits a byte (0 for no data)."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(data)
    return float(-(p * np.log2(p)).sum())


def entropy_literal(data: bytes) -> float:
    """The same entropy one byte value at a time, the way the definition reads."""
    if not data:
        return 0.0
    total = 0.0
    for c in range(256):
        n = data.count(bytes((c,)))
        if n:
            p = n / len(data)
            total -= p * math.log2(p)
    return total


def imphash(pe: P.PE) -> str:
    """Mandiant's import hash: md5 of 'dll.function' pairs in import order, lower case, the DLL without .dll/.ocx/.sys;
    an import by ordinal from ws2_32, wsock32 or oleaut32 is named from pefile's tables, any other one is 'ordN'."""
    if not pe.imports:
        return ""
    parts = []
    for imp in pe.imports:
        lib = imp.dll.lower()
        stem, dot, ext = lib.rpartition(".")
        if dot and ext in ("ocx", "sys", "dll"):
            lib = stem
        if imp.name is None:
            raw = ordlookup.ordLookup(imp.dll.lower().encode("latin-1"), imp.ordinal or 0, make_name=True)
            func = raw.decode("latin-1") if isinstance(raw, bytes) else str(raw)
        else:
            func = imp.name
        parts.append(f"{lib}.{func.lower()}")
    return hashlib.md5(",".join(parts).encode("latin-1"), usedforsecurity=False).hexdigest()


@dataclass(frozen=True)
class Strings:
    ascii: int
    utf16: int
    urls: tuple[str, ...]
    ipv4: tuple[str, ...]
    registry: int


def strings(data: bytes, keep: int = 20) -> Strings:
    """Printable runs of 6 characters or more (ASCII and UTF-16LE), and the URLs, IPv4 addresses and registry paths in them."""
    asc = ASCII.findall(data)
    wide = [w.decode("utf-16-le").encode("ascii") for w in UTF16.findall(data)]
    urls: dict[str, None] = {}
    ips: dict[str, None] = {}
    registry = 0
    for run in (*asc, *wide):
        for m in URL.findall(run):
            urls.setdefault(m.decode("ascii"), None)
        for m in IPV4.findall(run):
            text = m.decode("ascii")
            try:
                ipaddress.IPv4Address(text)
            except ValueError:
                continue
            ips.setdefault(text, None)
        registry += len(REGISTRY.findall(run))
    return Strings(len(asc), len(wide), tuple(list(urls)[:keep]), tuple(list(ips)[:keep]), registry)


def overlay_extra(pe: P.PE) -> int:
    """Bytes after the last section that are not the Authenticode signature (YARA's and this module's same rule)."""
    start = P.overlay_offset(pe)
    after = pe.size - start
    if after <= 0:
        return 0
    sig_at, sig_size = pe.directory(P.DIR_SECURITY)
    if sig_size and sig_at >= start and sig_at + sig_size <= pe.size:
        return after - sig_size
    return after


def section_entropies(data: bytes, pe: P.PE) -> list[float]:
    return [entropy(P.section_bytes(data, pe, s)) for s in pe.sections]


def traits(data: bytes, pe: P.PE, now: int, entropies: list[float] | None = None) -> list[str]:
    """The names of the traits of the file, in the order of TRAITS."""
    ent = entropies if entropies is not None else section_entropies(data, pe)
    names = {imp.name for imp in pe.imports if imp.name}
    found: set[str] = set()
    if any(s.name in PACKER_SECTIONS for s in pe.sections):
        found.add("packer_section")
    if any(s.executable and s.raw_size and e >= ENTROPY_HIGH for s, e in zip(pe.sections, ent, strict=True)):
        found.add("high_entropy_code")
    if any(s.executable and s.writable for s in pe.sections):
        found.add("writable_code")
    ep = pe.entry_point
    if ep and not any(
        s.executable and s.virtual_address <= ep < s.virtual_address + max(s.virtual_size, s.raw_size)
        for s in pe.sections
    ):
        found.add("entry_outside_code")
    if all(n in names or (n == "CreateRemoteThread" and "CreateRemoteThreadEx" in names) for n in INJECTION):
        found.add("injection_imports")
    if names.intersection(DEBUGGER_CHECKS):
        found.add("debugger_check")
    if not pe.is_dotnet and ep and len(pe.imports) < FEW_IMPORTS:
        found.add("few_imports")
    if pe.checksum and pe.checksum != P.checksum(data, pe.checksum_offset):
        found.add("checksum_mismatch")
    if pe.timestamp > now:
        found.add("future_timestamp")
    if overlay_extra(pe) >= OVERLAY_MIN:
        found.add("overlay")
    if pe.has_tls:
        found.add("tls")
    dc = pe.dll_characteristics
    if not dc & P.DLLCHAR_DYNAMIC_BASE:
        found.add("no_aslr")
    if not dc & P.DLLCHAR_NX_COMPAT:
        found.add("no_dep")
    if not dc & P.DLLCHAR_GUARD_CF:
        found.add("no_cfg")
    if pe.pe32plus and not dc & P.DLLCHAR_HIGH_ENTROPY_VA:
        found.add("no_high_entropy_va")
    if not pe.security_size:
        found.add("no_embedded_signature")
    return [t for t in TRAITS if t in found]


def describe(data: bytes, pe: P.PE, now: int) -> dict[str, Any]:
    """The record of one parsed file (without its path, hashes or YARA results)."""
    ent = section_entropies(data, pe)
    s = strings(data)
    return {
        "machine": P.MACHINES.get(pe.machine, f"{pe.machine:#x}"),
        "bits": 64 if pe.pe32plus else 32,
        "dll": pe.is_dll,
        "subsystem": P.SUBSYSTEMS.get(pe.subsystem, str(pe.subsystem)),
        "dotnet": pe.is_dotnet,
        "timestamp": pe.timestamp,
        "entry_point": pe.entry_point,
        "sections": [
            {
                "name": sec.name,
                "virtual_address": sec.virtual_address,
                "virtual_size": sec.virtual_size,
                "raw_size": sec.raw_size,
                "characteristics": sec.characteristics,
                "entropy": e,
            }
            for sec, e in zip(pe.sections, ent, strict=True)
        ],
        "import_dlls": list(pe.import_dlls),
        "imports": len(pe.imports),
        "imported": sorted({imp.name for imp in pe.imports if imp.name}),
        "imphash": imphash(pe),
        "export_name": pe.export_name,
        "exports": pe.export_names,
        "signature_size": pe.security_size,
        "overlay_extra": overlay_extra(pe),
        "checksum": pe.checksum,
        "checksum_computed": P.checksum(data, pe.checksum_offset),
        "strings": {
            "ascii": s.ascii,
            "utf16": s.utf16,
            "urls": list(s.urls),
            "ipv4": list(s.ipv4),
            "registry": s.registry,
        },
        "warnings": list(pe.warnings),
        "traits": traits(data, pe, now, ent),
    }


def hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
