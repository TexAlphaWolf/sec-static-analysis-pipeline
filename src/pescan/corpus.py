"""Synthetic corpora: random PE files with known traits, decoys that look close to a trait without having it, and damaged
copies for robustness. Nothing here is executable code; the 'code' sections hold filler bytes.
"""

from __future__ import annotations

import json
import random
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import build as B
from .features import HARDENING, INDICATORS, OVERLAY_MIN, PACKER_SECTIONS

NOW = 1_800_000_000  # the time the corpus is scanned at (15 January 2027), so future_timestamp is reproducible

COMMON: dict[str, list[str | int]] = {
    "KERNEL32.dll": [
        "GetProcAddress",
        "LoadLibraryW",
        "CreateFileW",
        "ReadFile",
        "WriteFile",
        "CloseHandle",
        "GetLastError",
        "HeapAlloc",
        "HeapFree",
        "Sleep",
        "ExitProcess",
        "GetModuleHandleW",
        "GetCurrentProcess",
        "VirtualAlloc",
        "VirtualProtect",
    ],
    "USER32.dll": ["MessageBoxW", "CreateWindowExW", "GetMessageW", "DispatchMessageW", "DefWindowProcW"],
    "ADVAPI32.dll": ["RegOpenKeyExW", "RegQueryValueExW", "RegCloseKey", "OpenProcessToken"],
    "WS2_32.dll": [3, 4, 9, 23, 115, "getaddrinfo"],
    "api-ms-win-core-memory-l1-1-0.dll": ["VirtualQuery", "VirtualFree"],
}

DEFAULT_RATES = {
    "packer_section": 0.08,
    "high_entropy_code": 0.10,
    "writable_code": 0.08,
    "entry_outside_code": 0.06,
    "injection_imports": 0.06,
    "debugger_check": 0.12,
    "few_imports": 0.08,
    "checksum_mismatch": 0.08,
    "future_timestamp": 0.06,
    "overlay": 0.08,
    "tls": 0.10,
}
DECOY_RATE = 0.15


@dataclass
class Sample:
    name: str
    data: bytes
    truth: list[str]
    decoys: list[str]


def _low(rng: random.Random, n: int) -> bytes:
    alphabet = bytes(rng.sample(range(256), 24))
    return bytes(rng.choice(alphabet) for _ in range(n))


def _high(rng: random.Random, n: int) -> bytes:
    return rng.randbytes(n)


def sample(rng: random.Random, index: int, rates: dict[str, float] | None = None) -> Sample:
    """One random PE file and the traits it was built with."""
    rates = rates or DEFAULT_RATES
    want = {t for t in INDICATORS if rng.random() < rates.get(t, 0.0)}
    if "few_imports" in want:
        want.discard("injection_imports")  # three more imports would make it four
    decoys: set[str] = set()
    spec = B.Spec(pe32plus=rng.random() < 0.7, dll=rng.random() < 0.4, subsystem=rng.choice((2, 3)))
    spec.timestamp = (
        rng.randrange(NOW + 86400, NOW + 400 * 86400)
        if "future_timestamp" in want
        else rng.randrange(1_000_000_000, NOW)
    )
    dotnet = "few_imports" not in want and rng.random() < 0.08
    spec.dotnet = dotnet

    code_size = 512 * rng.randrange(8, 64)
    code = _high(rng, code_size) if "high_entropy_code" in want else _low(rng, code_size)
    code_ch = B.CODE | (B.DATA & 0x80000000 if "writable_code" in want else 0)
    code_name = rng.choice(PACKER_SECTIONS) if "packer_section" in want else ".text"
    sections = [B.SectionSpec(code_name, code, code_ch)]
    rdata = _low(rng, 512 * rng.randrange(1, 16))
    if rng.random() < DECOY_RATE:  # compressed data that is not code: not high_entropy_code
        rdata = _high(rng, 512 * rng.randrange(8, 16))
        decoys.add("high_entropy_code")
    sections.append(B.SectionSpec(".rdata", rdata, B.RDATA))
    sections.append(B.SectionSpec(".data", _low(rng, 512 * rng.randrange(1, 4)), B.DATA, virtual_size=0x2000))
    if rng.random() < 0.5:
        sections.append(B.SectionSpec(".rsrc", _low(rng, 512 * rng.randrange(1, 8)), B.RDATA))
    spec.sections = sections

    if "entry_outside_code" in want:
        spec.entry = (1, rng.randrange(0, 256) * 2)
    elif spec.dll and rng.random() < 0.3:
        spec.entry = None  # a resource-only style DLL: no entry point at all
        decoys.add("entry_outside_code")
    else:
        spec.entry = (0, rng.randrange(0, 256) * 2)
    has_entry = spec.entry is not None

    imports: dict[str, list[str | int]] = {}
    if dotnet:
        imports["mscoree.dll"] = ["_CorDllMain" if spec.dll else "_CorExeMain"]
        decoys.add("few_imports")
    elif "few_imports" in want:
        imports["KERNEL32.dll"] = rng.sample(
            COMMON["KERNEL32.dll"], rng.randrange(1, 3 if "debugger_check" in want else 4)
        )
    else:
        for dll in rng.sample(sorted(COMMON), rng.randrange(1, len(COMMON) + 1)):
            names = COMMON[dll]
            imports[dll] = rng.sample(names, rng.randrange(1, len(names) + 1))
        if sum(len(v) for v in imports.values()) < 4:
            imports.setdefault("KERNEL32.dll", [])
            for n in COMMON["KERNEL32.dll"]:
                if n not in imports["KERNEL32.dll"]:
                    imports["KERNEL32.dll"].append(n)
                if sum(len(v) for v in imports.values()) >= 4:
                    break
        if not has_entry and rng.random() < 0.5:
            imports = {"KERNEL32.dll": ["Sleep"]}  # few imports but no entry point: not few_imports
            decoys.add("few_imports")
    if "injection_imports" in want:
        dll = rng.choice(("KERNEL32.dll", "api-ms-win-core-processthreads-l1-1-0.dll"))
        imports.setdefault(dll, []).extend(
            ["VirtualAllocEx", "WriteProcessMemory", rng.choice(("CreateRemoteThread", "CreateRemoteThreadEx"))]
        )
    elif rng.random() < DECOY_RATE and not dotnet and "few_imports" not in want:
        imports.setdefault("KERNEL32.dll", []).extend(["VirtualAllocEx", "WriteProcessMemory"])  # two of the three
        decoys.add("injection_imports")
    if "debugger_check" in want:
        imports.setdefault("KERNEL32.dll", []).append(rng.choice(("IsDebuggerPresent", "CheckRemoteDebuggerPresent")))
    spec.imports = [(dll, list(dict.fromkeys(names))) for dll, names in imports.items() if names]
    if spec.dll and rng.random() < 0.7:
        spec.export = (f"sample{index}.dll", [f"Function{i}" for i in range(rng.randrange(1, 12))])
    spec.tls_callbacks = rng.randrange(1, 4) if "tls" in want else 0

    if "checksum_mismatch" in want:
        spec.checksum = "bad"
    else:
        spec.checksum = rng.choice(("good", "zero"))
        if spec.checksum == "zero":
            decoys.add("checksum_mismatch")
    if "overlay" in want:
        spec.overlay = _low(rng, rng.randrange(OVERLAY_MIN, 8 * OVERLAY_MIN))
    elif rng.random() < DECOY_RATE:
        spec.overlay = _low(rng, rng.randrange(1, OVERLAY_MIN - 8))
        decoys.add("overlay")
    signed = rng.random() < 0.4
    if signed:
        spec.signature = 8 * rng.randrange(100, 1200)
        if not spec.overlay:
            decoys.add("overlay")

    dc = 0x8000
    hardening = set()
    for flag, name in ((0x40, "no_aslr"), (0x100, "no_dep"), (0x4000, "no_cfg"), (0x20, "no_high_entropy_va")):
        if rng.random() < 0.75:
            dc |= flag
        elif name != "no_high_entropy_va" or spec.pe32plus:
            hardening.add(name)
    if spec.pe32plus and not dc & 0x20:
        hardening.add("no_high_entropy_va")
    spec.dll_characteristics = dc
    if not signed:
        hardening.add("no_embedded_signature")

    want.discard("few_imports")
    if not dotnet and has_entry and sum(len(n) for _, n in spec.imports) < 4:
        want.add("few_imports")
    truth = list(want) + [h for h in HARDENING if h in hardening]
    ext = "dll" if spec.dll else "exe"
    order = INDICATORS + HARDENING
    return Sample(f"sample{index:05d}.{ext}", B.build(spec), sorted(set(truth), key=order.index), sorted(decoys))


def corpus(n: int, seed: int, rates: dict[str, float] | None = None) -> Iterator[Sample]:
    rng = random.Random(seed)
    for i in range(n):
        yield sample(rng, i, rates)


MUTATIONS = ("truncate", "header_bytes", "lfanew", "sections", "directory", "section_table", "imports")


def damage(data: bytes, rng: random.Random) -> tuple[bytes, list[str]]:
    """A damaged copy of a PE file: one to three random mutations, named."""
    out = bytearray(data)
    done = []
    for _ in range(rng.randrange(1, 4)):
        kind = rng.choice(MUTATIONS)
        done.append(kind)
        lfanew = int.from_bytes(out[0x3C:0x40], "little") if len(out) >= 0x40 else 0
        if kind == "truncate" and len(out) > 2:
            del out[rng.randrange(1, len(out)) :]
        elif kind == "header_bytes":
            for _ in range(rng.randrange(1, 9)):
                if len(out) > 1:
                    out[rng.randrange(0, min(len(out), 0x400))] = rng.randrange(256)
        elif kind == "lfanew" and len(out) >= 0x40:
            struct.pack_into("<I", out, 0x3C, rng.choice((0, 0x40, len(out) - 2, 0xFFFFFFF0, rng.randrange(0, 0x400))))
        elif kind == "sections" and lfanew + 8 <= len(out):
            struct.pack_into("<H", out, lfanew + 6, rng.choice((0, 1, 0xFFFF, rng.randrange(0, 200))))
        elif kind == "directory" and lfanew + 24 + 2 <= len(out):
            magic = int.from_bytes(out[lfanew + 24 : lfanew + 26], "little")
            base = lfanew + 24 + (112 if magic == 0x20B else 96)
            at = base + 8 * rng.randrange(0, 16)
            if at + 8 <= len(out):
                struct.pack_into("<II", out, at, rng.randrange(0, 1 << 32), rng.randrange(0, 1 << 32))
        elif kind == "section_table" and lfanew + 22 <= len(out):
            opt = int.from_bytes(out[lfanew + 20 : lfanew + 22], "little")
            at = lfanew + 24 + opt + 40 * rng.randrange(0, 4) + rng.choice((8, 12, 16, 20, 36))
            if at + 4 <= len(out):
                struct.pack_into(
                    "<I", out, at, rng.choice((0, 0xFFFFFFFF, rng.randrange(0, 1 << 32), rng.randrange(0, 0x10000)))
                )
        elif kind == "imports" and len(out) > 0x600:
            for _ in range(rng.randrange(4, 32)):
                out[rng.randrange(0x400, len(out))] = rng.randrange(256)
    return bytes(out), done


def write_corpus(out: str | Path, n: int, seed: int, damaged: int = 0) -> dict[str, Any]:
    """Write `n` files and `truth.json` (their traits) into `out`; with `damaged`, also that many damaged copies of each
    file in `out/damaged` (no truth: what is right for a broken file is the question)."""
    folder = Path(out)
    folder.mkdir(parents=True, exist_ok=True)
    truth: dict[str, list[str]] = {}
    rng = random.Random(seed + 1_000_003)
    n_damaged = 0
    for s in corpus(n, seed):
        (folder / s.name).write_bytes(s.data)
        truth[s.name] = s.truth
        for k in range(damaged):
            (folder / "damaged").mkdir(exist_ok=True)
            bad, _kinds = damage(s.data, rng)
            (folder / "damaged" / f"{s.name}.{k}").write_bytes(bad)
            n_damaged += 1
    doc = {"kind": "truth", "seed": seed, "now": NOW, "files": truth}
    (folder / "truth.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    return {"files": n, "damaged": n_damaged, "truth": doc}
