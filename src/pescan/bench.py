"""Timings on generated files: each step on its own, the whole scan with 1 to N workers, and the fast and literal versions of
the entropy and the checksum."""

from __future__ import annotations

import os
import platform
import random
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Any

from . import __version__, yarascan
from . import build as B
from . import corpus as C
from . import features as F
from . import pe as P
from . import reference as R
from . import scan as S
from . import verify as V


def _time(fn: Callable[[], object], repeat: int) -> float:
    runs = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        runs.append(time.perf_counter() - t0)
    return statistics.median(runs)


def run_bench(
    sizes: list[int], repeat: int, seed: int, workers: list[int], verify_files: int, say: Callable[[str], None]
) -> dict[str, Any]:
    steps = []
    for n in sizes:
        files = [s.data for s in C.corpus(n, seed)]
        mb = sum(map(len, files)) / 1e6
        parsed = [P.parse(d) for d in files]
        jobs: list[tuple[str, Callable[[list[bytes], list[P.PE]], object]]] = [
            ("parse", lambda fs, ps: [P.parse(d) for d in fs]),
            ("hashes", lambda fs, ps: [F.hashes(d) for d in fs]),
            ("traits, strings, entropy", lambda fs, ps: [F.describe(d, p, C.NOW) for d, p in zip(fs, ps, strict=True)]),
            ("YARA rules", lambda fs, ps: [yarascan.match(d, C.NOW) for d in fs]),
            ("pefile (reference)", lambda fs, ps: [R.view_reference(d) for d in fs]),
        ]
        for name, job in jobs:
            sec = _time(partial(job, files, parsed), repeat)
            steps.append({"files": n, "mb": mb, "step": name, "seconds": sec})
            say(f"  {n:,} files, {name}: {sec:.3f} s")

    largest = max(sizes)
    worker_rows = []
    with tempfile.TemporaryDirectory() as tmp:
        C.write_corpus(tmp, largest, seed)
        found = list(S.walk([tmp]))
        opts = S.Options(now=C.NOW)
        for w in workers:
            sec = _time(partial(S.scan, found, opts, w), repeat)
            worker_rows.append({"workers": w, "files": len(found), "seconds": sec})
            say(f"  whole scan, {w} workers: {sec:.3f} s")

    rng = random.Random(seed)
    blob = rng.randbytes(4 << 20)
    pe_blob = B.build(B.Spec(sections=[B.SectionSpec(".text", blob, B.CODE)]))
    off = P.parse(pe_blob).checksum_offset
    pairs = [
        {
            "what": "entropy of 4 MiB",
            "fast_s": _time(lambda: F.entropy(blob), repeat),
            "literal_s": _time(lambda: F.entropy_literal(blob), max(1, repeat // 2)),
            "same": abs(F.entropy(blob) - F.entropy_literal(blob)) < 1e-12,
        },
        {
            "what": "checksum of a 4 MiB file",
            "fast_s": _time(lambda: P.checksum(pe_blob, off), repeat),
            "literal_s": _time(lambda: B.checksum_of(pe_blob, off), max(1, repeat // 2)),
            "same": P.checksum(pe_blob, off) == B.checksum_of(pe_blob, off),
        },
    ]
    say("  verification")
    checks, details = V.verify(verify_files, seed, 3)
    return {
        "kind": "bench",
        "environment": {
            "pescan": __version__,
            "python": platform.python_version(),
            "system": f"{platform.system()} {platform.machine()}",
            "cpus": os.cpu_count(),
            "seed": seed,
            "repeat": repeat,
            "cmdline": " ".join(sys.argv[1:]),
        },
        "steps": steps,
        "workers": worker_rows,
        "pairs": pairs,
        "yara_retries": list(yarascan.RETRIES),
        "verification": {
            "files": verify_files,
            "seed": seed,
            "damaged": details["damaged"],
            "ok": all(c.ok for c in checks),
            "lines": [[c.name, c.detail] for c in checks],
            "details": details,
        },
    }


def write(result: dict[str, Any], out: Path) -> None:
    import json

    from . import report

    out.mkdir(parents=True, exist_ok=True)
    (out / "bench.json").write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8", newline="\n")
    (out / "bench.md").write_text(report.render_bench(result), encoding="utf-8", newline="\n")
    report.bench_figure(result, out / "bench.png")
