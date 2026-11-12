"""Every result is computed twice; this checks the two agree. On generated files the truth is known too; on damaged copies
nothing is right or wrong, but the parser must refuse them with its own error and never fail in another way."""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass
from typing import Any

import pefile

from . import build as B
from . import corpus as C
from . import features as F
from . import pe as P
from . import reference as R
from . import yarascan


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def verify(files: int = 300, seed: int = 1, damaged: int = 3) -> tuple[list[Check], dict[str, Any]]:
    samples = list(C.corpus(files, seed))
    checks: list[Check] = []
    py_wrong: Counter[str] = Counter()
    ya_wrong: Counter[str] = Counter()
    ref_diff: Counter[str] = Counter()
    ref_files = 0
    max_ent = 0.0
    sections = 0
    checksum_same = 0
    truth_counts: Counter[str] = Counter()
    for s in samples:
        pe = P.parse(s.data)
        got = F.traits(s.data, pe, C.NOW)
        by_yara = yarascan.match(s.data, C.NOW)
        truth_counts.update(s.truth)
        for t in set(got) ^ set(s.truth):
            py_wrong[t] += 1
        for t in set(by_yara) ^ set(s.truth):
            ya_wrong[t] += 1
        d = R.differences(R.view_own(s.data), R.view_reference(s.data))
        ref_diff.update(d)
        ref_files += bool(d)
        for sec in pe.sections:
            raw = P.section_bytes(s.data, pe, sec)
            max_ent = max(max_ent, abs(F.entropy(raw) - F.entropy_literal(raw)))
            sections += 1
        ours = P.checksum(s.data, pe.checksum_offset)
        literal = B.checksum_of(s.data, pe.checksum_offset)
        theirs = pefile.PE(data=s.data, fast_load=True).generate_checksum()
        checksum_same += ours == literal == theirs
    n_traits = sum(truth_counts.values())
    checks.append(
        Check(
            "Python traits against the truth",
            not py_wrong,
            f"{files:,} files, {n_traits:,} traits set, {sum(py_wrong.values())} wrong {dict(py_wrong) or ''}".strip(),
        )
    )
    checks.append(
        Check(
            "YARA rules against the truth",
            not ya_wrong,
            f"{files:,} files, {sum(ya_wrong.values())} wrong {dict(ya_wrong) or ''}".strip(),
        )
    )
    checks.append(
        Check(
            "parser against pefile (20 fields, imports and import hash included)",
            ref_files == 0,
            f"{files - ref_files:,} of {files:,} files identical{'; ' + str(dict(ref_diff)) if ref_diff else ''}",
        )
    )
    checks.append(
        Check(
            "entropy: NumPy against one byte value at a time",
            max_ent <= 1e-12,
            f"{sections:,} sections, largest difference {max_ent:.1e} bits",
        )
    )
    checks.append(
        Check(
            "checksum: NumPy, word by word, and pefile",
            checksum_same == files,
            f"{checksum_same:,} of {files:,} files give the same checksum three ways",
        )
    )

    rng = random.Random(seed + 7)
    stats: Counter[str] = Counter()
    field_diff: Counter[str] = Counter()
    yara_diff: Counter[str] = Counter()
    crashes: list[str] = []
    for s in samples:
        for _ in range(damaged):
            bad, _kinds = C.damage(s.data, rng)
            stats["damaged"] += 1
            own = ref = None
            try:
                pe = P.parse(bad)
                own = R.view_own(bad)
                rec_traits = F.traits(bad, pe, C.NOW)
                F.describe(bad, pe, C.NOW)
            except P.PEError:
                stats["own_refused"] += 1
            except Exception as e:  # the one thing that must not happen
                crashes.append(f"{type(e).__name__}: {e}")
            try:
                ref = R.view_reference(bad)
            except pefile.PEFormatError:
                stats["ref_refused"] += 1
            except Exception:
                stats["ref_error"] += 1
            ya: list[str] | None
            try:
                ya = yarascan.match(bad, C.NOW)
            except Exception:
                stats["yara_error"] += 1
                ya = None
            if own is not None and ref is not None:
                stats["both_read"] += 1
                d = R.differences(own, ref)
                field_diff.update(d)
                stats["both_identical"] += not d
            if own is not None and ya is not None:
                stats["yara_compared"] += 1
                diff = set(ya) ^ set(rec_traits)
                yara_diff.update(diff)
                stats["yara_same"] += not diff
    checks.append(
        Check(
            "damaged copies: the parser fails only with its own error",
            not crashes,
            f"{stats['damaged']:,} copies, {stats['own_refused']:,} refused, {len(crashes)} other failures"
            + (f" (first: {crashes[0]})" if crashes else ""),
        )
    )
    details = {
        "files": files,
        "seed": seed,
        "damaged": stats["damaged"],
        "traits_set": n_traits,
        "truth_counts": dict(truth_counts),
        "sections": sections,
        "entropy_max_diff": max_ent,
        "checksum_same": checksum_same,
        "damaged_stats": dict(stats),
        "damaged_field_differences": dict(sorted(field_diff.items())),
        "damaged_yara_differences": dict(sorted(yara_diff.items())),
    }
    return checks, details
