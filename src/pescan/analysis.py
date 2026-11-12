"""The summary of a scan: what the files are, how they are built, which traits they have, and how often the two ways of
computing each result agree. A pure function of the records."""

from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import urlsplit

from . import __version__
from .features import ENTROPY_HIGH, HARDENING, INDICATORS, TRAITS

TOP = 15
FLAGGED_MIN = 3
FLAGGED_KEEP = 25
ENTROPY_BINS = 16  # 0.5 bit wide, 0 to 8
EXAMPLES = 8


def _share(n: int, d: int) -> float | None:
    return n / d if d else None


def _top(counter: Counter[str], n: int = TOP) -> list[list[Any]]:
    return [[k, v] for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]]


def build(
    records: list[dict[str, Any]],
    source: str,
    now: int,
    elapsed_s: float | None,
    options: dict[str, Any],
    truth: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    kinds = Counter(r["kind"] for r in records)
    pes = [r for r in records if r["kind"] == "pe"]
    n = len(pes)
    pe_bytes = sum(r["size"] for r in pes)
    all_bytes = sum(r["size"] or 0 for r in records)

    trait_counts = {t: sum(t in r["traits"] for r in pes) for t in TRAITS}
    with_yara = [r for r in pes if r.get("yara") is not None]
    yara_counts = {t: sum(t in r["yara"] for r in with_yara) for t in TRAITS}
    disagree = {t: sum((t in r["traits"]) != (t in r["yara"]) for r in with_yara) for t in TRAITS}
    yara = {
        "files": len(with_yara),
        "errors": sum(1 for r in pes if r.get("yara") is None and "yara_error" in r),
        "retried": sum(1 for r in pes if r.get("yara_retried")),
        "same_traits": sum(1 for r in with_yara if r["traits"] == r["yara"]),
        "counts": yara_counts,
        "disagreements": disagree,
    }

    refs = [r["reference"] for r in pes if "reference" in r]
    compared = [x for x in refs if "differences" in x]
    field_diff: Counter[str] = Counter()
    for x in compared:
        field_diff.update(x["differences"])
    reference = (
        {
            "files": len(refs),
            "refused": len(refs) - len(compared),
            "compared": len(compared),
            "identical": sum(1 for x in compared if not x["differences"]),
            "checksum_compared": sum(1 for x in compared if x["checksum_compared"]),
            "field_differences": dict(sorted(field_diff.items())),
            "refusals": _top(Counter(next(iter(x["refused"].split(":")), "") for x in refs if "refused" in x), 5),
        }
        if refs
        else None
    )

    exec_hist = [0] * ENTROPY_BINS
    other_hist = [0] * ENTROPY_BINS
    exec_high = exec_total = 0
    section_names: Counter[str] = Counter()
    for r in pes:
        for s in r["sections"]:
            b = min(int(s["entropy"] * 2), ENTROPY_BINS - 1)
            section_names[s["name"]] += 1
            if s["characteristics"] & 0x20000000 and s["raw_size"]:
                exec_hist[b] += 1
                exec_total += 1
                exec_high += s["entropy"] >= ENTROPY_HIGH
            elif s["raw_size"]:
                other_hist[b] += 1

    dlls: Counter[str] = Counter()
    funcs: Counter[str] = Counter()
    for r in pes:
        dlls.update({d.lower() for d in r["import_dlls"]})
        funcs.update(r["imported"])
    imphashes = Counter(r["imphash"] for r in pes if r["imphash"])
    hosts: Counter[str] = Counter()
    for r in pes:
        hosts.update({(urlsplit(u).hostname or "").lower() for u in r["strings"]["urls"]} - {""})

    indicators_per_file = Counter(min(sum(t in r["traits"] for t in INDICATORS), 5) for r in pes)
    flagged = sorted(
        ([r["path"], [t for t in r["traits"] if t in INDICATORS]] for r in pes),
        key=lambda x: (-len(x[1]), x[0].lower()),
    )
    flagged = [f for f in flagged if len(f[1]) >= FLAGGED_MIN][:FLAGGED_KEEP]

    examples = {
        t: sorted((r["path"] for r in pes if t in r["traits"]), key=str.lower)[:EXAMPLES]
        for t in TRAITS
        if trait_counts[t]
    }
    decades = Counter(1970 + 10 * ((r["timestamp"] // 31_556_952) // 10) for r in pes)
    timestamps = {
        "decades": [[d, decades[d]] for d in sorted(decades)],
        "zero": sum(r["timestamp"] == 0 for r in pes),
        "after_now": trait_counts["future_timestamp"],
    }

    accuracy = None
    if truth is not None:
        accuracy = _accuracy(pes, truth)

    return {
        "kind": "scan",
        "version": __version__,
        "source": source,
        "now": now,
        "elapsed_s": elapsed_s,
        "options": options,
        "files": {
            "total": len(records),
            "pe": n,
            "not_pe": kinds["not_pe"],
            "malformed": kinds["malformed"],
            "unreadable": kinds["unreadable"],
            "too_big": kinds["too_big"],
            "bytes": all_bytes,
            "pe_bytes": pe_bytes,
            "malformed_reasons": _top(
                Counter(r["error"].split(" (")[0] for r in records if r["kind"] == "malformed"), 5
            ),
        },
        "pe": {
            "machines": _top(Counter(r["machine"] for r in pes)),
            "bits_64": sum(r["bits"] == 64 for r in pes),
            "dll": sum(r["dll"] for r in pes),
            "subsystems": _top(Counter(r["subsystem"] for r in pes)),
            "dotnet": sum(r["dotnet"] for r in pes),
            "signed_embedded": sum(r["signature_size"] > 0 for r in pes),
            "checksum_zero": sum(r["checksum"] == 0 for r in pes),
            "checksum_right": sum(r["checksum"] != 0 and r["checksum"] == r["checksum_computed"] for r in pes),
            "no_imports": sum(r["imports"] == 0 for r in pes),
            "exports": sum(r["exports"] > 0 for r in pes),
            "with_warnings": sum(bool(r["warnings"]) for r in pes),
        },
        "traits": trait_counts,
        "indicators_per_file": [indicators_per_file.get(i, 0) for i in range(6)],
        "flagged": flagged,
        "examples": examples,
        "timestamps": timestamps,
        "yara": yara,
        "reference": reference,
        "entropy": {
            "executable": exec_hist,
            "other": other_hist,
            "executable_sections": exec_total,
            "executable_high": exec_high,
        },
        "top_section_names": _top(section_names),
        "top_dlls": _top(dlls),
        "top_functions": _top(funcs),
        "imphash": {"distinct": len(imphashes), "largest_groups": _top(imphashes, 5)},
        "strings": {
            "files_with_urls": sum(bool(r["strings"]["urls"]) for r in pes),
            "files_with_ipv4": sum(bool(r["strings"]["ipv4"]) for r in pes),
            "files_with_registry": sum(r["strings"]["registry"] > 0 for r in pes),
            "top_hosts": _top(hosts, 10),
        },
        "accuracy": accuracy,
        "speed": {
            "files_per_s": len(records) / elapsed_s if elapsed_s else None,
            "mb_per_s": all_bytes / 1e6 / elapsed_s if elapsed_s else None,
        },
        "groups": {"indicators": list(INDICATORS), "hardening": list(HARDENING)},
    }


def _accuracy(pes: list[dict[str, Any]], truth: dict[str, list[str]]) -> dict[str, Any]:
    """Per trait: true positives, false positives and false negatives of the Python and the YARA traits against the truth."""
    out: dict[str, Any] = {"files": 0, "missing": 0, "python": {}, "yara": {}}
    rows = []
    for r in pes:
        t = truth.get(r["path"])
        if t is None:
            out["missing"] += 1
            continue
        rows.append((set(t), set(r["traits"]), set(r.get("yara") or [])))
    out["files"] = len(rows)
    for side, k in (("python", 1), ("yara", 2)):
        for trait in TRAITS:
            tp = sum(1 for row in rows if trait in row[0] and trait in row[k])
            fp = sum(1 for row in rows if trait not in row[0] and trait in row[k])
            fn = sum(1 for row in rows if trait in row[0] and trait not in row[k])
            out[side][trait] = [tp, fp, fn]
    out["exact_python"] = sum(1 for row in rows if row[0] == row[1])
    out["exact_yara"] = sum(1 for row in rows if row[0] == row[2])
    return out


def summary_lines(rep: dict[str, Any]) -> list[str]:
    f, p, t = rep["files"], rep["pe"], rep["traits"]
    lines = [
        f"{rep['source']}: {f['total']:,} files, {f['pe']:,} PE ({f['pe_bytes'] / 1e6:,.1f} MB), {f['not_pe']:,} not PE, "
        f"{f['malformed']:,} malformed, {f['unreadable']:,} unreadable, {f['too_big']:,} too big",
    ]
    if f["pe"]:
        lines.append(
            f"{p['bits_64']:,} 64-bit, {p['dll']:,} DLLs, {p['dotnet']:,} .NET, {p['signed_embedded']:,} with an embedded signature"
        )
        top = [f"{k} {v:,}" for k, v in sorted(((k, t[k]) for k in INDICATORS), key=lambda kv: -kv[1]) if v][:5]
        lines.append("indicators: " + (", ".join(top) if top else "none"))
        per = rep["indicators_per_file"]
        lines.append(f"files with 3 or more indicators: {sum(per[3:]):,}")
    y = rep["yara"]
    if y["files"]:
        lines.append(f"YARA agrees with the Python traits on {y['same_traits']:,} of {y['files']:,} files")
    ref = rep["reference"]
    if ref:
        lines.append(
            f"pefile: {ref['identical']:,} of {ref['compared']:,} files read identically, {ref['refused']:,} refused by pefile"
        )
    acc = rep["accuracy"]
    if acc:
        lines.append(
            f"against the truth: {acc['exact_python']:,} of {acc['files']:,} files exactly right (Python), {acc['exact_yara']:,} (YARA)"
        )
    return lines
