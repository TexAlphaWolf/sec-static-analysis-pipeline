"""Markdown and a figure from a scan summary (report.json) or a benchmark (bench.json): both pure functions of the JSON."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .features import DESCRIPTIONS, ENTROPY_HIGH, HARDENING, INDICATORS


def pct(n: int, d: int) -> str:
    return f"{100 * n / d:.1f}%" if d else "n/a"


def duration(s: float) -> str:
    if s < 1:
        return f"{s * 1000:.1f} ms"
    if s < 120:
        return f"{s:.2f} s"
    return f"{s / 60:.1f} min"


def clean(text: object) -> str:
    """A name taken from a file, safe in a Markdown line: control characters as \\xNN, table bars escaped."""
    return "".join(f"\\x{ord(c):02x}" if ord(c) < 0x20 or ord(c) == 0x7F else c for c in str(text)).replace("|", "\\|")


def _table(head: list[str], rows: list[list[Any]]) -> list[str]:
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(clean(c) for c in row) + " |" for row in rows]
    return out


def render_report(rep: dict[str, Any]) -> str:
    f, p, t, y = rep["files"], rep["pe"], rep["traits"], rep["yara"]
    n = f["pe"]
    lines = [
        "# Static analysis report",
        "",
        f"Source: {clean(rep['source'])}. pescan {rep['version']}. Traits computed at Unix time {rep['now']}.",
        *(["", f"Published copy: {rep['published']}."] if rep.get("published") else []),
        "",
        "## Files",
        "",
        *_table(
            ["What", "Files"],
            [
                ["Files read", f"{f['total']:,}"],
                ["PE files", f"{n:,}"],
                ["Not PE (no MZ header)", f"{f['not_pe']:,}"],
                ["Malformed (MZ, but no readable PE header)", f"{f['malformed']:,}"],
                ["Unreadable", f"{f['unreadable']:,}"],
                ["Larger than the limit", f"{f['too_big']:,}"],
            ],
        ),
        "",
        f"{f['bytes'] / 1e6:,.1f} MB read, of which {f['pe_bytes'] / 1e6:,.1f} MB in PE files.",
    ]
    if rep["elapsed_s"]:
        lines.append(
            f"Scanned in {duration(rep['elapsed_s'])}: {rep['speed']['files_per_s']:,.1f} files and "
            f"{rep['speed']['mb_per_s']:,.1f} MB a second."
        )
    if f["malformed_reasons"]:
        lines += ["", "Malformed: " + "; ".join(f"{clean(k)} ({v:,})" for k, v in f["malformed_reasons"]) + "."]
    if n:
        lines += [
            "",
            "## What they are",
            "",
            *_table(
                ["What", "Files", "Share"],
                [
                    ["64-bit", f"{p['bits_64']:,}", pct(p["bits_64"], n)],
                    ["DLLs", f"{p['dll']:,}", pct(p["dll"], n)],
                    [".NET assemblies", f"{p['dotnet']:,}", pct(p["dotnet"], n)],
                    ["Authenticode signature in the file", f"{p['signed_embedded']:,}", pct(p["signed_embedded"], n)],
                    ["Header checksum set and right", f"{p['checksum_right']:,}", pct(p["checksum_right"], n)],
                    ["Header checksum zero", f"{p['checksum_zero']:,}", pct(p["checksum_zero"], n)],
                    ["No imports", f"{p['no_imports']:,}", pct(p["no_imports"], n)],
                    ["Exports functions", f"{p['exports']:,}", pct(p["exports"], n)],
                    ["Parser warnings", f"{p['with_warnings']:,}", pct(p["with_warnings"], n)],
                ],
            ),
            "",
            "Machines: "
            + ", ".join(f"{k} {v:,}" for k, v in p["machines"])
            + ". Subsystems: "
            + ", ".join(f"{k} {v:,}" for k, v in p["subsystems"])
            + ".",
            "",
            "## Indicators",
            "",
            "A trait is a fact about how the file is built, not a verdict: benign software has many of them.",
            "",
            *_table(
                ["Trait", "Meaning", "Files", "Share", "YARA", "Disagree"],
                [
                    [k, DESCRIPTIONS[k], f"{t[k]:,}", pct(t[k], n), f"{y['counts'][k]:,}", f"{y['disagreements'][k]:,}"]
                    for k in INDICATORS
                ],
            ),
            "",
            "Indicators per file: "
            + ", ".join(f"{i if i < 5 else '5 or more'}: {v:,}" for i, v in enumerate(rep["indicators_per_file"]))
            + ".",
            "",
            "## Hardening",
            "",
            *_table(
                ["Missing", "Meaning", "Files", "Share", "YARA", "Disagree"],
                [
                    [k, DESCRIPTIONS[k], f"{t[k]:,}", pct(t[k], n), f"{y['counts'][k]:,}", f"{y['disagreements'][k]:,}"]
                    for k in HARDENING
                ],
            ),
        ]
        ex = [k for k in INDICATORS if k in rep["examples"]]
        if ex:
            lines += ["", "Files with each indicator (the first few by name):", ""]
            lines += [
                f"- {k} ({t[k]:,}): "
                + ", ".join(map(clean, rep["examples"][k]))
                + ("..." if t[k] > len(rep["examples"][k]) else "")
                for k in ex
            ]
        ts = rep["timestamps"]
        lines += [
            "",
            "## Link time stamps",
            "",
            "By decade: " + ", ".join(f"{d}s {c:,}" for d, c in ts["decades"]) + f". {ts['after_now']:,} "
            f"({pct(ts['after_now'], n)}) are later than the time of the scan and {ts['zero']:,} are zero.",
        ]
        e = rep["entropy"]
        lines += [
            "",
            "## Sections",
            "",
            f"{e['executable_high']:,} of {e['executable_sections']:,} executable sections have an entropy of "
            f"{ENTROPY_HIGH} bits a byte or more. Most common section names: "
            + ", ".join(f"{clean(k)} {v:,}" for k, v in rep["top_section_names"][:10])
            + ".",
            "",
            "## Imports",
            "",
            *_table(["DLL", "Files importing it"], [[k, f"{v:,}"] for k, v in rep["top_dlls"][:10]]),
            "",
            *_table(["Function", "Files importing it"], [[k, f"{v:,}"] for k, v in rep["top_functions"][:10]]),
            "",
            f"{rep['imphash']['distinct']:,} distinct import hashes; the largest groups: "
            + ", ".join(f"{k[:12]}... {v:,}" for k, v in rep["imphash"]["largest_groups"])
            + ".",
            "",
            "## Strings",
            "",
            f"{rep['strings']['files_with_urls']:,} files contain a URL, {rep['strings']['files_with_ipv4']:,} an IPv4 "
            f"address and {rep['strings']['files_with_registry']:,} a registry path. Most common hosts: "
            + (", ".join(f"{clean(k)} {v:,}" for k, v in rep["strings"]["top_hosts"]) or "none")
            + ".",
        ]
        if rep["flagged"]:
            lines += [
                "",
                "## Files with three indicators or more",
                "",
                *_table(["File", "Indicators"], [[path, ", ".join(ind)] for path, ind in rep["flagged"]]),
            ]
    lines += ["", "## Two ways of computing", ""]
    if y["files"]:
        lines.append(
            f"YARA rules ([`traits.yar`](https://github.com/TexAlphaWolf/sec-static-analysis-pipeline/blob/main/src/pescan/rules/traits.yar)) "
            f"and the Python traits give the same set on {y['same_traits']:,} of {y['files']:,} files"
            + (f"; {y['errors']:,} files could not be matched by YARA" if y["errors"] else "")
            + (
                f"; {y['retried']:,} scan{' was' if y['retried'] == 1 else 's were'} reported by YARA as timed out and run again"
                if y.get("retried")
                else ""
            )
            + "."
        )
    else:
        lines.append("YARA was not run.")
    ref = rep["reference"]
    if ref:
        diffs = ", ".join(f"{k} {v:,}" for k, v in ref["field_differences"].items()) or "none"
        lines.append(
            f"pefile read {ref['compared']:,} of {ref['files']:,} files (it refused {ref['refused']:,}); on "
            f"{ref['identical']:,} every field is the same as this parser's. Fields that differ: {diffs}. "
            f"The checksum was compared on {ref['checksum_compared']:,} files (pefile's is slow beyond 4 MiB)."
        )
    else:
        lines.append("The pefile comparison was not run (`--reference`).")
    acc = rep["accuracy"]
    if acc:
        lines += [
            "",
            "## Against the truth",
            "",
            f"{acc['files']:,} files have a known truth: the Python traits are exactly right on {acc['exact_python']:,} and "
            f"the YARA rules on {acc['exact_yara']:,}.",
            "",
            *_table(
                ["Trait", "Python right / false / missed", "YARA right / false / missed"],
                [
                    [k, "/".join(map(str, acc["python"][k])), "/".join(map(str, acc["yara"][k]))]
                    for k in INDICATORS + HARDENING
                ],
            ),
        ]
    return "\n".join(lines) + "\n"


def report_figure(rep: dict[str, Any], path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    n = max(rep["files"]["pe"], 1)
    fig, ax = plt.subplots(2, 2, figsize=(13.2, 8.8))
    fig.suptitle(f"{rep['source']}: {rep['files']['pe']:,} PE files")
    t = rep["traits"]
    ax[0, 0].barh(list(INDICATORS)[::-1], [100 * t[k] / n for k in INDICATORS][::-1], color="#0072B2")
    ax[0, 0].set_title("Indicators (% of PE files)")
    ax[0, 1].barh(list(HARDENING)[::-1], [100 * t[k] / n for k in HARDENING][::-1], color="#D55E00")
    ax[0, 1].set_title("Hardening missing (% of PE files)")
    e = rep["entropy"]
    centres = [0.25 + 0.5 * i for i in range(len(e["executable"]))]
    ax[1, 0].bar([c - 0.12 for c in centres], e["executable"], width=0.24, label="executable", color="#009E73")
    ax[1, 0].bar([c + 0.12 for c in centres], e["other"], width=0.24, label="other", color="#999999")
    ax[1, 0].axvline(ENTROPY_HIGH, color="black", linewidth=0.8, linestyle="--")
    ax[1, 0].set_title("Section entropy (bits a byte)")
    ax[1, 0].set_ylabel("sections")
    ax[1, 0].legend(frameon=False)
    per = rep["indicators_per_file"]
    ax[1, 1].bar(["0", "1", "2", "3", "4", "5+"], per, color="#CC79A7")
    ax[1, 1].set_title("Indicators per file")
    ax[1, 1].set_ylabel("files")
    for a in ax.flat:
        a.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(path, dpi=100)
    plt.close(fig)


def render_bench(b: dict[str, Any]) -> str:
    env = b["environment"]
    lines = [
        "# Benchmark",
        "",
        f"pescan {env['pescan']}, Python {env['python']}, {env['system']}, {env['cpus']} CPUs; seed {env['seed']}, "
        f"median of {env['repeat']} runs.",
        "",
        "## Throughput by step",
        "",
        *_table(
            ["Files", "MB", "Step", "Time", "Files a second", "MB a second"],
            [
                [
                    f"{r['files']:,}",
                    f"{r['mb']:.1f}",
                    r["step"],
                    duration(r["seconds"]),
                    f"{r['files'] / r['seconds']:,.0f}",
                    f"{r['mb'] / r['seconds']:,.1f}",
                ]
                for r in b["steps"]
            ],
        ),
        "",
        "## Workers",
        "",
        *_table(
            ["Workers", "Time", "Files a second"],
            [[w["workers"], duration(w["seconds"]), f"{w['files'] / w['seconds']:,.0f}"] for w in b["workers"]],
        ),
        "",
        "## Two implementations of the same number",
        "",
        *_table(
            ["What", "Fast", "Literal", "Ratio", "Same result"],
            [
                [
                    c["what"],
                    duration(c["fast_s"]),
                    duration(c["literal_s"]),
                    f"{c['literal_s'] / c['fast_s']:,.0f}x",
                    "yes" if c["same"] else "no",
                ]
                for c in b["pairs"]
            ],
        ),
    ]
    v = b["verification"]
    lines += [
        "",
        "## Verification",
        "",
        f"{v['files']:,} generated files and {v['damaged']:,} damaged copies (seed {v['seed']}).",
        "",
        *_table(["Check", "Result"], [[k, val] for k, val in v["lines"]]),
    ]
    retries = b.get("yara_retries") or []
    if retries:
        lines += [
            "",
            f"YARA reported {len(retries)} scan(s) in this process as timed out after "
            + ", ".join(duration(s) for s in retries)
            + " (its limit is 60 s); each was run again and gave a result.",
        ]
    return "\n".join(lines) + "\n"


def bench_figure(b: dict[str, Any], path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(1, 2, figsize=(12, 4.4))
    largest = max(r["files"] for r in b["steps"])
    rows = [r for r in b["steps"] if r["files"] == largest]
    ax[0].barh([r["step"] for r in rows][::-1], [r["mb"] / r["seconds"] for r in rows][::-1], color="#0072B2")
    ax[0].set_title(f"MB a second by step ({largest:,} files)")
    ax[1].plot(
        [w["workers"] for w in b["workers"]],
        [w["files"] / w["seconds"] for w in b["workers"]],
        marker="o",
        color="#D55E00",
    )
    ax[1].set_title("Whole scan: files a second by workers")
    ax[1].set_xlabel("workers")
    for a in ax:
        a.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(path, dpi=100)
    plt.close(fig)
