"""pescan: the command line."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from . import __version__, analysis, report
from . import corpus as C
from . import scan as S

EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2


def _truth_for(paths: list[str]) -> dict[str, list[str]] | None:
    """The truth.json of a generated corpus, when a single directory that has one is scanned."""
    if len(paths) != 1 or not Path(paths[0]).is_dir():
        return None
    tf = Path(paths[0]) / "truth.json"
    if not tf.exists():
        return None
    doc = json.loads(tf.read_text(encoding="utf-8"))
    files = doc.get("files") if isinstance(doc, dict) else None
    if not isinstance(files, dict):
        raise ValueError(f"{tf} is not a truth file of `pescan corpus`")
    return {str(k): list(v) for k, v in files.items()}


def cmd_scan(a: argparse.Namespace) -> int:
    truth = _truth_for(a.paths)
    now = a.now if a.now is not None else int(time.time())
    if truth is not None and a.now is None:
        now = C.NOW  # a generated corpus is scanned at the time its truth was made for
    opts = S.Options(now=now, yara=not a.no_yara, reference=a.reference, max_bytes=a.max_mb << 20)
    found = list(S.walk(a.paths, a.depth))
    if not found:
        raise ValueError("no files to scan")
    records, elapsed = S.scan(found, opts, workers=a.workers, progress=S.stderr)
    source = a.name or ", ".join(a.paths)
    options = {
        "depth": a.depth,
        "max_mb": a.max_mb,
        "yara": opts.yara,
        "reference": opts.reference,
        "workers": a.workers,
    }
    rep = analysis.build(records, source, now, elapsed, options, truth)
    for line in analysis.summary_lines(rep):
        print(line)
    if a.out:
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "report.json").write_text(json.dumps(rep, indent=1) + "\n", encoding="utf-8")
        (out / "report.md").write_text(report.render_report(rep), encoding="utf-8")
        report.report_figure(rep, out / "summary.png")
        with (out / "files.jsonl").open("w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r, separators=(",", ":")) + "\n")
        print(f"written: {out / 'report.json'}, {out / 'report.md'}, {out / 'summary.png'}, {out / 'files.jsonl'}")
    return EXIT_OK


def cmd_show(a: argparse.Namespace) -> int:
    now = a.now if a.now is not None else int(time.time())
    opts = S.Options(now=now, reference=a.reference)
    rec = S.read_and_examine(Path(a.file), Path(a.file).name, opts)
    print(json.dumps(rec, indent=1))
    return EXIT_OK if rec["kind"] == "pe" else EXIT_FAIL


def cmd_corpus(a: argparse.Namespace) -> int:
    res = C.write_corpus(a.out, a.files, a.seed, a.damaged)
    counts: dict[str, int] = {}
    for traits in res["truth"]["files"].values():
        for t in traits:
            counts[t] = counts.get(t, 0) + 1
    print(f"written: {a.out} ({res['files']:,} files, {res['damaged']:,} damaged copies, truth.json)")
    print("traits set: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    return EXIT_OK


def cmd_verify(a: argparse.Namespace) -> int:
    from . import verify

    checks, details = verify.verify(a.files, a.seed, a.damaged)
    for c in checks:
        print(f"{'ok  ' if c.ok else 'FAIL'} {c.name}: {c.detail}")
    st = details["damaged_stats"]
    print(
        f"damaged copies read by both parsers: {st.get('both_read', 0):,}, identical on {st.get('both_identical', 0):,}; "
        f"YARA and Python traits the same on {st.get('yara_same', 0):,} of {st.get('yara_compared', 0):,}"
    )
    bad = [c for c in checks if not c.ok]
    print(f"{len(checks) - len(bad)} of {len(checks)} checks passed")
    return EXIT_FAIL if bad else EXIT_OK


def cmd_bench(a: argparse.Namespace) -> int:
    from . import bench

    sizes = [int(x) for x in a.sizes.split(",") if x.strip()]
    workers = [int(x) for x in a.workers.split(",") if x.strip()]
    if not sizes or min(sizes) < 1 or not workers or min(workers) < 1:
        raise ValueError("--sizes and --workers need whole numbers of 1 or more")
    result = bench.run_bench(sizes, a.repeat, a.seed, workers, a.verify_files, lambda m: print(m, flush=True))
    bench.write(result, Path(a.out))
    print(f"written: {Path(a.out) / 'bench.json'}, {Path(a.out) / 'bench.md'}, {Path(a.out) / 'bench.png'}")
    return EXIT_OK if result["verification"]["ok"] else EXIT_FAIL


def cmd_render(a: argparse.Namespace) -> int:
    doc: dict[str, Any] = json.loads(Path(a.json).read_text(encoding="utf-8"))
    kind = doc.get("kind")
    if kind == "scan":
        text = report.render_report(doc)
    elif kind == "bench":
        text = report.render_bench(doc)
    else:
        raise ValueError(f"{a.json} is neither a scan report nor a benchmark")
    if a.output:
        Path(a.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return EXIT_OK


def cmd_rules(a: argparse.Namespace) -> int:
    from . import yarascan

    sys.stdout.write(yarascan.rules_text())
    return EXIT_OK


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pescan",
        description="Static analysis of Windows PE files: hashes, imports, sections, strings and traits, computed twice "
        "(this parser and pefile; Python and YARA). Files are read, never run.",
    )
    p.add_argument("--version", action="version", version=f"pescan {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan files and folders, write a report")
    s.add_argument("paths", nargs="+")
    s.add_argument("--out", help="folder for report.json, report.md, summary.png and files.jsonl")
    s.add_argument("--name", help="name of the source in the report")
    s.add_argument("--depth", type=int, default=None, help="folder levels to descend (0: only the files in the folder)")
    s.add_argument("--max-mb", type=int, default=S.MAX_MB, help="skip files larger than this (default %(default)s)")
    s.add_argument("--workers", type=int, default=1, help="processes (default 1)")
    s.add_argument("--reference", action="store_true", help="also read every file with pefile and compare")
    s.add_argument("--no-yara", action="store_true", help="do not run the YARA rules")
    s.add_argument("--now", type=int, help="Unix time for future_timestamp (default: now)")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("show", help="the full record of one file, as JSON")
    s.add_argument("file")
    s.add_argument("--reference", action="store_true")
    s.add_argument("--now", type=int)
    s.set_defaults(fn=cmd_show)

    s = sub.add_parser("corpus", help="write generated PE files with known traits (and damaged copies)")
    s.add_argument("out")
    s.add_argument("--files", type=int, default=200)
    s.add_argument("--seed", type=int, default=1)
    s.add_argument("--damaged", type=int, default=0, help="damaged copies of each file")
    s.set_defaults(fn=cmd_corpus)

    s = sub.add_parser("verify", help="compare the two ways of computing every result")
    s.add_argument("--files", type=int, default=int(os.environ.get("PESCAN_TEST_FILES", "300")))
    s.add_argument("--seed", type=int, default=1)
    s.add_argument("--damaged", type=int, default=3)
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("bench", help="time each step and the whole scan")
    s.add_argument("--sizes", default="100,500")
    s.add_argument("--workers", default="1,2,4")
    s.add_argument("--repeat", type=int, default=3)
    s.add_argument("--seed", type=int, default=1)
    s.add_argument("--verify-files", type=int, default=300)
    s.add_argument("--out", default="bench-out")
    s.set_defaults(fn=cmd_bench)

    s = sub.add_parser("render", help="Markdown from a report.json or bench.json")
    s.add_argument("json")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_render)

    s = sub.add_parser("rules", help="print the YARA rules (to use them with yara itself)")
    s.set_defaults(fn=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    a = parser().parse_args(argv)
    try:
        code: int = a.fn(a)
        return code
    except (ValueError, FileNotFoundError, OSError) as e:
        print(f"pescan: {e}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
