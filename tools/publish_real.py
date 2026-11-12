"""Make a scan report of a real folder fit to publish: a generic name for the source and file names only for the rare
traits (at most 50 files), so the report shows what Windows ships without listing the other software of the computer it
ran on. Every number is kept. Usage: python tools/publish_real.py report.json "C:\\Windows\\System32 (Windows 11)" docs/real
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pescan import report

RARE = 50


def publish(rep: dict, source: str) -> dict:
    out = dict(rep)
    out["source"] = source
    out["examples"] = {k: v for k, v in rep["examples"].items() if rep["traits"][k] <= RARE}
    out["published"] = f"source renamed; file names kept only for traits found in at most {RARE} files"
    return out


def main(argv: list[str]) -> int:
    src, source, dest = argv
    rep = publish(json.loads(Path(src).read_text(encoding="utf-8")), source)
    base = Path(dest)
    base.parent.mkdir(parents=True, exist_ok=True)
    base.with_suffix(".json").write_text(json.dumps(rep, indent=1) + "\n", encoding="utf-8")
    base.with_suffix(".md").write_text(report.render_report(rep), encoding="utf-8")
    report.report_figure(rep, base.with_suffix(".png"))
    print(f"written: {base.with_suffix('.json')}, {base.with_suffix('.md')}, {base.with_suffix('.png')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
