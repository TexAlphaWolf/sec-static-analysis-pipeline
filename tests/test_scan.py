"""Walking folders, the kind of each file, workers, and the summary built from the records."""

from __future__ import annotations

import contextlib
import os
from collections.abc import Callable
from pathlib import Path

import pytest

from pescan import analysis
from pescan import corpus as C
from pescan import scan as S

from .conftest import NOW


@pytest.fixture
def tree(tmp_path: Path, make: Callable[..., bytes]) -> Path:
    root = tmp_path / "in"
    (root / "sub" / "deeper").mkdir(parents=True)
    (root / "a.exe").write_bytes(make())
    (root / "B.dll").write_bytes(make(dll=True, signature=0))
    (root / "notes.txt").write_text("not a program", encoding="utf-8")
    (root / "broken.exe").write_bytes(b"MZ" + b"\0" * 100)
    (root / "sub" / "c.exe").write_bytes(make(checksum="bad"))
    (root / "sub" / "deeper" / "d.exe").write_bytes(make())
    with contextlib.suppress(OSError):  # Windows needs a privilege to make one; the walk skips links anyway
        (root / "link.exe").symlink_to(root / "a.exe")
    return root


def test_walk_order_depth_and_links(tree: Path) -> None:
    assert [n for _, n in S.walk([tree])] == [
        "a.exe",
        "B.dll",
        "broken.exe",
        "notes.txt",
        "sub/c.exe",
        "sub/deeper/d.exe",
    ]
    assert [n for _, n in S.walk([tree], depth=0)] == ["a.exe", "B.dll", "broken.exe", "notes.txt"]
    assert [n for _, n in S.walk([tree], depth=1)][-1] == "sub/c.exe"
    assert [n for _, n in S.walk([tree / "a.exe"])] == ["a.exe"]
    with pytest.raises(FileNotFoundError):
        list(S.walk([tree / "missing"]))


def test_kinds_of_file(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    opts = S.Options(now=NOW, reference=True)
    recs = {n: S.read_and_examine(p, n, opts) for p, n in S.walk([tree])}
    assert {n: r["kind"] for n, r in recs.items()} == {
        "a.exe": "pe",
        "B.dll": "pe",
        "broken.exe": "malformed",
        "notes.txt": "not_pe",
        "sub/c.exe": "pe",
        "sub/deeper/d.exe": "pe",
    }
    assert (
        recs["broken.exe"]["error"].startswith("the PE header is outside the file")
        or "PE" in recs["broken.exe"]["error"]
    )
    assert recs["a.exe"]["reference"] == {"differences": [], "checksum_compared": True}
    assert recs["sub/c.exe"]["traits"] == recs["sub/c.exe"]["yara"] == ["checksum_mismatch"]
    assert S.read_and_examine(tree / "a.exe", "a.exe", S.Options(now=NOW, max_bytes=100))["kind"] == "too_big"
    assert S.examine(b"", "e", opts)["kind"] == "not_pe"

    def denied(*a: object, **k: object) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "open", denied)
    rec = S.read_and_examine(tree / "a.exe", "a.exe", opts)
    assert rec["kind"] == "unreadable" and "Permission denied" in rec["error"]


def test_yara_and_pefile_failures_are_recorded(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from pescan import reference, yarascan

    def boom(*a: object, **k: object) -> list[str]:
        raise RuntimeError("timeout")

    monkeypatch.setattr(yarascan, "match", boom)
    monkeypatch.setattr(reference, "view_reference", boom)
    rec = S.read_and_examine(tree / "a.exe", "a.exe", S.Options(now=NOW, reference=True))
    assert rec["yara"] is None and rec["yara_error"] == "RuntimeError: timeout" and "yara_retried" not in rec
    assert rec["reference"] == {"refused": "RuntimeError: timeout"}


def test_workers_give_the_same_records(tree: Path) -> None:
    files = list(S.walk([tree]))
    lines: list[str] = []
    one, t1 = S.scan(files, S.Options(now=NOW), workers=1, progress=lines.append)
    two, t2 = S.scan(files, S.Options(now=NOW), workers=2)
    assert one == two and t1 > 0 and t2 > 0
    assert lines == []  # fewer files than a progress step
    S.PROGRESS_EVERY, old = 2, S.PROGRESS_EVERY
    try:
        S.scan(files, S.Options(now=NOW), progress=lines.append)
    finally:
        S.PROGRESS_EVERY = old
    assert len(lines) == 3 and lines[0].startswith("  2 of 6 files")


def test_summary_of_a_scan(tree: Path) -> None:
    files = list(S.walk([tree]))
    recs, sec = S.scan(files, S.Options(now=NOW, reference=True))
    truth = {"a.exe": [], "B.dll": ["no_embedded_signature"], "sub/c.exe": ["checksum_mismatch", "overlay"]}
    rep = analysis.build(recs, "tree", NOW, sec, {}, truth)
    f = rep["files"]
    assert (f["total"], f["pe"], f["not_pe"], f["malformed"]) == (6, 4, 1, 1)
    assert rep["traits"]["checksum_mismatch"] == 1 and rep["traits"]["no_embedded_signature"] == 1
    assert rep["yara"]["same_traits"] == 4 and rep["reference"]["identical"] == 4
    assert rep["pe"]["dll"] == 1 and rep["pe"]["signed_embedded"] == 3 and rep["pe"]["checksum_right"] == 3
    acc = rep["accuracy"]
    assert acc["files"] == 3 and acc["missing"] == 1 and acc["exact_python"] == 2
    assert acc["python"]["overlay"] == [0, 0, 1] and acc["python"]["checksum_mismatch"] == [1, 0, 0]
    assert rep["indicators_per_file"] == [3, 1, 0, 0, 0, 0] and rep["flagged"] == []
    assert rep["top_dlls"] == [["kernel32.dll", 4]] and rep["entropy"]["executable_sections"] == 4
    assert rep["examples"] == {"checksum_mismatch": ["sub/c.exe"], "no_embedded_signature": ["B.dll"]}
    assert rep["timestamps"] == {"decades": [[2020, 4]], "zero": 0, "after_now": 0}  # NOW - 1000 s is in January 2027
    lines = analysis.summary_lines(rep)
    assert lines[0].startswith("tree: 6 files, 4 PE") and "against the truth: 2 of 3" in lines[-1]
    assert analysis.build([], "nothing", NOW, None, {})["speed"]["files_per_s"] is None


def test_corpus_summary_flags_files(tmp_path: Path) -> None:
    C.write_corpus(tmp_path / "c", 60, 3)
    recs, sec = S.scan(list(S.walk([tmp_path / "c"])), S.Options(now=C.NOW))
    rep = analysis.build(recs, "c", C.NOW, sec, {})
    assert rep["flagged"] and all(len(f[1]) >= 3 for f in rep["flagged"])
    assert sum(rep["indicators_per_file"]) == 60 and rep["files"]["not_pe"] == 1  # truth.json
    assert os.path.basename(rep["flagged"][0][0]).startswith("sample")


def test_a_retried_yara_scan_is_counted(tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from pescan import yarascan

    real = yarascan.match

    def once(data: bytes, now: int) -> list[str]:
        yarascan.RETRIES.append(61.0)
        return real(data, now)

    monkeypatch.setattr(yarascan, "match", once)
    recs, sec = S.scan(list(S.walk([tree], depth=0)), S.Options(now=NOW))
    assert all(r.get("yara_retried") for r in recs if r["kind"] == "pe")
    rep = analysis.build(recs, "t", NOW, sec, {})
    assert rep["yara"]["retried"] == 2
    from pescan import report

    assert "2 scans were reported by YARA as timed out and run again" in report.render_report(rep)
    rep["yara"]["retried"] = 1
    assert "1 scan was reported by YARA as timed out and run again" in report.render_report(rep)
