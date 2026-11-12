"""The command line, end to end on generated files."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from pescan import cli, report
from pescan import corpus as C


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    code = cli.main(list(args))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


@pytest.fixture
def made(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Path:
    out = tmp_path / "corpus"
    code, text, _ = run(capsys, "corpus", str(out), "--files", "40", "--seed", "4", "--damaged", "1")
    assert code == 0 and "40 files, 40 damaged copies" in text
    return out


def test_scan_a_corpus_with_its_truth(made: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(capsys, "scan", str(made), "--out", str(tmp_path / "r"), "--reference", "--name", "corpus")
    assert code == 0 and err == ""
    assert "against the truth: 40 of 40 files exactly right (Python), 40 (YARA)" in out
    rep = json.loads((tmp_path / "r" / "report.json").read_text(encoding="utf-8"))
    assert rep["now"] == C.NOW and rep["source"] == "corpus" and rep["options"]["reference"] is True
    assert (tmp_path / "r" / "summary.png").stat().st_size > 10_000
    lines = (tmp_path / "r" / "files.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == rep["files"]["total"] == 81
    md = (tmp_path / "r" / "report.md").read_text(encoding="utf-8")
    assert md == report.render_report(rep) and "## Against the truth" in md


def test_scan_options(made: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "scan", str(made), "--depth", "0", "--no-yara", "--now", "1", "--workers", "2")
    assert code == 0 and "41 files, 40 PE" in out and "YARA agrees" not in out and "pefile" not in out
    assert "future_timestamp 40" in out  # every time stamp is later than one second after 1970
    code, _, err = run(capsys, "scan", str(tmp_path / "nothing-here"))
    assert code == 2 and "no such file" in err
    (tmp_path / "empty").mkdir()
    code, _, err = run(capsys, "scan", str(tmp_path / "empty"))
    assert code == 2 and "no files" in err
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "truth.json").write_text("[]", encoding="utf-8")
    (tmp_path / "bad" / "x.bin").write_bytes(b"x")
    code, _, err = run(capsys, "scan", str(tmp_path / "bad"))
    assert code == 2 and "not a truth file" in err


def test_show(made: Path, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    truth = json.loads((made / "truth.json").read_text(encoding="utf-8"))["files"]
    first = sorted(truth)[0]
    code, out, _ = run(capsys, "show", str(made / first), "--reference", "--now", str(C.NOW))
    rec = json.loads(out)
    assert code == 0 and rec["kind"] == "pe" and rec["reference"]["differences"] == []
    assert rec["traits"] == truth[first]
    (tmp_path / "t.txt").write_text("hello", encoding="utf-8")
    code, out, _ = run(capsys, "show", str(tmp_path / "t.txt"))
    assert code == 1 and json.loads(out)["kind"] == "not_pe"


def test_verify_and_rules(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "verify", "--files", "30", "--damaged", "1")
    assert code == 0 and "6 of 6 checks passed" in out and "FAIL" not in out
    code, out, _ = run(capsys, "rules")
    assert code == 0 and out.count("\nrule ") == 16 and 'import "pe"' in out


def test_verify_failure_exit_code(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    from pescan import features

    real = features.traits
    monkeypatch.setattr(features, "traits", lambda *a, **k: [*real(*a, **k), "tls"])
    code, out, _ = run(capsys, "verify", "--files", "10", "--damaged", "0")
    assert code == 1 and "FAIL Python traits against the truth" in out


def test_bench_and_render(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "b"
    code, text, _ = run(
        capsys,
        "bench",
        "--sizes",
        "10,20",
        "--workers",
        "1,2",
        "--repeat",
        "1",
        "--verify-files",
        "10",
        "--out",
        str(out),
    )
    assert code == 0 and "written:" in text
    b = json.loads((out / "bench.json").read_text(encoding="utf-8"))
    assert [r["files"] for r in b["steps"]] == [10] * 5 + [20] * 5 and [w["workers"] for w in b["workers"]] == [1, 2]
    assert all(p["same"] for p in b["pairs"]) and b["verification"]["ok"] and b["yara_retries"] == []
    assert "timed out" not in report.render_bench(b)
    assert "each was run again" in report.render_bench(b | {"yara_retries": [61.2]})
    assert (out / "bench.png").stat().st_size > 10_000
    code, md, _ = run(capsys, "render", str(out / "bench.json"))
    assert code == 0 and md == (out / "bench.md").read_text(encoding="utf-8")
    code, _, _ = run(capsys, "render", str(out / "bench.json"), "-o", str(tmp_path / "x.md"))
    assert code == 0 and (tmp_path / "x.md").read_text(encoding="utf-8") == md
    (tmp_path / "other.json").write_text('{"kind": "x"}', encoding="utf-8")
    code, _, err = run(capsys, "render", str(tmp_path / "other.json"))
    assert code == 2 and "neither" in err
    code, _, err = run(capsys, "bench", "--sizes", "0")
    assert code == 2


def test_render_a_scan(
    made: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], make: Callable[..., bytes]
) -> None:
    run(capsys, "scan", str(made), "--out", str(tmp_path / "r"))
    code, md, _ = run(capsys, "render", str(tmp_path / "r" / "report.json"))
    assert code == 0 and md.startswith("# Static analysis report") and "## Files with three indicators or more" in md
    assert "The pefile comparison was not run" in md
    (tmp_path / "one").mkdir()
    (tmp_path / "one" / "a.txt").write_text("x", encoding="utf-8")
    run(capsys, "scan", str(tmp_path / "one"), "--out", str(tmp_path / "r1"), "--no-yara")
    md = (tmp_path / "r1" / "report.md").read_text(encoding="utf-8")
    assert "YARA was not run" in md and "## Indicators" not in md


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert "pescan 1.0.0" in capsys.readouterr().out


def test_names_from_files_cannot_break_the_markdown() -> None:
    assert report.clean("a|b\r\nc\x7f") == "a\\|b\\x0d\\x0ac\\x7f"
    rows = report._table(["Name"], [["x|y\n"]])
    assert rows[-1] == "| x\\|y\\x0a |"
