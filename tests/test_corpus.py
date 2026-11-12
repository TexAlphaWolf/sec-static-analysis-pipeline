"""Random corpora: truth, Python, YARA and pefile all agree; damaged copies never break the parser."""

from __future__ import annotations

import contextlib
import json
import random
from pathlib import Path

import pefile
import pytest

from pescan import corpus as C
from pescan import features as F
from pescan import pe as P
from pescan import reference as R
from pescan import verify as V
from pescan import yarascan

from .conftest import FILES, SEED


def test_the_corpus_is_reproducible() -> None:
    a = [(s.name, s.data, s.truth) for s in C.corpus(20, SEED)]
    b = [(s.name, s.data, s.truth) for s in C.corpus(20, SEED)]
    assert a == b
    assert a != [(s.name, s.data, s.truth) for s in C.corpus(20, SEED + 1)]


def test_truth_python_yara_and_pefile_agree() -> None:
    seen: set[str] = set()
    decoys: set[str] = set()
    for s in C.corpus(FILES, SEED):
        pe = P.parse(s.data)
        assert F.traits(s.data, pe, C.NOW) == s.truth, s.name
        assert yarascan.match(s.data, C.NOW) == s.truth, s.name
        assert R.differences(R.view_own(s.data), R.view_reference(s.data)) == [], s.name
        seen.update(s.truth)
        decoys.update(s.decoys)
    if FILES >= 200:  # every trait and every kind of decoy turns up
        assert seen == set(F.TRAITS)
        assert decoys == {
            "high_entropy_code",
            "entry_outside_code",
            "few_imports",
            "injection_imports",
            "checksum_mismatch",
            "overlay",
        }


def test_damaged_copies_fail_only_with_the_parsers_error() -> None:
    rng = random.Random(SEED)
    kinds: set[str] = set()
    for s in C.corpus(max(FILES // 4, 20), SEED + 5):
        for _ in range(4):
            bad, done = C.damage(s.data, rng)
            kinds.update(done)
            try:
                pe = P.parse(bad)
            except P.PEError:
                continue
            F.describe(bad, pe, C.NOW)
            R.view_own(bad)
            yarascan.match(bad, C.NOW)
            with contextlib.suppress(pefile.PEFormatError):
                R.view_reference(bad)
    assert kinds == set(C.MUTATIONS)


def test_rates_change_what_is_drawn() -> None:
    none = {t: 0.0 for t in C.DEFAULT_RATES}
    for s in C.corpus(30, SEED, none):
        assert not set(s.truth) & {t for t in F.INDICATORS if t != "few_imports"}
    every = {t: 1.0 for t in C.DEFAULT_RATES}
    s = next(C.corpus(1, SEED, every))
    assert {"packer_section", "high_entropy_code", "writable_code", "entry_outside_code", "tls", "overlay"} <= set(
        s.truth
    )


def test_write_corpus(tmp_path: Path) -> None:
    res = C.write_corpus(tmp_path / "c", 5, SEED, damaged=2)
    names = sorted(p.name for p in (tmp_path / "c").iterdir())
    assert names == sorted(["damaged", "truth.json", *res["truth"]["files"]]) and len(names) == 7
    assert b"\r" not in (tmp_path / "c" / "truth.json").read_bytes()  # the same bytes on every system
    truth = json.loads((tmp_path / "c" / "truth.json").read_text(encoding="utf-8"))
    assert truth["now"] == C.NOW and len(truth["files"]) == 5 and res["damaged"] == 10
    assert len(list((tmp_path / "c" / "damaged").iterdir())) == 10


def test_reference_differences_and_refusal() -> None:
    a = {k: 1 for k in R.FIELDS} | {"entropy": [1.0, 2.0]}
    assert R.differences(a, dict(a)) == []
    assert R.differences(a, a | {"entropy": [1.0, 2.0 + 1e-12]}) == []
    assert R.differences(a, a | {"entropy": [1.0, 2.1], "machine": 2}) == ["machine", "entropy"]
    assert R.differences(a, a | {"entropy": [1.0]}) == ["entropy"]
    with pytest.raises(pefile.PEFormatError):
        R.view_reference(b"MZ" + b"\0" * 200)


def test_verify_passes() -> None:
    checks, details = V.verify(max(FILES // 4, 30), SEED, 2)
    assert all(c.ok for c in checks), [c for c in checks if not c.ok]
    assert len(checks) == 6 and details["damaged"] == 2 * max(FILES // 4, 30)
    assert details["entropy_max_diff"] <= 1e-12
