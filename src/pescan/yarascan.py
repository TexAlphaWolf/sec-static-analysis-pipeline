"""The traits as YARA rules (rules/traits.yar), matched with yara-python."""

from __future__ import annotations

import time
from functools import lru_cache
from importlib import resources

import yara

from .features import TRAITS

TIMEOUT_S = 60


def rules_text() -> str:
    return resources.files("pescan").joinpath("rules/traits.yar").read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def compiled() -> yara.Rules:
    return yara.compile(source=rules_text(), externals={"now": 0})


RETRIES: list[float] = []  # seconds (measured here) of the scans YARA reported as timed out and that were run again


def match(data: bytes, now: int) -> list[str]:
    """The traits the YARA rules find in `data`, in the order of TRAITS. A scan YARA reports as timed out is run once
    more: on a virtual machine whose clock jumps, a scan of a few milliseconds has been seen to time out."""
    t0 = time.perf_counter()
    try:
        found = compiled().match(data=data, externals={"now": now}, timeout=TIMEOUT_S)
    except yara.TimeoutError:
        RETRIES.append(time.perf_counter() - t0)
        found = compiled().match(data=data, externals={"now": now}, timeout=TIMEOUT_S)
    hits = {m.rule for m in found}
    return [t for t in TRAITS if t in hits]
