"""Shared helpers: small PE files built from a specification, and the size of the random corpora."""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

import pytest

from pescan import build as B

FILES = int(os.environ.get("PESCAN_TEST_FILES", "200"))
SEED = int(os.environ.get("PESCAN_TEST_SEED", "1"))
NOW = 1_800_000_000


def text(n: int = 2048, low: bool = True) -> bytes:
    """Filler for a code section: few byte values (low entropy) or all of them in turn (entropy 8)."""
    return bytes((i * 7) % 16 for i in range(n)) if low else bytes(i % 256 for i in range(n))


def spec(**kw: Any) -> B.Spec:
    base: dict[str, Any] = {
        "sections": [B.SectionSpec(".text", text(), B.CODE), B.SectionSpec(".rdata", b"abc" * 300, B.RDATA)],
        "imports": [("KERNEL32.dll", ["GetProcAddress", "LoadLibraryW", "CreateFileW", "ReadFile"])],
        "timestamp": NOW - 1000,
        "dll_characteristics": 0x4160 | 0x8000,
        "signature": 512,
    }
    base.update(kw)
    return B.Spec(**base)


@pytest.fixture
def make() -> Callable[..., bytes]:
    def _make(**kw: Any) -> bytes:
        return B.build(spec(**kw))

    return _make
