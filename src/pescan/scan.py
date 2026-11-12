"""Walking the input, one record per file: what it is, its hashes, its traits in Python and in YARA, and (optionally) the
fields on which this package's parser and pefile disagree. Files are read, never executed or written."""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import features as F
from . import pe as P

MAX_MB = 256
PROGRESS_EVERY = 500


@dataclass(frozen=True)
class Options:
    now: int
    yara: bool = True
    reference: bool = False
    max_bytes: int = MAX_MB << 20


def walk(paths: Iterable[str | Path], depth: int | None = None) -> Iterator[tuple[Path, str]]:
    """(file, name to report) for every regular file under the paths, in sorted order; symbolic links are not followed."""
    for root in paths:
        root = Path(root)
        if root.is_file():
            yield root, root.name
            continue
        if not root.is_dir():
            raise FileNotFoundError(f"no such file or directory: {root}")
        stack: list[tuple[Path, int]] = [(root, 0)]
        found: list[Path] = []
        while stack:
            folder, level = stack.pop()
            try:
                entries = list(os.scandir(folder))
            except OSError:
                continue
            for e in entries:
                try:
                    if e.is_symlink():
                        continue
                    if e.is_file(follow_symlinks=False):
                        found.append(Path(e.path))
                    elif e.is_dir(follow_symlinks=False) and (depth is None or level < depth):
                        stack.append((Path(e.path), level + 1))
                except OSError:
                    continue
        for f in sorted(found, key=lambda p: p.relative_to(root).as_posix().lower()):
            yield f, f.relative_to(root).as_posix()


def examine(data: bytes, name: str, opts: Options) -> dict[str, Any]:
    """The record of one file already in memory."""
    rec: dict[str, Any] = {"path": name, "size": len(data)}
    if len(data) < 2 or data[:2] != b"MZ":
        rec["kind"] = "not_pe"
        return rec
    rec.update(F.hashes(data))
    try:
        pe = P.parse(data)
    except P.PEError as e:
        rec["kind"] = "malformed"
        rec["error"] = str(e)
        return rec
    rec["kind"] = "pe"
    rec.update(F.describe(data, pe, opts.now))
    if opts.yara:
        from . import yarascan

        retries = len(yarascan.RETRIES)
        try:
            rec["yara"] = yarascan.match(data, opts.now)
            if len(yarascan.RETRIES) > retries:
                rec["yara_retried"] = True
        except Exception as e:  # a YARA error (timeout, bad file) is recorded, not fatal
            rec["yara"] = None
            rec["yara_error"] = f"{type(e).__name__}: {e}"
    if opts.reference:
        rec["reference"] = compare_reference(data)
    return rec


def compare_reference(data: bytes) -> dict[str, Any]:
    import pefile

    from . import reference as R

    try:
        ref = R.view_reference(data)
    except pefile.PEFormatError as e:
        return {"refused": str(e)}
    except Exception as e:  # pefile can fail in other ways on odd files; that is a result too
        return {"refused": f"{type(e).__name__}: {e}"}
    own = R.view_own(data)
    return {
        "differences": R.differences(own, ref),
        "checksum_compared": ref["checksum_computed"] is not None,
    }


def read_and_examine(path: Path, name: str, opts: Options) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size > opts.max_bytes:
            return {"path": name, "size": size, "kind": "too_big"}
        with path.open("rb") as fh:
            head = fh.read(2)
            if head != b"MZ":
                return {"path": name, "size": size, "kind": "not_pe"}
            data = head + fh.read()
    except OSError as e:
        return {"path": name, "size": None, "kind": "unreadable", "error": f"{type(e).__name__}: {e.strerror or e}"}
    return examine(data, name, opts)


def _one(args: tuple[str, str, Options]) -> dict[str, Any]:
    return read_and_examine(Path(args[0]), args[1], args[2])


def scan(
    files: Iterable[tuple[Path, str]],
    opts: Options,
    workers: int = 1,
    progress: Callable[[str], None] | None = None,
) -> tuple[list[dict[str, Any]], float]:
    """Every record, in the order of `files`, and the seconds it took."""
    t0 = time.perf_counter()
    records: list[dict[str, Any]] = []
    items = [(str(p), n, opts) for p, n in files]

    def note() -> None:
        if progress and len(records) % PROGRESS_EVERY == 0:
            progress(f"  {len(records):,} of {len(items):,} files, {time.perf_counter() - t0:.0f} s")

    if workers <= 1:
        for item in items:
            records.append(_one(item))
            note()
    else:
        # results are counted as they finish (a large file does not hold the progress back) and put back in order
        done: list[dict[str, Any] | None] = [None] * len(items)
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_one, item): i for i, item in enumerate(items)}
            for fut in as_completed(futures):
                done[futures[fut]] = fut.result()
                records.append({})
                note()
        records = [r for r in done if r is not None]
    return records, time.perf_counter() - t0


def stderr(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)
