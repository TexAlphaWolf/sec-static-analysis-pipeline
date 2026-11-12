# Architecture

```text
 files and folders ──> scan.walk ──> scan.read_and_examine (one process or several)
                                        │  not MZ: not_pe        too large: too_big     OSError: unreadable
                                        ▼
                                     pe.parse ──── PEError ──> malformed
                                        │
            ┌───────────────────────────┼─────────────────────────────┐
            ▼                           ▼                             ▼
   features.describe            yarascan.match                reference (pefile)
   hashes, imphash, entropy,    rules/traits.yar              the same 20 fields,
   checksum, strings, traits    (the traits again)            compared with pe.parse
            └───────────────────────────┬─────────────────────────────┘
                                        ▼
                     one record per file (files.jsonl)
                                        ▼
                     analysis.build ──> report.json ──> report.render_report ──> report.md
                                                    └─> report.report_figure ──> summary.png

 corpus.corpus / build.build ──> generated PE files + truth.json (+ damaged copies)
 verify.verify ──> parser vs pefile, Python vs YARA vs truth, fast vs literal, damaged copies
 bench.run_bench ──> bench.json ──> bench.md, bench.png
```

| Module | Role |
|---|---|
| `pe.py` | the PE parser: headers, section table, address map, imports, exports, checksum, overlay start |
| `features.py` | hashes, import hash, entropy (fast and literal), strings, overlay, the traits, one file's record |
| `rules/traits.yar`, `yarascan.py` | the traits as YARA rules; a scan that YARA reports as timed out is run once more |
| `reference.py` | the same fields read by pefile and by `pe.py`, and their differences |
| `build.py` | a PE writer that shares no code with the parser (its own layout and its own word-by-word checksum) |
| `corpus.py` | random specifications with known traits, decoys, damaged copies, `truth.json` |
| `scan.py` | walking folders (sorted, no symbolic links, depth), reading, records, several processes |
| `analysis.py` | the summary of a scan: counts, traits, agreement, entropy histogram, imports, strings, time stamps, accuracy |
| `report.py` | Markdown and figures from `report.json` and `bench.json` (pure functions) |
| `verify.py`, `bench.py` | the comparisons, and the timings |
| `cli.py` | `scan`, `show`, `corpus`, `verify`, `bench`, `render`, `rules` |

Choices:

- **Bytes in memory, offsets checked.** A file is read whole (up to the size limit) and every structure is taken from the bytes
  with its offset and length checked first, so a damaged file can only end in `PEError`. Nothing is mapped, loaded or run.
- **The loader's rules, as pefile has them.** Where the format is ambiguous the parser does what pefile does, so the two can be
  compared value by value; the differences that remain on damaged files are counted, not hidden.
- **The truth comes from the writer, not the reader.** `build.py` places every table itself and computes the checksum its own
  way, and `corpus.py` decides each trait before the file exists; the parser is never used to decide what a generated file is.
- **Records first, summary second.** `files.jsonl` keeps everything about every file; `report.json` is a pure function of the
  records, and the Markdown and the figure are pure functions of `report.json`, so a report can be rebuilt (`pescan render`) and
  the documentation checked against it (`tests/test_docs.py`).
- **Processes, not threads.** The work is Python and C under the GIL; files are spread over processes and the records are put
  back in the order of the files.
- **The container is the safety boundary.** Three parsers read hostile input, one of them in C (YARA); the image runs without
  network, capabilities or a writable root, as an unprivileged user, with the input mounted read-only.
