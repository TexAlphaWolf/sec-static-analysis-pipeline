# Changelog

## 1.0.0

First release.

- A PE parser written from the specification (headers, section table, address map, imports by name and ordinal, exports,
  checksum, overlay), compared field by field with pefile.
- Hashes, Mandiant's import hash, section entropy, strings (URLs, IPv4 addresses, registry paths) and sixteen traits: eleven
  indicators and five hardening checks, written both in Python and as YARA rules (`pescan rules`).
- A PE writer and a corpus generator with known traits, decoys and damaged copies; `pescan verify` compares parser and pefile,
  Python and YARA and the truth, fast and literal entropy and checksum, and checks that damaged files only raise `PEError`.
- `pescan scan` over files and folders with several processes, with optional pefile comparison; `report.json`, `report.md`,
  a figure and one JSON line per file.
- Measured: Windows 11 System32 (4,405 PE files: pefile and YARA agree on all of them) and a benchmark on 1,000 generated files.
- Docker image (Python 3.13, unprivileged, read-only root, no network), end-to-end scripts for bash and PowerShell, CI on
  Python 3.11 to 3.14, Windows and macOS, CodeQL.
