# Security

## Model

pescan **reads files that may be hostile** and writes a report. It never runs them, loads them or unpacks them: a PE file is
bytes in memory, and every value taken from it is checked against the size of the file before it is used. It starts no service
and opens no network connection.

- **Three parsers read the input.** pescan's own parser (Python, bounds checked, limits on the number of sections, DLLs and
  imports), pefile (Python) and YARA's `pe` module (C, through yara-python). A bug in a parser written in C is the most serious
  risk with hostile files; run scans of untrusted files in the Docker image, as below.
- **What it reads:** the files and folders given to `scan` and `show` (symbolic links are not followed, files above `--max-mb`,
  256 MiB by default, are skipped, unreadable files are reported), a `truth.json` next to a generated corpus, and a `report.json`
  or `bench.json` given to `render`.
- **What it writes:** only where the options say: `scan --out`, `corpus DIR`, `bench --out` and `render -o`. `files.jsonl` lists
  the names and hashes of every file scanned: keep it private if the folder is.
- **No file is ever executed.** The generated corpus holds well-formed PE files whose "code" is filler bytes; they are not
  programs and contain no malware. No sample of real malware is in the repository, and none is needed to run the tests.
- **The Docker image** runs as an unprivileged user and works with a read-only root filesystem (plus `--tmpfs /tmp` for
  matplotlib's cache), no capabilities and no network (`--network none`); `tools/run_real.ps1` mounts the folder to scan
  read-only. A YARA scan of one file stops after 60 seconds.
- **Traits are not verdicts.** A file with many indicators is not shown to be malicious, and a file with none is not shown to be
  safe; see [`docs/limitations.md`](docs/limitations.md).

## Reporting

If you find a vulnerability, please open a private security advisory on the GitHub repository (Security tab) rather than a public
issue.
