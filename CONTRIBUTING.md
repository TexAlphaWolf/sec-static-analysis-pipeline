# Contributing

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest --cov
```

No service is needed. yara-python has wheels for Python 3.11 to 3.13; on 3.14 it is compiled from source, which needs a C
compiler. `PESCAN_TEST_FILES` and `PESCAN_TEST_SEED` run the same tests on a larger (or different) generated corpus (CI also
uses 1,000 files with seed 11).

Rules that keep the project honest:

- **A trait is written twice.** A new or changed trait goes into `features.py` (Python) and `rules/traits.yar` (YARA) with the
  same definition, into `DESCRIPTIONS`, into the generator (`corpus.py`, with its truth and, when one is easy to make, a decoy
  that looks close to it without having it) and into `tests/test_features.py`, both as a case and as a near miss. The tests run
  every case through both and require the same answer.
- **The parser is compared with pefile on every field.** A change to `pe.py` must keep `pescan verify` at "identical" on the
  generated corpus; where the format leaves room, follow the loader's rules as pefile implements them and say so in
  `docs/method.md`.
- **Damaged files must not break anything.** The parser may refuse a file only with `PEError`; any other exception on a damaged
  copy fails `verify` and the tests.
- **Numbers in the README and `docs/analysis.md` come from `docs/*.json`**, and `tests/test_docs.py` checks them. After a change
  to the traits or the generator, regenerate the demo report and the benchmark (`tools/run_full.ps1`) and update the text where a
  number moved.
- **No real malware in the repository**, not even "for testing". The corpus generator makes the files the tests need.
