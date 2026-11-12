# Benchmark

pescan 1.0.0, Python 3.13.18, Linux x86_64, 12 CPUs; seed 1, median of 3 runs.

## Throughput by step

| Files | MB | Step | Time | Files a second | MB a second |
|---|---|---|---|---|---|
| 200 | 5.7 | parse | 9.6 ms | 20,811 | 590.4 |
| 200 | 5.7 | hashes | 12.1 ms | 16,519 | 468.6 |
| 200 | 5.7 | traits, strings, entropy | 262.2 ms | 763 | 21.6 |
| 200 | 5.7 | YARA rules | 109.2 ms | 1,831 | 51.9 |
| 200 | 5.7 | pefile (reference) | 2.23 s | 90 | 2.5 |
| 1,000 | 28.2 | parse | 57.8 ms | 17,301 | 488.2 |
| 1,000 | 28.2 | hashes | 62.2 ms | 16,083 | 453.9 |
| 1,000 | 28.2 | traits, strings, entropy | 1.11 s | 900 | 25.4 |
| 1,000 | 28.2 | YARA rules | 537.6 ms | 1,860 | 52.5 |
| 1,000 | 28.2 | pefile (reference) | 15.46 s | 65 | 1.8 |

## Workers

| Workers | Time | Files a second |
|---|---|---|
| 1 | 2.00 s | 500 |
| 2 | 1.23 s | 814 |
| 4 | 760.8 ms | 1,316 |
| 8 | 536.9 ms | 1,865 |

## Two implementations of the same number

| What | Fast | Literal | Ratio | Same result |
|---|---|---|---|---|
| entropy of 4 MiB | 13.8 ms | 370.9 ms | 27x | yes |
| checksum of a 4 MiB file | 0.4 ms | 322.0 ms | 883x | yes |

## Verification

1,000 generated files and 3,000 damaged copies (seed 1).

| Check | Result |
|---|---|
| Python traits against the truth | 1,000 files, 2,407 traits set, 0 wrong |
| YARA rules against the truth | 1,000 files, 0 wrong |
| parser against pefile (20 fields, imports and import hash included) | 1,000 of 1,000 files identical |
| entropy: NumPy against one byte value at a time | 4,498 sections, largest difference 2.4e-14 bits |
| checksum: NumPy, word by word, and pefile | 1,000 of 1,000 files give the same checksum three ways |
| damaged copies: the parser fails only with its own error | 3,000 copies, 842 refused, 0 other failures |
