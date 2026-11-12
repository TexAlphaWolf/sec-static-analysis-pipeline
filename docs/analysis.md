# Analysis

Three sources: a real folder ([`real.json`](real.json): the files directly in `C:\Windows\System32` of a Windows 11 computer,
scanned in Docker with 12 processes, with pefile and YARA), the benchmark ([`bench.json`](bench.json): Docker on Linux x86_64,
12 CPUs, Python 3.13.18, medians of 3 runs, 1,000 generated files verified) and the demo corpus ([`report.json`](report.json):
300 generated files and 300 damaged copies, seed 1). The published copy of the real report has a generic source name and keeps
file names only for traits found in at most 50 files ([`tools/publish_real.py`](../tools/publish_real.py)); every number is
the one measured.

## 1. A real folder: Windows 11 System32

4,716 files, 3,014.5 MB, read in 103 s (45.8 files and 29.2 MB a second, with every file also read by pefile). 4,405 are PE
files (2,983.1 MB) and 311 are not; none is malformed, none unreadable, none above the size limit. 4,387 are 64-bit and 18 are
32-bit; 3,756 are DLLs; 28 are .NET assemblies; subsystems are console (2,654), GUI (1,471), native (272: drivers and boot
components) and boot application (8).

**The two ways of computing agree everywhere.** pefile reads the 4,405 files and gives the same value as pescan's parser for
every one of the 20 compared fields, on every file; the checksum is compared on the 4,306 files of 4 MiB or less. YARA gives
the same set of traits as the Python code on 4,405 of 4,405 files. One YARA scan was reported as timed out (a limit of 60
seconds, on files that take milliseconds) and gave its result when run again; the benchmark run on the same computer had
none. The likely cause is the clock of the virtual machine that runs Docker; it is not shown.

**Indicators.**

| Trait | Files | Share |
|---|---|---|
| debugger_check | 2,875 | 65.3% |
| future_timestamp | 2,362 | 53.6% |
| tls | 1,243 | 28.2% |
| few_imports | 21 | 0.5% |
| high_entropy_code | 6 | 0.1% |
| injection_imports | 4 | 0.1% |
| packer_section, writable_code, entry_outside_code, checksum_mismatch, overlay | 0 | 0% |

Three indicators are common in benign files, and they are the three most often used alone in rules of thumb:

- `IsDebuggerPresent` is imported by 2,875 files. The start-up and failure code of the Visual C++ runtime calls it, so most
  programs built with Visual C++ import it; it says nothing on its own.
- **The link time stamp is not a time.** 2,362 files (53.6%) have one later than the scan. By decade they are spread evenly:
  272 in the 1970s, 332 in the 1980s, 441 in the 2020s (the most), 212 in the 2100s (a decade cut short in 2106, where 32 bits
  of seconds end). Windows is built reproducibly, and the field then holds a value derived from the build. For values spread
  evenly over all 32-bit numbers, 58.2% would fall after the time of the scan; 53.6% do, the difference being the files with
  a real date.
- 1,243 files have a TLS directory, which compilers emit for thread-local variables.

Files with each count of indicators: 690 with none, 1,569 with one, 1,500 with two, 642 with three and 4 with four; none has
five. 641 of the 642 files with three have exactly `debugger_check`, `future_timestamp` and `tls`, and the 4 with four add one
rare indicator to those three (the counts by file come from the full record list, which stays on the computer). Counting indicators
would rank a large part of the operating system as the most suspicious thing on the disk.

The rare indicators have reasons that the file names give away:

- **Compressed or encrypted code (6 files):** `ClipUp.exe`, `GenValObj.exe`, `SppExtComObj.Exe` and `sppsvc.exe` belong to
  Windows licensing and software protection, whose code is obfuscated on purpose; `d3dcsx_42.dll` (Direct3D) and
  `WMVDECOD.DLL` (a media decoder) complete the list. They are 6 of 8,021 executable sections with raw data; the others are
  mostly between 5.5 and 6.5 bits a byte (3,479), and 3,881 are below 0.5: mostly the small `fothk` sections (3,584 files have
  one) that are nearly empty.
- **Process injection imports (4):** `dbgeng.dll` (the debugger engine), `Faultrep.dll` (error reporting), `ttdinject.exe`
  (time travel debugging) and `kernel32.dll`. Writing into another process is their job.
- **Fewer than 4 imports (21):** hypervisor, boot, microcode and firmware files (`hvix64.exe`, `hvax64.exe`,
  `mcupdate_GenuineIntel.dll`, `HalExtPL080.dll`...), which run before or outside the usual DLLs.

**Hardening and signing.** 37 files (0.8%) lack ASLR, 101 (2.3%) DEP, 419 (9.5%) Control Flow Guard and 137 64-bit files
(3.1%) high-entropy ASLR; among the first are old DirectX helper libraries (`d3dx9_24.dll`...). 3,308 files (75.1%) have no
signature of their own: Windows signs them in catalogs, so a file-by-file view would call three quarters of the system
"unsigned". The header checksum is right on 4,404 files and zero on 1; no file has a wrong one.

**Imports and strings.** 3,837 distinct import hashes among 4,405 files, the largest group of 10: the import hash separates
almost every Windows binary, which is what makes it useful to group samples of one family. The most imported DLLs are the API
sets (`api-ms-win-core-processthreads-l1-1-0.dll` in 2,842 files) and the most imported functions come from the C runtime's
start-up (`GetCurrentThreadId` in 3,834). 1,732 files contain a URL, most often `www.microsoft.com` (1,161 files) and
`crl.microsoft.com` (1,073); the second is where Microsoft's certificates point for revocation lists, so most of those are
probably inside signatures.

## 2. Speed

On 1,000 generated files (28.2 MB), one process:

| Step | Time | MB a second |
|---|---|---|
| parse (pescan) | 57.8 ms | 488.2 |
| hashes (MD5, SHA-1, SHA-256) | 62.2 ms | 453.9 |
| traits, strings, entropy | 1.11 s | 25.4 |
| YARA rules | 537.6 ms | 52.5 |
| pefile (reference) | 15.46 s | 1.8 |

pescan's parser is 267 times faster than pefile here, because it reads only what the analysis needs; the slowest own step is
the strings (two regular expressions over every byte). A whole scan of the 1,001 files of a corpus takes 2.00 s with 1 process,
1.23 s with 2, 760.8 ms with 4 and 536.9 ms with 8: 500, 814, 1,316 and 1,865 files a second. The NumPy entropy of 4 MiB takes
13.8 ms against 370.9 ms one byte value at a time (27 times), the NumPy checksum of a 4 MiB file 0.4 ms against 322.0 ms one
word at a time (883 times), with the same results. On System32 the pefile comparison sets the pace: 29.2 MB a second with 12
processes.

## 3. Verification

1,000 generated files (seed 1) with 2,407 traits set: the Python traits and the YARA rules are wrong 0 times; the parser reads
all 1,000 like pefile; 4,498 sections have the same entropy both ways within 2.4e-14 bits; the three checksums agree on all
1,000 files.

3,000 damaged copies: the parser refuses 842 with its own error and never fails in another way; pefile refuses 838. Both read
2,153 and agree on every field of 2,085; the 68 others differ in imports (58), and so in import hash (58), export (9), data
directories (3) and checksum (3): after random bytes land in an import table the two parsers stop in different places. YARA and
Python give the same traits on 1,823 of 2,158 damaged copies; the largest difference is `writable_code` (257): with a wrong
section count YARA reads every declared section header, garbage included, while pescan and pefile stop at the first empty one.
None of this happens on intact files.

## 4. The demo corpus

300 generated files and one damaged copy of each: 601 files, 526 PE, 2 not PE (one damaged copy lost its `MZ`, and
`truth.json`) and 73 malformed. On the 300 intact files both rule sets match the truth exactly; YARA agrees with Python on 473 of
the 526 PE files and pefile reads 517 the same, the differences being on damaged copies. The generator's rates make every trait
appear (from 30 files with `injection_imports` to 148 with `checksum_mismatch`, counting damaged copies), with 76 files having
three indicators or more.

## What this does not say

Nothing here is measured on malware: the indicators were counted on one computer's System32 and on generated files. The real
folder shows what the traits look like on benign software (most of the common ones are noise) and that the parser holds on
4,405 real programs; it cannot say how many malicious files the traits would find or miss. See
[`limitations.md`](limitations.md).
