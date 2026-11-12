# Static analysis report

Source: demo: 300 generated files and 300 damaged copies (seed 1). pescan 1.0.0. Traits computed at Unix time 1800000000.

## Files

| What | Files |
|---|---|
| Files read | 601 |
| PE files | 526 |
| Not PE (no MZ header) | 2 |
| Malformed (MZ, but no readable PE header) | 73 |
| Unreadable | 0 |
| Larger than the limit | 0 |

15.7 MB read, of which 13.8 MB in PE files.
Scanned in 6.20 s: 97.0 files and 2.5 MB a second.

Malformed: the PE header is outside the file (37); no PE signature at 0x40 (12); no PE signature at 0x0 (8); no PE signature at 0x125 (1); no PE signature at 0x137 (1).

## What they are

| What | Files | Share |
|---|---|---|
| 64-bit | 359 | 68.3% |
| DLLs | 227 | 43.2% |
| .NET assemblies | 53 | 10.1% |
| Authenticode signature in the file | 181 | 34.4% |
| Header checksum set and right | 141 | 26.8% |
| Header checksum zero | 237 | 45.1% |
| No imports | 98 | 18.6% |
| Exports functions | 140 | 26.6% |
| Parser warnings | 44 | 8.4% |

Machines: x64 359, x86 167. Subsystems: windows gui 274, windows console 252.

## Indicators

A trait is a fact about how the file is built, not a verdict: benign software has many of them.

| Trait | Meaning | Files | Share | YARA | Disagree |
|---|---|---|---|---|---|
| packer_section | a section named like a packer's (UPX0, .aspack, .themida ...) | 43 | 8.2% | 43 | 0 |
| high_entropy_code | an executable section with entropy of 7.2 bits a byte or more (compressed or encrypted) | 41 | 7.8% | 41 | 0 |
| writable_code | a section that is both writable and executable | 40 | 7.6% | 81 | 41 |
| entry_outside_code | an entry point that is not inside an executable section | 58 | 11.0% | 55 | 3 |
| injection_imports | imports VirtualAllocEx, WriteProcessMemory and CreateRemoteThread together | 30 | 5.7% | 31 | 3 |
| debugger_check | imports IsDebuggerPresent or CheckRemoteDebuggerPresent | 49 | 9.3% | 49 | 0 |
| few_imports | native code with an entry point and fewer than 4 imported functions | 112 | 21.3% | 108 | 10 |
| checksum_mismatch | a header checksum that is set but wrong | 148 | 28.1% | 148 | 0 |
| future_timestamp | a link time stamp later than the time of the scan | 31 | 5.9% | 31 | 0 |
| overlay | at least 512 bytes after the last section that are not the signature | 58 | 11.0% | 48 | 10 |
| tls | a TLS directory (code that can run before the entry point) | 39 | 7.4% | 39 | 0 |

Indicators per file: 0: 161, 1: 173, 2: 116, 3: 62, 4: 12, 5 or more: 2.

## Hardening

| Missing | Meaning | Files | Share | YARA | Disagree |
|---|---|---|---|---|---|
| no_aslr | not built for address space randomisation (no DYNAMIC_BASE) | 145 | 27.6% | 145 | 0 |
| no_dep | not marked compatible with data execution prevention (no NX_COMPAT) | 133 | 25.3% | 133 | 0 |
| no_cfg | not built with Control Flow Guard (no GUARD_CF) | 101 | 19.2% | 101 | 0 |
| no_high_entropy_va | 64-bit without high-entropy ASLR (no HIGH_ENTROPY_VA) | 69 | 13.1% | 69 | 0 |
| no_embedded_signature | no Authenticode signature in the file (it may still be signed in a catalog) | 345 | 65.6% | 345 | 0 |

Files with each indicator (the first few by name):

- packer_section (43): damaged/sample00009.dll.0, damaged/sample00023.dll.0, damaged/sample00054.exe.0, damaged/sample00059.exe.0, damaged/sample00092.exe.0, damaged/sample00094.dll.0, damaged/sample00102.dll.0, damaged/sample00114.exe.0...
- high_entropy_code (41): damaged/sample00019.exe.0, damaged/sample00037.exe.0, damaged/sample00086.exe.0, damaged/sample00092.exe.0, damaged/sample00108.dll.0, damaged/sample00119.dll.0, damaged/sample00133.exe.0, damaged/sample00134.dll.0...
- writable_code (40): damaged/sample00007.exe.0, damaged/sample00027.dll.0, damaged/sample00058.exe.0, damaged/sample00059.exe.0, damaged/sample00078.dll.0, damaged/sample00080.dll.0, damaged/sample00081.exe.0, damaged/sample00087.exe.0...
- entry_outside_code (58): damaged/sample00006.exe.0, damaged/sample00015.exe.0, damaged/sample00017.dll.0, damaged/sample00018.exe.0, damaged/sample00020.dll.0, damaged/sample00030.exe.0, damaged/sample00031.dll.0, damaged/sample00032.exe.0...
- injection_imports (30): damaged/sample00034.exe.0, damaged/sample00040.exe.0, damaged/sample00065.dll.0, damaged/sample00087.exe.0, damaged/sample00104.exe.0, damaged/sample00121.exe.0, damaged/sample00127.dll.0, damaged/sample00223.dll.0...
- debugger_check (49): damaged/sample00004.dll.0, damaged/sample00066.dll.0, damaged/sample00081.exe.0, damaged/sample00083.exe.0, damaged/sample00098.dll.0, damaged/sample00104.exe.0, damaged/sample00128.exe.0, damaged/sample00149.dll.0...
- few_imports (112): damaged/sample00001.exe.0, damaged/sample00005.exe.0, damaged/sample00006.exe.0, damaged/sample00009.dll.0, damaged/sample00013.dll.0, damaged/sample00014.exe.0, damaged/sample00015.exe.0, damaged/sample00017.dll.0...
- checksum_mismatch (148): damaged/sample00001.exe.0, damaged/sample00003.exe.0, damaged/sample00004.dll.0, damaged/sample00007.exe.0, damaged/sample00008.dll.0, damaged/sample00009.dll.0, damaged/sample00010.exe.0, damaged/sample00011.dll.0...
- future_timestamp (31): damaged/sample00007.exe.0, damaged/sample00028.exe.0, damaged/sample00034.exe.0, damaged/sample00036.dll.0, damaged/sample00058.exe.0, damaged/sample00075.dll.0, damaged/sample00097.exe.0, damaged/sample00109.exe.0...
- overlay (58): damaged/sample00001.exe.0, damaged/sample00014.exe.0, damaged/sample00017.dll.0, damaged/sample00022.exe.0, damaged/sample00024.exe.0, damaged/sample00042.exe.0, damaged/sample00072.exe.0, damaged/sample00078.dll.0...
- tls (39): damaged/sample00010.exe.0, damaged/sample00016.dll.0, damaged/sample00017.dll.0, damaged/sample00019.exe.0, damaged/sample00051.dll.0, damaged/sample00080.dll.0, damaged/sample00106.exe.0, damaged/sample00119.dll.0...

## Link time stamps

By decade: 2000s 176, 2010s 184, 2020s 166. 31 (5.9%) are later than the time of the scan and 0 are zero.

## Sections

41 of 500 executable sections have an entropy of 7.2 bits a byte or more. Most common section names: .rdata 481, .data 475, .idata 470, .text 451, .rsrc 232,  10, .MPRESS1 6, .adata 6, .enigma1 4, .vmp1 4.

## Imports

| DLL | Files importing it |
|---|---|
| kernel32.dll | 320 |
| api-ms-win-core-memory-l1-1-0.dll | 201 |
| user32.dll | 198 |
| advapi32.dll | 195 |
| ws2_32.dll | 191 |
| mscoree.dll | 37 |
| api-ms-win-core-processthreads-l1-1-0.dll | 19 |
| advapi32.dlln | 1 |
| api-ms-win-core-memory-l1-1-0.dllä | 1 |
| file and cannot be run.\x0d\x0a$ | 1 |

| Function | Files importing it |
|---|---|
| GetProcAddress | 155 |
| VirtualFree | 146 |
| VirtualQuery | 145 |
| LoadLibraryW | 134 |
| RegQueryValueExW | 129 |
| DispatchMessageW | 128 |
| MessageBoxW | 128 |
| CreateWindowExW | 124 |
| OpenProcessToken | 124 |
| RegCloseKey | 123 |

276 distinct import hashes; the largest groups: f34d5f2d4577... 17, e82dd51b0771... 13, dae02f32a21e... 12, 0f63bf17b359... 4, 8fec26d8206a... 4.

## Strings

0 files contain a URL, 0 an IPv4 address and 0 a registry path. Most common hosts: none.

## Files with three indicators or more

| File | Indicators |
|---|---|
| damaged/sample00017.dll.0 | entry_outside_code, few_imports, checksum_mismatch, overlay, tls |
| damaged/sample00080.dll.0 | writable_code, entry_outside_code, checksum_mismatch, overlay, tls |
| damaged/sample00051.dll.0 | entry_outside_code, few_imports, checksum_mismatch, tls |
| damaged/sample00104.exe.0 | writable_code, injection_imports, debugger_check, checksum_mismatch |
| damaged/sample00161.exe.0 | entry_outside_code, few_imports, checksum_mismatch, tls |
| damaged/sample00162.dll.0 | packer_section, entry_outside_code, few_imports, overlay |
| damaged/sample00193.exe.0 | entry_outside_code, few_imports, checksum_mismatch, future_timestamp |
| damaged/sample00208.exe.0 | debugger_check, checksum_mismatch, overlay, tls |
| damaged/sample00210.dll.0 | high_entropy_code, entry_outside_code, debugger_check, overlay |
| damaged/sample00216.dll.0 | packer_section, writable_code, few_imports, checksum_mismatch |
| damaged/sample00223.dll.0 | high_entropy_code, injection_imports, checksum_mismatch, tls |
| damaged/sample00245.dll.0 | few_imports, checksum_mismatch, future_timestamp, overlay |
| damaged/sample00250.exe.0 | packer_section, debugger_check, few_imports, checksum_mismatch |
| sample00080.dll | writable_code, entry_outside_code, injection_imports, tls |
| damaged/sample00001.exe.0 | few_imports, checksum_mismatch, overlay |
| damaged/sample00007.exe.0 | writable_code, checksum_mismatch, future_timestamp |
| damaged/sample00009.dll.0 | packer_section, few_imports, checksum_mismatch |
| damaged/sample00015.exe.0 | entry_outside_code, few_imports, checksum_mismatch |
| damaged/sample00019.exe.0 | high_entropy_code, checksum_mismatch, tls |
| damaged/sample00020.dll.0 | entry_outside_code, few_imports, checksum_mismatch |
| damaged/sample00030.exe.0 | entry_outside_code, few_imports, checksum_mismatch |
| damaged/sample00031.dll.0 | entry_outside_code, few_imports, checksum_mismatch |
| damaged/sample00032.exe.0 | entry_outside_code, few_imports, checksum_mismatch |
| damaged/sample00034.exe.0 | injection_imports, checksum_mismatch, future_timestamp |
| damaged/sample00037.exe.0 | high_entropy_code, few_imports, checksum_mismatch |

## Two ways of computing

YARA rules ([`traits.yar`](https://github.com/TexAlphaWolf/sec-static-analysis-pipeline/blob/main/src/pescan/rules/traits.yar)) and the Python traits give the same set on 473 of 526 files.
pefile read 526 of 526 files (it refused 0); on 517 every field is the same as this parser's. Fields that differ: export 1, imphash 8, imports 8. The checksum was compared on 526 files (pefile's is slow beyond 4 MiB).

## Against the truth

300 files have a known truth: the Python traits are exactly right on 300 and the YARA rules on 300.

| Trait | Python right / false / missed | YARA right / false / missed |
|---|---|---|
| packer_section | 24/0/0 | 24/0/0 |
| high_entropy_code | 25/0/0 | 25/0/0 |
| writable_code | 21/0/0 | 21/0/0 |
| entry_outside_code | 16/0/0 | 16/0/0 |
| injection_imports | 20/0/0 | 20/0/0 |
| debugger_check | 32/0/0 | 32/0/0 |
| few_imports | 24/0/0 | 24/0/0 |
| checksum_mismatch | 21/0/0 | 21/0/0 |
| future_timestamp | 16/0/0 | 16/0/0 |
| overlay | 25/0/0 | 25/0/0 |
| tls | 20/0/0 | 20/0/0 |
| no_aslr | 80/0/0 | 80/0/0 |
| no_dep | 77/0/0 | 77/0/0 |
| no_cfg | 60/0/0 | 60/0/0 |
| no_high_entropy_va | 41/0/0 | 41/0/0 |
| no_embedded_signature | 198/0/0 | 198/0/0 |
