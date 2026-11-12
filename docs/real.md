# Static analysis report

Source: C:\Windows\System32 (Windows 11). pescan 1.0.0. Traits computed at Unix time 1794521162.

Published copy: source renamed; file names kept only for traits found in at most 50 files.

## Files

| What | Files |
|---|---|
| Files read | 4,716 |
| PE files | 4,405 |
| Not PE (no MZ header) | 311 |
| Malformed (MZ, but no readable PE header) | 0 |
| Unreadable | 0 |
| Larger than the limit | 0 |

3,014.5 MB read, of which 2,983.1 MB in PE files.
Scanned in 103.06 s: 45.8 files and 29.2 MB a second.

## What they are

| What | Files | Share |
|---|---|---|
| 64-bit | 4,387 | 99.6% |
| DLLs | 3,756 | 85.3% |
| .NET assemblies | 28 | 0.6% |
| Authenticode signature in the file | 1,097 | 24.9% |
| Header checksum set and right | 4,404 | 100.0% |
| Header checksum zero | 1 | 0.0% |
| No imports | 472 | 10.7% |
| Exports functions | 3,518 | 79.9% |
| Parser warnings | 0 | 0.0% |

Machines: x64 4,387, x86 18. Subsystems: windows console 2,654, windows gui 1,471, native 272, boot application 8.

## Indicators

A trait is a fact about how the file is built, not a verdict: benign software has many of them.

| Trait | Meaning | Files | Share | YARA | Disagree |
|---|---|---|---|---|---|
| packer_section | a section named like a packer's (UPX0, .aspack, .themida ...) | 0 | 0.0% | 0 | 0 |
| high_entropy_code | an executable section with entropy of 7.2 bits a byte or more (compressed or encrypted) | 6 | 0.1% | 6 | 0 |
| writable_code | a section that is both writable and executable | 0 | 0.0% | 0 | 0 |
| entry_outside_code | an entry point that is not inside an executable section | 0 | 0.0% | 0 | 0 |
| injection_imports | imports VirtualAllocEx, WriteProcessMemory and CreateRemoteThread together | 4 | 0.1% | 4 | 0 |
| debugger_check | imports IsDebuggerPresent or CheckRemoteDebuggerPresent | 2,875 | 65.3% | 2,875 | 0 |
| few_imports | native code with an entry point and fewer than 4 imported functions | 21 | 0.5% | 21 | 0 |
| checksum_mismatch | a header checksum that is set but wrong | 0 | 0.0% | 0 | 0 |
| future_timestamp | a link time stamp later than the time of the scan | 2,362 | 53.6% | 2,362 | 0 |
| overlay | at least 512 bytes after the last section that are not the signature | 0 | 0.0% | 0 | 0 |
| tls | a TLS directory (code that can run before the entry point) | 1,243 | 28.2% | 1,243 | 0 |

Indicators per file: 0: 690, 1: 1,569, 2: 1,500, 3: 642, 4: 4, 5 or more: 0.

## Hardening

| Missing | Meaning | Files | Share | YARA | Disagree |
|---|---|---|---|---|---|
| no_aslr | not built for address space randomisation (no DYNAMIC_BASE) | 37 | 0.8% | 37 | 0 |
| no_dep | not marked compatible with data execution prevention (no NX_COMPAT) | 101 | 2.3% | 101 | 0 |
| no_cfg | not built with Control Flow Guard (no GUARD_CF) | 419 | 9.5% | 419 | 0 |
| no_high_entropy_va | 64-bit without high-entropy ASLR (no HIGH_ENTROPY_VA) | 137 | 3.1% | 137 | 0 |
| no_embedded_signature | no Authenticode signature in the file (it may still be signed in a catalog) | 3,308 | 75.1% | 3,308 | 0 |

Files with each indicator (the first few by name):

- high_entropy_code (6): ClipUp.exe, d3dcsx_42.dll, GenValObj.exe, SppExtComObj.Exe, sppsvc.exe, WMVDECOD.DLL
- injection_imports (4): dbgeng.dll, Faultrep.dll, kernel32.dll, ttdinject.exe
- few_imports (21): HalExtIntcLpioDMA.dll, HalExtIntcPseDMA.dll, HalExtPL080.dll, hvax64.exe, hvix64.exe, iumdll.dll, mcupdate_AuthenticAMD.dll, mcupdate_GenuineIntel.dll...

## Link time stamps

By decade: 1970s 272, 1980s 332, 1990s 301, 2000s 373, 2010s 416, 2020s 441, 2030s 314, 2040s 275, 2050s 264, 2060s 328, 2070s 270, 2080s 315, 2090s 292, 2100s 212. 2,362 (53.6%) are later than the time of the scan and 0 are zero.

## Sections

6 of 8,021 executable sections have an entropy of 7.2 bits a byte or more. Most common section names: .rsrc 4,346, .text 4,187, .data 4,186, .reloc 4,181, .rdata 4,042, .pdata 3,957, fothk 3,584, .didat 1,995, .imrsiv 56, INIT 46.

## Imports

| DLL | Files importing it |
|---|---|
| api-ms-win-core-processthreads-l1-1-0.dll | 2,842 |
| api-ms-win-core-sysinfo-l1-1-0.dll | 2,828 |
| api-ms-win-core-profile-l1-1-0.dll | 2,793 |
| api-ms-win-core-errorhandling-l1-1-0.dll | 2,776 |
| api-ms-win-core-libraryloader-l1-2-0.dll | 2,693 |
| api-ms-win-core-synch-l1-1-0.dll | 2,425 |
| ntdll.dll | 2,402 |
| api-ms-win-core-handle-l1-1-0.dll | 2,350 |
| api-ms-win-core-debug-l1-1-0.dll | 2,328 |
| api-ms-win-core-heap-l1-1-0.dll | 2,304 |

| Function | Files importing it |
|---|---|
| GetCurrentThreadId | 3,834 |
| GetCurrentProcessId | 3,833 |
| GetSystemTimeAsFileTime | 3,824 |
| QueryPerformanceCounter | 3,820 |
| RtlLookupFunctionEntry | 3,695 |
| RtlCaptureContext | 3,680 |
| RtlVirtualUnwind | 3,680 |
| __C_specific_handler | 3,671 |
| SetUnhandledExceptionFilter | 3,669 |
| GetCurrentProcess | 3,666 |

3,837 distinct import hashes; the largest groups: dae02f32a21e... 10, 0666ed1f1c91... 7, 0deb7e66a485... 6, 88867f47f9d2... 6, b52012fa7925... 5.

## Strings

1,732 files contain a URL, 1,111 an IPv4 address and 193 a registry path. Most common hosts: www.microsoft.com 1,161, crl.microsoft.com 1,073, schemas.microsoft.com 455, www.w3.org 176, go.microsoft.com 117, microsoft.com 64, login.microsoft.com 52, cacerts.digicert.com 48, crl3.digicert.com 48, crl4.digicert.com 48.

## Files with three indicators or more

| File | Indicators |
|---|---|
| ClipUp.exe | high_entropy_code, debugger_check, future_timestamp, tls |
| dbgeng.dll | injection_imports, debugger_check, future_timestamp, tls |
| Faultrep.dll | injection_imports, debugger_check, future_timestamp, tls |
| ttdinject.exe | injection_imports, debugger_check, future_timestamp, tls |
| aadauthhelper.dll | debugger_check, future_timestamp, tls |
| aadcloudap.dll | debugger_check, future_timestamp, tls |
| aadtb.dll | debugger_check, future_timestamp, tls |
| AboutSettingsHandlers.dll | debugger_check, future_timestamp, tls |
| AboveLockAppHost.dll | debugger_check, future_timestamp, tls |
| AccountsRt.dll | debugger_check, future_timestamp, tls |
| AcGenral.dll | debugger_check, future_timestamp, tls |
| aclui.dll | debugger_check, future_timestamp, tls |
| ActivationClient.dll | debugger_check, future_timestamp, tls |
| ActiveSyncProvider.dll | debugger_check, future_timestamp, tls |
| adhsvc.dll | debugger_check, future_timestamp, tls |
| aeinv.dll | debugger_check, future_timestamp, tls |
| aepic.dll | debugger_check, future_timestamp, tls |
| agentactivationruntimewindows.dll | debugger_check, future_timestamp, tls |
| AgentGovernanceCSP.dll | debugger_check, future_timestamp, tls |
| AggregatorHost.exe | debugger_check, future_timestamp, tls |
| APHostService.dll | debugger_check, future_timestamp, tls |
| APMon.dll | debugger_check, future_timestamp, tls |
| AppContracts.dll | debugger_check, future_timestamp, tls |
| AppExtension.dll | debugger_check, future_timestamp, tls |
| appinfo.dll | debugger_check, future_timestamp, tls |

## Two ways of computing

YARA rules ([`traits.yar`](https://github.com/TexAlphaWolf/sec-static-analysis-pipeline/blob/main/src/pescan/rules/traits.yar)) and the Python traits give the same set on 4,405 of 4,405 files; 1 scan was reported by YARA as timed out and run again.
pefile read 4,405 of 4,405 files (it refused 0); on 4,405 every field is the same as this parser's. Fields that differ: none. The checksum was compared on 4,306 files (pefile's is slow beyond 4 MiB).
