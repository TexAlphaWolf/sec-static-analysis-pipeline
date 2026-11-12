# Limitations

- **Traits are not verdicts, and none was measured on malware.** The indicators were counted on one computer's System32 and on
  generated files. The real folder shows how often each fires on benign software (`debugger_check` on 65.3% of the files,
  `future_timestamp` on 53.6%, `tls` on 28.2%), so those three should not be used alone; how many malicious files the rarer ones
  catch, and how many they miss, is not measured here. No malware sample is in the repository.
- **One real folder.** The files directly in `C:\Windows\System32` of one Windows 11 computer (4,716 files), not its
  subfolders, not other versions of Windows, not third-party software. Some numbers (the share of 64-bit files, of embedded
  signatures) are properties of Windows, not of software in general.
- **The time stamp test is weak by nature.** Reproducible builds put a value derived from the build in the time stamp field, so
  a "future" date is normal for Windows files; the trait is kept because it is a classic one, and the real folder shows why it
  is weak.
- **What is not parsed.** No disassembly, no unpacking, no emulation; resources, debug information, relocations, delay-load
  imports, bound imports and the .NET metadata are not read (a .NET file is recognised by its header only). The Authenticode
  signature is seen as present or absent; it is not checked, and catalog signatures are not seen at all, so
  `no_embedded_signature` is not "unsigned".
- **Entropy is a blunt signal.** A section of 7.2 bits a byte or more is compressed, encrypted or random-looking; obfuscated
  code below that and plain data above it (images in a code section) exist. The threshold is conventional, not tuned.
- **Strings are a sample.** Runs of 6 or more printable ASCII or UTF-16LE characters; URLs, IPv4 addresses and registry paths
  found in them; a record keeps the first 20 URLs and addresses. Encoded or stacked strings are not found.
- **Damaged files.** On a damaged section table YARA reads every declared header while pefile and pescan stop at an empty or
  impossible one, so traits computed from sections can differ (1,823 of 2,158 damaged copies have the same traits both ways);
  after random bytes in an import table the two parsers can stop at different entries (68 of 2,153 differ). On intact files,
  generated or real, no difference was found.
- **YARA timeouts.** One scan of System32 was reported by YARA as timed out after a limit of 60 seconds, on files that take
  milliseconds; it gave its result when run again, and the report counts such retries. The cause, probably the clock of the
  virtual machine that runs Docker, is not shown.
- **Sizes and speed.** Files above 256 MiB are skipped by default (`--max-mb`); a file is read whole into memory. The speed is
  Python's: 488 MB a second to parse, but 25 MB a second for strings, entropy and traits in one process, so large folders want
  several processes (`--workers`). The pefile comparison is much slower (1.8 MB a second) and its checksum is compared only up
  to 4 MiB.
- **Python 3.14.** yara-python publishes wheels up to Python 3.13; on 3.14 it is compiled from source, which needs a C
  compiler (CI does it on Linux). The Docker image uses Python 3.13.
