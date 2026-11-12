# Method

What every number in a report means, and the choices behind it.

## Reading a file

A file is read whole into memory (files above `--max-mb`, 256 MiB by default, are skipped and counted). It is **not PE** if it
does not start with `MZ`; it is **malformed** if it starts with `MZ` but the parser cannot find a PE header it can read (the
pointer at offset 0x3C leads outside the file, there is no `PE\0\0` signature, the optional header is cut short or has an
unknown magic). Everything else is a PE file, even when parts of it are damaged; what could not be read is listed in the
record's `warnings`.

The parser ([`pe.py`](../src/pescan/pe.py)) takes from the headers: machine, number of sections, link time stamp,
characteristics, PE32 or PE32+, entry point, image base, section and file alignment, size of image and of headers, the
header checksum, subsystem, DLL characteristics and the data directories. Then:

- **Section table.** At most 2,048 entries are read; the table ends at an entry that is all zeros, or at one with three or more
  impossible values (raw data past the end of the file, a rounded pointer past the end, a virtual size or address above
  256 MiB, a pointer not aligned to the file alignment). This is where pefile stops too. YARA reads every entry the header
  declares, which matters only for damaged files.
- **Addresses.** An address (RVA) belongs to the section whose range holds it; a section's range is the larger of its virtual
  and raw size, cut at the start of the next section, and the raw size is not believed when it runs past the end of the file.
  Raw pointers are rounded down to 512 bytes and section addresses to the section alignment, as the Windows loader does. An
  address in no section is a file offset (the headers).
- **Imports.** The import directory is a list of descriptors ending with an all-zero one (at most 4,096); for each DLL the
  lookup table (or the address table when there is none) lists functions until a zero entry (at most 8,192 per DLL). The high
  bit marks an import by ordinal; otherwise the entry points to a hint and a name.
- **Exports.** The DLL name and the number of functions and of names in the export directory.
- **Signature, TLS, .NET.** The security directory gives the offset and size of the Authenticode blob (its presence is
  reported, it is not verified); a TLS directory and a CLR (.NET) header are reported when their directory entry is set.

## What is computed

- **Hashes:** MD5, SHA-1 and SHA-256 of the whole file.
- **Import hash:** Mandiant's definition, so the value matches pefile's and VirusTotal's: for each import in order,
  `dll.function` in lower case, the DLL without `.dll`, `.ocx` or `.sys`; an import by ordinal from `ws2_32`, `wsock32` or
  `oleaut32` is named from pefile's tables, any other one is `ordN`; the MD5 of the list joined by commas. A file without
  imports has none.
- **Entropy:** Shannon entropy in bits per byte of each section's raw bytes (0 for an empty one, 8 for bytes all equally
  frequent). Compressed or encrypted data is near 8; machine code is usually between 5.5 and 6.5.
- **Checksum:** the value the header's CheckSum field should hold: the file's 32-bit words (the field itself skipped) added
  with end-around carry, folded to 16 bits, plus the file size.
- **Overlay:** the bytes after the end of the last section's raw data. The Authenticode signature lives there in a signed
  file, so the `overlay` trait counts what is left once the signature is taken out.
- **Strings:** runs of 6 or more printable characters, in ASCII and in UTF-16LE. In them: URLs (the host is an IPv4 address or
  a name ending in letters, so the ASN.1 tag that follows a URL in a certificate is not read as part of it), IPv4 addresses
  (each part 0 to 255) and registry paths. A record keeps the first 20 distinct URLs and addresses.

## The traits

Each trait is written in [`features.py`](../src/pescan/features.py) and in [`rules/traits.yar`](../src/pescan/rules/traits.yar)
with the same definition.

| Trait | Definition |
|---|---|
| `packer_section` | a section is named like a packer's: UPX0, UPX1, UPX2, .aspack, .adata, .packed, MPRESS1/2, .petite, .nsp0-2, .vmp0-2, .themida, .enigma1/2, PEC2, .perplex, .yP, .kkrunch |
| `high_entropy_code` | an executable section with raw data has an entropy of 7.2 bits a byte or more |
| `writable_code` | a section is both executable and writable |
| `entry_outside_code` | the entry point is not 0 and no executable section holds it |
| `injection_imports` | the file imports `VirtualAllocEx`, `WriteProcessMemory` and `CreateRemoteThread` (or `...Ex`), from any DLL |
| `debugger_check` | the file imports `IsDebuggerPresent` or `CheckRemoteDebuggerPresent` |
| `few_imports` | native code (no .NET header) with an entry point imports fewer than 4 functions |
| `checksum_mismatch` | the header checksum is not 0 and not the computed one |
| `future_timestamp` | the link time stamp is later than the time of the scan |
| `overlay` | 512 bytes or more after the last section that are not the signature |
| `tls` | the file has a TLS directory |
| `no_aslr` | DLL characteristics lack DYNAMIC_BASE |
| `no_dep` | they lack NX_COMPAT |
| `no_cfg` | they lack GUARD_CF |
| `no_high_entropy_va` | a PE32+ file lacks HIGH_ENTROPY_VA |
| `no_embedded_signature` | the security directory is empty (the file may still be signed in a catalog) |

The thresholds (7.2 bits, 4 imports, 512 bytes) are conventional, not tuned: the real folder shows how often each fires on
benign files.

## Two ways of computing

- **Parser against pefile.** 20 fields are compared on every file with `--reference` and in `verify`: the header fields, the
  data directories, the sections (sorted by address, as pefile keeps them) and their entropies (equal within 1e-9), the
  imports in order (by name or ordinal), the export, the import hash and the computed checksum (pefile's is one Python loop per
  word, so it is compared only on files up to 4 MiB).
- **Python against YARA.** The set of traits from `features.py` and from the YARA rules, file by file.
- **Fast against literal.** The entropy with NumPy against one byte value at a time, and the checksum with NumPy against one
  word at a time (and pefile's).
- **Against the truth.** The corpus generator sets each trait from its specification without parsing anything, and writes
  decoys: compressed data in a section that is not code, a DLL without an entry point, two of the three injection imports, a
  .NET file with one import, a checksum of zero, an overlay of under 512 bytes, a signature that is all of the overlay. A
  corpus is scanned at a fixed time (15 January 2027) so `future_timestamp` is reproducible.
- **Damaged copies.** Each generated file is damaged one to three times (truncated, random header bytes, a random pointer to
  the PE header, a random section count, a random data directory, a random section header field, random bytes in the imports).
  There is no right answer for a broken file, so nothing is scored, but the parser must refuse it only with its own `PEError`:
  any other exception fails `verify`. Where both parsers read a damaged copy, and where Python and YARA both run, the
  differences are counted.
