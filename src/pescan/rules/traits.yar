/*
  The traits of pescan, as YARA rules. Each rule has the name of a trait in features.py and the same definition, written with
  YARA's pe and math modules; `pescan verify` and the scan report count the files where the two disagree.
  External variable: now (Unix time of the scan), for future_timestamp.
*/

import "pe"
import "math"

private rule native_with_entry
{
    condition:
        pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address == 0 and pe.entry_point_raw != 0
}

rule packer_section : indicator
{
    meta:
        description = "a section named like a packer's (UPX0, .aspack, .themida ...)"
    condition:
        for any s in pe.sections : (
            s.name == "UPX0" or s.name == "UPX1" or s.name == "UPX2" or s.name == ".aspack" or s.name == ".adata" or
            s.name == ".packed" or s.name == "MPRESS1" or s.name == "MPRESS2" or s.name == ".MPRESS1" or
            s.name == ".MPRESS2" or s.name == ".petite" or s.name == ".nsp0" or s.name == ".nsp1" or s.name == ".nsp2" or
            s.name == ".vmp0" or s.name == ".vmp1" or s.name == ".vmp2" or s.name == ".themida" or s.name == ".enigma1" or
            s.name == ".enigma2" or s.name == "PEC2" or s.name == ".perplex" or s.name == ".yP" or s.name == ".kkrunch"
        )
}

rule high_entropy_code : indicator
{
    meta:
        description = "an executable section with entropy of 7.2 bits a byte or more"
    condition:
        for any s in pe.sections : (
            s.characteristics & pe.SECTION_MEM_EXECUTE and s.raw_data_size > 0 and
            math.entropy(s.raw_data_offset & 0xFFFFFE00, s.raw_data_size) >= 7.2
        )
}

rule writable_code : indicator
{
    meta:
        description = "a section that is both writable and executable"
    condition:
        for any s in pe.sections : (s.characteristics & pe.SECTION_MEM_EXECUTE and s.characteristics & pe.SECTION_MEM_WRITE)
}

rule entry_outside_code : indicator
{
    meta:
        description = "an entry point that is not inside an executable section"
    condition:
        pe.is_pe and pe.entry_point_raw != 0 and not for any s in pe.sections : (
            s.characteristics & pe.SECTION_MEM_EXECUTE and pe.entry_point_raw >= s.virtual_address and (
                pe.entry_point_raw < s.virtual_address + s.virtual_size or
                pe.entry_point_raw < s.virtual_address + s.raw_data_size
            )
        )
}

rule injection_imports : indicator
{
    meta:
        description = "imports VirtualAllocEx, WriteProcessMemory and CreateRemoteThread together"
    condition:
        pe.imports(/./, /^VirtualAllocEx$/) > 0 and pe.imports(/./, /^WriteProcessMemory$/) > 0 and
        pe.imports(/./, /^CreateRemoteThread(Ex)?$/) > 0
}

rule debugger_check : indicator
{
    meta:
        description = "imports IsDebuggerPresent or CheckRemoteDebuggerPresent"
    condition:
        pe.imports(/./, /^(IsDebuggerPresent|CheckRemoteDebuggerPresent)$/) > 0
}

rule few_imports : indicator
{
    meta:
        description = "native code with an entry point and fewer than 4 imported functions"
    condition:
        native_with_entry and pe.number_of_imported_functions < 4
}

rule checksum_mismatch : indicator
{
    meta:
        description = "a header checksum that is set but wrong"
    condition:
        pe.checksum != 0 and pe.checksum != pe.calculate_checksum()
}

rule future_timestamp : indicator
{
    meta:
        description = "a link time stamp later than the time of the scan"
    condition:
        pe.timestamp > now
}

rule overlay : indicator
{
    meta:
        description = "at least 512 bytes after the last section that are not the signature"
    condition:
        pe.overlay.size >= 512 and (
            pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].size == 0 or
            pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].virtual_address < pe.overlay.offset or
            pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].virtual_address +
                pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].size > filesize or
            pe.overlay.size - pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].size >= 512
        )
}

rule tls : indicator
{
    meta:
        description = "a TLS directory (code that can run before the entry point)"
    condition:
        pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_TLS].virtual_address != 0
}

rule no_aslr : hardening
{
    condition:
        pe.is_pe and not pe.dll_characteristics & pe.DYNAMIC_BASE
}

rule no_dep : hardening
{
    condition:
        pe.is_pe and not pe.dll_characteristics & pe.NX_COMPAT
}

rule no_cfg : hardening
{
    condition:
        pe.is_pe and not pe.dll_characteristics & pe.GUARD_CF
}

rule no_high_entropy_va : hardening
{
    condition:
        pe.is_pe and pe.is_64bit() and not pe.dll_characteristics & pe.HIGH_ENTROPY_VA
}

rule no_embedded_signature : hardening
{
    condition:
        pe.is_pe and pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].size == 0
}
