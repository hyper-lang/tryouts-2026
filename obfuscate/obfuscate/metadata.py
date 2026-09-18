"""NET CLI metadata identity handling: MVID, module GUID, version, strong-name, debug (R3).

Pure-Python metadata hardening pass.  All edits are in-place, constant-length
byte patches on a mutable ``bytearray`` — never changes PE section layout or
metadata stream offsets.

Sub-passes (all default-on):

1. **MVID** — replace the 16-byte #GUID heap entry for the MVID with a
   seed-derived random GUID.
2. **Module GUID** — replace the 16-byte #GUID heap entry at index 2.
3. **Timestamp** — randomize the COFF header TimeDateStamp.
4. **Assembly version** — randomize major / minor / build / revision (each u2
   in the Assembly table row).
5. **Strong-name soft-strip** — zero the signature bytes and clear the
   ``afPublicKey`` flag in Assembly.Flags.
6. **PE checksum** — zero the Optional Header CheckSum field.
7. **Rich header** — replace the XOR key with a seed-derived variant and
   re-encode the DanS marker so the header is still decodable.
8. **Debug directory** — zero each IMAGE_DEBUG_DIRECTORY row (28 bytes each)
   in place to remove CodeView / native-image / PDB references.
"""

from __future__ import annotations

import hashlib
import struct
from typing import List, Tuple

from obfuscate.pe import (
    _ASSEMBLY_FLAG_PUBLIC_KEY,
    _COFF_OFFSET,
    _GUID_SIZE,
    _OPTIONAL_OFFSET,
    _TIMESTAMP_COFF_OFFSET,
)


# Attributes that we neutralize (name -> catalog_id prefix for findings)
_AUTHORSHIP_ATTRS = {
    "AssemblyCompanyAttribute": "company",
    "AssemblyProductAttribute": "product",
    "AssemblyCopyrightAttribute": "copyright",
}

# Debuggable attribute name
_DEBUGGABLE_ATTR = "DebuggableAttribute"

# VS_VERSION_INFO StringFileInfo keys to scrub
_VERSION_INFO_KEYS = (
    "CompanyName",
    "ProductName",
    "OriginalFilename",
    "FileDescription",
    "FileVersion",
)


def _seed_random_text(seed: int, domain: str, length: int) -> str:
    """Generate deterministic random ASCII text of exact length.
    
    Generates printable ASCII (0x20-0x7E) to ensure it's valid UTF-8/UTF-16LE.
    """
    key = hashlib.sha256(f"{seed}:{domain}".encode()).digest()
    result = []
    i = 0
    while len(result) < length:
        if i >= len(key):
            key = hashlib.sha256(key).digest()
            i = 0
        b = key[i]
        i += 1
        if 0x20 <= b <= 0x7E:
            result.append(chr(b))
    return "".join(result[:length])


def _replace_blob_in_place(data: bytearray, blob_offset: int, blob_size: int, 
                           new_content: bytes, findings: List[Tuple[str, int, str]],
                           catalog_id: str, description: str) -> bool:
    """Replace blob content in-place if size matches exactly.
    
    CustomAttribute blobs have format: prolog(2) + serString(len + utf8).
    We need to replace just the UTF-8 string portion with equal-length content.
    """
    if blob_offset < 0 or blob_offset + blob_size > len(data):
        return False
    
    # Parse the blob to find the string content offset and length
    # Format: u2 prolog (0x0001) + serString (compressed_len + utf8_bytes)
    if blob_size < 4:
        return False
    
    prolog = struct.unpack_from("<H", data, blob_offset)[0]
    if prolog != 1:
        return False
    
    # Decode compressed length
    pos = blob_offset + 2
    first = data[pos]
    if (first & 0x80) == 0:
        str_len = first
        pos += 1
    elif (first & 0xC0) == 0x80:
        if pos + 1 >= blob_offset + blob_size:
            return False
        str_len = ((first & 0x3F) << 8) | data[pos + 1]
        pos += 2
    elif (first & 0xE0) == 0xC0:
        if pos + 3 >= blob_offset + blob_size:
            return False
        str_len = int.from_bytes(data[pos:pos + 4], "big") & 0x1FFFFFFF
        pos += 4
    else:
        return False
    
    str_end = pos + str_len
    if str_end > blob_offset + blob_size:
        return False
    
    # Check if new content fits exactly
    if len(new_content) != str_len:
        return False
    
    # Replace the string content in-place
    data[pos:str_end] = new_content
    findings.append(("attributes", pos, f"{catalog_id}: {description}"))
    return True


def _scrub_version_info_string(data: bytearray, offset: int, length: int,
                                new_content: bytes, findings: List[Tuple[str, int, str]],
                                catalog_id: str, description: str) -> bool:
    """Replace a VS_VERSION_INFO string value in-place if size matches.
    
    VS_VERSION_INFO strings are UTF-16LE. The length is in characters (not bytes).
    """
    if offset < 0 or offset + length * 2 > len(data):
        return False
    
    # The new content must be exactly the same number of characters
    if len(new_content) != length * 2:
        return False
    
    # Replace in-place
    data[offset:offset + length * 2] = new_content
    findings.append(("attributes", offset, f"{catalog_id}: {description}"))
    return True


def attributes_pass(
    pe_info: dict,
    data: bytearray,
    seed: int,
) -> List[Tuple[str, int, str]]:
    """Apply the R3 attributes hardening pass in-place on *data.
    
    Neutralizes:
    1. Authorship custom attributes (Company, Product, Copyright) by replacing
       the blob string value with equal-length random text (seed-derived).
    2. DebuggableAttribute by neutralizing its value.
    3. .rsrc VS_VERSION_INFO StringFileInfo strings (CompanyName, ProductName,
       OriginalFilename, FileDescription, FileVersion) via equal-length 
       in-place replacement when encoding allows constant-length edit.
    
    When size mismatch prevents in-place edit, report as untouched with 
    mitigation 'none'.
    
    Parameters
    ----------
    pe_info : dict
        Result of ``obfuscate.pe.analyze()`` with metadata containing
        custom_attributes and version_info.
    data : bytearray
        Mutable image bytes. Modified in-place; never resized.
    seed : int
        Seed for deterministic, reproducible randomization.
    
    Returns
    -------
    list of (catalog_id, offset, description)
        One tuple per mutation applied. ``catalog_id`` is ``"attributes"``.
    """
    findings: List[Tuple[str, int, str]] = []
    md = pe_info.get("metadata", {})
    
    custom_attrs = md.get("custom_attributes", {})
    version_info = md.get("version_info", {})
    
    # --- 1. Neutralize authorship custom attributes ---
    for attr_name, catalog_suffix in _AUTHORSHIP_ATTRS.items():
        attr_info = custom_attrs.get(attr_name)
        if not attr_info:
            findings.append(("attributes", 0, f"{attr_name}: not found (mitigation=none)"))
            continue
        
        blob_offset = attr_info.get("blob_offset", 0)
        blob_size = attr_info.get("blob_size", 0)
        decoded = attr_info.get("decoded")
        
        if not decoded:
            findings.append(("attributes", 0, f"{attr_name}: could not decode (mitigation=none)"))
            continue
        
        # Generate replacement text of exact same length
        new_text = _seed_random_text(seed, f"attr_{catalog_suffix}", len(decoded))
        new_bytes = new_text.encode("utf-8")
        
        if not _replace_blob_in_place(data, blob_offset, blob_size, new_bytes, findings,
                                       f"attr_{catalog_suffix}", f"{attr_name} neutralized"):
            findings.append(("attributes", 0, f"{attr_name}: size mismatch, left untouched (mitigation=none)"))
    
    # --- 2. Neutralize DebuggableAttribute ---
    debuggable_info = custom_attrs.get(_DEBUGGABLE_ATTR)
    if debuggable_info:
        blob_offset = debuggable_info.get("blob_offset", 0)
        blob_size = debuggable_info.get("blob_size", 0)
        
        # DebuggableAttribute blob: prolog(2) + u2 enum value + padding
        # We replace the enum value (2 bytes at offset +2) with 0 (Default)
        if blob_offset and blob_offset + 4 <= len(data) and blob_size >= 4:
            data[blob_offset + 2:blob_offset + 4] = b"\x00\x00"
            findings.append(("attributes", blob_offset + 2, "DebuggableAttribute neutralized"))
        else:
            findings.append(("attributes", 0, "DebuggableAttribute: size mismatch, left untouched (mitigation=none)"))
    else:
        findings.append(("attributes", 0, "DebuggableAttribute: not found (mitigation=none)"))
    
    # --- 3. Scrub VS_VERSION_INFO StringFileInfo strings ---
    string_file_info = version_info.get("string_file_info", {})
    for key in _VERSION_INFO_KEYS:
        info = string_file_info.get(key)
        if not info:
            findings.append(("attributes", 0, f"VS_VERSION_INFO.{key}: not found (mitigation=none)"))
            continue
        
        offset = info.get("offset", 0)
        length = info.get("length", 0)
        decoded = info.get("value", "")
        
        if not decoded or length == 0:
            findings.append(("attributes", 0, f"VS_VERSION_INFO.{key}: empty, left untouched (mitigation=none)"))
            continue
        
        # Generate replacement text of exact same character length
        new_text = _seed_random_text(seed, f"vi_{key.lower()}", len(decoded))
        new_bytes = new_text.encode("utf-16le")
        
        if not _scrub_version_info_string(data, offset, length, new_bytes, findings,
                                           f"vi_{key.lower()}", f"VS_VERSION_INFO.{key} neutralized"):
            findings.append(("attributes", 0, f"VS_VERSION_INFO.{key}: size mismatch, left untouched (mitigation=none)"))
    
    return findings

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# PE32+ optional-header CheckSum field: at byte 64 from the optional header
# start in the builder's struct layout (matches the fixture's checksum_offset).
_CHECKSUM_FILE_OFFSET = _OPTIONAL_OFFSET + 64

_DEBUG_ROW_SIZE = 28  # sizeof(IMAGE_DEBUG_DIRECTORY)


def _seed_bytes(seed: int, length: int, domain: str) -> bytes:
    """Deterministic seed-derived byte sequence via hashlib.

    Returns ``hashlib.sha256(f"{seed}:{domain}".encode()).digest()[:length]``.
    """
    return hashlib.sha256(f"{seed}:{domain}".encode()).digest()[:length]


def _seed_u32(seed: int, domain: str) -> int:
    """Deterministic seed-derived u32 value."""
    return struct.unpack_from("<I", _seed_bytes(seed, 4, domain))[0]


def _seed_u16(seed: int, domain: str) -> int:
    """Deterministic seed-derived u16 value."""
    return struct.unpack_from("<H", _seed_bytes(seed, 2, domain))[0]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def metadata_pass(
    pe_info: dict,
    data: bytearray,
    seed: int,
) -> List[Tuple[str, int, str]]:
    """Apply the R3 metadata hardening pass in-place on *data*.

    Parameters
    ----------
    pe_info : dict
        Result of ``obfuscate.pe.analyze()`` enriched with ``"data"`` and
        ``"path"`` keys (the ``pe_info`` contract used throughout the project).
    data : bytearray
        Mutable image bytes.  Modified in-place; never resized.
    seed : int
        Seed for deterministic, reproducible randomization via hashlib.

    Returns
    -------
    list of (catalog_id, offset, description)
        One tuple per mutation applied.  ``catalog_id`` is ``"metadata"``
        (matching the catalog mitigation vocabulary).
    """
    findings: List[Tuple[str, int, str]] = []
    md = pe_info.get("metadata", {})
    pe = pe_info.get("pe", {})
    debug = pe_info.get("debug", {})
    rich = pe_info.get("rich")

    # --- 1. Randomize MVID (#GUID heap entry at index 1) -------------------
    mvid_off = md.get("mvid_offset", 0)
    if mvid_off and mvid_off + _GUID_SIZE <= len(data):
        new_mvid = _seed_bytes(seed, _GUID_SIZE, "mvid")
        data[mvid_off:mvid_off + _GUID_SIZE] = new_mvid
        findings.append(("metadata", mvid_off, "MVID randomized"))

    # --- 2. Randomize module GUID (#GUID heap entry at index 2) -------------
    mod_guid_off = md.get("module_guid_offset", 0)
    if mod_guid_off and mod_guid_off + _GUID_SIZE <= len(data):
        new_guid = _seed_bytes(seed, _GUID_SIZE, "module_guid")
        data[mod_guid_off:mod_guid_off + _GUID_SIZE] = new_guid
        findings.append(("metadata", mod_guid_off, "module GUID randomized"))

    # --- 3. Randomize COFF timestamp ---------------------------------------
    stamp_offset = _COFF_OFFSET + _TIMESTAMP_COFF_OFFSET
    if stamp_offset + 4 <= len(data):
        new_stamp = _seed_u32(seed, "timestamp")
        data[stamp_offset:stamp_offset + 4] = struct.pack("<I", new_stamp)
        findings.append(("metadata", stamp_offset, "PE timestamp randomized"))

    # --- 4. Randomize assembly version (4 × u2 in Assembly table row 0) ----
    asm_fields = md.get("assembly_fields", {})
    ver_fields = ("major", "minor", "build", "revision")
    ver_off = asm_fields.get(ver_fields[0], 0)
    if ver_off:
        parts = []
        for field, dom in zip(ver_fields,
                              ("ver_major", "ver_minor", "ver_build", "ver_revision")):
            off = asm_fields[field]
            if off + 2 > len(data):
                break
            new_val = _seed_u16(seed, dom)
            parts.append(new_val)
            data[off:off + 2] = struct.pack("<H", new_val)
        if len(parts) == 4:
            findings.append(("metadata", ver_off,
                             f"assembly version randomized to {'.'.join(str(p) for p in parts)}"))

    # --- 5. Soft-strip strong-name signature block --------------------------
    # The strong-name RVA/size live in the CLI (COR20) header at fixed offsets
    # 32 and 36 from the CLI header start, which pe_info reports.
    cli_off = pe.get("cli_header", {}).get("offset", 0) if isinstance(pe.get("cli_header"), dict) else 0
    sn_rva = sn_size = 0
    if cli_off:
        if cli_off + 40 <= len(data):
            sn_rva = struct.unpack_from("<I", data, cli_off + 32)[0]
            sn_size = struct.unpack_from("<I", data, cli_off + 36)[0]
    md_root_off = md.get("metadata_root_offset", 0)
    md_root_rva = md.get("metadata_root_rva", 0)
    if sn_rva and sn_size and md_root_off and md_root_rva:
        sn_file_off = md_root_off + (sn_rva - md_root_rva)
        end = sn_file_off + sn_size
        if sn_file_off >= 0 and end <= len(data):
            data[sn_file_off:end] = b"\x00" * sn_size
            findings.append(("metadata", sn_file_off,
                             f"strong-name signature zeroed ({sn_size} bytes)"))
    # Clear afPublicKey flag in Assembly.Flags
    asm_flags_off = asm_fields.get("flags", 0)
    if asm_flags_off and asm_flags_off + 4 <= len(data):
        flags = struct.unpack_from("<I", data, asm_flags_off)[0]
        if flags & _ASSEMBLY_FLAG_PUBLIC_KEY:
            data[asm_flags_off:asm_flags_off + 4] = struct.pack(
                "<I", flags & ~_ASSEMBLY_FLAG_PUBLIC_KEY)
            findings.append(("metadata", asm_flags_off, "strong-name flag cleared"))

    # --- 6. Zero PE checksum -----------------------------------------------
    if _CHECKSUM_FILE_OFFSET + 4 <= len(data):
        old_cksum = struct.unpack_from("<I", data, _CHECKSUM_FILE_OFFSET)[0]
        data[_CHECKSUM_FILE_OFFSET:_CHECKSUM_FILE_OFFSET + 4] = b"\x00\x00\x00\x00"
        findings.append(("metadata", _CHECKSUM_FILE_OFFSET,
                         f"PE checksum zeroed (was {old_cksum:#x})"))

    # --- 7. Normalize Rich header XOR key -----------------------------------
    if rich and rich.get("offset"):
        _normalize_rich_header(data, rich["offset"], seed, findings)

    # --- 8. Zero debug directory rows --------------------------------------
    for row in debug.get("rows", []):
        row_off = row.get("file_offset", 0)
        data_off = row.get("data_offset", 0)
        data_size = row.get("data_size", 0)
        dtype = row.get("type", 0)
        type_name = row.get("type_name", "unknown")
        if row_off and row_off + _DEBUG_ROW_SIZE <= len(data):
            data[row_off:row_off + _DEBUG_ROW_SIZE] = b"\x00" * _DEBUG_ROW_SIZE
            findings.append(("metadata", row_off,
                             f"debug directory row zeroed (type={dtype}/{type_name})"))
        if data_off and data_size and data_off + data_size <= len(data):
            data[data_off:data_off + data_size] = b"\x00" * data_size
            findings.append(("metadata", data_off,
                             f"debug data zeroed ({data_size} bytes, type={dtype})"))

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_rich_header(
    data: bytearray,
    dans_offset: int,
    seed: int,
    findings: List[Tuple[str, int, str]],
) -> None:
    """Replace the Rich header XOR key with a seed-derived variant.

    The DanS marker (4 bytes XORed with the key) is re-encoded so the
    header remains decodable with the new key.  The old key is stored in
    the 4 bytes immediately after the DanS marker on disk.
    """
    if dans_offset + 8 > len(data):
        return
    old_key = bytes(data[dans_offset + 4:dans_offset + 8])
    new_key = _seed_bytes(seed, 4, "rich_key")
    if new_key == old_key:
        return
    # DanS on disk = real_DanS XOR old_key → must become real_DanS XOR new_key
    # real_DanS XOR old_key XOR old_key XOR new_key = real_DanS XOR new_key
    dans_on_disk = bytes(data[dans_offset:dans_offset + 4])
    new_dans = bytes(a ^ b ^ c for a, b, c in zip(dans_on_disk, old_key, new_key))
    data[dans_offset:dans_offset + 4] = new_dans
    data[dans_offset + 4:dans_offset + 8] = new_key
    findings.append(("metadata", dans_offset, "Rich header key normalized"))
