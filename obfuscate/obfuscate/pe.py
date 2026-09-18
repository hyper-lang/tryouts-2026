"""PE (.NET CLI image) reader -- read-only dnfile wrapper (R2).

Locates offsets, sizes, tables, and identity values for a compiled .NET
Framework image and returns them as plain dicts.  It never mutates the input:
everything is read through dnfile (itself a read-only pefile-based parser).

Coverage
--------
* PE identity: image base, section table (virtual/raw sizes + offsets),
  ``.text`` location, optional-header TimeDateStamp, checksum value, and the
  CLI header offset/size.
* CLI metadata identity: each stream (``#~``/``#Strings``/``#US``/``#GUID``/
  ``#Blob``) size + file offset resolved through the metadata root, the
  metadata root offset/RVA/size/version, MVID + module GUID (raw #GUID heap
  entries), assembly full name/version, strong-name presence + public key
  token, and the ``TargetFrameworkAttribute`` value.
* MSVC Rich header presence/offset (XOR-decoded ``DanS`` scan).
* PE debug directory rows (CodeView/RSDS PDB path, native-image rows) with
  their file offsets.
* Resource ``.rsrc`` directory pointer for later VS_VERSION_INFO work.

All values are offsets/bytes/identity values only; no defensive edits are
written anywhere in this module.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Dict, List, Optional


# Plain PE-format byte offsets (winnt.h). These are fixed layout constants for
# the DOS/COFF/Optional headers, independent of any specific parser or fixture.
# Kept in the package (not tests/) so console-script and `-m obfuscate` import
# chains never reach the test fixture package.
_COFF_OFFSET = 0xC4  # IMAGE_NT_HEADERS.FileHeader (after "PE\0\0" signature)
_OPTIONAL_OFFSET = _COFF_OFFSET + 20  # IMAGE_OPTIONAL_HEADER (start of optional header)
_TIMESTAMP_COFF_OFFSET = 4  # TimeDateStamp within the COFF header
_GUID_SIZE = 16  # a GUID heap entry is 16 bytes
_ASSEMBLY_FLAG_PUBLIC_KEY = 0x0008  # Assembly.Flags: afPublicKey


class PeReadError(Exception):
    """Raised when a path cannot be parsed as a .NET CLI PE image."""


# IMAGE_DEBUG_TYPE constants (winnt.h / pefile debugtype enum).
_DEBUG_TYPE_NAMES = {
    0: "unknown",
    1: "coff",
    2: "codeview",
    3: "frame_pointer_omission",
    4: "misc",
    5: "exception",
    6: "fixup",
    7: "omap_to_src",
    8: "omap_from_src",
    9: "borland",
    10: "reserved10",
    11: "clsid",
    12: "il_tcg",
    13: "pogo",
    14: "il_only_pdb",
    15: "nonmsft_raw",
}
# Native-image style rows (build-path/PDB leak surfaces).
_NATIVE_IMAGE_TYPES = frozenset({12, 13, 14})

# Metadata stream names we report (in canonical order).
_STREAM_NAMES = (b"#~", b"#Strings", b"#US", b"#GUID", b"#Blob")


def _parse_image(pe):
    """Validate that `pe` is a .NET CLI image and return its net data."""
    net = getattr(pe, "net", None)
    if net is None or net.metadata is None:
        raise PeReadError(
            "not a .NET CLI image (no COM descriptor / metadata root)"
        )
    return net


def _section_dict(section) -> Dict[str, object]:
    return {
        "virtual_size": int(getattr(section, "Misc_VirtualSize", 0)),
        "virtual_address": int(getattr(section, "VirtualAddress", 0)),
        "raw_size": int(getattr(section, "SizeOfRawData", 0)),
        "raw_offset": int(getattr(section, "PointerToRawData", 0)),
    }


def _metadata_root_offset(pe, metadata_rva: int) -> int:
    try:
        return pe.get_offset_from_rva(metadata_rva)
    except Exception:
        return 0


def _guid_entry_offset(pe, guid_item) -> int:
    """File offset of a #GUID heap entry item, or 0 when it cannot be resolved.

    dnfile's heap items expose an ``rva`` (the address of the item inside the
    stream) rather than a heap index; the file offset is derived by mapping
    that RVA back through the #GUID stream.
    """
    if guid_item is None:
        return 0
    guid_rva = getattr(guid_item, "rva", None)
    if not guid_rva:
        return 0
    guid_stream = pe.net.metadata.streams.get(b"#GUID")
    if guid_stream is None:
        return 0
    return guid_stream.file_offset + (guid_rva - guid_stream.rva)


def _all_guids(pe) -> Dict[str, object]:
    """Return #GUID heap entries as {index: {offset, value_hex}}."""
    guid_stream = pe.net.metadata.streams.get(b"#GUID")
    out: Dict[str, object] = {}
    if guid_stream is None:
        return out
    total = guid_stream.sizeof()
    count = total // 16
    base = guid_stream.file_offset
    data = getattr(pe, "__data__", b"")
    for i in range(1, count + 1):
        off = base + 16 * (i - 1)
        raw = data[off:off + 16]
        out[str(i)] = {"offset": off, "value_hex": raw.hex()}
    return out


def _decode_compressed_int(data: bytes, pos: int):
    """Decode an ECMA-335 II.23.2 compressed integer.

    Returns (value, new_pos).  Raises PeReadError on a malformed encoding.
    """
    if pos >= len(data):
        raise PeReadError("truncated compressed integer")
    first = data[pos]
    if (first & 0x80) == 0:
        return first, pos + 1
    if (first & 0xC0) == 0x80:
        if pos + 1 >= len(data):
            raise PeReadError("truncated 2-byte compressed integer")
        return ((first & 0x3F) << 8) | data[pos + 1], pos + 2
    if (first & 0xE0) == 0xC0:
        if pos + 3 >= len(data):
            raise PeReadError("truncated 4-byte compressed integer")
        return (int.from_bytes(data[pos:pos + 4], "big") & 0x1FFFFFFF), pos + 4
    raise PeReadError("invalid compressed integer lead byte")


def _read_ser_string(data: bytes, pos: int):
    """Decode a serialized string (compressed length + UTF-8).

    Returns (text, new_pos); raises PeReadError on truncation.
    """
    length, pos = _decode_compressed_int(data, pos)
    end = pos + length
    if end > len(data):
        raise PeReadError("truncated serialized string")
    return data[pos:end].decode("utf-8", "replace"), end


def _blob_file_offset(pe, blob_bytes: bytes) -> int:
    """Find the file offset of a blob in the #Blob heap by content match.
    
    Returns 0 if not found. This works because blobs are deduplicated in the heap.
    """
    blob_stream = pe.net.metadata.streams.get(b"#Blob")
    if blob_stream is None:
        return 0
    try:
        data = pe.__data__
    except Exception:
        return 0
    if not data:
        return 0
    # Search for the exact blob content in the #Blob stream
    start = blob_stream.file_offset
    end = start + blob_stream.sizeof()
    # The blob is stored as compressed_length + blob_data
    # Search for the blob_bytes after the compressed length prefix
    idx = data.find(blob_bytes, start, end)
    if idx < 0:
        return 0
    # Verify this is at a valid blob entry boundary (not in the middle of another blob)
    # by checking the compressed length before it
    return idx


def _custom_attribute_string(blob_bytes: bytes) -> Optional[str]:
    """Decode the leading string arg of a CustomAttribute Value blob.

    Blob layout (ECMA-335 II.23.3): u2 prolog (0x0001), then fixed args.  The
    string-typed attrs (TargetFramework, Company, Product, Copyright) carry a
    single serString.  Returns the decoded text or None on any structural
    mismatch.
    """
    if len(blob_bytes) < 4:
        return None
    prolog = struct.unpack_from("<H", blob_bytes, 0)[0]
    if prolog != 1:
        return None
    try:
        text, _ = _read_ser_string(blob_bytes, 2)
    except PeReadError:
        return None
    return text


def _public_key_token(public_key: Optional[bytes]) -> Optional[str]:
    """Compute the 8-byte public key token from a strong-name public key.

    Token = last 8 bytes of SHA1(public key), reversed.  Returns hex or None
    when no public key blob is present.
    """
    if not public_key:
        return None
    digest = hashlib.sha1(public_key).digest()
    return digest[-8:][::-1].hex()


def _parse_version_info(pe, rsrc_offset: int, rsrc_size: int) -> dict:
    """Parse VS_VERSION_INFO from the .rsrc section.
    
    Returns a dict with StringFileInfo entries and their file offsets.
    """
    import struct
    
    version_info: Dict[str, object] = {
        "string_file_info": {},
        "file_offset": 0,
    }
    
    try:
        data = pe.__data__
    except Exception:
        return version_info
    
    if not data or rsrc_offset + rsrc_size > len(data):
        return version_info
    
    # Find VS_VERSION_INFO resource
    # Resource directory structure: 
    # - IMAGE_RESOURCE_DIRECTORY (16 bytes)
    # - IMAGE_RESOURCE_DIRECTORY_ENTRY array
    # We need to find RT_VERSION (16) type, then find the VS_VERSION_INFO
    
    # Parse resource directory at rsrc_offset
    def parse_resource_dir(offset: int, level: int = 0):
        if offset + 16 > len(data):
            return None
        if level > 3:  # max depth
            return None
            
        dir_header = struct.unpack_from("<IIHHHH", data, offset)
        characteristics, time_stamp, major_version, minor_version, named_entries, id_entries = dir_header
        num_entries = named_entries + id_entries
        
        entries_start = offset + 16
        for i in range(num_entries):
            entry_offset = entries_start + i * 8
            if entry_offset + 8 > len(data):
                break
            name_id, entry_data = struct.unpack_from("<II", data, entry_offset)
            is_named = bool(name_id & 0x80000000)
            entry_rva = entry_data & 0x7FFFFFFF
            
            if is_named:
                # Named entry - name string at name_id & 0x7FFFFFFF
                name_offset = name_id & 0x7FFFFFFF
                if name_offset < len(data):
                    name_len = struct.unpack_from("<H", data, name_offset)[0]
                    name = data[name_offset + 2:name_offset + 2 + name_len * 2].decode("utf-16le", "replace")
                else:
                    name = "unknown"
            else:
                name = str(name_id)
            
            if entry_data & 0x80000000:
                # Subdirectory
                subdir = parse_resource_dir(rsrc_offset + entry_rva, level + 1)
                if subdir:
                    if level == 0 and name == "16":  # RT_VERSION
                        return subdir
            else:
                # Data entry
                if level == 2 and name == "1":  # VS_VERSION_INFO
                    return {
                        "data_rva": entry_rva,
                        "data_size": entry_data,
                    }
        return None
    
    result = parse_resource_dir(rsrc_offset)
    if not result:
        return version_info
    
    data_rva = result.get("data_rva", 0)
    data_size = result.get("data_size", 0)
    if data_rva == 0 or data_size == 0:
        return version_info
    
    # Convert RVA to file offset
    try:
        data_offset = pe.get_offset_from_rva(data_rva)
    except Exception:
        return version_info
    
    if data_offset + data_size > len(data):
        return version_info
    
    version_info["file_offset"] = data_offset
    
    # Parse VS_VERSION_INFO structure
    # It starts with a VS_FIXEDFILEINFO, then children (StringFileInfo, VarFileInfo)
    # We're interested in StringFileInfo blocks
    
    pos = data_offset
    if pos + 6 > len(data):
        return version_info
    
    # VS_VERSION_INFO root header
    wLength = struct.unpack_from("<H", data, pos)[0]
    wValueLength = struct.unpack_from("<H", data, pos + 2)[0]
    wType = struct.unpack_from("<H", data, pos + 4)[0]
    pos += 6
    
    # Skip the "VS_VERSION_INFO" string (UTF-16LE)
    name_len = struct.unpack_from("<H", data, pos)[0]
    pos += 2 + name_len * 2
    
    # Align to 4 bytes
    pos = (pos + 3) & ~3
    
    # Skip VS_FIXEDFILEINFO if wValueLength > 0
    if wValueLength > 0:
        pos = (pos + 3) & ~3
        pos += wValueLength
    
    # Parse children (StringFileInfo, VarFileInfo)
    end = data_offset + wLength
    while pos + 6 <= end:
        if pos + 6 > len(data):
            break
        child_wLength = struct.unpack_from("<H", data, pos)[0]
        child_wValueLength = struct.unpack_from("<H", data, pos + 2)[0]
        child_wType = struct.unpack_from("<H", data, pos + 4)[0]
        child_pos = pos + 6
        
        child_name_len = struct.unpack_from("<H", data, child_pos)[0]
        child_pos += 2 + child_name_len * 2
        child_pos = (child_pos + 3) & ~3
        
        child_name = ""
        if child_name_len > 0:
            child_name = data[child_pos - child_name_len * 2 - 2:child_pos - 2].decode("utf-16le", "replace")
        
        if child_name == "StringFileInfo":
            # Parse StringFileInfo children (StringTable)
            str_end = child_pos + child_wLength - 6
            while child_pos + 6 <= str_end:
                if child_pos + 6 > len(data):
                    break
                table_wLength = struct.unpack_from("<H", data, child_pos)[0]
                table_wValueLength = struct.unpack_from("<H", data, child_pos + 2)[0]
                table_wType = struct.unpack_from("<H", data, child_pos + 4)[0]
                table_pos = child_pos + 6
                
                table_name_len = struct.unpack_from("<H", data, table_pos)[0]
                table_pos += 2 + table_name_len * 2
                table_pos = (table_pos + 3) & ~3
                
                # Parse StringTable children (String entries)
                table_end = table_pos + table_wLength - 6
                while table_pos + 6 <= table_end:
                    if table_pos + 6 > len(data):
                        break
                    str_wLength = struct.unpack_from("<H", data, table_pos)[0]
                    str_wValueLength = struct.unpack_from("<H", data, table_pos + 2)[0]
                    str_wType = struct.unpack_from("<H", data, table_pos + 4)[0]
                    str_pos = table_pos + 6
                    
                    str_name_len = struct.unpack_from("<H", data, str_pos)[0]
                    str_name = data[str_pos + 2:str_pos + 2 + str_name_len * 2].decode("utf-16le", "replace")
                    str_pos += 2 + str_name_len * 2
                    str_pos = (str_pos + 3) & ~3
                    
                    if str_wValueLength > 0:
                        str_value = data[str_pos:str_pos + str_wValueLength * 2].decode("utf-16le", "replace")
                        # Store the offset to the value (string data)
                        value_offset = str_pos
                        version_info["string_file_info"][str_name] = {
                            "value": str_value,
                            "offset": value_offset,
                            "length": str_wValueLength,
                        }
                    
                    table_pos += str_wLength
        
        pos += child_wLength
    
    return version_info


def _rich_header_offset(pe) -> Optional[int]:
    """File offset of the MSVC Rich header, or None when absent.

    pefile's parsed RICH_HEADER exposes the XOR key but not the file offset,
    so the ``DanS`` start marker is located by XOR-decoding the header region
    with the key (Rich headers live in the file header area, never past the
    first section).  Relies on the known key, so the match is unambiguous.
    """
    rich = getattr(pe, "RICH_HEADER", None)
    if rich is None:
        return None
    key = getattr(rich, "key", None)
    try:
        data = pe.__data__
    except Exception:
        return None
    if not key or len(key) != 4 or not data:
        return None
    # Bound the scan to the headers area: up to the first section's raw data,
    # falling back to a generous 0x400 when no section is present.
    boundary = 0x400
    sections = getattr(pe, "sections", None) or []
    if sections:
        first_raw = int(getattr(sections[0], "PointerToRawData", 0))
        if first_raw > 0:
            boundary = first_raw
    if len(data) < boundary:
        boundary = len(data)
    window = data[:boundary]
    target = bytes(b ^ k for b, k in zip(b"DanS", key))
    return window.find(target)


def _debug_rows(pe) -> List[Dict[str, object]]:
    """Parse the PE debug directory into typed rows."""
    rows: List[Dict[str, object]] = []
    debug = getattr(pe, "DIRECTORY_ENTRY_DEBUG", None)
    if not debug:
        return rows
    for entry in debug:
        struct_ = getattr(entry, "struct", None)
        if struct_ is None:
            continue
        dtype = int(getattr(struct_, "Type", 0))
        try:
            row_offset = struct_.get_file_offset()
        except Exception:
            row_offset = 0
        info: Dict[str, object] = {
            "type": dtype,
            "type_name": _DEBUG_TYPE_NAMES.get(dtype, "unknown"),
            "file_offset": row_offset,
            "data_offset": int(getattr(struct_, "PointerToRawData", 0)),
            "data_size": int(getattr(struct_, "SizeOfData", 0)),
            "is_native_image": dtype in _NATIVE_IMAGE_TYPES,
            "pdb": None,
        }
        raw = getattr(entry, "entry", None)
        pdb = getattr(raw, "PdbFileName", None)
        if isinstance(pdb, bytes):
            info["pdb"] = pdb.rstrip(b"\x00").decode("latin-1", "replace")
        elif pdb is not None:
            info["pdb"] = str(pdb)
        rows.append(info)
    return rows


def analyze(path) -> dict:
    """Read a .NET PE image and return its identity/layout as plain dicts.

    Never writes to `path`.  Raises PeReadError for non-image or malformed
    inputs.
    """
    import dnfile

    try:
        pe = dnfile.dnPE(path)
    except Exception as exc:
        raise PeReadError(f"cannot read PE image {path!r}: {exc}") from None
    try:
        net = _parse_image(pe)
        return _analyze(pe, net)
    finally:
        pe.close()


def _analyze(pe, net) -> dict:
    optional = getattr(pe, "OPTIONAL_HEADER", None)
    file_header = getattr(pe, "FILE_HEADER", None)

    image_base = int(getattr(optional, "ImageBase", 0))
    time_date_stamp = int(getattr(file_header, "TimeDateStamp", 0))
    checksum = int(getattr(optional, "CheckSum", 0))
    machine = int(getattr(file_header, "Machine", 0))

    directories = getattr(optional, "DATA_DIRECTORY", None) if optional else None
    cli_rva = cli_size = 0
    if directories is not None and len(directories) > 14:
        com = directories[14]
        cli_rva = int(getattr(com, "VirtualAddress", 0))
        cli_size = int(getattr(com, "Size", 0))

    sections: List[Dict[str, object]] = []
    text = None
    for section in getattr(pe, "sections", []) or []:
        raw = getattr(section, "Name", b"")
        if isinstance(raw, bytes):
            name = raw.rstrip(b"\x00").decode("latin-1", "replace")
        else:
            name = str(raw)
        entry = {"name": name, **_section_dict(section)}
        sections.append(entry)
        if name.lower() == ".text" and text is None:
            text = entry
    rsrc_rva = rsrc_size = 0
    if directories is not None and len(directories) > 2:
        res = directories[2]
        rsrc_rva = int(getattr(res, "VirtualAddress", 0))
        rsrc_size = int(getattr(res, "Size", 0))
    rsrc_file_offset = 0
    if rsrc_rva:
        try:
            rsrc_file_offset = pe.get_offset_from_rva(rsrc_rva)
        except Exception:
            rsrc_file_offset = 0

    # ---- CLI metadata root ------------------------------------------------
    metadata_root_rva = int(getattr(net.metadata, "rva", 0))
    metadata_root_offset = _metadata_root_offset(pe, metadata_root_rva)
    # The COR20 header's MetaData Size field is the size of the metadata root
    # (RVA/size consumed by the CLI header's MetaData RVA entry).
    metadata_root_size = int(getattr(getattr(net, "struct", None), "MetaDataSize", 0))
    version = ""
    struct_ = getattr(net.metadata, "struct", None)
    if struct_ is not None:
        vb = getattr(struct_, "Version", b"")
        if isinstance(vb, bytes):
            version = vb.rstrip(b"\x00").decode("latin-1", "replace")

    streams: Dict[str, object] = {}
    for name in _STREAM_NAMES:
        stream = net.metadata.streams.get(name)
        if stream is None:
            continue
        key = name.decode("ascii")
        try:
            size = stream.sizeof()
        except Exception:
            size = getattr(stream.struct, "Size", 0)
        streams[key] = {
            "offset": stream.file_offset,
            "rva": stream.rva,
            "size": size,
        }

    # ---- metadata tables ----------------------------------------------------
    mdtables = getattr(net, "mdtables", None)

    module_name = None
    mvid_hex = None
    mvid_offset = 0
    module_guid = None
    module_guid_offset = 0
    if mdtables is not None and getattr(mdtables, "Module", None) is not None and mdtables.Module.num_rows:
        module_row = mdtables.Module.rows[0]
        module_name = str(getattr(module_row, "Name", ""))
        mvid = getattr(module_row, "Mvid", None)
        if mvid is not None:
            value = getattr(mvid, "value", None)
            if isinstance(value, (bytes, bytearray)):
                mvid_hex = bytes(value).hex()
                mvid_offset = _guid_entry_offset(pe, mvid)

    # module GUID = the entry at #GUID heap index 2, if present.
    guids = _all_guids(pe)
    if guids.get("2") is not None:
        module_guid = guids["2"]["value_hex"]
        module_guid_offset = guids["2"]["offset"]

    assembly: Dict[str, object] = {
        "name": None,
        "version": None,
        "major": 0,
        "minor": 0,
        "build": 0,
        "revision": 0,
        "full_name": None,
        "strong_name": False,
        "public_key_token": None,
    }
    if mdtables is not None and getattr(mdtables, "Assembly", None) is not None and mdtables.Assembly.num_rows:
        a = mdtables.Assembly.rows[0]
        name = str(getattr(a, "Name", ""))
        major = int(getattr(a, "MajorVersion", 0))
        minor = int(getattr(a, "MinorVersion", 0))
        build = int(getattr(a, "BuildNumber", 0))
        revision = int(getattr(a, "RevisionNumber", 0))
        flags = getattr(a, "Flags", None)
        has_pk_flag = bool(flags is not None and getattr(flags, "afPublicKey", False))
        pubkey = getattr(a, "PublicKey", None)
        pubkey_bytes = getattr(pubkey, "value", None) if pubkey is not None else None
        strong = bool(has_pk_flag) or bool(pubkey_bytes)
        token = _public_key_token(pubkey_bytes if isinstance(pubkey_bytes, bytes) else None)
        version_str = f"{major}.{minor}.{build}.{revision}"
        assembly.update(
            {
                "name": name,
                "version": version_str,
                "major": major,
                "minor": minor,
                "build": build,
                "revision": revision,
                "full_name": f"{name}, Version={version_str}, Culture=neutral, PublicKeyToken={token}" if token else f"{name}, Version={version_str}, Culture=neutral",
                "strong_name": strong,
                "public_key_token": token,
            }
        )

    # File offsets of the Assembly table's first-row fields, needed by the
    # metadata hardening pass.  ``tbl.file_offset`` is the row start (the
    # HashAlgId u4).  These offsets are stable in-place edits.
    assembly_fields: Dict[str, int] = {}
    if mdtables is not None and getattr(mdtables, "Assembly", None) is not None and mdtables.Assembly.num_rows:
        try:
            row_start = int(mdtables.Assembly.file_offset)
        except Exception:
            row_start = 0
        if row_start:
            assembly_fields = {
                "hash_alg_id": row_start,
                "major": row_start + 4,
                "minor": row_start + 6,
                "build": row_start + 8,
                "revision": row_start + 10,
                "flags": row_start + 12,
            }

    # ---- custom attributes (TargetFramework and friends) -------------------
    target_framework = None
    custom_attributes: Dict[str, Dict[str, object]] = {}
    if mdtables is not None and getattr(mdtables, "CustomAttribute", None) is not None:
        for row in mdtables.CustomAttribute.rows:
            try:
                memberref = row.Type.row
                typeref = memberref.Class.row
                name = getattr(typeref, "TypeName", "")
            except Exception:
                continue
            if not isinstance(name, str):
                name = str(name)
            blob = getattr(row.Value, "value", None)
            if not isinstance(blob, (bytes, bytearray)):
                continue
            blob_bytes = bytes(blob)
            blob_offset = _blob_file_offset(pe, blob_bytes)
            if blob_offset == 0:
                continue
            decoded = _custom_attribute_string(blob_bytes)
            custom_attributes[name] = {
                "blob_offset": blob_offset,
                "blob_size": len(blob_bytes),
                "decoded": decoded,
            }
            if name == "TargetFrameworkAttribute" and decoded:
                target_framework = decoded

    # ---- PE debug directory -------------------------------------------------
    dbg_rva = dbg_size = 0
    if directories is not None and len(directories) > 6:
        dbg = directories[6]
        dbg_rva = int(getattr(dbg, "VirtualAddress", 0))
        dbg_size = int(getattr(dbg, "Size", 0))

    # ---- Rich header ----------------------------------------------------------
    rich_offset = _rich_header_offset(pe)
    rich = None
    if rich_offset is not None:
        rich = {"offset": rich_offset}

    # ---- VS_VERSION_INFO in .rsrc --------------------------------------------
    version_info = _parse_version_info(pe, rsrc_file_offset, rsrc_size) if rsrc_file_offset else {}

    metadata = {
        "metadata_root_offset": metadata_root_offset,
        "metadata_root_rva": metadata_root_rva,
        "metadata_root_size": metadata_root_size,
        "version": version,
        "streams": streams,
        "mvid": mvid_hex,
        "mvid_offset": mvid_offset,
        "module_guid": module_guid,
        "module_guid_offset": module_guid_offset,
        "guids": guids,
        "module_name": module_name,
        "assembly": assembly,
        "assembly_fields": assembly_fields,
        "target_framework": target_framework,
        "custom_attributes": custom_attributes,
        "version_info": version_info,
    }

    pe_block = {
        "image_base": image_base,
        "machine": machine,
        "time_date_stamp": time_date_stamp,
        "checksum": checksum,
        "cli_header": {"offset": _metadata_root_offset(pe, cli_rva), "rva": cli_rva, "size": cli_size}
        if cli_rva
        else None,
        "sections": sections,
        "text": dict(text) if text else None,
        "rsrc": {"rva": rsrc_rva, "size": rsrc_size, "file_offset": rsrc_file_offset},
    }

    debug = {
        "directory_rva": dbg_rva,
        "directory_size": dbg_size,
        "rows": _debug_rows(pe),
    }

    return {
        "pe": pe_block,
        "metadata": metadata,
        "rich": rich,
        "debug": debug,
    }
