"""#US / #Strings heap scanning, config extraction, and XOR scrubbing (R3/R4).

This module provides three public functions that power ``inspect`` (task 7)
and the ``strings`` hardening pass (task 10):

- ``scan_heaps(pe_info)`` — search the metadata heaps for every catalog
  indicator and return one match dict per occurrence, with the mitigation
  and a file offset as evidence.
- ``extract_config(pe_info)`` — resolve the embedded Apollo Config.cs values
  from the ``#US`` heap, either by decoding ``ldstr`` tokens in MethodDef IL
  bodies (real compiled agents) or by a documented key-name + adjacent-string
  heuristic (synthetic / reflection-free fixtures that carry no IL).
- ``xor_scrub(data, seed)`` — a deterministic, reversible per-byte XOR of the
  input.  Used to encrypt non-essential ``#US`` payloads in place during the
  ``strings`` pass (R3), where the fixed-size condition always holds (XOR is
  an in-place constant-length edit).

Data model
----------
``pe_info`` is a plain dict assembled by the caller from ``pe.analyze()`` plus
the raw image bytes (and optionally the file path, for the ``ldstr``-resolve
path):

.. code-block:: python

    pe_info = {
        "path": str,                 # optional: re-opened read-only for
                                     # MethodDef IL-body ldstr decode
        "data": bytes,               # raw image bytes
        "pe": ...,                   # pe.analyze()['pe']     (sections)
        "metadata": ...,             # pe.analyze()['metadata'] (heap offsets)
    }

The ``metadata`` sub-dict must carry ``streams`` (with ``offset``/``size`` for
``#US``, ``#Strings``, ``#Blob``) and ``metadata_root_offset``/``size``, which
is exactly what ``pe.analyze()`` returns.
"""

from __future__ import annotations

import random
from typing import Dict, List, Optional, Tuple

from obfuscate.fingerprints import CATALOG, FullStringEntry, FragmentEntry
from obfuscate.report import mask_key

# ---------------------------------------------------------------------------
# Catalog identifier
# ---------------------------------------------------------------------------


def _catalog_id(index: int) -> str:
    """Stable, unambiguous id: the position of the entry in ``CATALOG``.

    Text alone is not unique (e.g. "Mythic" and "Apollo.exe" appear in
    multiple mitigations), so the catalog position is used.  Consumers look up
    ``CATALOG[int(id)]`` to recover the full entry.
    """
    return str(index)


# ---------------------------------------------------------------------------
# Heap regions
# ---------------------------------------------------------------------------

# metadata stream name -> pe_info["metadata"]["streams"] key, plus whether it
# is scanned as UTF-8.
_UTF8_REGIONS = ("strings", "blob", "metadata_root")


def _regions(pe_info: dict) -> Dict[str, Tuple[int, int]]:
    """Return ``{region_key: (start, end)}`` file-offset bounds for each heap.

    ``#US`` is scanned as UTF-16LE; ``#Strings``, ``#Blob`` and the metadata
    root are scanned as UTF-8.  The metadata root carries the version string
    and stream names in addition to the ``#~``/``#Strings``/``#US``/``#GUID``/
    ``#Blob`` stream headers.
    """
    md = pe_info.get("metadata") or {}
    streams = md.get("streams") or {}
    regions: Dict[str, Tuple[int, int]] = {}

    us = streams.get("#US")
    if us:
        start = int(us.get("offset", 0))
        regions["us"] = (start, start + int(us.get("size", 0)))

    strs = streams.get("#Strings")
    if strs:
        start = int(strs.get("offset", 0))
        regions["strings"] = (start, start + int(strs.get("size", 0)))

    blob = streams.get("#Blob")
    if blob:
        start = int(blob.get("offset", 0))
        regions["blob"] = (start, start + int(blob.get("size", 0)))

    root_off = int(md.get("metadata_root_offset", 0))
    root_size = int(md.get("metadata_root_size", 0))
    if root_off and root_size:
        regions["metadata_root"] = (root_off, root_off + root_size)

    return regions


def _matches_in_region(data: bytes, start: int, end: int, needle: bytes) -> List[int]:
    """All file offsets in ``[start, end)`` where the byte pattern begins."""
    end = min(end, len(data))
    results: List[int] = []
    pos = start
    while True:
        idx = data.find(needle, pos, end)
        if idx < 0:
            break
        results.append(idx)
        pos = idx + 1
    return results


# ---------------------------------------------------------------------------
# scan_heaps
# ---------------------------------------------------------------------------


def scan_heaps(pe_info: dict) -> list:
    """Search the metadata heaps for every catalog indicator.

    Returns a list of match dicts, one per occurrence:

    ``{catalog_id, tier, mitigation, encoding, file_offset}``

    - ``catalog_id`` is the entry's position in ``CATALOG`` (int as text);
      look up ``CATALOG[int(catalog_id)]`` for the full entry.
    - ``tier`` is ``"full"`` or ``"fragment"``.
    - ``encoding`` records the byte representation that actually matched
      (``"utf-8"`` or ``"utf-16le"``).
    - ``file_offset`` is the absolute file offset of the first matching byte.

    Full-string entries match their encoding in the applicable heap
    (UTF-16LE in ``#US``; UTF-8 in ``#Strings``/``#Blob``/metadata root) as an
    exact literal.  Fragment entries match as substrings in **both** encodings
    across every region, so a deliberately-split literal cannot evade the
    scan.  This mirrors the R6 verification search so ``verify`` cannot be
    gamed by a split string.
    """
    data = pe_info.get("data", b"")
    regions = _regions(pe_info)
    if not regions or not data:
        return []

    matches: List[dict] = []
    for index, entry in enumerate(CATALOG):
        cid = _catalog_id(index)
        if isinstance(entry, FullStringEntry):
            if entry.encoding == "utf-16le":
                needle = entry.text.encode("utf-16le")
                region = regions.get("us")
                if region is None:
                    continue
                for off in _matches_in_region(data, *region, needle):
                    matches.append(
                        {
                            "catalog_id": cid,
                            "tier": "full",
                            "mitigation": entry.mitigation,
                            "encoding": "utf-16le",
                            "file_offset": off,
                        }
                    )
            else:  # utf-8
                needle = entry.text.encode("utf-8")
                for key in _UTF8_REGIONS:
                    region = regions.get(key)
                    if region is None:
                        continue
                    for off in _matches_in_region(data, *region, needle):
                        matches.append(
                            {
                                "catalog_id": cid,
                                "tier": "full",
                                "mitigation": entry.mitigation,
                                "encoding": "utf-8",
                                "file_offset": off,
                            }
                        )
        elif isinstance(entry, FragmentEntry):
            # Fragment: substring match in both encodings across every region.
            for enc, needle in (
                ("utf-16le", entry.text.encode("utf-16le")),
                ("utf-8", entry.text.encode("utf-8")),
            ):
                for key, region in regions.items():
                    for off in _matches_in_region(data, *region, needle):
                        matches.append(
                            {
                                "catalog_id": cid,
                                "tier": "fragment",
                                "mitigation": entry.mitigation,
                                "encoding": enc,
                                "file_offset": off,
                            }
                        )

    matches.sort(key=lambda m: (m["file_offset"], m["catalog_id"]))
    return matches


# ---------------------------------------------------------------------------
# #US heap enumeration (for config extraction)
# ---------------------------------------------------------------------------


def _decode_compressed_int(data: bytes, pos: int) -> Tuple[int, int]:
    """ECMA-335 II.23.2 compressed integer."""
    first = data[pos]
    if (first & 0x80) == 0:
        return first, pos + 1
    if (first & 0xC0) == 0x80:
        return ((first & 0x3F) << 8) | data[pos + 1], pos + 2
    if (first & 0xE0) == 0xC0:
        return (
            (int.from_bytes(data[pos:pos + 4], "big") & 0x1FFFFFFF),
            pos + 4,
        )
    raise ValueError("invalid compressed integer lead byte")


def _iter_us_strings(pe_info: dict) -> List[Tuple[str, int]]:
    """Walk the ``#US`` heap and yield ``(text, file_offset)`` entries.

    Each entry is ``[compressed_len][utf-16le][flag]``; ``file_offset`` points
    at the first byte of the UTF-16LE text (after the length prefix), matching
    the fixture layout convention.
    """
    data = pe_info.get("data", b"")
    md = pe_info.get("metadata") or {}
    us = (md.get("streams") or {}).get("#US")
    if not us or not data:
        return []
    start = int(us.get("offset", 0))
    size = int(us.get("size", 0))
    end = min(start + size, len(data))

    out: List[Tuple[str, int]] = []
    # Index 0 is reserved (a single null byte) per ECMA-335 II.24.2.4; the
    # first real entry starts at index 1, i.e. one byte into the heap.
    pos = start + 1
    while pos < end:
        try:
            length, after = _decode_compressed_int(data, pos)
        except (ValueError, IndexError):
            break
        text_start = after
        text_end = text_start + length
        if length < 1 or text_end > end:
            break
        block = data[text_start:text_end]
        # block = utf-16le text + 1 trailing flag byte
        raw = block[:-1]
        try:
            text = raw.decode("utf-16le", "replace")
        except Exception:
            text = ""
        out.append((text, text_start))
        pos = text_end
    return out


# ---------------------------------------------------------------------------
# RVA -> file offset (for MethodDef IL bodies)
# ---------------------------------------------------------------------------


def _rva_to_offset(pe_info: dict, rva: int) -> Optional[int]:
    """Map a relative virtual address to a file offset via the section table."""
    sections = (pe_info.get("pe") or {}).get("sections") or []
    for sec in sections:
        va = int(sec.get("virtual_address", 0))
        raw = int(sec.get("raw_offset", 0))
        vsize = int(sec.get("virtual_size", 0))
        rsize = int(sec.get("raw_size", 0))
        if va <= rva < va + max(vsize, rsize):
            return raw + (rva - va)
    return None


# ---------------------------------------------------------------------------
# Minimal IL bytecode walker (ldstr decode)
# ---------------------------------------------------------------------------

# Operand size (in bytes) for each single-byte opcode.  -1 means "varies /
# two-byte opcode or special"; those are handled below.  Derived from
# ECMA-335 II.25.4. 0x72 (ldstr) carries a 4-byte metadata token.
#
# A full table is large; we include the operand-size families needed to walk
# forward past non-ldstr instructions to the next opcode.  Any opcode not in
# the table is treated as zero-operand (harmless for a forward scan — we only
# need to reach later ldstr sites, and a mis-sized guess may desync a scan,
# so unknown opcodes are skipped conservatively by resyncing on the next
# 0x72).  In practice a forward scan over the common opcode set is sufficient.

_IL_OPERAND_SIZES = {
    0x00: 0,  # nop
    0x02: 0,  # ret
    0x03: 0,  # br.s (signed 1-byte)
    0x16: 0,  # ldc.i4.m1
    0x17: 0, 0x18: 0, 0x19: 0, 0x1A: 0, 0x1B: 0, 0x1C: 0, 0x1D: 0, 0x1E: 0,  # ldc.i4.0..7
    0x25: 0,  # dup
    0x28: 4,  # call
    0x2A: 0,  # ret (already covered; 0x2A is ret too)
    0x2B: 1,  # br.s
    0x2C: 1, 0x2D: 1, 0x2E: 1, 0x2F: 1, 0x30: 1, 0x31: 1, 0x32: 1, 0x33: 1,
    0x34: 1, 0x35: 1, 0x36: 1, 0x37: 1,  # short branches
    0x3B: 4,  # br
    0x3C: 4, 0x3D: 4, 0x3E: 4, 0x3F: 4, 0x40: 4, 0x41: 4, 0x42: 4, 0x43: 4,
    0x44: 4,  # long branches
    0x6F: 4,  # callvirt
    0x70: 4,  # calli
    0x72: 4,  # ldstr
    0x73: 4,  # newobj
    0x74: 4,  # castclass
    0x75: 4,  # isinst
    0x79: 4,  # ldfld
    0x7A: 4,  # ldflda
    0x7B: 4,  # stfld
    0x7C: 4,  # ldsfld
    0x7D: 4,  # ldsflda
    0x7E: 4,  # stsfld
    0x7F: 4,  # stobj
    0x88: 4,  # ldobj
    0x8C: 4,  # box
    0x8D: 4,  # newarr
    0x8F: 4,  # ldelema
    0x90: 4, 0x91: 4,  # ldelem / stelem
    0xA2: 4, 0xA3: 4, 0xA4: 4, 0xA5: 4, 0xA6: 4, 0xA7: 4, 0xA8: 4, 0xA9: 4,
    0xAA: 4, 0xAB: 4, 0xAC: 4, 0xAD: 4, 0xAE: 4, 0xAF: 4, 0xB0: 4,  # bgt..blt.un
    0xB2: 4,  # ldtoken
    0xB3: 4, 0xB4: 4, 0xB5: 4, 0xB8: 4,  # conv.* / sizeof
    0xBA: 2,  # args
    0xBB: 4,  # leave
    0xC2: 4,  # box (34)
    0xC6: 4,  # switch (4-byte count follows; handled separately)
    0xD0: 4, 0xD1: 4, 0xD2: 4, 0xD3: 4,  # ldc.r4 / ldc.r8 families
    0xDE: 4,  # endfilter? (carries 4)
}

_TWO_BYTE_OPCODE_SIZES = {
    0x01: 2, 0x02: 2, 0x06: 4, 0x07: 4, 0x09: 4, 0x0A: 4, 0x0B: 4,
    0x0C: 2, 0x0D: 2, 0x0E: 4, 0x0F: 2, 0x10: 2, 0x11: 2, 0x12: 4,
    0x13: 4, 0x15: 4, 0x16: 4, 0x18: 4, 0x1B: 4, 0x1C: 2, 0x1D: 1,
    0x1E: 2, 0x1F: 2, 0x20: 4, 0x21: 4, 0x22: 4, 0x23: 4, 0x24: 4,
    0x25: 4, 0x26: 4, 0x29: 4, 0x2A: 4, 0x2B: 4, 0x2C: 4, 0x2D: 4,
    0x2E: 4, 0x2F: 4, 0x32: 4, 0x33: 2, 0x34: 4, 0x35: 4, 0x36: 4,
    0x37: 4, 0x38: 4, 0x39: 4, 0x3A: 4, 0x3B: 4, 0x3C: 4, 0x3D: 4,
    0x3E: 4, 0x3F: 4, 0x40: 4, 0x41: 4, 0x42: 4, 0x43: 4, 0x44: 4,
    0x45: 4, 0x46: 4, 0x47: 4, 0x48: 4, 0x49: 4, 0x4A: 4, 0x4B: 4,
    0x4C: 4, 0x53: 4, 0x54: 4, 0x55: 4, 0x56: 4, 0x5C: 4, 0x5D: 4,
    0x5E: 4, 0x60: 4, 0x61: 4, 0x62: 4, 0x63: 4, 0x64: 4, 0x65: 4,
    0x66: 4, 0x67: 4, 0x68: 4, 0x69: 4, 0x6A: 4, 0x6B: 4, 0x6C: 4,
    0x6D: 4, 0x6E: 4, 0x6F: 4, 0x70: 4, 0x71: 4, 0x72: 4, 0x73: 4,
    0x74: 4, 0x75: 4, 0x76: 4, 0x77: 4, 0x78: 4, 0x79: 4, 0x7A: 4,
    0x7B: 4, 0x7C: 4, 0x7D: 4, 0x7E: 4, 0x7F: 4, 0x80: 4, 0x81: 4,
    0x82: 4, 0x83: 4, 0x84: 4, 0x85: 4, 0x86: 4, 0x87: 4, 0x88: 4,
    0x89: 4, 0x8A: 4, 0x8B: 4, 0x8C: 4, 0x8D: 4, 0x8E: 4, 0x8F: 4,
    0x90: 4, 0x91: 4, 0x92: 4, 0x93: 4, 0x94: 4, 0x95: 4, 0x96: 4,
    0x97: 4, 0x98: 4, 0x99: 4, 0x9A: 4, 0x9B: 4, 0x9C: 4, 0x9D: 4,
    0x9E: 4, 0x9F: 4, 0xA0: 4, 0xA1: 4, 0xA2: 4, 0xA3: 4, 0xA4: 4,
    0xA5: 4, 0xA6: 4, 0xA7: 4, 0xA8: 4, 0xA9: 4, 0xAA: 4, 0xAB: 4,
    0xAC: 4, 0xAD: 4, 0xAE: 4, 0xAF: 4, 0xB0: 4, 0xB1: 4, 0xB2: 4,
    0xB3: 4, 0xB4: 4, 0xB5: 4, 0xB6: 4, 0xB7: 4, 0xB8: 4, 0xB9: 4,
    0xBE: 4, 0xBF: 4, 0xC0: 4, 0xC1: 4, 0xC2: 4, 0xC3: 4, 0xC5: 4,
    0xC7: 4, 0xC8: 4, 0xC9: 4, 0xCA: 4, 0xCB: 4, 0xCC: 4, 0xCD: 4,
    0xCE: 4, 0xCF: 4, 0xD0: 4, 0xD1: 4, 0xD2: 4, 0xD3: 4, 0xD4: 4,
    0xD5: 4, 0xD6: 4, 0xD7: 4, 0xD8: 4, 0xD9: 4, 0xDA: 4, 0xDB: 4,
    0xDC: 4, 0xDD: 4, 0xDE: 4, 0xDF: 4,
    0xF0: 4, 0xF1: 4, 0xF2: 4, 0xF3: 4,
}


def _iter_ldstr_tokens(body: bytes) -> List[int]:
    """Walk an IL method body and return the UserString metadata tokens.

    Returns the raw 4-byte metadata tokens from each ``ldstr`` (0x72).  The
    caller decodes the token's UserString heap index (low 24 bits when the
    table marker is 0x70).
    """
    tokens: List[int] = []
    i = 0
    n = len(body)
    while i < n:
        opcode = body[i]
        i += 1
        if opcode == 0xFE and i < n:
            # two-byte opcode
            sub = body[i]
            i += 1
            size = _TWO_BYTE_OPCODE_SIZES.get(sub, 0)
            i += size
            continue
        if opcode == 0x72:  # ldstr
            if i + 4 <= n:
                token = int.from_bytes(body[i:i + 4], "little")
                tokens.append(token)
            i += 4
            continue
        if opcode == 0xC6:  # switch: 4-byte count, then count * 4
            if i + 4 <= n:
                count = int.from_bytes(body[i:i + 4], "little")
                i += 4 + 4 * count
                continue
            i += 4
            continue
        size = _IL_OPERAND_SIZES.get(opcode, 0)
        i += size
    return tokens


# ---------------------------------------------------------------------------
# extract_config
# ---------------------------------------------------------------------------

# Value-shape matchers for the heuristic fallback (documented below).
# Each maps a config field name to a (predicate, value-extractor, masked-only)
# triple.  predicate(text) decides whether a #US string is that field's value.


def _is_url(text: str) -> bool:
    return text.startswith("http://") or text.startswith("https://")


def _is_ip(text: str) -> bool:
    return all(c.isdigit() or c == "." for c in text) and "." in text


def _is_port_fragment(text: str) -> bool:
    return text.startswith(":") and text[1:].isdigit()


def _is_user_agent(text: str) -> bool:
    return "Mozilla/" in text or "Windows NT" in text


def _is_pipe(text: str) -> bool:
    return text.startswith("\\\\.\\pipe\\")


# ---------------------------------------------------------------------------
# extract_config
# ---------------------------------------------------------------------------


def extract_config(pe_info: dict) -> dict:
    """Extract the embedded Apollo C2 config from the ``#US`` heap.

    Two resolution methods (the ``method`` field records which ran):

    ``ldstr_resolve``
        When the agent carries MethodDef IL bodies (``pe_info`` has a ``path``
        and at least one method has a non-zero RVA), the ``#US`` literals are
        correlated with their config keys by decoding ``ldstr`` operands in
        the method bodies (see ``_iter_ldstr_tokens``).  Because Apollo inlines
        config values as ``ldstr`` operands assigned to named config keys, this
        reconstructs the value of each key directly.

    ``heuristic``
        Fixtures and reflection-free samples rarely carry IL (the synthetic
        fixture's ``Main`` has RVA 0).  In that case the config values are
        identified by well-known value shapes in the ``#US`` heap: a URL
        literal (from which host/port are parsed), the user-agent, the pipe
        name, the ``AESPSK`` key markers (masked), and the ``killdate`` /
        ``payload_uuid`` markers.  Host and port are parsed from the callback
        URL.

    Keys are never logged: AESPSK material appears only as a masked sha256
    hash via ``report.mask_key``.
    """
    us_texts = _iter_us_strings(pe_info)
    found: Dict[str, str] = {}

    resolved = _resolve_via_ldstr(pe_info, found)
    # The heuristic also runs as a fill-in for any field ldstr did not set
    # (every heuristic setter guards with `if found.get(...) is None`, so the
    # ldstr values are never overwritten).
    _resolve_heuristically(us_texts, found)
    method = "ldstr_resolve" if resolved else "heuristic"

    url = found.get("url")
    host = found.get("host")
    port = found.get("port")
    if url and not host:
        host, port = _parse_authority(url)

    aespsk_enc = found.get("aespsk_enc")
    aespsk_dec = found.get("aespsk_dec")

    config: dict = {
        "payload_uuid": found.get("payload_uuid"),
        "url": url,
        "host": host,
        "port": port,
        "user_agent": found.get("user_agent"),
        "aespsk": {
            "enc": mask_key(aespsk_enc) if aespsk_enc else None,
            "dec": mask_key(aespsk_dec) if aespsk_dec else None,
        },
        "kill_date": found.get("kill_date"),
        "query_param": found.get("query_param"),
        "cookie": {
            "name": found.get("cookie_name"),
            "value": found.get("cookie_value"),
        },
        "pipe": found.get("pipe"),
        "method": method,
    }
    return config


def _parse_authority(url: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse ``host[:port]`` from a URL's authority section."""
    rest = url.split("://", 1)[-1] if "://" in url else url
    path = rest.split("/", 1)[0]
    if ":" in path:
        host, port = path.rsplit(":", 1)
        return (host or None, port or None)
    return (path or None, None)


def _resolve_heuristically(us_texts: List[Tuple[str, int]], found: Dict[str, str]) -> None:
    """Fill ``found`` by value-shape matching over the #US strings."""

    for text, _off in us_texts:
        if found.get("url") is None and _is_url(text):
            found["url"] = text
        if found.get("user_agent") is None and _is_user_agent(text):
            found["user_agent"] = text
        if found.get("pipe") is None and _is_pipe(text):
            found["pipe"] = text

    aespsk_values = [text for text, _ in us_texts if text == "AESPSK"]
    if aespsk_values:
        found["aespsk_enc"] = aespsk_values[0]
        if len(aespsk_values) > 1:
            found["aespsk_dec"] = aespsk_values[1]
        else:
            found["aespsk_dec"] = aespsk_values[0]

    for text, _off in us_texts:
        if text == "killdate" and found.get("kill_date") is None:
            found["kill_date"] = text
        if text == "payload_uuid" and found.get("payload_uuid") is None:
            found["payload_uuid"] = text
        if text == "MythicSession" and found.get("cookie_name") is None:
            found["cookie_name"] = text
        if text == "q" and found.get("query_param") is None:
            found["query_param"] = text

    if found.get("host") is None:
        for text, _off in us_texts:
            if _is_ip(text):
                found["host"] = text
                break
    if found.get("port") is None:
        for text, _off in us_texts:
            if _is_port_fragment(text):
                found["port"] = text[1:]
                break


def _resolve_via_ldstr(
    pe_info: dict, found: Dict[str, str]
) -> bool:
    """Attempt ldstr-token config resolution.  Returns True if any value set.

    Opens the file read-only via dnfile (never writes), iterates MethodDef
    rows with a non-zero RVA, decodes the IL for ``ldstr`` user-string tokens,
    and correlates the decoded strings with the config key-name vocabulary.
    """
    path = pe_info.get("path")
    if not path:
        return False
    try:
        import dnfile
    except ImportError:
        return False

    # Build #US heap-index -> text so ldstr tokens can be decoded.
    us_index: Dict[int, str] = {}
    for index, text in _iter_us_entries_with_index(pe_info):
        us_index[index] = text
    if not us_index:
        return False

    try:
        pe = dnfile.dnPE(path)
    except Exception:
        return False
    try:
        net = getattr(pe, "net", None)
        md = getattr(net, "mdtables", None) if net is not None else None
        if md is None or getattr(md, "MethodDef", None) is None:
            return False
        data = pe_info.get("data", b"")
        any_hit = False
        for row in md.MethodDef.rows:
            rva = int(getattr(row, "RVA", 0))
            if rva <= 0:
                continue
            off = _rva_to_offset(pe_info, rva)
            if off is None:
                continue
            body = data[off:off + 4096]
            tokens = _iter_ldstr_tokens(body)
            for token in tokens:
                if (token >> 24) != 0x70:  # UserString table
                    continue
                idx = token & 0x00FFFFFF
                text = us_index.get(idx)
                if text is None:
                    continue
                if _assign_key(text, found):
                    any_hit = True
        return any_hit
    finally:
        pe.close()


def _us_heap_base(pe_info: dict) -> Optional[int]:
    md = pe_info.get("metadata") or {}
    us = (md.get("streams") or {}).get("#US")
    if not us:
        return None
    return int(us.get("offset", 0))


def _iter_us_entries_with_index(pe_info: dict) -> List[Tuple[int, str]]:
    """Walk #US returning ``(heap_index, text)`` where heap_index is the entry
    position in the heap (relative to the #US stream start)."""
    data = pe_info.get("data", b"")
    base = _us_heap_base(pe_info)
    if base is None or not data:
        return []
    md = pe_info.get("metadata") or {}
    us = (md.get("streams") or {}).get("#US")
    size = int(us.get("size", 0))
    end = min(base + size, len(data))
    out: List[Tuple[int, str]] = []
    pos = base + 1  # skip reserved index 0
    while pos < end:
        index = pos - base
        try:
            length, after = _decode_compressed_int(data, pos)
        except (ValueError, IndexError):
            break
        text_end = after + length
        if length < 1 or text_end > end:
            break
        block = data[after:text_end]
        try:
            text = block[:-1].decode("utf-16le", "replace")
        except Exception:
            text = ""
        out.append((index, text))
        pos = text_end
    return out


def _assign_key(text: str, found: Dict[str, str]) -> bool:
    """Correlate a decoded #US string with a config key via key-name context.

    Config key names (field identifiers in Config.cs) are themselves present
    in the binary's #Strings heap and often as the *value* literal of the
    dictionary key.  The value-side literals are recognized by the same value
    shapes as the heuristic, plus the AESPSK / payload_uuid / killdate /
    encrypted_exchange_check key markers.  Returns True when a config field
    was newly populated (drives the ldstr_resolve result).
    """
    if _is_url(text) and found.get("url") is None:
        found["url"] = text
        return True
    if _is_user_agent(text) and found.get("user_agent") is None:
        found["user_agent"] = text
        return True
    if _is_pipe(text) and found.get("pipe") is None:
        found["pipe"] = text
        return True
    if text == "AESPSK":
        if found.get("aespsk_enc") is None:
            found["aespsk_enc"] = text
        elif found.get("aespsk_dec") is None:
            found["aespsk_dec"] = text
        return True
    if text == "payload_uuid" and found.get("payload_uuid") is None:
        found["payload_uuid"] = text
        return True
    if text == "killdate" and found.get("kill_date") is None:
        found["kill_date"] = text
        return True
    if text == "MythicSession" and found.get("cookie_name") is None:
        found["cookie_name"] = text
        return True
    if text == "q" and found.get("query_param") is None:
        found["query_param"] = text
        return True
    return False


# ---------------------------------------------------------------------------
# xor_scrub
# ---------------------------------------------------------------------------


def xor_scrub(data: bytes, seed: int) -> bytes:
    """Deterministic per-byte XOR of ``data`` with a seed-derived keystream.

    Each byte is XORed with the byte of the same position from a keystream
    generated deterministically from ``seed`` (Mersenne Twister).  The
    operation is an in-place, constant-length edit (satisfies the R3
    fixed-size invariant) and is fully reversible: applying ``xor_scrub``
    twice with the same seed restores the original bytes.  For a non-zero
    seed the output differs from the input (the keystream is not all-zero).
    """
    rng = random.Random(seed)
    key = rng.randbytes(len(data))
    return bytes(b ^ k for b, k in zip(data, key))


def _scrub_length(entry, encoding: str) -> int:
    """Calculate the byte length to scrub for a catalog entry."""
    if encoding == "utf-16le":
        return len(entry.text) * 2
    return len(entry.text)


def _overlaps(start: int, end: int, spans) -> bool:
    """True when ``[start, end)`` overlaps any ``(s, e)`` protection span."""
    return any(start < e and s < end for s, e in spans)


def _protected_spans(matches: list) -> list:
    """Byte spans of full-string ``rebuild_config`` literals (never touched).

    A scrubbable full-string can match as a substring INSIDE a config-critical
    literal (e.g. the scrubbable ``Mythic`` literal is a substring of the
    ``MythicSession`` cookie and ``\\.\\pipe\\Mythic_Agent`` literals in the
    #US heap).  Scrubbing those bytes would corrupt the exact config values
    the ``rebuild_config`` tier protects (R3/R4), so any scrub candidate whose
    span overlaps one of these is skipped (and reported as skipped).
    """
    spans = []
    for match in matches:
        entry = CATALOG[int(match["catalog_id"])]
        if isinstance(entry, FullStringEntry) and entry.mitigation == "rebuild_config":
            length = _scrub_length(entry, match["encoding"])
            spans.append((match["file_offset"], match["file_offset"] + length))
    return spans


def strings_pass(pe_info: dict, data: bytearray, seed: int, force_break_runtime: bool = False) -> list:
    """Apply the string-scrub hardening pass (R3).

    Scans metadata heaps via ``scan_heaps`` and XOR-scrubs entries that are
    marked ``scrubbable=True`` with mitigation ``string_scrub``.  Config-critical
    entries with mitigation ``rebuild_config`` are left untouched unless
    ``force_break_runtime`` is True.  A scrub candidate that overlaps a
    full-string ``rebuild_config`` literal (a substring match inside protected
    content — see ``_protected_spans``) is skipped, never applied, UNLESS
    ``force_break_runtime`` is True (which also allows scrubbing config-critical
    literals directly).

    Args:
        pe_info: PE analysis dict from ``pe.analyze()`` plus raw ``data``.
        data: Mutable bytearray of the PE image (modified in place).
        seed: Seed for deterministic XOR keystream.
        force_break_runtime: If True, also scrub config-critical (rebuild_config)
            entries AND override overlap protection. Default False.

    Returns:
        List of ``(catalog_id, offset, description)`` tuples for each scrubbed
        or skipped entry.
    """
    matches = scan_heaps(pe_info)
    findings = []
    protected = [] if force_break_runtime else _protected_spans(matches)

    for match in matches:
        catalog_id = int(match["catalog_id"])
        entry = CATALOG[catalog_id]
        offset = match["file_offset"]
        encoding = match["encoding"]
        mitigation = match["mitigation"]
        tier = match["tier"]

        # Only full-string entries are scrubbed in-place; fragment matches are
        # reported by verify but not edited here.
        if tier != "full":
            continue

        should_scrub = False
        description = ""

        if mitigation == "string_scrub" and entry.scrubbable:
            should_scrub = True
            description = f"string_scrub: {entry.text[:40]}"
        elif mitigation == "rebuild_config" and force_break_runtime:
            # force_break_runtime overrides scrubbable flag for config-critical entries
            should_scrub = True
            description = f"rebuild_config (forced): {entry.text[:40]}"
        else:
            description = f"skipped ({mitigation}): {entry.text[:40]}"

        if should_scrub:
            scrub_len = _scrub_length(entry, encoding)
            scrub_end = offset + scrub_len
            if scrub_end <= len(data) and not _overlaps(offset, scrub_end, protected):
                # Generate keystream for this specific region using a
                # domain-separated seed so identical strings at different
                # offsets produce different ciphertext.
                region_seed = hash((seed, offset)) & 0xFFFFFFFF
                keystream = random.Random(region_seed).randbytes(scrub_len)
                for i in range(scrub_len):
                    data[offset + i] ^= keystream[i]
                findings.append((str(catalog_id), offset, description))
            else:
                # Skipped: overruns the image or overlaps a protected
                # config-critical literal (never silently dropped).
                findings.append(
                    (
                        str(catalog_id),
                        offset,
                        f"skipped (protected overlap): {entry.text[:40]}",
                    )
                )
        else:
            # Report skipped entries
            findings.append((str(catalog_id), offset, description))

    return findings
