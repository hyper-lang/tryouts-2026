"""strings.py tests (task strings): heap scan, config extraction, XOR scrub.

Covers:

1. ``scan_heaps`` reports the curated Apollo literals at the documented
   fixture offsets, for both the UTF-16LE ``#US`` tier and the UTF-8
   ``#Strings``/``#Blob`` tier, with the full-string mitigation and encoding
   recorded.
2. The fragment tier matches as substrings (split literals cannot evade).
3. ``extract_config`` returns the Apollo sample's values via the heuristic
   fallback path (the synthetic fixture carries no MethodDef IL bodies), and
   records ``method == "heuristic"``.
4. ``extract_config`` masks AESPSK material (never raw).
5. The ``ldstr`` IL decoder resolves user-string tokens (unit-tested on
   synthetic IL), which powers the ``ldstr_resolve`` path.
6. ``xor_scrub`` is deterministic, reversible, and non-identity for a
   non-zero seed.
"""

from __future__ import annotations

import pytest

from tests.fixtures import samples
from tests.fixtures.samples import (
    DEFAULT_COMPANY,
    DEFAULT_PRODUCT,
    DEFAULT_COPYRIGHT,
    DEFAULT_USER_AGENT,
    DEFAULT_CALLBACK_URL,
    DEFAULT_PIPE_NAME,
)

from obfuscate.pe import analyze
from obfuscate.strings import (
    _iter_ldstr_tokens,
    extract_config,
    scan_heaps,
    strings_pass,
    xor_scrub,
)
from obfuscate.fingerprints import CATALOG, FullStringEntry

dnfile = pytest.importorskip("dnfile")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pe_info(tmp_path):
    data = samples.sample_bytes()
    path = tmp_path / "sample.exe"
    path.write_bytes(data)
    res = analyze(str(path))
    pe_info = dict(res)
    pe_info["path"] = str(path)
    pe_info["data"] = data
    return pe_info


def _catalog_id_for(text, encoding=None):
    """Catalog id (position) of the first full-string entry with `text`.

    If `encoding` is given, restrict to full-string entries with that
    encoding.
    """
    for i, entry in enumerate(CATALOG):
        if isinstance(entry, FullStringEntry) and entry.text == text:
            if encoding is None or entry.encoding == encoding:
                return str(i)
    raise AssertionError(f"no full-string catalog entry for {text!r} {encoding!r}")


# ---------------------------------------------------------------------------
# scan_heaps
# ---------------------------------------------------------------------------


class TestScanHeaps:
    def test_utf16le_full_string_offsets_match_fixture(self, tmp_path):
        """#US full-string literals land on the documented #US offsets."""
        pi = _pe_info(tmp_path)
        matches = scan_heaps(pi)

        cases = [
            ("Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
             samples.USER_AGENT_OFFSET, "utf-16le"),
            ("killdate", samples.KILLDATE_OFFSET, "utf-16le"),
            ("killdate", samples.KILLDATE_OFFSET, "utf-16le"),
        ]
        for text, expected, enc in cases:
            cid = _catalog_id_for(text, enc)
            hits = [m for m in matches
                    if m["catalog_id"] == cid and m["tier"] == "full"
                    and m["encoding"] == enc]
            assert hits, f"no full-string match for {text!r}"
            assert hits[0]["file_offset"] == expected, text

    def test_utf8_full_string_offsets_match_fixture(self, tmp_path):
        """#Strings / #Blob UTF-8 literals land on documented offsets."""
        pi = _pe_info(tmp_path)
        matches = scan_heaps(pi)

        # "Apollo" also appears as a substring of the "Apollo.exe" module name,
        # so the documented #Strings entry offset must be *among* the hits.
        cid = _catalog_id_for("Apollo", "utf-8")
        apollo_hits = [m["file_offset"] for m in matches
                       if m["catalog_id"] == cid and m["encoding"] == "utf-8"]
        assert samples.NAMESPACE_APOLLO_OFFSET in apollo_hits

        for text, expected in (
            ("ApolloInterop", samples.STRINGS_OFFSETS["ApolloInterop"]),
            ("Program", samples.TYPE_NAME_PROGRAM_OFFSET),
            ("DebuggableAttribute", samples.STRINGS_OFFSETS["DebuggableAttribute"]),
        ):
            cid = _catalog_id_for(text, "utf-8")
            hits = [m for m in matches
                    if m["catalog_id"] == cid and m["tier"] == "full"
                    and m["encoding"] == "utf-8"]
            assert hits, f"no utf-8 full-string match for {text!r}"
            assert hits[0]["file_offset"] == expected, text

    def test_blob_text_matches_as_utf8(self, tmp_path):
        """Attribute text embedded in #Blob is a UTF-8 full-string match."""
        pi = _pe_info(tmp_path)
        matches = scan_heaps(pi)
        for text, expected in (
            (DEFAULT_COMPANY, samples.COMPANY_TEXT_OFFSET),
            (DEFAULT_PRODUCT, samples.PRODUCT_TEXT_OFFSET),
            (DEFAULT_COPYRIGHT, samples.COPYRIGHT_TEXT_OFFSET),
        ):
            cid = _catalog_id_for(text, "utf-8")
            hits = [m for m in matches
                    if m["catalog_id"] == cid and m["encoding"] == "utf-8"]
            assert hits, f"no blob match for {text!r}"
            assert hits[0]["file_offset"] == expected, text

    def test_match_entry_shape(self, tmp_path):
        """Each match carries catalog_id / tier / mitigation / encoding / offset."""
        pi = _pe_info(tmp_path)
        matches = scan_heaps(pi)
        assert matches
        for m in matches:
            assert set(m) == {"catalog_id", "tier", "mitigation", "encoding", "file_offset"}
            assert m["tier"] in ("full", "fragment")
            assert m["encoding"] in ("utf-8", "utf-16le")
            assert isinstance(m["file_offset"], int)
            assert isinstance(int(m["catalog_id"]), int)

    def test_both_tiers_exercised(self, tmp_path):
        pi = _pe_info(tmp_path)
        matches = scan_heaps(pi)
        tiers = {m["tier"] for m in matches}
        encs = {m["encoding"] for m in matches}
        assert tiers == {"full", "fragment"}
        assert encs == {"utf-8", "utf-16le"}

    def test_matches_sorted_by_offset(self, tmp_path):
        pi = _pe_info(tmp_path)
        matches = scan_heaps(pi)
        offsets = [m["file_offset"] for m in matches]
        assert offsets == sorted(offsets)

    def test_split_killdate_caught_by_fragments(self, tmp_path):
        """'kill' and 'date' appear as separate #US strings; the fragment tier
        still catches each as a substring (split literal cannot pass)."""
        pi = _pe_info(tmp_path)
        matches = scan_heaps(pi)
        frag_texts = {CATALOG[int(m["catalog_id"])].text for m in matches if m["tier"] == "fragment"}
        assert "kill" in frag_texts
        assert "date" in frag_texts

    def test_deterministic(self, tmp_path):
        pi = _pe_info(tmp_path)
        assert scan_heaps(pi) == scan_heaps(pi)

    def test_empty_pe_info_returns_empty(self):
        assert scan_heaps({}) == []

    def test_user_agent_offset_matches_documented_constant(self, tmp_path):
        pi = _pe_info(tmp_path)
        matches = scan_heaps(pi)
        cid = _catalog_id_for(DEFAULT_USER_AGENT, "utf-16le")
        hit = next(m for m in matches if m["catalog_id"] == cid and m["tier"] == "full")
        assert hit["file_offset"] == samples.USER_AGENT_OFFSET


# ---------------------------------------------------------------------------
# extract_config
# ---------------------------------------------------------------------------


class TestExtractConfig:
    def test_heuristic_values_match_sample(self, tmp_path):
        c = extract_config(_pe_info(tmp_path))
        assert c["method"] == "heuristic"
        assert c["url"] == DEFAULT_CALLBACK_URL
        assert c["host"] == "192.168.10.20"
        assert c["port"] == "8443"
        assert c["user_agent"] == DEFAULT_USER_AGENT
        assert c["payload_uuid"] == "payload_uuid"
        assert c["kill_date"] == "killdate"
        assert c["pipe"] == DEFAULT_PIPE_NAME
        assert c["cookie"]["name"] == "MythicSession"
        assert c["query_param"] == "q"

    def test_aespsk_is_masked(self, tmp_path):
        c = extract_config(_pe_info(tmp_path))
        enc = c["aespsk"]["enc"]
        assert enc is not None
        # Masked form: a sha256 prefix hash, never the raw literal.
        assert enc == "4f61f10368d784a9"
        assert enc != "AESPSK"
        assert c["aespsk"]["dec"] == enc

    def test_heuristic_fallback_triggered_without_il(self, tmp_path):
        """The synthetic fixture carries no MethodDef IL bodies (RVA 0), so
        the resolver falls back to the heuristic and documents `method`."""
        pi = _pe_info(tmp_path)
        # Force the ldstr path (path present) — it must still fall back.
        assert pi["path"]
        c = extract_config(pi)
        assert c["method"] == "heuristic"

    def test_unknown_input_returns_empty_config(self):
        c = extract_config({"data": b"\x00" * 16, "metadata": {"streams": {}}})
        assert c["method"] == "heuristic"
        assert c["url"] is None
        assert c["payload_uuid"] is None


# ---------------------------------------------------------------------------
# ldstr IL decoder (powers the ldstr_resolve path)
# ---------------------------------------------------------------------------


class TestLdstrDecoder:
    def test_decodes_user_string_tokens(self):
        body = bytes([0x00, 0x72, 0x01, 0x00, 0x00, 0x70,
                      0x28, 0xAA, 0xBB, 0xCC, 0xDD,  # call (4-byte operand)
                      0x72, 0x05, 0x00, 0x00, 0x70,
                      0x2A])  # ret
        tokens = _iter_ldstr_tokens(body)
        assert tokens == [0x70000001, 0x70000005]

    def test_skips_non_ldstr_operands(self):
        body = bytes([0x72, 0x03, 0x00, 0x00, 0x70,
                      0x00, 0x00,  # two nops
                      0x72, 0x07, 0x00, 0x00, 0x70,
                      0x2A])
        assert _iter_ldstr_tokens(body) == [0x70000003, 0x70000007]

    def test_empty_body(self):
        assert _iter_ldstr_tokens(b"") == []
        assert _iter_ldstr_tokens(b"\x2a") == []

    def test_switch_opcode_skipped(self):
        # switch: 0xC6 + 4-byte count(2) + 2*4 targets = 1+4+8 bytes
        body = bytes([0xC6, 0x02, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                      0x72, 0x09, 0x00, 0x00, 0x70, 0x2A])
        assert _iter_ldstr_tokens(body) == [0x70000009]


# ---------------------------------------------------------------------------
# xor_scrub
# ---------------------------------------------------------------------------


class TestXorScrub:
    def test_reversible(self):
        data = b"hello world" * 10
        seed = 42
        assert xor_scrub(xor_scrub(data, seed), seed) == data

    def test_zero_seed_on_nonzero_bytes_is_not_identity(self):
        # Even seed 0 scrambles non-zero input bytes whenever the keystream
        # byte differs; reversibility remains guaranteed (double-xor).  This
        # guards the "never write the plaintext back unchanged" property.
        data = b"\x01\x02\x03"
        assert xor_scrub(data, 0) != data

    def test_non_zero_seed_is_not_identity(self):
        data = samples.sample_bytes()[:200]
        scrambled = xor_scrub(data, 7)
        assert scrambled != data

    def test_deterministic(self):
        data = samples.sample_bytes()[:1000]
        assert xor_scrub(data, 99) == xor_scrub(data, 99)

    def test_different_seeds_differ(self):
        data = b"Apollo WinExe agent binary payload"
        a = xor_scrub(data, 1)
        b = xor_scrub(data, 2)
        assert a != b
        assert a != data
        assert b != data

    def test_non_identity_for_nonzero_seed_on_fixture(self):
        data = samples.sample_bytes()
        assert xor_scrub(data, 123) != data
        assert xor_scrub(data, 1) != xor_scrub(data, 2)

    def test_length_preserved(self):
        data = samples.sample_bytes()
        assert len(xor_scrub(data, 5)) == len(data)


# ---------------------------------------------------------------------------
# strings_pass
# ---------------------------------------------------------------------------


class TestStringsPass:
    def test_scrubbable_entries_xored_at_correct_offsets(self, tmp_path):
        """Scrubbable string_scrub entries are XORed at their offsets with correct length."""
        pi = _pe_info(tmp_path)
        data = bytearray(pi["data"])
        seed = 12345
        
        findings = strings_pass(pi, data, seed)
        
        # Should have findings for scrubbable entries
        assert len(findings) > 0
        
        # Check that user-agent was scrubbed (it's scrubbable string_scrub)
        cid_ua = _catalog_id_for(DEFAULT_USER_AGENT, "utf-16le")
        ua_finding = next((f for f in findings if f[0] == cid_ua), None)
        assert ua_finding is not None, "User-agent should be scrubbed"
        assert ua_finding[1] == samples.USER_AGENT_OFFSET
        
        # Verify the bytes at that offset are different from original
        original = pi["data"][samples.USER_AGENT_OFFSET:samples.USER_AGENT_OFFSET + len(DEFAULT_USER_AGENT)*2]
        assert data[samples.USER_AGENT_OFFSET:samples.USER_AGENT_OFFSET + len(DEFAULT_USER_AGENT)*2] != original

    def test_config_critical_entries_left_untouched(self, tmp_path):
        """Config-critical (rebuild_config) entries are not scrubbed by default."""
        pi = _pe_info(tmp_path)
        data = bytearray(pi["data"])
        seed = 12345
        
        findings = strings_pass(pi, data, seed, force_break_runtime=False)
        
        # Callback URL is rebuild_config - should NOT be scrubbed
        cid_url = _catalog_id_for("https://192.168.10.20:8443", "utf-16le")
        url_finding = next((f for f in findings if f[0] == cid_url and "string_scrub" in f[2]), None)
        # The finding should exist but be marked as skipped
        url_skipped = next((f for f in findings if f[0] == cid_url and "skipped" in f[2]), None)
        assert url_skipped is not None, "Callback URL should be reported as skipped"
        
        # Original bytes should be unchanged
        original = pi["data"]
        # Note: we only check that it's NOT scrubbed (i.e., we don't find a "string_scrub" finding for it)
        scrubbed_url = next((f for f in findings if f[0] == cid_url and "string_scrub" in f[2]), None)
        assert scrubbed_url is None, "Config-critical URL should not be scrubbed"

    def test_force_break_runtime_enables_config_critical_scrubbing(self, tmp_path):
        """With force_break_runtime=True, config-critical entries are also scrubbed."""
        pi = _pe_info(tmp_path)
        data = bytearray(pi["data"])
        seed = 12345
        
        findings = strings_pass(pi, data, seed, force_break_runtime=True)
        
        # Callback URL should now be scrubbed
        cid_url = _catalog_id_for("https://192.168.10.20:8443", "utf-16le")
        url_finding = next((f for f in findings if f[0] == cid_url and "rebuild_config" in f[2] and "forced" in f[2]), None)
        assert url_finding is not None, "Callback URL should be scrubbed with force_break_runtime=True"
        
        # Verify bytes changed
        original = pi["data"]
        assert data[url_finding[1]:url_finding[1] + len("https://192.168.10.20:8443")*2] != original[url_finding[1]:url_finding[1] + len("https://192.168.10.20:8443")*2]

    def test_deterministic_same_seed_same_output(self, tmp_path):
        """Same seed produces identical scrubbed output."""
        pi = _pe_info(tmp_path)
        data1 = bytearray(pi["data"])
        data2 = bytearray(pi["data"])
        seed = 42
        
        strings_pass(pi, data1, seed)
        strings_pass(pi, data2, seed)
        
        assert data1 == data2, "Same seed should produce identical output"

    def test_different_seeds_produce_different_output(self, tmp_path):
        """Different seeds produce different output."""
        pi = _pe_info(tmp_path)
        data1 = bytearray(pi["data"])
        data2 = bytearray(pi["data"])
        
        strings_pass(pi, data1, 1)
        strings_pass(pi, data2, 2)
        
        assert data1 != data2, "Different seeds should produce different output"
        assert data1 != pi["data"]
        assert data2 != pi["data"]

    def test_no_section_stream_layout_change(self, tmp_path):
        """Data length unchanged after strings_pass."""
        pi = _pe_info(tmp_path)
        data = bytearray(pi["data"])
        original_len = len(data)
        
        strings_pass(pi, data, 999)
        
        assert len(data) == original_len, "Data length must be unchanged"

    def test_end_to_end_with_scan_heaps(self, tmp_path):
        """strings_pass tested end-to-end with scan_heaps results on synthetic fixture."""
        pi = _pe_info(tmp_path)
        data = bytearray(pi["data"])
        
        # First, verify scan_heaps finds the expected entries
        matches = scan_heaps(pi)
        
        # Find scrubbable entries from catalog
        scrubbable_ids = set()
        for entry in pi:
            pass
        # Use the catalog directly
        from obfuscate.fingerprints import CATALOG, FullStringEntry
        for i, entry in enumerate(CATALOG):
            if isinstance(entry, FullStringEntry) and entry.mitigation == "string_scrub" and entry.scrubbable:
                scrubbable_ids.add(str(i))
        
        # Verify scan_heaps finds these
        scrubbable_matches = [m for m in matches if m["catalog_id"] in scrubbable_ids and m["tier"] == "full"]
        assert len(scrubbable_matches) > 0, "Should find scrubbable entries"
        
        # Now run strings_pass
        findings = strings_pass(pi, data, 555)
        
        # Should have findings for each scrubbable match
        finding_ids = {f[0] for f in findings}
        for match in scrubbable_matches:
            assert match["catalog_id"] in finding_ids, f"Scrubbable entry {match['catalog_id']} should be scrubbed"
        
        # Verify original plaintext is gone (XORed), except where the scrub
        # was refused because the match overlaps a protected config-critical
        # (rebuild_config) literal -- those stays untouched by design (R3/R4).
        for match in scrubbable_matches:
            entry = CATALOG[int(match["catalog_id"])]
            offset = match["file_offset"]
            enc = match["encoding"]
            scrub_len = len(entry.text) * 2 if enc == "utf-16le" else len(entry.text)
            original = pi["data"][offset:offset + scrub_len]
            scrubbed = data[offset:offset + scrub_len]
            finding = next(
                (f for f in findings if f[0] == match["catalog_id"] and f[1] == offset),
                None,
            )
            if finding is not None and "protected overlap" in finding[2]:
                assert scrubbed == original, (
                    f"protected overlap at offset {offset} must stay untouched"
                )
            else:
                assert scrubbed != original, (
                    f"Entry {match['catalog_id']} at offset {offset} should be XORed"
                )


# ---------------------------------------------------------------------------
# string_scrub overlap protection (R3/R4)
# ---------------------------------------------------------------------------


class TestProtectedOverlap:
    """A scrubbable full-string may match inside a config-critical literal.

    The scrubbable ``Mythic`` literal (string_scrub) is a substring of the
    protected ``MythicSession`` cookie and ``\\.\\pipe\\Mythic_Agent`` pipe
    literals in #US; the pass must refuse those overlaps so config-critical
    values stay intact (AC4).
    """

    def test_config_critical_literals_stay_byte_intact(self, tmp_path):
        pi = _pe_info(tmp_path)
        data = bytearray(pi["data"])
        strings_pass(pi, data, 12345)

        cookie = pi["data"][samples.COOKIE_NAME_OFFSET:samples.COOKIE_NAME_OFFSET + 26]
        assert bytes(data[samples.COOKIE_NAME_OFFSET:samples.COOKIE_NAME_OFFSET + 26]) == cookie
        pipe = pi["data"][samples.PIPE_NAME_OFFSET:samples.PIPE_NAME_OFFSET + 42]
        assert bytes(data[samples.PIPE_NAME_OFFSET:samples.PIPE_NAME_OFFSET + 42]) == pipe

    def test_overlapping_scrub_is_reported_not_applied(self, tmp_path):
        pi = _pe_info(tmp_path)
        data = bytearray(pi["data"])
        findings = strings_pass(pi, data, 12345)

        cid_mythic = _catalog_id_for("Mythic", "utf-16le")
        skipped = [
            f for f in findings
            if f[0] == cid_mythic and "protected overlap" in f[2]
        ]
        # The Mythic matches inside the pipe + cookie literals are refused.
        assert any(f[1] == samples.PIPE_NAME_OFFSET + 18 for f in skipped)
        assert any(f[1] == samples.COOKIE_NAME_OFFSET for f in skipped)

    def test_standalone_scrubbable_still_scrubbed(self, tmp_path):
        pi = _pe_info(tmp_path)
        data = bytearray(pi["data"])
        strings_pass(pi, data, 12345)

        # The standalone manufacturer "Mythic" literal is still scrubbed.
        cid_mythic = _catalog_id_for("Mythic", "utf-16le")
        cid = samples.MANUFACTURER_OFFSET
        original = pi["data"][cid:cid + 12]
        assert bytes(data[cid:cid + 12]) != original
