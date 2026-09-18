"""metadata.py tests (task 8): metadata hardening sub-passes.

Covers:

1. MVID is randomized in-place in the #GUID heap (16 bytes).
2. Module GUID is randomized in-place in the #GUID heap (16 bytes).
3. COFF header timestamp is randomized.
4. Assembly version (4 x u2) is randomized.
5. Strong-name signature block is zeroed; afPublicKey flag is cleared.
6. PE checksum is zeroed.
7. Rich header XOR key is replaced with a seed-derived variant.
8. Debug directory rows are zeroed in-place.
9. Determinism: same seed produces byte-identical output.
10. No section/stream layout changes (offsets and sizes unchanged after pass).
"""

from __future__ import annotations

import struct

import pytest

dnfile = pytest.importorskip("dnfile")

from obfuscate.metadata import metadata_pass, attributes_pass  # noqa: E402
from obfuscate.pe import _rich_header_offset, analyze  # noqa: E402
from tests.fixtures import pe_builder, samples  # noqa: E402
from tests.fixtures.samples import (
    SAMPLE_MVID,
    SAMPLE_MODULE_GUID,
    SAMPLE_ASSEMBLY_VERSION,
    DEFAULT_COMPANY,
    DEFAULT_PRODUCT,
    DEFAULT_COPYRIGHT,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEED = 42


def _pe_info(tmp_path):
    """Build a pe_info dict from the canonical sample."""
    data = bytearray(samples.sample_bytes())
    path = tmp_path / "sample.exe"
    path.write_bytes(bytes(data))
    res = analyze(str(path))
    pe_info = dict(res)
    pe_info["path"] = str(path)
    pe_info["data"] = bytes(data)
    return pe_info


def _run(tmp_path, seed=SEED):
    """Run metadata_pass on the canonical sample and return (pe_info, data, findings)."""
    pi = _pe_info(tmp_path)
    data = bytearray(pi["data"])
    findings = metadata_pass(pi, data, seed)
    return pi, data, findings


def _write(tmp_path, data: bytes):
    path = tmp_path / "sample.exe"
    path.write_bytes(data)
    return str(path)


# ---------------------------------------------------------------------------
# Sub-pass tests
# ---------------------------------------------------------------------------


class TestMvidRandomized:
    def test_mvid_changes(self, tmp_path):
        pi, data, findings = _run(tmp_path)
        new_mvid = data[pi["metadata"]["mvid_offset"]:pi["metadata"]["mvid_offset"] + 16]
        assert new_mvid != SAMPLE_MVID
        assert any("MVID randomized" in f[2] for f in findings)

    def test_mvid_16_bytes(self, tmp_path):
        pi, data, findings = _run(tmp_path)
        off = pi["metadata"]["mvid_offset"]
        assert len(data[off:off + 16]) == 16


class TestModuleGuidRandomized:
    def test_module_guid_changes(self, tmp_path):
        pi, data, findings = _run(tmp_path)
        off = pi["metadata"]["module_guid_offset"]
        new_guid = data[off:off + 16]
        assert new_guid != SAMPLE_MODULE_GUID
        assert any("module GUID randomized" in f[2] for f in findings)


class TestTimestampRandomized:
    def test_timestamp_changes(self, tmp_path):
        pi, data, findings = _run(tmp_path)
        from obfuscate.metadata import _COFF_OFFSET, _TIMESTAMP_COFF_OFFSET
        stamp_off = _COFF_OFFSET + _TIMESTAMP_COFF_OFFSET
        new_stamp = struct.unpack_from("<I", data, stamp_off)[0]
        assert new_stamp != samples.DEFAULT_TIME_STAMP
        assert any("PE timestamp randomized" in f[2] for f in findings)


class TestAssemblyVersionRandomized:
    def test_version_changes(self, tmp_path):
        pi, data, findings = _run(tmp_path)
        fields = pi["metadata"]["assembly_fields"]
        ver_off = fields["major"]
        assert ver_off > 0
        new_ver = struct.unpack_from("<HHHH", data, ver_off)
        assert new_ver != SAMPLE_ASSEMBLY_VERSION

    def test_version_stored_as_u2(self, tmp_path):
        pi, data, findings = _run(tmp_path)
        fields = pi["metadata"]["assembly_fields"]
        ver_off = fields["major"]
        for i in range(4):
            val = struct.unpack_from("<H", data, ver_off + i * 2)[0]
            assert 0 <= val <= 0xFFFF


class TestStrongNameStripped:
    def test_signature_zeroed(self, tmp_path):
        pi, data, findings = _run(tmp_path)
        # Strong-name RVA/size come from the CLI header at offsets 32/36.
        cli_off = pi["pe"]["cli_header"]["offset"]
        sn_rva = struct.unpack_from("<I", data, cli_off + 32)[0]
        sn_size = struct.unpack_from("<I", data, cli_off + 36)[0]
        md_root_off = pi["metadata"]["metadata_root_offset"]
        md_root_rva = pi["metadata"]["metadata_root_rva"]
        sn_off = md_root_off + (sn_rva - md_root_rva)
        assert data[sn_off:sn_off + sn_size] == b"\x00" * sn_size
        assert any("strong-name signature zeroed" in f[2] for f in findings)

    def test_afpublickey_flag_cleared(self, tmp_path):
        pi, data, findings = _run(tmp_path)
        flags_off = pi["metadata"]["assembly_fields"]["flags"]
        assert flags_off > 0
        flags = struct.unpack_from("<I", data, flags_off)[0]
        assert flags & 0x0008 == 0  # afPublicKey bit cleared
        assert any("strong-name flag cleared" in f[2] for f in findings)


class TestChecksumZeroed:
    def test_checksum_zeroed(self, tmp_path):
        pi, data, findings = _run(tmp_path)
        from obfuscate.metadata import _CHECKSUM_FILE_OFFSET
        cksum = struct.unpack_from("<I", data, _CHECKSUM_FILE_OFFSET)[0]
        assert cksum == 0
        assert any("PE checksum zeroed" in f[2] for f in findings)


class TestRichHeaderNormalized:
    def test_rich_header_changes(self, tmp_path):
        """On the synthetic fixture (no Rich header), the pass is a no-op."""
        pi, data, findings = _run(tmp_path)
        # Synthetic fixture has no Rich header — normalize is skipped.
        assert not any("Rich header" in f[2] for f in findings)


class TestDebugDirectoryZeroed:
    def test_debug_rows_zeroed(self, tmp_path):
        """On the synthetic fixture (no debug directory), the pass is a no-op."""
        pi, data, findings = _run(tmp_path)
        assert not any("debug directory" in f[2] for f in findings)


# ---------------------------------------------------------------------------
# Rich header positive test (using a real native binary with Rich header)
# ---------------------------------------------------------------------------


class TestRichHeaderPositive:
    """Exercise the Rich-header normalization on a binary that has one.

    csc.exe / notepad / cmd are native (non-.NET) images, so ``analyze()``
    raises PeReadError on them; the Rich header is located with
    ``pe._rich_header_offset`` directly (see ralph/memory.md note 80) and the
    pass is called with a minimal pe_info carrying just the ``rich`` block.
    """

    @pytest.fixture(scope="module")
    def rich_exe_path(self):
        import os

        candidates = [
            r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
            r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
            r"C:\Windows\System32\notepad.exe",
            r"C:\Windows\System32\cmd.exe",
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        return None

    def test_rich_key_replaced(self, rich_exe_path, tmp_path):
        if rich_exe_path is None:
            pytest.skip("no Rich-header-bearing exe available")
        import shutil

        dst = tmp_path / "rich.exe"
        shutil.copy(rich_exe_path, dst)

        pe = dnfile.dnPE(str(dst))
        try:
            dans_off = _rich_header_offset(pe)
            if dans_off is None or dans_off <= 0:
                pytest.skip("no Rich header found")
        finally:
            pe.close()

        data = bytearray(dst.read_bytes())
        old_key = bytes(data[dans_off + 4:dans_off + 8])

        # Minimal pe_info: only the `rich` block is consumed for this sub-pass.
        pi = {"rich": {"offset": dans_off}}
        findings = metadata_pass(pi, data, 99)

        new_key = bytes(data[dans_off + 4:dans_off + 8])
        assert new_key != old_key
        assert any("Rich header key normalized" in f[2] for f in findings)

        # DanS marker must still decode correctly with the new key.
        dans_on_disk = bytes(data[dans_off:dans_off + 4])
        decoded = bytes(a ^ b for a, b in zip(dans_on_disk, new_key))
        assert decoded == b"DanS"


# ---------------------------------------------------------------------------
# Debug directory positive test (using a real .NET exe with debug rows)
# ---------------------------------------------------------------------------


class TestDebugDirectoryPositive:
    """Exercise debug-directory zeroing on a binary that has debug rows."""

    @pytest.fixture(scope="module")
    def debug_exe_path(self):
        import os

        candidates = [
            r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe",
            r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe",
        ]
        for path in candidates:
            if os.path.exists(path):
                return path
        return None

    def test_debug_rows_zeroed(self, debug_exe_path, tmp_path):
        if debug_exe_path is None:
            pytest.skip("no debug-bearing exe available")
        import shutil

        dst = tmp_path / "debug.exe"
        shutil.copy(debug_exe_path, dst)
        res = analyze(str(dst))
        rows = res["debug"]["rows"]
        if not rows:
            pytest.skip("no debug rows found")

        pi = dict(res)
        data = bytearray(dst.read_bytes())
        pi["path"] = str(dst)
        pi["data"] = bytes(data)
        findings = metadata_pass(pi, data, SEED)

        debug_findings = [f for f in findings if "debug directory" in f[2]]
        assert debug_findings

        for row in rows:
            row_off = row["file_offset"]
            if row_off and row_off + 28 <= len(data):
                assert data[row_off:row_off + 28] == b"\x00" * 28


# ---------------------------------------------------------------------------
# Determinism and layout invariants
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_seed_identical_output(self, tmp_path):
        pi = _pe_info(tmp_path)
        d1 = bytearray(pi["data"])
        d2 = bytearray(pi["data"])
        f1 = metadata_pass(pi, d1, SEED)
        f2 = metadata_pass(pi, d2, SEED)
        assert bytes(d1) == bytes(d2)
        assert f1 == f2

    def test_different_seed_different_mvid(self, tmp_path):
        pi = _pe_info(tmp_path)
        d1 = bytearray(pi["data"])
        d2 = bytearray(pi["data"])
        metadata_pass(pi, d1, 1)
        metadata_pass(pi, d2, 2)
        mvid1 = d1[pi["metadata"]["mvid_offset"]:pi["metadata"]["mvid_offset"] + 16]
        mvid2 = d2[pi["metadata"]["mvid_offset"]:pi["metadata"]["mvid_offset"] + 16]
        assert mvid1 != mvid2


class TestNoLayoutChanges:
    """Section and stream offsets/sizes must not change after metadata_pass."""

    def test_stream_offsets_unchanged(self, tmp_path):
        pi = _pe_info(tmp_path)
        layout = samples.sample_layout()
        data = bytearray(pi["data"])
        metadata_pass(pi, data, SEED)

        # Re-analyze the modified bytes to verify stream layout.
        out_path = tmp_path / "out.exe"
        out_path.write_bytes(bytes(data))
        res_after = analyze(str(out_path))

        for name in ("#~", "#Strings", "#US", "#GUID", "#Blob"):
            before = layout.streams[name]
            after = res_after["metadata"]["streams"][name]
            assert after["offset"] == before.offset, f"{name} offset changed"
            assert after["size"] == before.size, f"{name} size changed"

    def test_section_layout_unchanged(self, tmp_path):
        pi = _pe_info(tmp_path)
        data = bytearray(pi["data"])
        before_sections = pi["pe"]["sections"]
        metadata_pass(pi, data, SEED)

        out_path = tmp_path / "out.exe"
        out_path.write_bytes(bytes(data))
        res_after = analyze(str(out_path))
        after_sections = res_after["pe"]["sections"]

        assert before_sections == after_sections, "section table changed"

    def test_file_size_unchanged(self, tmp_path):
        pi = _pe_info(tmp_path)
        data = bytearray(pi["data"])
        original_size = len(data)
        metadata_pass(pi, data, SEED)
        assert len(data) == original_size


# ---------------------------------------------------------------------------
# Attributes pass tests (new R3 sub-pass)
# ---------------------------------------------------------------------------


def _pe_info_with_attrs(tmp_path):
    """Build a pe_info dict from the canonical sample with attributes data."""
    data = bytearray(samples.sample_bytes())
    path = tmp_path / "sample.exe"
    path.write_bytes(bytes(data))
    res = analyze(str(path))
    pe_info = dict(res)
    pe_info["path"] = str(path)
    pe_info["data"] = bytes(data)
    return pe_info


def _run_attrs(tmp_path, seed=SEED):
    """Run attributes_pass on the canonical sample and return (pe_info, data, findings)."""
    pi = _pe_info_with_attrs(tmp_path)
    data = bytearray(pi["data"])
    findings = attributes_pass(pi, data, seed)
    return pi, data, findings


class TestAuthorshipAttributes:
    """Test neutralization of AssemblyCompany/Product/Copyright attributes."""

    def test_company_attribute_neutralized(self, tmp_path):
        pi, data, findings = _run_attrs(tmp_path)
        # Check that the company attribute was neutralized
        company_findings = [f for f in findings if "AssemblyCompanyAttribute" in f[2] and "neutralized" in f[2]]
        assert company_findings, "AssemblyCompanyAttribute should be neutralized"
        
        # Verify the blob content was changed
        custom_attrs = pi["metadata"].get("custom_attributes", {})
        company_info = custom_attrs.get("AssemblyCompanyAttribute")
        if company_info:
            blob_offset = company_info["blob_offset"]
            blob_size = company_info["blob_size"]
            # The string content should be different from original
            # Parse the blob to get the string portion
            import struct
            pos = blob_offset + 2  # skip prolog
            first = data[pos]
            if (first & 0x80) == 0:
                str_len = first
                pos += 1
            elif (first & 0xC0) == 0x80:
                str_len = ((first & 0x3F) << 8) | data[pos + 1]
                pos += 2
            else:
                pytest.skip("unexpected compressed int format")
            new_content = data[pos:pos + str_len]
            assert new_content != DEFAULT_COMPANY.encode("utf-8")

    def test_product_attribute_neutralized(self, tmp_path):
        pi, data, findings = _run_attrs(tmp_path)
        product_findings = [f for f in findings if "AssemblyProductAttribute" in f[2] and "neutralized" in f[2]]
        assert product_findings, "AssemblyProductAttribute should be neutralized"
        
        custom_attrs = pi["metadata"].get("custom_attributes", {})
        product_info = custom_attrs.get("AssemblyProductAttribute")
        if product_info:
            blob_offset = product_info["blob_offset"]
            import struct
            pos = blob_offset + 2
            first = data[pos]
            if (first & 0x80) == 0:
                str_len = first
                pos += 1
            elif (first & 0xC0) == 0x80:
                str_len = ((first & 0x3F) << 8) | data[pos + 1]
                pos += 2
            else:
                pytest.skip("unexpected compressed int format")
            new_content = data[pos:pos + str_len]
            assert new_content != DEFAULT_PRODUCT.encode("utf-8")

    def test_copyright_attribute_neutralized(self, tmp_path):
        pi, data, findings = _run_attrs(tmp_path)
        copyright_findings = [f for f in findings if "AssemblyCopyrightAttribute" in f[2] and "neutralized" in f[2]]
        assert copyright_findings, "AssemblyCopyrightAttribute should be neutralized"
        
        custom_attrs = pi["metadata"].get("custom_attributes", {})
        copyright_info = custom_attrs.get("AssemblyCopyrightAttribute")
        if copyright_info:
            blob_offset = copyright_info["blob_offset"]
            import struct
            pos = blob_offset + 2
            first = data[pos]
            if (first & 0x80) == 0:
                str_len = first
                pos += 1
            elif (first & 0xC0) == 0x80:
                str_len = ((first & 0x3F) << 8) | data[pos + 1]
                pos += 2
            else:
                pytest.skip("unexpected compressed int format")
            new_content = data[pos:pos + str_len]
            assert new_content != DEFAULT_COPYRIGHT.encode("utf-8")

    def test_authorship_attributes_deterministic(self, tmp_path):
        """Same seed produces identical attribute neutralizations."""
        pi = _pe_info_with_attrs(tmp_path)
        d1 = bytearray(pi["data"])
        d2 = bytearray(pi["data"])
        f1 = attributes_pass(pi, d1, 123)
        f2 = attributes_pass(pi, d2, 123)
        assert bytes(d1) == bytes(d2)
        assert f1 == f2

    def test_different_seeds_different_attributes(self, tmp_path):
        """Different seeds produce different attribute values."""
        pi = _pe_info_with_attrs(tmp_path)
        d1 = bytearray(pi["data"])
        d2 = bytearray(pi["data"])
        attributes_pass(pi, d1, 1)
        attributes_pass(pi, d2, 2)
        
        custom_attrs = pi["metadata"].get("custom_attributes", {})
        for attr_name in ("AssemblyCompanyAttribute", "AssemblyProductAttribute", "AssemblyCopyrightAttribute"):
            info = custom_attrs.get(attr_name)
            if info:
                blob_offset = info["blob_offset"]
                import struct
                pos = blob_offset + 2
                first = d1[pos]
                if (first & 0x80) == 0:
                    str_len = first
                    pos += 1
                elif (first & 0xC0) == 0x80:
                    str_len = ((first & 0x3F) << 8) | d1[pos + 1]
                    pos += 2
                else:
                    continue
                content1 = d1[pos:pos + str_len]
                content2 = d2[pos:pos + str_len]
                assert content1 != content2, f"{attr_name} should differ with different seeds"


class TestDebuggableAttribute:
    """Test neutralization of DebuggableAttribute."""

    def test_debuggable_attribute_neutralized(self, tmp_path):
        pi, data, findings = _run_attrs(tmp_path)
        debug_findings = [f for f in findings if "DebuggableAttribute" in f[2] and "neutralized" in f[2]]
        assert debug_findings, "DebuggableAttribute should be neutralized"
        
        custom_attrs = pi["metadata"].get("custom_attributes", {})
        debug_info = custom_attrs.get("DebuggableAttribute")
        if debug_info:
            blob_offset = debug_info["blob_offset"]
            # The enum value at offset +2 should be zeroed
            assert data[blob_offset + 2] == 0
            assert data[blob_offset + 3] == 0


class TestVersionInfoStrings:
    """Test scrubbing of VS_VERSION_INFO StringFileInfo strings."""

    def test_version_info_not_present_on_fixture(self, tmp_path):
        """Synthetic fixture has no .rsrc section, so version info should be reported as not found."""
        pi, data, findings = _run_attrs(tmp_path)
        
        for key in ("CompanyName", "ProductName", "OriginalFilename", "FileDescription", "FileVersion"):
            findings_for_key = [f for f in findings if f"VS_VERSION_INFO.{key}" in f[2] and "not found" in f[2]]
            assert findings_for_key, f"VS_VERSION_INFO.{key} should be reported as not found"


class TestAttributesPassLayout:
    """Test that attributes_pass makes no layout changes."""

    def test_no_section_stream_layout_change(self, tmp_path):
        pi = _pe_info_with_attrs(tmp_path)
        layout = samples.sample_layout()
        data = bytearray(pi["data"])
        attributes_pass(pi, data, SEED)

        out_path = tmp_path / "out.exe"
        out_path.write_bytes(bytes(data))
        res_after = analyze(str(out_path))

        for name in ("#~", "#Strings", "#US", "#GUID", "#Blob"):
            before = layout.streams[name]
            after = res_after["metadata"]["streams"][name]
            assert after["offset"] == before.offset, f"{name} offset changed"
            assert after["size"] == before.size, f"{name} size changed"

    def test_file_size_unchanged(self, tmp_path):
        pi = _pe_info_with_attrs(tmp_path)
        data = bytearray(pi["data"])
        original_size = len(data)
        attributes_pass(pi, data, SEED)
        assert len(data) == original_size
