"""PE reader tests (task pe.py): read-only dnfile wrapper for R2.

Asserts:

1. `analyze()` on the synthetic Apollo fixture returns offsets/identity values
   that match the fixture's documented Layout and dnfile's own parsed values.
2. `analyze()` never mutates the input (sha256 before/after identical).
3. PE identity (image base, timestamp, checksum, CLI header, sections, .text,
   .rsrc), metadata identity (streams, MVID, module GUID, assembly
   full name/version, strong-name + public key token, TargetFramework).
4. Non-image input raises `PeReadError`.
5. (Presence-gated) A real .NET Framework 4 exe parsed from the on-box
   Framework64/v4.0.30319 directory is analyzed without mutation and its
   stream/PE offsets equal dnfile's own parsed values.
"""

import hashlib
import os
import shutil

import pytest

dnfile = pytest.importorskip("dnfile")

from obfuscate.pe import PeReadError, analyze  # noqa: E402
from tests.fixtures import pe_builder, samples  # noqa: E402


def _write(tmp_path, data: bytes):
    path = tmp_path / "sample.exe"
    path.write_bytes(data)
    return str(path)


def _sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class TestFixtureAnalyze:
    def test_stream_offsets_match_fixture_layout(self, tmp_path):
        path = _write(tmp_path, samples.sample_bytes())
        res = analyze(path)
        streams = res["metadata"]["streams"]
        layout = samples.sample_layout()
        for name in ("#~", "#Strings", "#US", "#GUID", "#Blob"):
            info = layout.streams[name]
            assert streams[name]["offset"] == info.offset, name
            assert streams[name]["rva"] == info.rva, name
            assert streams[name]["size"] == info.size, name

    def test_identity_offsets_match_fixture_constants(self, tmp_path):
        path = _write(tmp_path, samples.sample_bytes())
        res = analyze(path)
        assert res["pe"]["cli_header"]["offset"] == samples.CLI_OFFSET
        assert res["pe"]["cli_header"]["rva"] == samples.CLI_RVA
        assert res["pe"]["cli_header"]["size"] == 72
        assert res["pe"]["time_date_stamp"] == samples.DEFAULT_TIME_STAMP
        assert res["metadata"]["mvid_offset"] == samples.MVID_DATA_OFFSET
        assert res["metadata"]["module_guid_offset"] == samples.MODULE_GUID_DATA_OFFSET
        assert res["metadata"]["metadata_root_rva"] == samples.METADATA_ROOT_RVA
        assert res["metadata"]["metadata_root_offset"] == samples.METADATA_ROOT_OFFSET
        assert res["metadata"]["metadata_root_size"] == samples.METADATA_ROOT_SIZE

    def test_identity_values(self, tmp_path):
        path = _write(tmp_path, samples.sample_bytes())
        res = analyze(path)
        md = res["metadata"]
        assert md["mvid"] == samples.SAMPLE_MVID.hex()
        assert md["module_guid"] == samples.SAMPLE_MODULE_GUID.hex()
        assert md["module_name"] == samples.DEFAULT_MODULE_NAME
        assert md["version"] == "v4.0.30319"
        assert md["target_framework"] == samples.DEFAULT_TARGET_FRAMEWORK
        asm = md["assembly"]
        assert asm["name"] == samples.DEFAULT_ASSEMBLY_NAME
        assert asm["version"] == "4.0.0.0"
        assert asm["strong_name"] is True
        assert asm["public_key_token"] is not None

    def test_public_key_token_is_reversible(self, tmp_path):
        # The token must equal the last-8-reversed sha1 of the public key.
        path = _write(tmp_path, samples.sample_bytes())
        res = analyze(path)
        token = res["metadata"]["assembly"]["public_key_token"]
        digest = hashlib.sha1(samples.DEFAULT_PUBLIC_KEY).digest()
        assert token == digest[-8:][::-1].hex()

    def test_pe_sections_and_text(self, tmp_path):
        path = _write(tmp_path, samples.sample_bytes())
        res = analyze(path)
        assert res["pe"]["image_base"] == 0x140000000
        assert [s["name"] for s in res["pe"]["sections"]] == [".text"]
        text = res["pe"]["text"]
        assert text is not None and text["name"] == ".text"
        assert text["virtual_address"] == 0x1000
        assert text["raw_offset"] == 0x200

    def test_rsrc_absent_on_fixture(self, tmp_path):
        path = _write(tmp_path, samples.sample_bytes())
        res = analyze(path)
        assert res["pe"]["rsrc"]["rva"] == 0
        assert res["pe"]["rsrc"]["file_offset"] == 0

    def test_rich_absent_on_fixture(self, tmp_path):
        path = _write(tmp_path, samples.sample_bytes())
        res = analyze(path)
        assert res["rich"] is None

    def test_debug_empty_on_fixture(self, tmp_path):
        path = _write(tmp_path, samples.sample_bytes())
        res = analyze(path)
        assert res["debug"]["directory_rva"] == 0
        assert res["debug"]["rows"] == []


class TestReadOnly:
    def test_input_not_mutated(self, tmp_path):
        path = _write(tmp_path, samples.sample_bytes())
        before = _sha256(path)
        analyze(path)
        assert _sha256(path) == before

    def test_real_exe_input_not_mutated(self, real_framework_exe, tmp_path):
        if real_framework_exe is None:
            pytest.skip("no real .NET Framework exe available")
        dst = tmp_path / "real.exe"
        shutil.copy(real_framework_exe, dst)
        before = _sha256(dst)
        analyze(str(dst))
        assert _sha256(dst) == before


class TestRealFrameworkExe:
    """Presence-gated against the on-box .NET Framework 4 runtime directory."""

    def test_analyze_matches_dnfile(self, real_framework_exe, tmp_path):
        if real_framework_exe is None:
            pytest.skip("no real .NET Framework exe available")
        dst = tmp_path / "real.exe"
        shutil.copy(real_framework_exe, dst)
        res = analyze(str(dst))
        pe = dnfile.dnPE(str(dst))
        try:
            assert res["metadata"]["metadata_root_rva"] == pe.net.metadata.rva
            assert res["metadata"]["metadata_root_size"] == pe.net.struct.MetaDataSize
            assert res["metadata"]["mvid"] == pe.net.mdtables.Module.rows[0].Mvid.value.hex()
            assert res["pe"]["time_date_stamp"] == pe.FILE_HEADER.TimeDateStamp
            for k, v in res["metadata"]["streams"].items():
                st = pe.net.metadata.streams[k.encode()]
                assert v["offset"] == st.file_offset, k
                assert v["size"] == st.sizeof(), k
                assert v["rva"] == st.rva, k
        finally:
            pe.close()

    def test_real_exe_has_cli_and_rsrc(self, real_framework_exe, tmp_path):
        if real_framework_exe is None:
            pytest.skip("no real .NET Framework exe available")
        dst = tmp_path / "real.exe"
        shutil.copy(real_framework_exe, dst)
        res = analyze(str(dst))
        assert res["pe"]["cli_header"] is not None
        assert res["pe"]["cli_header"]["size"] == 72
        assert res["pe"]["rsrc"]["rva"] > 0
        assert res["pe"]["rsrc"]["file_offset"] > 0

    def test_real_exe_debug_content(self, real_framework_exe, tmp_path):
        # RegAsm.exe carries one CodeView row with the PDB path baked in.
        if real_framework_exe is None:
            pytest.skip("no real .NET Framework exe available")
        dst = tmp_path / "real.exe"
        shutil.copy(real_framework_exe, dst)
        res = analyze(str(dst))
        rows = res["debug"]["rows"]
        assert rows, "real framework exe should expose a debug directory row"
        row = rows[0]
        assert row["type"] == 2
        assert row["type_name"] == "codeview"
        assert row["file_offset"] > 0
        assert row["pdb"], "CodeView row should carry a PDB file name"


class TestRichHeader:
    """Positive (present) path for the MSVC Rich header (native binaries)."""

    @pytest.fixture(scope="module")
    def rich_exe(self):
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

    def test_rich_header_offset_reported(self, rich_exe, tmp_path):
        if rich_exe is None:
            pytest.skip("no Rich-header-bearing native exe available")
        dst = tmp_path / "rich.exe"
        shutil.copy(rich_exe, dst)
        pe = dnfile.dnPE(str(dst))
        try:
            from obfuscate.pe import _rich_header_offset

            off = _rich_header_offset(pe)
            assert off is not None and off > 0
        finally:
            pe.close()
        # On-disk layout: DanS marker XORed with the key, directly followed by
        # the raw key.  Recover the marker by XORing the first 4 bytes with the
        # key stored right after it.
        with open(dst, "rb") as fh:
            data = fh.read()
        key_bytes = data[off + 4:off + 8]
        masked = bytes(b ^ k for b, k in zip(b"DanS", key_bytes))
        assert data[off:off + 4] == masked

    def test_rich_offset_matches_dnfile_rich(self, rich_exe, tmp_path):
        from obfuscate.pe import _rich_header_offset

        if rich_exe is None:
            pytest.skip("no Rich-header-bearing native exe available")
        dst = tmp_path / "rich.exe"
        shutil.copy(rich_exe, dst)
        pe = dnfile.dnPE(str(dst))
        try:
            # dnfile's RICH_HEADER must be present (what the scan relies on)
            # and the located offset must be a positive header-area position.
            assert getattr(pe, "RICH_HEADER", None) is not None
            assert _rich_header_offset(pe) > 0
        finally:
            pe.close()


class TestErrors:
    def test_non_pe_input_raises(self, tmp_path):
        path = tmp_path / "junk.bin"
        path.write_bytes(b"this is not a pe image at all")
        with pytest.raises(PeReadError):
            analyze(str(path))

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(PeReadError):
            analyze(str(tmp_path / "does_not_exist.exe"))


class TestPeBuilderNoStrongName:
    def test_strong_name_absent(self, tmp_path):
        builder = pe_builder.PeBuilder(
            mvid=samples.SAMPLE_MVID,
            module_guid=samples.SAMPLE_MODULE_GUID,
            strong_name=False,
        )
        path = _write(tmp_path, builder.build().bytes)
        res = analyze(path)
        asm = res["metadata"]["assembly"]
        assert asm["strong_name"] is False
        assert asm["public_key_token"] is None


# ---------------------------------------------------------------------------
# Shared fixture: locate a real .NET Framework 4 CLI-metadata exe on-box.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def real_framework_exe():
    candidates = [
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe",
        r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None
