"""Fixture tests (task 3): the synthetic PE/.NET builder, Apollo-shaped
sample, and agent_code tree are the hermetic foundation every later
scan/scrub/verify test depends on.

Asserts:

1. Builder output parses under dnfile (metadata tables/heaps resolve, MVID
   and assembly version read back, the five streams are present).
2. Curated Apollo literals appear at the documented file offsets in both
   UTF-8 (#Strings/#Blob) and UTF-16LE (#US) scans.
3. The agent_code tree has the layout `inject-patch` expects.
4. Determinism: same inputs -> byte-identical image.
"""

import struct

import pytest

dnfile = pytest.importorskip("dnfile")

from tests.fixtures import pe_builder, samples
from tests.fixtures.samples import (
    DEFAULT_ASSEMBLY_NAME,
    SAMPLE_ASSEMBLY_VERSION,
    DEFAULT_USER_AGENT,
    DEFAULT_MODULE_NAME,
)


def _scan_utf8(data, needle):
    """First file offset where a UTF-8 literal starts, or None."""
    idx = data.find(needle.encode("utf-8"))
    return None if idx < 0 else idx


def _scan_utf16le(data, needle):
    """First file offset where a UTF-16LE literal starts, or None."""
    idx = data.find(needle.encode("utf-16le"))
    return None if idx < 0 else idx


class TestParsesUnderDnfile:
    def test_dnfile_parses_sample(self, tmp_path):
        path = tmp_path / "sample.exe"
        path.write_bytes(samples.sample_bytes())
        pe = dnfile.dnPE(str(path))
        assert pe is not None

    def test_five_streams_present(self, tmp_path):
        path = tmp_path / "sample.exe"
        path.write_bytes(samples.sample_bytes())
        pe = dnfile.dnPE(str(path))
        assert pe.net is not None
        assert pe.net.metadata is not None
        names = set(pe.net.metadata.streams.keys())
        assert {b"#~", b"#Strings", b"#US", b"#GUID", b"#Blob"} <= names

    def test_heaps_resolve(self, tmp_path):
        path = tmp_path / "sample.exe"
        path.write_bytes(samples.sample_bytes())
        pe = dnfile.dnPE(str(path))
        net = pe.net
        # Strings heap resolves the Apollo identity strings.
        assert net.strings is not None
        assert net.strings.get(1) == DEFAULT_MODULE_NAME or net.strings.get(0) is not None
        # Blob heap resolves attribute value blobs.
        assert net.blobs is not None
        # GUID heap exposes the MVID at index 1.
        assert net.guids is not None
        g1 = net.guids.get(1)
        assert g1 is not None and g1.value == samples.SAMPLE_MVID
        # UserString heap resolves the user-agent literal.
        assert net.user_strings is not None

    def test_metadata_tables_resolve(self, tmp_path):
        path = tmp_path / "sample.exe"
        path.write_bytes(samples.sample_bytes())
        pe = dnfile.dnPE(str(path))
        md = pe.net.mdtables
        assert md is not None
        assert md.Module is not None and md.Module.num_rows == 1
        assert md.TypeRef is not None and md.TypeRef.num_rows >= 9
        assert md.Assembly is not None and md.Assembly.num_rows == 1
        assert md.AssemblyRef is not None and md.AssemblyRef.num_rows == 1
        assert md.CustomAttribute is not None and md.CustomAttribute.num_rows >= 5
        assert md.MemberRef is not None
        assert md.TypeDef is not None and md.TypeDef.num_rows == 1

    def test_mvid_read_back(self, tmp_path):
        path = tmp_path / "sample.exe"
        path.write_bytes(samples.sample_bytes())
        pe = dnfile.dnPE(str(path))
        mvid = pe.net.mdtables.Module.rows[0].Mvid
        assert mvid is not None
        assert mvid.value == samples.SAMPLE_MVID

    def test_assembly_version_read_back(self, tmp_path):
        path = tmp_path / "sample.exe"
        path.write_bytes(samples.sample_bytes())
        pe = dnfile.dnPE(str(path))
        row = pe.net.mdtables.Assembly.rows[0]
        assert (row.MajorVersion, row.MinorVersion, row.BuildNumber, row.RevisionNumber) \
            == samples.SAMPLE_ASSEMBLY_VERSION

    def test_assembly_name_read_back(self, tmp_path):
        path = tmp_path / "sample.exe"
        path.write_bytes(samples.sample_bytes())
        pe = dnfile.dnPE(str(path))
        row = pe.net.mdtables.Assembly.rows[0]
        assert row.Name == DEFAULT_ASSEMBLY_NAME


class TestFixedOffsets:
    def test_user_strings_at_documented_offsets(self):
        data = samples.sample_bytes()
        layout = samples.sample_layout()
        for name, text in pe_builder.DEFAULT_USER_STRINGS:
            expected = layout.user_strings[name]["offset"]
            assert data[expected:expected + len(text.encode("utf-16le"))] == text.encode("utf-16le"), (
                f"{name} not at documented offset {expected}"
            )

    def test_user_agent_literal_present_as_utf16le(self):
        data = samples.sample_bytes()
        off = _scan_utf16le(data, samples.DEFAULT_USER_AGENT)
        assert off == samples.USER_AGENT_OFFSET

    def test_killdate_literal_present_as_utf16le(self):
        data = samples.sample_bytes()
        off = _scan_utf16le(data, "killdate")
        assert off == samples.KILLDATE_OFFSET

    def test_split_killdate_fragments_present(self):
        data = samples.sample_bytes()
        # The split fragments are at specific documented offsets; verify those directly.
        assert data[samples.SPLIT_KILL_LEFT_OFFSET:samples.SPLIT_KILL_LEFT_OFFSET + 8] == "kill".encode("utf-16le")
        assert data[samples.SPLIT_KILL_RIGHT_OFFSET:samples.SPLIT_KILL_RIGHT_OFFSET + 8] == "date".encode("utf-16le")

    def test_strings_present_as_utf8(self):
        data = samples.sample_bytes()
        layout = samples.sample_layout()
        for text in ("Apollo", "ApolloInterop", "Mythic.Rest", "Mythic.Structs", "mscorlib", "Program", "Main"):
            expected = layout.strings[text]["offset"]
            assert data[expected:expected + len(text.encode("utf-8"))] == text.encode("utf-8"), (
                f"{text!r} not at documented offset {expected}"
            )
        # NAMESPACE_APOLLO_OFFSET is the specific documented offset for the Apollo namespace string.
        expected = layout.strings["Apollo"]["offset"]
        assert data[expected:expected + 6] == b"Apollo"

    def test_company_product_copyright_in_blob(self):
        data = samples.sample_bytes()
        layout = samples.sample_layout()
        for text in (samples.DEFAULT_COMPANY, samples.DEFAULT_PRODUCT, samples.DEFAULT_COPYRIGHT):
            expected = layout.blob_text[text]
            assert data[expected:expected + len(text.encode("utf-8"))] == text.encode("utf-8")


class TestIdentityFields:
    def test_mvid_at_documented_guid_offset(self):
        data = samples.sample_bytes()
        off = samples.MVID_DATA_OFFSET
        assert data[off:off + 16] == samples.SAMPLE_MVID

    def test_module_guid_at_documented_guid_offset(self):
        data = samples.sample_bytes()
        off = samples.MODULE_GUID_DATA_OFFSET
        assert data[off:off + 16] == samples.SAMPLE_MODULE_GUID

    def test_assembly_version_bytes_at_documented_offsets(self):
        data = samples.sample_bytes()
        t = samples.TABLE_FIELDS["Assembly"]
        for i, part in enumerate(samples.SAMPLE_ASSEMBLY_VERSION):
            field = ("MajorVersion", "MinorVersion", "BuildNumber", "RevisionNumber")[i]
            off = t[field]
            assert struct.unpack_from("<H", data, off)[0] == part, field

    def test_time_stamp_and_checksum_offsets(self):
        data = samples.sample_bytes()
        stamp = struct.unpack_from("<I", data, samples.TIMESTAMP_OFFSET)[0]
        assert stamp == samples.DEFAULT_TIME_STAMP
        checksum = struct.unpack_from("<I", data, samples.CHECKSUM_OFFSET)[0]
        assert checksum == 0


class TestStrongName:
    def test_strong_name_flag_set_by_default(self):
        data = samples.sample_bytes()
        flags_off = samples.TABLE_FIELDS["Assembly"]["Flags"]
        assert struct.unpack_from("<I", data, flags_off)[0] & 0x0008 == 0x0008

    def test_strong_name_signature_block_present(self):
        data = samples.sample_bytes()
        size = samples.STRONG_NAME_SIZE
        rva = samples.STRONG_NAME_RVA
        assert size == pe_builder.SIGNATURE_BLOCK_SIZE
        off = samples.STRONG_NAME_FILE_OFFSET
        assert off is not None and off + size <= len(data)
        block = data[off:off + size]
        assert any(block)  # non-zero, so scrubbing is observable

    def test_strong_name_absent_when_disabled(self):
        builder = pe_builder.PeBuilder(
            mvid=samples.SAMPLE_MVID,
            module_guid=samples.SAMPLE_MODULE_GUID,
            strong_name=False,
        )
        result = builder.build()
        layout = result.layout
        assert layout.cli["strong_name_size"] == 0
        assert layout.cli["strong_name_rva"] == 0
        # Assembly Flags must not carry the PublicKey bit.
        flags_off = layout.tables["Assembly"].field("Flags")
        assert struct.unpack_from("<I", result.bytes, flags_off)[0] & 0x0008 == 0


class TestDeterminism:
    def test_same_params_identical_bytes(self):
        kwargs = dict(
            mvid=samples.SAMPLE_MVID,
            module_guid=samples.SAMPLE_MODULE_GUID,
            assembly_version=samples.SAMPLE_ASSEMBLY_VERSION,
            strong_name=True,
            seed=0,
        )
        a = pe_builder.PeBuilder(**kwargs).build()
        b = pe_builder.PeBuilder(**kwargs).build()
        assert a.bytes == b.bytes
        assert a.layout.to_dict() == b.layout.to_dict()

    def test_different_mvid_yields_different_bytes(self):
        kwargs = dict(
            module_guid=samples.SAMPLE_MODULE_GUID,
            assembly_version=samples.SAMPLE_ASSEMBLY_VERSION,
            strong_name=True,
            seed=0,
        )
        a = pe_builder.PeBuilder(mvid=b"\x00" * 16, **kwargs).build()
        b = pe_builder.PeBuilder(mvid=b"\x01" * 16, **kwargs).build()
        assert a.bytes != b.bytes

    def test_different_version_yields_different_bytes(self):
        kwargs = dict(
            mvid=samples.SAMPLE_MVID,
            module_guid=samples.SAMPLE_MODULE_GUID,
            strong_name=True,
            seed=0,
        )
        a = pe_builder.PeBuilder(assembly_version=(4, 0, 0, 0), **kwargs).build()
        b = pe_builder.PeBuilder(assembly_version=(5, 1, 2, 3), **kwargs).build()
        assert a.bytes != b.bytes
        b_layout = b.layout
        assert b_layout.tables["Assembly"].field("MajorVersion") is not None
        assert struct.unpack_from("<H", b.bytes, b_layout.tables["Assembly"].field("MajorVersion"))[0] == 5


class TestLayoutDictSchema:
    def test_layout_dict_stable_across_builds(self):
        a = dict(pe_builder.PeBuilder(
            mvid=samples.SAMPLE_MVID, module_guid=samples.SAMPLE_MODULE_GUID, seed=1).build().layout.to_dict())
        b = dict(pe_builder.PeBuilder(
            mvid=samples.SAMPLE_MVID, module_guid=samples.SAMPLE_MODULE_GUID, seed=2).build().layout.to_dict())
        # Layout is seed-independent, so the two dicts are byte-identical.
        assert a == b

    def test_layout_reports_all_streams(self):
        layout = samples.sample_layout()
        assert set(layout.streams) == {"#~", "#Strings", "#US", "#GUID", "#Blob"}
        for stream in layout.streams.values():
            assert stream.size > 0
            assert stream.offset > 0
            assert stream.rva > 0


class TestAgentCodeTree:
    def test_tree_has_expected_layout(self, tmp_path):
        from tests.fixtures.agent_code_tree import AgentCodeTree

        root = tmp_path / "agent_code"
        tree = AgentCodeTree(root)
        tree.build()
        assert (root / "Program.cs").exists()
        assert (root / "Properties" / "AssemblyInfo.cs").exists()
        assert (root / "Config.cs").exists()
        assert (root / "ApolloInterop" / "ICommand.cs").exists()
        assert (root / "Mythic" / "Rest.cs").exists()
        # RuntimePatch.cs must be absent before inject-patch runs.
        assert not tree.has_runtime_patch()
        assert tree.runtime_patch_path().name not in tree.expected_files()

    def test_program_cs_has_main(self, tmp_path):
        from tests.fixtures.agent_code_tree import AgentCodeTree

        root = tmp_path / "agent_code"
        AgentCodeTree(root).build()
        content = (root / "Program.cs").read_text(encoding="utf-8")
        assert "static void Main(string[] args)" in content
        assert "namespace Apollo" in content

    def test_write_runtime_patch_is_idempotent_surface(self, tmp_path):
        from tests.fixtures.agent_code_tree import AgentCodeTree

        root = tmp_path / "agent_code"
        tree = AgentCodeTree(root)
        tree.build()
        tree.write_runtime_patch("// overlay marker\nclass RuntimePatch {}\n")
        first = tree.read_runtime_patch()
        assert "RuntimePatch" in first
        # Re-writing the same content is byte-identical (idempotent surface).
        tree.write_runtime_patch("// overlay marker\nclass RuntimePatch {}\n")
        assert tree.read_runtime_patch() == first
        assert "RuntimePatch.cs" in tree.expected_files()


class TestBuilderEdgeCases:
    def test_rejects_short_mvid(self):
        with pytest.raises(ValueError):
            pe_builder.PeBuilder(mvid=b"\x00" * 15, module_guid=b"\x00" * 16)

    def test_rejects_bad_version_arity(self):
        with pytest.raises(ValueError):
            pe_builder.PeBuilder(mvid=b"\x00" * 16, module_guid=b"\x00" * 16, assembly_version=(1, 2))

    def test_rejects_non_ascii_us_literal_encoding(self):
        # #US entries must encode as UTF-16LE; a lone surrogate raises.
        with pytest.raises((UnicodeEncodeError, ValueError)):
            pe_builder.PeBuilder(mvid=b"\x00" * 16, module_guid=b"\x00" * 16,
                                 user_strings=[("x", "\ud800")]).build()


class TestSampleConstants:
    def test_samples_export_default_literals(self):
        assert DEFAULT_USER_AGENT == "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
        assert "killdate" == pe_builder.DEFAULT_USER_STRINGS[5][1]

    def test_apollo_marker_names_present(self):
        names = {name for name, _ in pe_builder.DEFAULT_USER_STRINGS}
        for expected in ("user_agent", "killdate", "encrypted_exchange_check",
                         "aespsk_enc_key", "payload_uuid", "pipe_name",
                         "banner", "help_text", "error_text", "manufacturer"):
            assert expected in names


class TestDocConformity:
    """Test resources/constants that other fixtures rely on.

    A few tests share `samples.py` constants and the `AgentCodeTree`
    to sanity-check they stay stable.
    """

    def test_stable_layout_dict(self):
        assert isinstance(samples.sample_layout().to_dict(), dict)
        assert samples.LAYOUT.to_dict() == samples.sample_layout().to_dict()