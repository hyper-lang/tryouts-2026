"""harden.py tests (task harden): the run_harden orchestrator (R3/R6a).

Covers:

1. Output is a valid PE parseable by dnfile (round-trip through the project
   analyze() wrapper).
2. Determinism: same seed produces byte-identical output and identical
   report JSON; a different seed produces a different MVID.
3. Section/stream layout preserved: offsets, sizes, and file length are
   unchanged after the passes.
4. Each pass individually disabled via its --no-* flag (metadata, attributes,
   strings) and enabled by default.
5. Config-critical strings untouched by default and scrubbed only with
   --force --break-runtime.
6. --checksum zero (default) vs recompute writes a valid PE image checksum.
7. Report hardening section shape (fixed keys, findings list, pass summary).
"""

from __future__ import annotations

import struct

import pytest

dnfile = pytest.importorskip("dnfile")

from obfuscate.harden import _checksum_offset, _compute_image_checksum, run_harden  # noqa: E402
from obfuscate.pe import analyze  # noqa: E402
from tests.fixtures import samples  # noqa: E402
from tests.fixtures.samples import (  # noqa: E402
    DEFAULT_CALLBACK_URL,
    DEFAULT_COMPANY,
    DEFAULT_USER_AGENT,
    SAMPLE_MVID,
)

SEED = 42

_HARDENING_KEYS = {
    "break_runtime",
    "checksum",
    "findings",
    "force",
    "input",
    "output",
    "passes",
    "schema_version",
    "seed",
}


def _input(tmp_path):
    path = tmp_path / "sample.exe"
    path.write_bytes(samples.sample_bytes())
    return str(path)


def _out(tmp_path, name="out.exe"):
    return str(tmp_path / name)


def _run(tmp_path, out_name="out.exe", **kwargs):
    """Run run_harden on a fresh sample; default seed applied unless provided."""
    kwargs.setdefault("seed", SEED)
    input_path = _input(tmp_path)
    output_path = _out(tmp_path, out_name)
    report = run_harden(input_path, output_path, **kwargs)
    return report, input_path, output_path


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def _slice(path, offset, length):
    return _read(path)[offset:offset + length]


# ---------------------------------------------------------------------------
# Valid output / parseability
# ---------------------------------------------------------------------------


class TestValidOutput:
    def test_output_parseable_by_dnfile(self, tmp_path):
        _, _, out = _run(tmp_path)
        pe = dnfile.dnPE(out)
        try:
            assert pe.net is not None
        finally:
            pe.close()
        res = analyze(out)
        assert res["metadata"]["streams"]["#US"]["size"] > 0
        assert res["metadata"]["mvid"] is not None
        assert res["pe"]["text"] is not None

    def test_output_differs_from_input_when_passes_run(self, tmp_path):
        _, inp, out = _run(tmp_path)
        assert _read(out) != _read(inp)

    def test_accepts_pathlib_paths(self, tmp_path):
        import pathlib

        inp = pathlib.Path(_input(tmp_path))
        out = tmp_path / "pathlib_out.exe"
        report = run_harden(inp, out, seed=SEED)
        assert report.to_dict()["command"] == "harden"
        assert out.exists()

    def test_invalid_checksum_mode_raises(self, tmp_path):
        inp = _input(tmp_path)
        with pytest.raises(ValueError):
            run_harden(inp, _out(tmp_path), seed=SEED, checksum="bogus")


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_seed_byte_identical(self, tmp_path):
        _, _, out1 = _run(tmp_path, out_name="a.exe")
        _, _, out2 = _run(tmp_path, out_name="b.exe")
        assert _read(out1) == _read(out2)

    def test_same_seed_report_identical(self, tmp_path):
        report1, _, _ = _run(tmp_path)
        report2, _, _ = _run(tmp_path)
        assert report1.json() == report2.json()

    def test_different_seed_different_mvid(self, tmp_path):
        _, _, out1 = _run(tmp_path, out_name="a.exe", seed=1)
        _, _, out2 = _run(tmp_path, out_name="b.exe", seed=2)
        mvid1 = analyze(out1)["metadata"]["mvid"]
        mvid2 = analyze(out2)["metadata"]["mvid"]
        assert mvid1 != mvid2
        assert mvid1 != SAMPLE_MVID.hex()
        assert mvid2 != SAMPLE_MVID.hex()

    def test_none_seed_defaults_deterministically(self, tmp_path):
        report1, _, out1 = _run(tmp_path, out_name="a.exe", seed=None)
        report2, _, out2 = _run(tmp_path, out_name="b.exe", seed=None)
        assert _read(out1) == _read(out2)
        assert report1.to_dict()["findings"]["hardening"]["seed"] == 0


# ---------------------------------------------------------------------------
# Layout preservation
# ---------------------------------------------------------------------------


class TestLayoutPreserved:
    def test_streams_sections_and_size_unchanged(self, tmp_path):
        _, inp, out = _run(tmp_path)
        before = analyze(inp)
        after = analyze(out)
        for name in ("#~", "#Strings", "#US", "#GUID", "#Blob"):
            key = name.replace("#", "")
            assert after["metadata"]["streams"][name]["offset"] == before["metadata"]["streams"][name]["offset"], f"{key} offset changed"
            assert after["metadata"]["streams"][name]["size"] == before["metadata"]["streams"][name]["size"], f"{key} size changed"
        assert after["pe"]["sections"] == before["pe"]["sections"], "section layout changed"
        assert len(_read(out)) == len(_read(inp)), "file size changed"


# ---------------------------------------------------------------------------
# Per-pass disable flags
# ---------------------------------------------------------------------------


class TestPassDisable:
    def test_no_metadata_keeps_mvid(self, tmp_path):
        _, inp, out = _run(tmp_path, no_metadata=True)
        assert analyze(out)["metadata"]["mvid"] == samples.SAMPLE_MVID.hex()

    def test_metadata_default_rerandomizes_mvid(self, tmp_path):
        _, inp, out = _run(tmp_path)
        assert analyze(out)["metadata"]["mvid"] != samples.SAMPLE_MVID.hex()

    def test_no_attributes_keeps_company_text(self, tmp_path):
        _, inp, out = _run(tmp_path, no_attributes=True)
        raw = DEFAULT_COMPANY.encode("utf-8")
        assert _slice(out, samples.COMPANY_TEXT_OFFSET, len(raw)) == raw

    def test_attributes_default_scrubs_company_text(self, tmp_path):
        _, inp, out = _run(tmp_path)
        raw = DEFAULT_COMPANY.encode("utf-8")
        assert _slice(out, samples.COMPANY_TEXT_OFFSET, len(raw)) != raw

    def test_no_strings_keeps_user_agent(self, tmp_path):
        _, inp, out = _run(tmp_path, no_strings=True)
        raw = DEFAULT_USER_AGENT.encode("utf-16le")
        assert _slice(out, samples.USER_AGENT_OFFSET, len(raw)) == raw

    def test_strings_default_scrubs_user_agent(self, tmp_path):
        _, inp, out = _run(tmp_path)
        raw = DEFAULT_USER_AGENT.encode("utf-16le")
        assert _slice(out, samples.USER_AGENT_OFFSET, len(raw)) != raw

    def test_all_disabled_output_equals_input(self, tmp_path):
        _, inp, out = _run(tmp_path, no_metadata=True, no_attributes=True, no_strings=True)
        assert _read(out) == _read(inp)


# ---------------------------------------------------------------------------
# Config-critical strings (R3/R4)
# ---------------------------------------------------------------------------


class TestConfigCriticalStrings:
    URL = DEFAULT_CALLBACK_URL.encode("utf-16le")

    def test_default_untouched(self, tmp_path):
        _, inp, out = _run(tmp_path)
        assert _slice(out, samples.CALLBACK_URL_OFFSET, len(self.URL)) == self.URL

    def test_force_break_runtime_scrubs(self, tmp_path):
        _, inp, out = _run(tmp_path, force=True, break_runtime=True)
        assert _slice(out, samples.CALLBACK_URL_OFFSET, len(self.URL)) != self.URL

    def test_force_alone_does_not_scrub(self, tmp_path):
        _, inp, out = _run(tmp_path, force=True)
        assert _slice(out, samples.CALLBACK_URL_OFFSET, len(self.URL)) == self.URL

    def test_break_runtime_alone_scrubs(self, tmp_path):
        _, inp, out = _run(tmp_path, break_runtime=True)
        assert _slice(out, samples.CALLBACK_URL_OFFSET, len(self.URL)) != self.URL


# ---------------------------------------------------------------------------
# Checksum handling (R3 --checksum)
# ---------------------------------------------------------------------------


class TestChecksum:
    def test_default_zeroes_checksum(self, tmp_path):
        _, inp, out = _run(tmp_path)
        data = _read(out)
        off = _checksum_offset(data)
        assert struct.unpack_from("<I", data, off)[0] == 0

    def test_recompute_writes_valid_checksum(self, tmp_path):
        _, inp, out = _run(tmp_path, checksum="recompute")
        data = _read(out)
        off = _checksum_offset(data)
        stored = struct.unpack_from("<I", data, off)[0]
        tmp = bytearray(data)
        tmp[off:off + 4] = b"\x00\x00\x00\x00"
        assert stored == _compute_image_checksum(bytes(tmp))
        assert stored != 0

    def test_recompute_without_metadata_pass(self, tmp_path):
        _, inp, out = _run(tmp_path, checksum="recompute", no_metadata=True)
        data = _read(out)
        off = _checksum_offset(data)
        stored = struct.unpack_from("<I", data, off)[0]
        tmp = bytearray(data)
        tmp[off:off + 4] = b"\x00\x00\x00\x00"
        assert stored == _compute_image_checksum(bytes(tmp))
        assert stored != 0

    def test_zero_without_metadata_pass(self, tmp_path):
        _, inp, out = _run(tmp_path, no_metadata=True)
        data = _read(out)
        off = _checksum_offset(data)
        assert struct.unpack_from("<I", data, off)[0] == 0


# ---------------------------------------------------------------------------
# Report hardening section
# ---------------------------------------------------------------------------


class TestReportShape:
    def test_hardening_section_keys_and_summary(self, tmp_path):
        report, _, _ = _run(tmp_path)
        h = report.to_dict()["findings"]["hardening"]
        assert set(h) == _HARDENING_KEYS
        assert h["passes"] == ["metadata", "attributes", "strings"]
        assert h["checksum"] == "zero"
        assert h["seed"] == SEED
        assert h["force"] is False
        assert h["break_runtime"] is False
        assert len(h["findings"]) > 0
        assert set(h["findings"][0]) == {"catalog_id", "offset", "description"}

    def test_pass_disable_flags_reflected(self, tmp_path):
        report, _, _ = _run(tmp_path, no_metadata=True, no_attributes=True, no_strings=True)
        h = report.to_dict()["findings"]["hardening"]
        assert h["passes"] == []
        assert len(h["findings"]) == 1
        assert h["findings"][0]["catalog_id"] == "checksum"

    def test_break_runtime_flag_reflected(self, tmp_path):
        report, _, _ = _run(tmp_path, break_runtime=True)
        h = report.to_dict()["findings"]["hardening"]
        assert h["break_runtime"] is True

    def test_authorization_note_present(self, tmp_path):
        report, _, _ = _run(tmp_path)
        doc = report.to_dict()
        assert doc["authorization_note"]
        assert doc["command"] == "harden"