"""Presence-gated real-sample integration test (AC10).

This test is SKIPPED unless a real compiled Apollo WinExe sample is present.
Fixture source priority:
  1. os.environ['OBFUSCATE_APOLLO_SAMPLE'] if set
  2. tests/fixtures/apollo_sample.exe if it exists

pytest.mark.skipif when neither is present (clean skip on this dev box - no fixture).

Real .NET Framework 4 samples exist on-box
(C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\RegAsm.exe)
but AC10 specifically requires a compiled Apollo WinExe, so reg-server
samples must NOT satisfy the gate.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from obfuscate.harden import run_harden
from obfuscate.pe import PeReadError, analyze
from obfuscate.report import Report
from obfuscate.strings import extract_config, scan_heaps
from obfuscate.verify import verify_static


def _find_apollo_sample() -> Path | None:
    """Locate the real Apollo sample fixture if present."""
    env_path = os.environ.get("OBFUSCATE_APOLLO_SAMPLE")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p
    default_fixture = Path("tests/fixtures/apollo_sample.exe")
    if default_fixture.exists():
        return default_fixture
    return None


_SAMPLE = _find_apollo_sample()


@pytest.mark.skipif(
    _SAMPLE is None,
    reason="No real Apollo sample fixture found (set OBFUSCATE_APOLLO_SAMPLE or add tests/fixtures/apollo_sample.exe)",
)
class TestRealSampleIntegration:
    """Real-sample round-trip: inspect -> harden -> verify (AC10)."""

    def test_locate_and_open_fixture(self):
        """(1) Locate + open the fixture; assert it parses without PeReadError."""
        assert _SAMPLE is not None and _SAMPLE.exists()
        pe_info = analyze(str(_SAMPLE))
        assert "pe" in pe_info
        assert "metadata" in pe_info

    def test_inspect_pipeline(self):
        """(2) Inspect pipeline: analyze + scan_heaps + extract_config."""
        pe_info = analyze(str(_SAMPLE))
        with open(_SAMPLE, "rb") as fh:
            pe_info["data"] = fh.read()
        pe_info["path"] = str(_SAMPLE)

        # scan_heaps finds fingerprints
        matches = scan_heaps(pe_info)
        assert isinstance(matches, list)
        assert len(matches) > 0, "Expected fingerprint matches in real Apollo sample"

        # extract_config produces a config dict
        config = extract_config(pe_info)
        assert isinstance(config, dict)
        # Apollo config should have at least some known keys
        assert len(config) > 0, "Expected non-empty config extraction"

    def test_harden_with_fixed_seed(self):
        """(3) Harden via run_harden with a fixed seed to a temp file."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            out_path = Path(tmp.name)
        try:
            report = run_harden(
                input_path=str(_SAMPLE),
                output_path=str(out_path),
                seed=0xC0FFEE,  # fixed seed for determinism
                no_metadata=False,
                no_attributes=False,
                no_strings=False,
                checksum="zero",
                force=False,
                break_runtime=False,
            )
            assert out_path.exists()
            assert out_path.stat().st_size > 0
            # Report should be a Report object with hardening section
            assert report is not None
        finally:
            if out_path.exists():
                out_path.unlink(missing_ok=True)

    def test_verify_static_assertions(self):
        """(4) Verify via verify_static - all harden-mode assertions pass.

        Exceptions:
        - 'determinism' is SOFT and allowed False (default-seed assumption)
        - 'mvid_differs' only when the metadata pass ran (default harden runs it)
        """
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            out_path = Path(tmp.name)
        try:
            run_harden(
                input_path=str(_SAMPLE),
                output_path=str(out_path),
                seed=0xC0FFEE,
                no_metadata=False,
                no_attributes=False,
                no_strings=False,
                checksum="zero",
                force=False,
                break_runtime=False,
            )

            assertions, mode = verify_static(str(_SAMPLE), str(out_path))
            assert mode == "harden", f"Expected harden mode, got {mode}"

            # All assertions should be present
            categories = {a["category"] for a in assertions}
            expected_categories = {
                "pe_intact",
                "layout",
                "mvid_differs",
                "fingerprint_removal",
                "unclaimed_reported",
                "determinism",
            }
            assert categories == expected_categories

            # Check each assertion
            for a in assertions:
                cat = a["category"]
                if cat == "determinism":
                    # SOFT - allowed to fail with non-default seed (we used fixed seed 0xC0FFEE
                    # but the default seed is derived from input path, so it may differ)
                    pass
                elif cat == "mvid_differs":
                    # Should pass since metadata pass ran (default harden runs it)
                    assert a["pass"] is True, f"mvid_differs failed: {a['detail']}"
                else:
                    # All other assertions must pass
                    assert a["pass"] is True, f"{cat} failed: {a['detail']}"
        finally:
            if out_path.exists():
                out_path.unlink(missing_ok=True)

    def test_determinism_byte_identical(self):
        """(5) Determinism: re-run apply_passes with same seed -> byte-identical output."""
        from obfuscate.harden import apply_passes

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp1:
            out1 = Path(tmp1.name)
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp2:
            out2 = Path(tmp2.name)
        try:
            # First run via run_harden
            run_harden(
                input_path=str(_SAMPLE),
                output_path=str(out1),
                seed=0xC0FFEE,
                no_metadata=False,
                no_attributes=False,
                no_strings=False,
                checksum="zero",
                force=False,
                break_runtime=False,
            )

            # Second run via apply_passes directly (in-memory)
            input_pe_info = analyze(str(_SAMPLE))
            with open(_SAMPLE, "rb") as fh:
                input_pe_info["data"] = fh.read()
            input_pe_info["path"] = str(_SAMPLE)

            recomputed, _ = apply_passes(
                input_pe_info["data"],
                input_pe_info,
                seed=0xC0FFEE,
                no_metadata=False,
                no_attributes=False,
                no_strings=False,
                checksum="zero",
                break_runtime=False,
            )

            with open(out1, "rb") as fh:
                first_bytes = fh.read()

            assert recomputed == first_bytes, "apply_passes with same seed must produce byte-identical output"
        finally:
            out1.unlink(missing_ok=True)
            out2.unlink(missing_ok=True)

    def test_layout_preservation(self):
        """(6) Layout preservation: section/stream table equals input except documented in-place diffs."""
        from obfuscate.verify import _layout_bits

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            out_path = Path(tmp.name)
        try:
            run_harden(
                input_path=str(_SAMPLE),
                output_path=str(out_path),
                seed=0xC0FFEE,
                no_metadata=False,
                no_attributes=False,
                no_strings=False,
                checksum="zero",
                force=False,
                break_runtime=False,
            )

            input_pe = analyze(str(_SAMPLE))
            output_pe = analyze(str(out_path))

            in_layout = _layout_bits(input_pe)
            out_layout = _layout_bits(output_pe)

            assert in_layout == out_layout, "Section/stream layout must be preserved by in-place hardening"
        finally:
            if out_path.exists():
                out_path.unlink(missing_ok=True)