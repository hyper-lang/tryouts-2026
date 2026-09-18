"""host.py tests (task 22, R5/AC6): toolchain discovery and mode B native host build.

This box has no cargo/gcc on PATH and the VS2019 ``cl.exe`` is not on PATH
either (it needs vcvars), so ``discover_toolchain`` returns ``None`` here and
the compile pipeline is exercised through a monkeypatched fake compiler.

Covers:

1. ``discover_toolchain`` returns ``None`` on this box and records the first
   usable probe when a fake compiler is present.
2. ``build_native_host`` with a fake toolchain produces a single self-contained
   exe whose embedded (hardened) payload still parses as a .NET image, and
   returns the ``hardening['host']``-shaped provenance dict.
3. ``--no-patch`` (``patch_enabled=False``) renders the canary baseline: the
   ``RUNTIME_PATCH_ENABLED`` compile-time gate is 0.
4. A missing .NET shim returns ``shim_unavailable`` (skipped, exit 0) with the
   toolchain recorded; a missing native toolchain or native-compile failure
   raises ``ToolchainError`` (exit 2, never silent).
5. ``apply_passes`` matches ``run_harden`` output byte-for-byte and is
   deterministic -- the shared in-memory pipeline host.py reuses (R5).
"""

from __future__ import annotations

import pytest

from obfuscate import host as host_mod
from obfuscate.harden import apply_passes, run_harden
from obfuscate.host import (
    _HOST_TOKENS,
    _byte_list,
    _render_shim,
    ToolchainError,
    build_native_host,
    discover_toolchain,
)
from obfuscate.pe import analyze
from obfuscate.synth import sample_bytes

SEED = 42

FAKE_GCC = {"name": "gcc", "version": "gcc (GCC) 12.2.0", "kind": "gcc"}
FAKE_SHIM = b"\x4D\x5A\x90\x00" + bytes(range(8))


def _fake_compile(captured):
    """A fake compile_host: record the rendered source, write a parseable
    .NET image to the output path."""

    def compile_host(host_source, output_path, toolchain):
        captured.append(host_source)
        with open(output_path, "wb") as fh:
            fh.write(sample_bytes())

    return compile_host


def _install_fake_toolchain(monkeypatch, compile_host=None, shim=FAKE_SHIM):
    monkeypatch.setattr(host_mod, "discover_toolchain", lambda: dict(FAKE_GCC))
    monkeypatch.setattr(host_mod, "build_shim", lambda apollo_bytes: shim)
    if compile_host is not None:
        monkeypatch.setattr(host_mod, "compile_host", compile_host)


def _harden(sample, seed=SEED):
    """Hardened payload exactly as build_native_host computes it."""
    return host_mod._harden_payload(sample, seed, False, False, False, "zero")


class TestToolchainDiscovery:
    def test_discover_toolchain_none_on_this_box(self):
        # No cargo/gcc/cc on PATH; VS2019 cl.exe is not on PATH (needs vcvars)
        # so the simple probe treats it as absent (R5).
        assert discover_toolchain() is None

    def test_discover_with_fake_compiler(self, monkeypatch):
        monkeypatch.setattr(
            host_mod.shutil,
            "which",
            lambda name, *a, **k: f"C:\\fake\\{name}.exe",
        )
        monkeypatch.setattr(host_mod, "_probe_version", lambda *a, **k: "fake 1.0")
        found = discover_toolchain()
        assert found is not None
        assert found["name"] == "cargo"
        assert found["kind"] == "rust"
        assert found["version"] == "fake 1.0"

    def test_probe_version_absent_binary_returns_none(self, monkeypatch):
        monkeypatch.setattr(host_mod.shutil, "which", lambda name, *a, **k: None)
        assert discover_toolchain() is None


class TestRenderShim:
    def test_shim_embeds_hardened_payload_bytes(self):
        hardened, _ = _harden(sample_bytes())
        source = _render_shim(hardened)
        assert "__APOLLO_BYTES__" not in source
        assert _byte_list(hardened) in source

    def test_embedded_payload_still_parses_as_dotnet(self, tmp_path):
        hardened, _ = _harden(sample_bytes())
        probe = tmp_path / "payload.exe"
        probe.write_bytes(hardened)
        info = analyze(str(probe))
        assert info["metadata"]["mvid"] is not None
        assert info["metadata"]["streams"]["#US"]["size"] > 0


class TestRenderHost:
    def test_all_tokens_substituted_and_gate_visible(self):
        hardened, _ = _harden(sample_bytes())
        shim = _render_shim(hardened)
        source = host_mod._render_host(True, SEED, b"\x00\x01\x02")
        for token in _HOST_TOKENS:
            assert token not in source, f"{token} left un-interpolated"
        assert "#define RUNTIME_PATCH_ENABLED 1" in source

    def test_deterministic_and_seed_varied(self):
        a1 = host_mod._render_host(True, SEED, FAKE_SHIM)
        a2 = host_mod._render_host(True, SEED, FAKE_SHIM)
        b = host_mod._render_host(True, SEED + 1, FAKE_SHIM)
        assert a1 == a2
        assert a1 != b

    def test_no_patch_renders_gate_zero(self):
        source = host_mod._render_host(False, SEED, FAKE_SHIM)
        assert "#define RUNTIME_PATCH_ENABLED 0" in source

    def test_patch_variants_are_seed_derived(self):
        from obfuscate.patch import variant

        for target, arch in (("amsi", "x86"), ("amsi", "x64"), ("etw", "x86"), ("etw", "x64")):
            token = f"__PATCH_{target.upper()}_{arch.upper()}__"
            source = host_mod._render_host(True, SEED, FAKE_SHIM)
            assert _byte_list(variant(SEED, arch, target)) in source


class TestBuildNativeHost:
    def test_fake_toolchain_builds_parseable_output(self, tmp_path, monkeypatch):
        captured = []
        _install_fake_toolchain(monkeypatch, compile_host=_fake_compile(captured))
        out = tmp_path / "patched_apollo.exe"
        prov = build_native_host(sample_bytes(), SEED, out, apollo_src="fake/agent_code")

        assert out.exists()
        info = analyze(str(out))
        assert info["metadata"]["mvid"] is not None

        assert prov["status"] == "ok"
        assert prov["toolchain"] == FAKE_GCC
        assert prov["shim"] == "compiled"
        assert prov["patch_enabled"] is True
        assert prov["seed"] == SEED
        assert prov["shim_size"] == len(FAKE_SHIM)
        assert prov["embed"]["marker"] == "host.c:SHIM_BYTES"
        assert prov["apollo_src"] == "fake/agent_code"
        assert len(captured) == 1
        # the compiled shim bytes flowed into the rendered host source
        assert _byte_list(FAKE_SHIM) in captured[0]

    def test_no_patch_is_canary_baseline_gate0(self, tmp_path, monkeypatch):
        captured = []
        _install_fake_toolchain(monkeypatch, compile_host=_fake_compile(captured))
        out = tmp_path / "baseline.exe"
        prov = build_native_host(sample_bytes(), SEED, out, patch_enabled=False)
        assert prov["patch_enabled"] is False
        assert "#define RUNTIME_PATCH_ENABLED 0" in captured[0]

        patched = _fake_compile(captured)
        monkeypatch.setattr(host_mod, "compile_host", patched)
        out2 = tmp_path / "patched.exe"
        prov2 = build_native_host(sample_bytes(), SEED, out2, patch_enabled=True)
        assert prov2["patch_enabled"] is True
        assert "#define RUNTIME_PATCH_ENABLED 1" in captured[1]

    def test_missing_shim_returns_shim_unavailable(self, tmp_path, monkeypatch):
        _install_fake_toolchain(monkeypatch, shim=None)
        out = tmp_path / "x.exe"
        prov = build_native_host(sample_bytes(), SEED, out)
        assert prov["status"] == "shim_unavailable"
        assert prov["shim"] == "unavailable"
        assert prov["toolchain"] == FAKE_GCC
        assert not out.exists()

    def test_no_toolchain_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr(host_mod, "discover_toolchain", lambda: None)
        out = tmp_path / "x.exe"
        with pytest.raises(ToolchainError):
            build_native_host(sample_bytes(), SEED, out)
        assert not out.exists()

    def test_native_compile_failure_raises(self, tmp_path, monkeypatch):
        def boom(host_source, output_path, toolchain):
            raise ToolchainError("native compile failed: syntax error")

        _install_fake_toolchain(monkeypatch, compile_host=boom)
        out = tmp_path / "x.exe"
        with pytest.raises(ToolchainError, match="native compile failed"):
            build_native_host(sample_bytes(), SEED, out)

    def test_seed_none_defaults(self, tmp_path, monkeypatch):
        captured = []
        _install_fake_toolchain(monkeypatch, compile_host=_fake_compile(captured))
        out = tmp_path / "n.exe"
        prov = build_native_host(sample_bytes(), None, out)
        assert prov["seed"] == 0

    def test_invalid_checksum_raises(self, tmp_path, monkeypatch):
        _install_fake_toolchain(monkeypatch)
        with pytest.raises(ValueError):
            build_native_host(sample_bytes(), SEED, tmp_path / "x.exe", checksum="bogus")


class TestApplyPassesShared:
    def _pe_info(self, tmp_path):
        inp = tmp_path / "sample.exe"
        inp.write_bytes(sample_bytes())
        pe_info = analyze(str(inp))
        pe_info["path"] = str(inp)
        pe_info["data"] = sample_bytes()
        return str(inp), pe_info

    def test_apply_passes_matches_run_harden_output(self, tmp_path):
        inp, pe_info = self._pe_info(tmp_path)
        out = tmp_path / "out.exe"
        run_harden(inp, out, SEED)
        expected = out.read_bytes()

        got1, findings1 = apply_passes(sample_bytes(), pe_info, SEED)
        got2, findings2 = apply_passes(sample_bytes(), pe_info, SEED)
        assert got1 == expected
        assert got1 == got2
        assert findings1 == findings2
        assert len(findings1) > 0

    def test_apply_passes_respects_no_flags(self, tmp_path):
        inp, pe_info = self._pe_info(tmp_path)
        got, findings = apply_passes(
            sample_bytes(),
            pe_info,
            SEED,
            no_metadata=True,
            no_attributes=True,
            no_strings=True,
        )
        assert got == sample_bytes()
        assert [f[0] for f in findings] == ["checksum"]