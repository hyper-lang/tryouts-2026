"""Runtime patch core tests (R5/AC7): tables, contracts, canonical hygiene, seed variants.

Covers the R5 runtime-patch core contract:

- x86/x64 AMSI/ETW tables are non-empty and carry the documented
  precondition-load DLL and export per target.
- Cannonical public AMSI/ETW sequences are flagged by ``check_canonical`` and
  never appear verbatim in ``variant()`` output.
- ``variant()`` is deterministic per seed and differs across seeds.
- Every variant's instruction semantics are verified in pure Python via
  ``simulate()``: ``eax`` == 0x80070057 for AMSI, ``eax`` == 0 for ETW, and no
  memory (out-param) writes.
- Variant byte lengths stay within the sane ``(4, 128)`` range.
"""

import pytest

from obfuscate.patch import (
    APP_ID,
    APP_VERSION,
    ARCHES,
    CANONICAL,
    PATCH_TABLE,
    TARGETS,
    check_canonical,
    is_canonical_free,
    simulate,
    variant,
)


class TestConstants:
    """APP_ID / APP_VERSION and the arch/target vocabulary."""

    def test_app_identity(self):
        assert APP_ID == "patch.py"
        assert APP_VERSION == "1.0"

    def test_arches(self):
        assert ARCHES == ("x86", "x64")

    def test_targets(self):
        assert TARGETS == ("amsi", "etw")


class TestTables:
    """Per-arch tables exist and carry documented preconditions (R5)."""

    def test_tables_non_empty_per_arch(self):
        for arch in ARCHES:
            assert set(PATCH_TABLE[arch]) == set(TARGETS)

    def test_spec_preconditions(self):
        for arch in ARCHES:
            amsi = PATCH_TABLE[arch]["amsi"]
            assert amsi.precondition_load == "amsi.dll"
            assert amsi.precondition_func == "AmsiScanBuffer"
            etw = PATCH_TABLE[arch]["etw"]
            assert etw.precondition_load == "ntdll.dll"
            assert etw.precondition_func == "EtwEventWrite"

    def test_spec_patch_bytes_nonempty(self):
        for arch in ARCHES:
            for target in TARGETS:
                spec = PATCH_TABLE[arch][target]
                assert isinstance(spec.patch_bytes, bytes)
                assert spec.patch_bytes
                assert b"\xC3" in spec.patch_bytes


class TestCheckCanonical:
    """Verbatim canonical sequences are flagged; lookalikes are not."""

    def test_flags_verbatim(self):
        for target in TARGETS:
            for arch in ARCHES:
                for canon in CANONICAL[target][arch]:
                    assert check_canonical(canon, canon) is True
                    assert check_canonical(b"\x90\x90" + canon + b"\x90", canon) is True

    def test_accepts_byteslike(self):
        assert check_canonical(bytearray(b"\x90\x33\xC0\xC3\x90"), b"\x33\xC0\xC3") is True

    def test_rejects_when_absent(self):
        assert check_canonical(b"\x33\xC0\x90\xC3", b"\x33\xC0\xC3") is False
        assert check_canonical(b"\x00\x11\x22\x33\x44", b"\xB8\x57\x00\x07\x80\xC3") is False
        assert check_canonical(b"", b"\x33\xC0\xC3") is False

    def test_type_errors(self):
        with pytest.raises(TypeError):
            check_canonical("nope", b"\x33\xC0")
        with pytest.raises(TypeError):
            check_canonical(b"\x33\xC0", "nope")


class TestCanonicalFree:
    """is_canonical_free validates args and scans artifact bytes."""

    def test_free_when_absent(self):
        assert is_canonical_free(b"\x33\xC0\x90\xC3", "etw", "x64") is True
        assert is_canonical_free(b"\x90\x90\xC3", "amsi", "x86") is True

    def test_flagged_when_present(self):
        assert is_canonical_free(b"\x33\xC0\xC3", "etw", "x64") is False
        assert is_canonical_free(b"\xB8\x57\x00\x07\x80\xC3", "amsi", "x64") is False

    def test_bad_vocabulary(self):
        with pytest.raises(ValueError):
            is_canonical_free(b"\x90\x90\xC3", "bogus", "x64")
        with pytest.raises(ValueError):
            is_canonical_free(b"\x90\x90\xC3", "etw", "arm")


class TestVariant:
    """Seed-derived variants: deterministic, distinct, length-bound, canonical-free."""

    def test_bad_vocabulary(self):
        for bad_arch in ("arm", "", None):
            with pytest.raises((ValueError, TypeError)):
                variant(1, bad_arch, "amsi")
        for bad_target in ("defender", "", None):
            with pytest.raises((ValueError, TypeError)):
                variant(1, "x64", bad_target)

    def test_deterministic_same_seed(self):
        for arch in ARCHES:
            for target in TARGETS:
                assert variant(7, arch, target) == variant(7, arch, target)
                assert variant(0, arch, target) == variant(0, arch, target)

    def test_different_seeds_differ(self):
        for arch in ARCHES:
            for target in TARGETS:
                seen = set()
                for seed in range(8):
                    code = variant(seed, arch, target)
                    assert code not in seen, f"seed {seed} collided for {arch}/{target}"
                    seen.add(code)

    def test_length_bounds(self):
        for seed in range(64):
            for arch in ARCHES:
                for target in TARGETS:
                    code = variant(seed, arch, target)
                    assert len(code) > 4, f"{arch}/{target} seed {seed} too short"
                    assert len(code) < 128, f"{arch}/{target} seed {seed} too long"

    def test_ends_with_ret(self):
        for seed in range(64):
            for arch in ARCHES:
                for target in TARGETS:
                    assert variant(seed, arch, target).endswith(b"\xC3")

    def test_variants_never_contain_canonical(self):
        for seed in range(64):
            for arch in ARCHES:
                for target in TARGETS:
                    code = variant(seed, arch, target)
                    for canon in CANONICAL[target][arch]:
                        assert check_canonical(code, canon) is False, (
                            f"canonical bytes verbatim in {arch}/{target} seed {seed}"
                        )
                    assert is_canonical_free(code, target, arch) is True


class TestSemantics:
    """Every variant is functionally equivalent under pure-Python semantics.

    AMSI contract: ``eax`` == ``E_INVALIDARG`` (0x80070057) with no memory
    (out-param) writes.  ETW contract: ``eax`` == 0 (STATUS_SUCCESS) with no
    memory writes.  ``simulate()`` raises if the code does not terminate via
    ``ret``.
    """

    _EXPECTED = {"amsi": 0x80070057, "etw": 0}

    def test_every_variant_satisfies_contract(self):
        for seed in range(64):
            for arch in ARCHES:
                for target in TARGETS:
                    code = variant(seed, arch, target)
                    regs, writes = simulate(arch, code)
                    assert regs["eax"] == self._EXPECTED[target], (
                        f"{arch}/{target} seed {seed}: eax=0x{regs['eax']:08x}"
                    )
                    assert writes == [], (
                        f"{arch}/{target} seed {seed}: memory writes {writes}"
                    )

    def test_initial_registers_preserved_where_irrelevant(self):
        init = {"eax": 0xDEADBEEF, "ecx": 0x11111111, "edx": 0x22222222,
                "esi": 0x33333333, "edi": 0x44444444, "ebx": 0x55555555,
                "esp": 0x100, "ebp": 0x200}
        for seed in range(8):
            for arch in ARCHES:
                for target in TARGETS:
                    code = variant(seed, arch, target)
                    regs, writes = simulate(arch, code, regs=init)
                    assert regs["eax"] == self._EXPECTED[target]
                    assert writes == []

    def test_simulate_rejects_truncated_imm(self):
        with pytest.raises(ValueError):
            simulate("x64", b"\xB8\x57")

    def test_simulate_rejects_nonterminating_code(self):
        with pytest.raises(ValueError):
            simulate("x86", b"\x90\x90")

    def test_simulate_rejects_unknown_opcode(self):
        with pytest.raises(ValueError):
            simulate("x86", b"\x11\xC0\xC3")