"""Runtime source artifacts tests (task 20, R5/AC7).

The mode A C# overlay (``patch_module/RuntimePatch.cs``), mode B managed shim
(``shim/ApolloShim.cs``), and mode B native host template (``host/host.c``) are
source-only artifacts consumed by ``inject-patch`` and ``host.py``.  These tests
pin the required markers and the AC7 hygiene invariant.

AC7 hard invariant: **no canonical public AMSI/ETW sequence from
``patch.CANONICAL`` appears verbatim in any runtime source.**  This is enforced
by scanning every file under the three runtime source directories (as raw file
bytes) for every canonical sequence of every arch/target.  The C# byte tables
are also required to be byte-for-byte ``patch.variant(42, arch, target)`` output
and to re-satisfy ``patch.simulate()`` (contract ``eax`` value, zero memory
writes) and ``is_canonical_free``, so a hand-edited table that breaks the
variant semantics fails here.
"""

import re
from pathlib import Path

import pytest

from obfuscate.patch import (
    CANONICAL,
    PATCH_TABLE,
    is_canonical_free,
    simulate,
    variant,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
PATCH_MODULE = REPO_ROOT / "patch_module"
SHIM = REPO_ROOT / "shim"
HOST = REPO_ROOT / "host"

RUNTIME_PATCH_CS = PATCH_MODULE / "RuntimePatch.cs"
APOLLO_SHIM_CS = SHIM / "ApolloShim.cs"
HOST_C = HOST / "host.c"

SOURCE_FILES = [
    RUNTIME_PATCH_CS,
    APOLLO_SHIM_CS,
    HOST_C,
]

# C# byte-table name -> (arch, target) used by variant().
TABLE_ARCH_TARGET = {
    "AMSI_PATCH_X86": ("x86", "amsi"),
    "AMSI_PATCH_X64": ("x64", "amsi"),
    "ETW_PATCH_X86": ("x86", "etw"),
    "ETW_PATCH_X64": ("x64", "etw"),
}


def _parse_csharp_byte_array(text: str, name: str) -> bytes:
    """Extract one `private static readonly byte[] <name> = { ... };` literal."""
    match = re.search(
        r"readonly\s+byte\[\]\s+" + re.escape(name) + r"\s*=\s*\{(.*?)\};",
        text,
        re.DOTALL,
    )
    assert match is not None, f"C# byte table {name} not found"
    body = match.group(1)
    values = [int(hexstr, 16) for hexstr in re.findall(r"0x([0-9A-Fa-f]{2})", body)]
    assert values, f"C# byte table {name} is empty"
    return bytes(values)


class TestSourcePresence:
    """All three dirs and the required files exist (acceptance: 'three dirs exist')."""

    def test_directories_exist(self):
        for d in (PATCH_MODULE, SHIM, HOST):
            assert d.is_dir(), f"missing source dir {d}"

    def test_required_files_exist(self):
        for path in SOURCE_FILES:
            assert path.is_file(), f"missing source file {path}"

    def test_each_dir_has_readme(self):
        for d in (PATCH_MODULE, SHIM, HOST):
            assert (d / "README.md").is_file(), f"missing {d / 'README.md'}"


class TestRuntimePatchCs:
    """R5 Mode A markers: P/Invoke surface, force-load, idempotency, gates."""

    @pytest.fixture(scope="class")
    def text(self):
        return RUNTIME_PATCH_CS.read_text(encoding="utf-8")

    def test_loader_api_present(self, text):
        for marker in ("LoadLibraryA", "GetModuleHandleA", "GetProcAddress", "VirtualProtect"):
            assert marker in text, f"RuntimePatch.cs missing loader API {marker}"

    def test_preconditions_match_patch_table(self, text):
        # Every PATCH_TABLE precondition (force-load DLL + export) is present:
        # amsi.dll/AmsiScanBuffer and ntdll.dll/EtwEventWrite.
        preconditions = set()
        for arch, targets in PATCH_TABLE.items():
            for target, spec in targets.items():
                preconditions.add(spec.precondition_load)
                preconditions.add(spec.precondition_func)
        for pc in sorted(preconditions):
            assert pc in text, f"RuntimePatch.cs missing PATCH_TABLE precondition {pc}"

    def test_const_gate_marker(self, text):
        assert "RUNTIME_PATCH_ENABLED" in text
        assert "// GATE:runtime_patch" in text

    def test_per_target_toggles(self, text):
        assert "// TOGGLE:amsi" in text
        assert "// TOGGLE:etw" in text
        assert "ENABLE_AMSI" in text
        assert "ENABLE_ETW" in text

    def test_toggle_markers_appear_once(self, text):
        # inject-patch rewrites the const line that owns each marker; a marker
        # must appear exactly once so the rewrite target is unambiguous.
        for marker in ("// GATE:runtime_patch", "// TOGGLE:amsi", "// TOGGLE:etw"):
            assert text.count(marker) == 1, f"marker {marker!r} must appear exactly once"

    def test_idempotency_guard(self, text):
        assert "_applied" in text
        assert "BytesMatch" in text

    def test_patched_state_reflected(self, text):
        assert "AmsiPatched" in text
        assert "EtwPatched" in text

    def test_x86_and_x64_tables_present(self, text):
        tables = {name: _parse_csharp_byte_array(text, name) for name in TABLE_ARCH_TARGET}
        assert len(tables["AMSI_PATCH_X86"]) > 0
        assert len(tables["AMSI_PATCH_X64"]) > 0
        assert len(tables["ETW_PATCH_X86"]) > 0
        assert len(tables["ETW_PATCH_X64"]) > 0
        # x86 and x64 tables must differ for each target.
        assert tables["AMSI_PATCH_X86"] != tables["AMSI_PATCH_X64"]
        assert tables["ETW_PATCH_X86"] != tables["ETW_PATCH_X64"]

    def test_tables_are_variant42_output(self):
        """Tables match patch.variant(42, arch, target) byte-for-byte."""
        text = RUNTIME_PATCH_CS.read_text(encoding="utf-8")
        for name, (arch, target) in TABLE_ARCH_TARGET.items():
            parsed = _parse_csharp_byte_array(text, name)
            expected = variant(42, arch, target)
            assert parsed == expected, (
                f"{name} drifted from variant(42, {arch}, {target})"
            )

    def test_tables_satisfy_contract_and_hygiene(self):
        """Each table verifies under simulate() and is canonical-free."""
        text = RUNTIME_PATCH_CS.read_text(encoding="utf-8")
        expected_eax = {"amsi": 0x80070057, "etw": 0}
        for name, (arch, target) in TABLE_ARCH_TARGET.items():
            table = _parse_csharp_byte_array(text, name)
            regs, writes = simulate(arch, table)
            assert regs["eax"] == expected_eax[target], f"{name}: eax=0x{regs['eax']:08x}"
            assert writes == [], f"{name}: memory writes {writes}"
            assert is_canonical_free(table, target, arch) is True

    def test_amsi_never_writes_result_out_param(self, text):
        """The AMSI tables contain no store instructions and no push/pop."""
        for name in ("AMSI_PATCH_X86", "AMSI_PATCH_X64"):
            table = _parse_csharp_byte_array(text, name)
            regs, writes = simulate("x86" if name.endswith("X86") else "x64", table)
            assert writes == []
            assert regs["eax"] == 0x80070057


class TestApolloShimCs:
    """R5 Mode B shim markers: entry shape, Assembly.Load, reflection, marker."""

    @pytest.fixture(scope="class")
    def text(self):
        return APOLLO_SHIM_CS.read_text(encoding="utf-8")

    def test_entry_point_shape(self, text):
        # ExecuteInDefaultAppDomain requires this exact shape.
        assert re.search(r"public\s+static\s+int\s+Main\s*\(\s*string\s*\[\]\s*args\s*\)", text)
        assert "public class ApolloShim" in text

    def test_assembly_load_marker(self, text):
        assert "Assembly.Load" in text

    def test_reflection_invocation(self, text):
        assert "GetMethod" in text
        assert "Invoke" in text
        assert "BindingFlags.Static" in text

    def test_payload_marker_injected_by_host(self, text):
        assert "__APOLLO_BYTES__" in text


class TestHostC:
    """R5 Mode B native template markers + the host.py interpolation contract."""

    @pytest.fixture(scope="class")
    def text(self):
        return HOST_C.read_text(encoding="utf-8")

    def test_force_load_present(self, text):
        assert "LoadLibraryA" in text
        assert '"amsi.dll"' in text
        assert '"ntdll.dll"' in text

    def test_patch_api_present(self, text):
        assert "GetProcAddress" in text
        assert "VirtualProtect" in text
        assert "FlushInstructionCache" in text

    def test_clr_hosting_present(self, text):
        assert "CLRCreateInstance" in text
        assert "ExecuteInDefaultAppDomain" in text
        assert "WideChar" in text or "MultiByteToWideChar" in text
        assert "CcdcShim.ApolloShim" in text

    def test_no_patch_gate(self, text):
        assert "RUNTIME_PATCH_ENABLED" in text
        assert "#if RUNTIME_PATCH_ENABLED" in text

    def test_interpolation_tokens_documented(self, text):
        # Tokens host.py must substitute before compiling (host/README.md).
        for token in (
            "__RUNTIME_PATCH_ENABLED__",
            "__PATCH_AMSI_X86__",
            "__PATCH_AMSI_X64__",
            "__PATCH_ETW_X86__",
            "__PATCH_ETW_X64__",
            "__SHIM_BYTES__",
        ):
            assert token in text, f"host.c missing interpolation token {token}"

    def test_x86_x64_arch_selection(self, text):
        assert "_WIN64" in text
        assert "__x86_64__" in text
        assert "__i386__" in text

    def test_shim_bytes_embedded(self, text):
        assert "SHIM_BYTES" in text


class TestHostMarkers:
    """R6/QA: host-mode markers survive DCE and OB_PATCH_MARKER is patch-gated.

    verify.py scans compiled host images for HOST_MARKER / EMBED_MARKER /
    PATCH_MARKER (shared with host.py).  The arrays are `volatile` and
    observably referenced by ob_marker_fold() from an always-executed path, so
    -O2 (gcc) / /OPT:REF (cl) cannot strip them from a real build -- an
    unreferenced const array would silently break host-mode detection.
    OB_PATCH_MARKER must be wrapped in the same `#if RUNTIME_PATCH_ENABLED`
    as the AMSI/ETW tables so a --no-patch canary baseline carries no marker
    and verify's `runtime_patch` assertion reports the baseline honestly.
    """

    @pytest.fixture(scope="class")
    def text(self):
        return HOST_C.read_text(encoding="utf-8")

    def test_markers_declared_volatile(self, text):
        for name in ("OB_HOST_MARKER", "OB_EMBED_MARKER", "OB_PATCH_MARKER"):
            assert re.search(
                r"static\s+volatile\s+const\s+unsigned\s+char\s+"
                + name
                + r"\s*\[\]",
                text,
            ), f"{name} is not a volatile const array (DCE risk)"

    def test_marker_bytes_match_verify_contract(self, text):
        from obfuscate.verify import EMBED_MARKER, HOST_MARKER, PATCH_MARKER

        assert HOST_MARKER.decode("ascii") in text
        assert (
            "0xAB, 0xCD, 0xEF, 0x01, 0xAB, 0xCD, 0xEF, 0x01" in text
        ), f"EMBED_MARKER bytes {EMBED_MARKER!r} drifted"
        assert PATCH_MARKER.decode("ascii") in text

    def test_markers_referenced_by_always_executed_fold(self, text):
        # Each marker name must appear at least twice: the declaration and an
        # observable read inside ob_marker_fold() (which main() calls
        # unconditionally; without it the arrays are dead const data).
        for name in ("OB_HOST_MARKER", "OB_EMBED_MARKER", "OB_PATCH_MARKER"):
            assert text.count(name) >= 2, f"{name} is declared but never referenced"
        assert text.count("ob_marker_fold") >= 1, "marker fold missing"
        assert text.count("ob_marker_prefix(") >= 2, (
            "marker fold is not observable (ob_marker_prefix must be defined "
            "and called from an always-executed path)"
        )

    def test_patch_marker_gated_by_runtime_patch(self, text):
        lines = text.splitlines()
        decl = next(
            i for i, ln in enumerate(lines) if "OB_PATCH_MARKER[]" in ln
        )
        assert lines[decl - 1].strip() == "#if RUNTIME_PATCH_ENABLED", (
            "OB_PATCH_MARKER must be gated by #if RUNTIME_PATCH_ENABLED so a "
            "--no-patch baseline omits it"
        )
        assert lines[decl + 1].strip() == "#endif"


class TestCanonicalFreeSources:
    """AC7: the canonical public AMSI/ETW sequences never appear verbatim
    in any runtime source file (raw byte scan, all three source dirs)."""

    def test_canonical_absent_from_every_source(self):
        offenders = []
        files = list(PATCH_MODULE.rglob("*")) + list(SHIM.rglob("*")) + list(HOST.rglob("*"))
        files = [f for f in files if f.is_file()]
        assert files, "no source files found to scan"
        for path in files:
            data = path.read_bytes()
            for target, arches in CANONICAL.items():
                for arch, seqs in arches.items():
                    for canon in seqs:
                        if canon in data:
                            offenders.append((str(path), target, arch, canon.hex()))
        assert offenders == [], f"canonical AMSI/ETW bytes found verbatim: {offenders}"

    def test_every_required_source_is_scanned(self):
        for path in SOURCE_FILES:
            assert path.is_file()