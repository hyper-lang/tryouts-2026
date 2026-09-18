"""CLI contract tests (R1): flag surface, exit codes, --version, authorization reminder."""

import argparse
import re
import subprocess
import sys
from pathlib import Path

import pytest

from obfuscate import DN_FILE_MIN, __version__
from obfuscate import host as host_mod
from obfuscate.cli import (
    AUTH_REMINDER,
    EXIT_FAILURE,
    EXIT_OK,
    EXIT_USAGE,
    _default_seed,
    _dnfile_version,
    build_parser,
    main,
    version_text,
)
from obfuscate.report import loads, schema_is_stable
from tests.fixtures import samples

# Shape of a discovered native toolchain (see tests/test_host.py for the same
# convention): no real cargo/gcc/cl is on PATH on this box, so the CLI tests
# monkeypatch `host.discover_toolchain`/`host.build_native_host` for hermetic
# failure/skip/passthrough paths.
FAKE_GCC = {"name": "gcc", "version": "gcc (GCC) 12.2.0", "kind": "gcc"}

# R1 flag surface, per subcommand (ordered for deterministic argv construction).
EXPECTED_FLAGS = {
    "inspect": {
        "positionals": ["input.exe"],
        "options": ["-o", "--report", "--target-image"],
    },
    "harden": {
        "positionals": ["input.exe"],
        "options": [
            "-o",
            "--output",
            "--seed",
            "--no-metadata",
            "--no-attributes",
            "--no-strings",
            "--checksum",
            "--force",
            "--break-runtime",
        ],
    },
    "inject-patch": {
        "positionals": [],
        "options": ["--apollo-src", "--patch", "--dry-run"],
    },
    "build-host": {
        "positionals": [],
        "options": [
            "--apollo-src",
            "-o",
            "--output",
            "--seed",
            "--no-metadata",
            "--no-attributes",
            "--no-strings",
            "--checksum",
            "--no-patch",
        ],
    },
    "verify": {
        "positionals": ["input.exe", "output.exe"],
        "options": ["-o", "--report", "--apollo-src", "--no-defender"],
    },
}

VALUE_FLAGS = {"-o", "--output", "--report", "--apollo-src", "--target-image"}


def _subparsers(parser):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices
    return {}


def _args_for(command, flags):
    """Build a minimal valid argv for a command (all flags present, placeholder values)."""
    argv = [command]
    for flag in flags["options"]:
        if flag in ("--patch",):
            argv += ["--patch", "amsi"]
        elif flag in ("--checksum",):
            argv += ["--checksum", "zero"]
        elif flag in ("--seed",):
            argv += ["--seed", "1"]
        elif flag in VALUE_FLAGS:
            argv += [flag, "placeholder.bin"]
        else:
            argv.append(flag)
    argv += flags["positionals"]
    return argv


def run_main(argv, capsys):
    """Translate main()'s return value or SystemExit into (code, stdout, stderr)."""
    try:
        code = main(argv)
        out, err = capsys.readouterr()
    except SystemExit as exc:
        out, err = capsys.readouterr()
        code = exc.code if exc.code is not None else 0
    return code, out, err


class TestFlagSurface:
    """Every R1 subcommand/flag exists and is accepted."""

    def test_subcommands_present(self):
        for name in EXPECTED_FLAGS:
            assert name in _subparsers(build_parser())

    def test_top_level_version_flag(self):
        parser = build_parser()
        assert "--version" in parser._option_string_actions

    def test_subparsers_required(self):
        sub_action = build_parser()._actions[-1]
        assert isinstance(sub_action, argparse._SubParsersAction)
        assert sub_action.required is True

    @pytest.mark.parametrize("command", sorted(EXPECTED_FLAGS))
    def test_r1_flags_all_accepted(self, command):
        sub = _subparsers(build_parser())[command]
        for flag in EXPECTED_FLAGS[command]["options"]:
            assert flag in sub._option_string_actions, f"{command}: missing {flag}"

    @pytest.mark.parametrize("command", sorted(EXPECTED_FLAGS))
    def test_r1_positionals_all_accepted(self, command):
        sub = _subparsers(build_parser())[command]
        accepted = [
            action.metavar
            for action in sub._actions
            if not action.option_strings and action.dest != "help"
        ]
        assert accepted == EXPECTED_FLAGS[command]["positionals"], (
            f"{command}: positionals {accepted} != {EXPECTED_FLAGS[command]['positionals']}"
        )

    def test_checksum_choices(self):
        sub = _subparsers(build_parser())["harden"]
        checksum = sub._option_string_actions["--checksum"]
        assert list(checksum.choices) == ["zero", "recompute"]
        assert checksum.default == "zero"

    def test_patch_choices(self):
        sub = _subparsers(build_parser())["inject-patch"]
        patch = sub._option_string_actions["--patch"]
        assert list(patch.choices) == ["amsi", "etw"]

    def test_harden_output_required(self):
        sub = _subparsers(build_parser())["harden"]
        assert sub._option_string_actions["-o"].required is True

    def test_build_host_output_required(self):
        sub = _subparsers(build_parser())["build-host"]
        assert sub._option_string_actions["-o"].required is True


class TestHelp:
    """--help documents every flag and exits 0."""

    @pytest.mark.parametrize(
        "argv",
        [["--help"]] + [[c, "--help"] for c in sorted(EXPECTED_FLAGS)],
        ids=["program"] + sorted(EXPECTED_FLAGS),
    )
    def test_help_exits_zero(self, argv, capsys):
        code, out, err = run_main(argv, capsys)
        assert code == EXIT_OK

    @pytest.mark.parametrize("command", sorted(EXPECTED_FLAGS))
    def test_help_documents_every_flag(self, command, capsys):
        code, out, err = run_main([command, "--help"], capsys)
        assert code == EXIT_OK
        for flag in EXPECTED_FLAGS[command]["options"]:
            assert flag in out, f"{command}: {flag} missing from --help"
        for pos in EXPECTED_FLAGS[command]["positionals"]:
            assert pos in out, f"{command}: positional {pos} missing from --help"


class TestUsageErrors:
    """Unknown flags/args exit 1 (R1)."""

    @pytest.mark.parametrize(
        "argv",
        [
            ["inspect", "x.exe", "--bogus"],
            ["inspect", "--bogus", "x.exe"],
            ["harden", "x.exe", "-o", "y.exe", "--bogus"],
            ["inject-patch", "--apollo-src", "s", "--bogus"],
            ["build-host", "--apollo-src", "s", "-o", "y.exe", "--bogus"],
            ["verify", "x.exe", "y.exe", "--bogus"],
            ["bogus-command"],
            [],
        ],
        ids=[
            "inspect_unknown",
            "inspect_unknown_pre",
            "harden_unknown",
            "inject_unknown",
            "host_unknown",
            "verify_unknown",
            "unknown_command",
            "no_command",
        ],
    )
    def test_unknown_flag_or_command_exits_one(self, argv, capsys):
        code, out, err = run_main(argv, capsys)
        assert code == EXIT_USAGE

    @pytest.mark.parametrize(
        "argv",
        [
            ["inspect"],
            ["inspect", "x.exe", "extra.exe"],
            ["harden", "x.exe"],
            ["harden", "x.exe", "-o"],
            ["inject-patch"],
            ["build-host"],
            ["build-host", "--apollo-src", "s"],
            ["verify"],
            ["verify", "x.exe"],
        ],
        ids=[
            "inspect_missing_positional",
            "inspect_extra_positional",
            "harden_missing_output",
            "harden_missing_output_value",
            "inject_missing_apollo_src",
            "host_missing_required",
            "host_missing_output",
            "verify_missing_positionals",
            "verify_missing_second_positional",
        ],
    )
    def test_bad_arity_exits_one(self, argv, capsys):
        code, out, err = run_main(argv, capsys)
        assert code == EXIT_USAGE

    def test_bad_checksum_choice_exits_one(self, capsys):
        code, out, err = run_main(["harden", "x.exe", "-o", "y.exe", "--checksum", "bogus"], capsys)
        assert code == EXIT_USAGE

    def test_bad_patch_choice_exits_one(self, capsys):
        code, out, err = run_main(["inject-patch", "--apollo-src", "s", "--patch", "bogus"], capsys)
        assert code == EXIT_USAGE

    def test_bad_seed_type_exits_one(self, capsys):
        code, out, err = run_main(["harden", "x.exe", "-o", "y.exe", "--seed", "abc"], capsys)
        assert code == EXIT_USAGE


class TestVersion:
    """--version prints Python, dnfile, and warns below the pinned minimum."""

    def test_version_exits_zero_and_mentions_runtime(self, capsys):
        code, out, err = run_main(["--version"], capsys)
        assert code == EXIT_OK
        assert f"obfuscate {__version__}" in out
        assert "Python" in out
        assert "dnfile" in out

    def test_version_text_warns_below_minimum(self, monkeypatch):
        monkeypatch.setattr("obfuscate.cli._dnfile_version", lambda: "0.17.0")
        text = version_text()
        assert f"below the pinned minimum {DN_FILE_MIN}" in text

    def test_version_text_no_warning_at_minimum(self, monkeypatch):
        monkeypatch.setattr("obfuscate.cli._dnfile_version", lambda: DN_FILE_MIN)
        text = version_text()
        assert "WARNING" not in text

    def test_version_text_warns_when_dnfile_missing(self, monkeypatch):
        monkeypatch.setattr("obfuscate.cli._dnfile_version", lambda: None)
        text = version_text()
        assert "not installed" in text
        assert "WARNING" in text

    def test_dnfile_version_reads_real_attr(self):
        version = _dnfile_version()
        assert version is not None and version != "unknown"

    def test_version_text_includes_discovered_toolchain(self, monkeypatch):
        monkeypatch.setattr(host_mod, "discover_toolchain", lambda: dict(FAKE_GCC))
        text = version_text()
        assert "toolchain gcc: gcc (GCC) 12.2.0" in text

    def test_version_text_omits_toolchain_when_absent(self, monkeypatch):
        monkeypatch.setattr(host_mod, "discover_toolchain", lambda: None)
        text = version_text()
        assert not any(line.startswith("toolchain") for line in text.splitlines())


class TestExitCodes:
    """0 success, 1 usage, 2 runtime failure; auth reminder on every command."""

    def test_valid_subcommand_maps_to_runtime_failure_2(self, capsys):
        code, out, err = run_main(["inspect", "whatever.exe"], capsys)
        assert code == EXIT_FAILURE

    def test_auth_reminder_printed_on_command(self, capsys):
        code, out, err = run_main(["inspect", "whatever.exe"], capsys)
        assert AUTH_REMINDER in out

    @pytest.mark.parametrize("command", sorted(EXPECTED_FLAGS))
    def test_auth_reminder_printed_on_every_subcommand(self, command, capsys):
        argv = _args_for(command, EXPECTED_FLAGS[command])
        code, out, err = run_main(argv, capsys)
        assert AUTH_REMINDER in out
        # Most commands fail on a placeholder source (EXIT_FAILURE); inject-patch
        # instead routes the non-checkout source into synthetic-tree mode and
        # succeeds (EXIT_OK) after wiring its synthetic overlay.
        expected = EXIT_OK if command == "inject-patch" else EXIT_FAILURE
        assert code == expected


class TestConsoleScript:
    """The installed `obfuscate` entry point behaves like cli.main."""

    def test_installed_version(self):
        proc = subprocess.run(
            [sys.executable, "-m", "obfuscate.cli", "--version"],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0
        assert "Python" in proc.stdout
        assert "dnfile" in proc.stdout

    def test_installed_unknown_flag_exits_one(self):
        proc = subprocess.run(
            [sys.executable, "-m", "obfuscate.cli", "inspect", "x.exe", "--bogus"],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 1


class TestCmdInspect:
    """R2: inspect on the synthetic fixture: exit 0, complete schema-stable report."""

    _MITIGATIONS = {"metadata", "attributes", "string_scrub", "rebuild_config", "runtime", "none"}

    def _sample(self, tmp_path):
        path = tmp_path / "sample.exe"
        samples.write_sample_to(path)
        return str(path)

    def test_inspect_exits_zero_on_fixture(self, tmp_path, capsys):
        code, out, err = run_main(["inspect", self._sample(tmp_path)], capsys)
        assert code == EXIT_OK

    def test_inspect_stdout_is_human_readable(self, tmp_path, capsys):
        code, out, err = run_main(["inspect", self._sample(tmp_path)], capsys)
        assert code == EXIT_OK
        assert AUTH_REMINDER in out
        assert "obfuscate inspect report" in out
        assert "## fingerprints" in out

    def test_o_writes_complete_json_report(self, tmp_path, capsys):
        sample = self._sample(tmp_path)
        out_path = tmp_path / "report.json"
        code, out, err = run_main(["inspect", sample, "-o", str(out_path)], capsys)
        assert code == EXIT_OK
        doc = loads(out_path.read_text(encoding="utf-8"))
        assert doc["command"] == "inspect"
        assert doc["authorization_note"]
        findings = doc["findings"]
        assert findings["pe"] is not None
        assert findings["metadata"] is not None
        assert findings["config"] is not None
        assert isinstance(findings["fingerprints"], list)
        assert findings["fingerprints"]

    def test_fingerprint_entry_shape(self, tmp_path, capsys):
        sample = self._sample(tmp_path)
        out_path = tmp_path / "report.json"
        code, out, err = run_main(["inspect", sample, "-o", str(out_path)], capsys)
        assert code == EXIT_OK
        fp = loads(out_path.read_text(encoding="utf-8"))["findings"]["fingerprints"][0]
        assert set(fp) == {
            "catalog_id",
            "tier",
            "mitigation",
            "encoding",
            "file_offset",
            "text",
            "schema_version",
        }
        assert isinstance(fp["file_offset"], int)
        assert fp["mitigation"] in self._MITIGATIONS

    def test_stdout_renders_human_report_with_target_image(self, tmp_path, capsys):
        code, out, err = run_main(
            ["inspect", self._sample(tmp_path), "--target-image", "Server 2019 + 4.8"],
            capsys,
        )
        assert code == EXIT_OK
        assert AUTH_REMINDER in out
        assert "Server 2019 + 4.8" in out

    def test_target_image_recorded_in_json(self, tmp_path, capsys):
        sample = self._sample(tmp_path)
        out_path = tmp_path / "report.json"
        code, out, err = run_main(
            ["inspect", sample, "-o", str(out_path), "--target-image", "Server 2019 + 4.8"],
            capsys,
        )
        assert code == EXIT_OK
        doc = loads(out_path.read_text(encoding="utf-8"))
        assert doc["target_image"] == "Server 2019 + 4.8"

    def test_config_extracted_and_aespsk_material_masked(self, tmp_path, capsys):
        sample = self._sample(tmp_path)
        out_path = tmp_path / "report.json"
        code, out, err = run_main(["inspect", sample, "-o", str(out_path)], capsys)
        assert code == EXIT_OK
        cfg = loads(out_path.read_text(encoding="utf-8"))["findings"]["config"]
        assert cfg["url"] == samples.DEFAULT_CALLBACK_URL
        assert cfg["host"] and cfg["port"]
        assert cfg["method"] == "heuristic"
        # The aespsk subtree is masked by field NAME at the JSON boundary
        # (report.redact), so only a 16-hex sha256 hash ever reaches the doc.
        masked = cfg["aespsk"]
        assert isinstance(masked, str)
        assert len(masked) == 16
        assert all(c in "0123456789abcdef" for c in masked)

    def test_report_schema_stable_across_runs(self, tmp_path, capsys):
        sample = self._sample(tmp_path)
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        code1, _, _ = run_main(
            ["inspect", sample, "-o", str(a), "--target-image", "Server 2019 default 4.7.2"],
            capsys,
        )
        code2, _, _ = run_main(
            ["inspect", sample, "-o", str(b), "--target-image", "Server 2019 + 4.8"],
            capsys,
        )
        assert code1 == code2 == EXIT_OK
        assert schema_is_stable(
            loads(a.read_text(encoding="utf-8")),
            loads(b.read_text(encoding="utf-8")),
        )

    def test_inspect_missing_file_fails_with_2(self, tmp_path, capsys):
        code, out, err = run_main(["inspect", str(tmp_path / "nope.exe")], capsys)
        assert code == EXIT_FAILURE
        assert "obfuscate: error:" in err


class TestCmdHarden:
    """R3: harden on the synthetic fixture: exit 0, deterministic output, schema-stable report."""

    def _sample(self, tmp_path):
        path = tmp_path / "sample.exe"
        samples.write_sample_to(path)
        return str(path)

    def test_harden_exits_zero(self, tmp_path, capsys):
        sample = self._sample(tmp_path)
        out = tmp_path / "out.exe"
        code, _, _ = run_main(["harden", sample, "-o", str(out), "--seed", "42"], capsys)
        assert code == EXIT_OK

    def test_output_is_valid_pe(self, tmp_path, capsys):
        sample = self._sample(tmp_path)
        out = tmp_path / "out.exe"
        run_main(["harden", sample, "-o", str(out), "--seed", "42"], capsys)
        from obfuscate.pe import analyze
        pe_info = analyze(str(out))
        assert pe_info is not None

    def test_report_json_has_hardening_section(self, tmp_path, capsys):
        from obfuscate.harden import run_harden

        sample = self._sample(tmp_path)
        out = tmp_path / "out.exe"
        code, stdout, _ = run_main(
            ["harden", sample, "-o", str(out), "--seed", "42"], capsys
        )
        assert code == EXIT_OK
        # The rendered stdout carries the hardening/passes narrative…
        assert "hardening" in stdout.lower() or "passes" in stdout.lower()
        # …and the underlying report JSON carries a non-null hardening section.
        report = run_harden(sample, str(out), 42)
        findings = report.to_dict()["findings"]
        assert findings["hardening"] is not None
        assert findings["hardening"]["seed"] == 42

    def test_stdout_renders_human_readable(self, tmp_path, capsys):
        sample = self._sample(tmp_path)
        out = tmp_path / "out.exe"
        code, stdout, _ = run_main(
            ["harden", sample, "-o", str(out), "--seed", "42"], capsys
        )
        assert code == EXIT_OK
        assert AUTH_REMINDER in stdout
        assert "harden" in stdout.lower() or "hardening" in stdout.lower()

    def test_report_json_stable_schema(self, tmp_path, capsys):
        """Two runs with same seed produce byte-identical output."""
        sample = self._sample(tmp_path)
        out1 = tmp_path / "out1.exe"
        out2 = tmp_path / "out2.exe"
        code1, _, _ = run_main(["harden", sample, "-o", str(out1), "--seed", "42"], capsys)
        code2, _, _ = run_main(["harden", sample, "-o", str(out2), "--seed", "42"], capsys)
        assert code1 == code2 == EXIT_OK
        assert out1.read_bytes() == out2.read_bytes()

    def test_different_seeds_produce_different_output(self, tmp_path, capsys):
        sample = self._sample(tmp_path)
        out1 = tmp_path / "out1.exe"
        out2 = tmp_path / "out2.exe"
        run_main(["harden", sample, "-o", str(out1), "--seed", "42"], capsys)
        run_main(["harden", sample, "-o", str(out2), "--seed", "99"], capsys)
        assert out1.read_bytes() != out2.read_bytes()

    def test_bad_checksum_value_is_usage_error(self, capsys):
        code, _, _ = run_main(
            ["harden", "x.exe", "-o", "y.exe", "--seed", "1", "--checksum", "bogus"],
            capsys,
        )
        assert code == EXIT_USAGE

    def test_default_seed_is_deterministic_per_input(self, tmp_path):
        s1 = _default_seed("foo.exe")
        s2 = _default_seed("foo.exe")
        s3 = _default_seed("bar.exe")
        assert s1 == s2
        assert s1 != s3


class TestCmdInjectPatch:
    """R5 Mode A / AC5: inject-patch on a synthetic agent_code tree."""

    _CALL = "CcdcHardening.RuntimePatch.ApplyPatches();"
    _MARKER = "RUNTIME_PATCH_WIRED"

    def _tree(self, tmp_path):
        from obfuscate.synth import AgentCodeTree

        root = tmp_path / "agent_code"
        AgentCodeTree(root).build()
        return root

    def test_exits_zero_and_wires_once(self, tmp_path, capsys):
        root = self._tree(tmp_path)
        code, out, err = run_main(
            ["inject-patch", "--apollo-src", str(root)], capsys
        )
        assert code == EXIT_OK
        program = (root / "Program.cs").read_text(encoding="utf-8")
        assert program.count(self._CALL) == 1
        assert program.count(self._MARKER) == 1
        assert (root / "RuntimePatch.cs").exists()
        assert AUTH_REMINDER in out

    def test_wiring_is_first_statement(self, tmp_path, capsys):
        root = self._tree(tmp_path)
        run_main(["inject-patch", "--apollo-src", str(root)], capsys)
        program = (root / "Program.cs").read_text(encoding="utf-8")
        body = program.split("static void Main", 1)[1]
        brace = body.index("{")
        after_brace = body[brace + 1 :]
        # The first non-whitespace content in Main is the wiring marker/call.
        assert self._MARKER in after_brace.splitlines()[0] or self._CALL in after_brace

    def test_re_run_is_idempotent(self, tmp_path, capsys):
        root = self._tree(tmp_path)
        code1, _, _ = run_main(["inject-patch", "--apollo-src", str(root)], capsys)
        assert code1 == EXIT_OK
        program1 = (root / "Program.cs").read_text(encoding="utf-8")
        patch1 = (root / "RuntimePatch.cs").read_text(encoding="utf-8")
        code2, out, err = run_main(["inject-patch", "--apollo-src", str(root)], capsys)
        assert code2 == EXIT_OK
        program2 = (root / "Program.cs").read_text(encoding="utf-8")
        patch2 = (root / "RuntimePatch.cs").read_text(encoding="utf-8")
        assert program2 == program1
        assert patch2 == patch1
        assert program2.count(self._CALL) == 1
        assert "already patched" in out

    def test_dry_run_changes_nothing(self, tmp_path, capsys):
        root = self._tree(tmp_path)
        before = (root / "Program.cs").read_text(encoding="utf-8")
        code, out, err = run_main(
            ["inject-patch", "--apollo-src", str(root), "--dry-run"], capsys
        )
        assert code == EXIT_OK
        after = (root / "Program.cs").read_text(encoding="utf-8")
        assert after == before
        assert self._CALL not in after
        assert not (root / "RuntimePatch.cs").exists()
        assert "would add RuntimePatch.cs" in out
        assert "diff" in out.lower() or "---" in out or "+++" in out

    def test_missing_flag_and_env_exits_one(self, tmp_path, capsys, monkeypatch):
        monkeypatch.delenv("APOLLO_SOURCE", raising=False)
        code, out, err = run_main(["inject-patch"], capsys)
        assert code == EXIT_USAGE
        assert "inject-patch" in err

    def test_env_alone_satisfies_source(self, tmp_path, capsys, monkeypatch):
        root = self._tree(tmp_path)
        monkeypatch.setenv("APOLLO_SOURCE", str(root))
        code, out, err = run_main(["inject-patch"], capsys)
        assert code == EXIT_OK
        program = (root / "Program.cs").read_text(encoding="utf-8")
        assert program.count(self._CALL) == 1
        assert (root / "RuntimePatch.cs").exists()

    def test_patch_amsi_leaves_etw_toggle_off(self, tmp_path, capsys):
        root = self._tree(tmp_path)
        code, _, _ = run_main(
            ["inject-patch", "--apollo-src", str(root), "--patch", "amsi"], capsys
        )
        assert code == EXIT_OK
        patch = (root / "RuntimePatch.cs").read_text(encoding="utf-8")
        assert re.search(r"ENABLE_AMSI\s*=\s*true", patch)
        assert re.search(r"ENABLE_ETW\s*=\s*false", patch)
        # Gate stays on (inject-patch never disables the whole patch).
        assert re.search(r"RUNTIME_PATCH_ENABLED\s*=\s*true", patch)

    def test_default_patch_enables_both(self, tmp_path, capsys):
        root = self._tree(tmp_path)
        run_main(["inject-patch", "--apollo-src", str(root)], capsys)
        patch = (root / "RuntimePatch.cs").read_text(encoding="utf-8")
        assert re.search(r"ENABLE_AMSI\s*=\s*true", patch)
        assert re.search(r"ENABLE_ETW\s*=\s*true", patch)

    def test_non_agent_code_path_uses_synthetic_mode(self, tmp_path, capsys):
        empty = tmp_path / "empty"
        empty.mkdir()
        code, out, err = run_main(
            ["inject-patch", "--apollo-src", str(empty)], capsys
        )
        assert code == EXIT_OK
        assert "synthetic-tree mode" in err
        assert "expected real layout" in err
        # The synthetic tree was wired; the empty dir is untouched.
        assert not (empty / "RuntimePatch.cs").exists()


class TestCmdBuildHost:
    """R5 Mode B / AC6: build-host CLI handler wiring and failure semantics.

    This box has no cargo/gcc/cl on PATH, so a real ``build-host`` fails the
    toolchain probe.  ``host.build_native_host``/``host.discover_toolchain``
    are monkeypatched here so every path (no-toolchain exit 2, shim-unavailable
    skip exit 0, flag pass-through, synthetic source resolution) is hermetic.
    """

    @staticmethod
    def _fake_prov(status="shim_unavailable", **overrides):
        prov = {
            "status": status,
            "toolchain": dict(FAKE_GCC),
            "shim": "unavailable" if status == "shim_unavailable" else "compiled",
            "patch_enabled": True,
            "seed": 42,
            "passes": ["metadata", "attributes", "strings"],
            "checksum": "zero",
            "apollo_src": "synthetic",
            "findings": [
                {"catalog_id": "checksum", "offset": 280, "description": "PE checksum zeroed (default)"}
            ],
        }
        prov.update(overrides)
        return prov

    def test_no_toolchain_exits_two_and_writes_no_output(self, tmp_path, capsys, monkeypatch):
        monkeypatch.delenv("APOLLO_SOURCE", raising=False)
        monkeypatch.setattr(host_mod, "discover_toolchain", lambda: None)
        out = tmp_path / "out.exe"
        code, out_text, err = run_main(["build-host", "-o", str(out)], capsys)
        assert code == EXIT_FAILURE
        assert "obfuscate: error:" in err
        assert "toolchain" in err.lower()
        assert not out.exists()

    def test_shim_unavailable_exits_zero_and_report_records(self, tmp_path, capsys, monkeypatch):
        monkeypatch.delenv("APOLLO_SOURCE", raising=False)
        monkeypatch.setattr(host_mod, "build_native_host", lambda *a, **k: self._fake_prov())
        out = tmp_path / "out.exe"
        code, out_text, err = run_main(["build-host", "-o", str(out), "--seed", "42"], capsys)
        assert code == EXIT_OK
        assert "shim_unavailable" in out_text
        assert "## hardening" in out_text
        assert AUTH_REMINDER in out_text
        assert not out.exists()

    def test_flags_passthrough_and_findings_reused(self, tmp_path, capsys, monkeypatch):
        monkeypatch.delenv("APOLLO_SOURCE", raising=False)
        record = {}

        def fake_build_native_host(apollo_bytes, seed, output_path, **kwargs):
            record["seed"] = seed
            record["output_path"] = output_path
            record.update(kwargs)
            return {
                "status": "shim_unavailable",
                "toolchain": dict(FAKE_GCC),
                "shim": "unavailable",
                "patch_enabled": kwargs["patch_enabled"],
                "seed": seed,
                "passes": [],
                "checksum": kwargs["checksum"],
                "apollo_src": kwargs["apollo_src"],
                "findings": [
                    {"catalog_id": "checksum", "offset": 280, "description": "xor-scrubbed config fragment"}
                ],
            }

        monkeypatch.setattr(host_mod, "build_native_host", fake_build_native_host)
        out = tmp_path / "out.exe"
        code, out_text, err = run_main(
            [
                "build-host",
                "-o", str(out),
                "--seed", "7",
                "--no-metadata",
                "--no-attributes",
                "--no-strings",
                "--checksum", "recompute",
                "--no-patch",
            ],
            capsys,
        )
        assert code == EXIT_OK
        assert record["seed"] == 7
        assert record["patch_enabled"] is False
        assert record["no_metadata"] is True
        assert record["no_attributes"] is True
        assert record["no_strings"] is True
        assert record["checksum"] == "recompute"
        assert record["output_path"] == str(out)
        # Report reuses the real provenance findings, never a hardcoded [].
        assert "xor-scrubbed config fragment" in out_text
        assert "passes:" in out_text

    def test_absent_flag_and_env_still_hits_synthetic_mode(self, tmp_path, capsys, monkeypatch):
        monkeypatch.delenv("APOLLO_SOURCE", raising=False)
        record = {}

        def fake_build_native_host(apollo_bytes, seed, output_path, **kwargs):
            record["apollo_bytes_size"] = len(apollo_bytes)
            record["apollo_src"] = kwargs["apollo_src"]
            return {
                "status": "shim_unavailable",
                "toolchain": dict(FAKE_GCC),
                "shim": "unavailable",
                "patch_enabled": True,
                "seed": seed,
                "passes": ["metadata", "attributes", "strings"],
                "checksum": "zero",
                "apollo_src": kwargs["apollo_src"],
                "findings": [],
            }

        monkeypatch.setattr(host_mod, "build_native_host", fake_build_native_host)
        out = tmp_path / "out.exe"
        code, out_text, err = run_main(["build-host", "-o", str(out)], capsys)
        assert code == EXIT_OK
        assert record["apollo_src"] == "synthetic"
        from obfuscate.synth import (
            SAMPLE_MVID,
            SAMPLE_MODULE_GUID,
            SAMPLE_SIGNATURE_SEED,
            build_apollo_sample,
        )

        expected = build_apollo_sample(
            mvid=SAMPLE_MVID,
            module_guid=SAMPLE_MODULE_GUID,
            seed=SAMPLE_SIGNATURE_SEED,
        ).bytes
        assert record["apollo_bytes_size"] == len(expected)

    def test_env_source_on_bad_layout_is_synthetic_too(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("APOLLO_SOURCE", str(tmp_path / "not_a_checkout"))
        record = {}

        def fake_build_native_host(apollo_bytes, seed, output_path, **kwargs):
            record["apollo_src"] = kwargs["apollo_src"]
            return self._fake_prov()

        monkeypatch.setattr(host_mod, "build_native_host", fake_build_native_host)
        out = tmp_path / "out.exe"
        code, out_text, err = run_main(["build-host", "-o", str(out)], capsys)
        assert code == EXIT_OK
        assert "synthetic-tree mode" in err
        assert record["apollo_src"] == "synthetic"

    def test_version_flag_shows_monkeypatched_toolchain(self, capsys, monkeypatch):
        monkeypatch.setattr(host_mod, "discover_toolchain", lambda: dict(FAKE_GCC))
        code, out, err = run_main(["--version"], capsys)
        assert code == EXIT_OK
        assert "toolchain gcc: gcc (GCC) 12.2.0" in out


class TestCmdVerify:
    """R6 / AC8: verify CLI handler wiring, soft determinism, report shape."""

    def _sample(self, tmp_path):
        path = tmp_path / "sample.exe"
        samples.write_sample_to(path)
        return str(path)

    def _harden_cli(self, tmp_path, capsys, seed=None):
        sample = self._sample(tmp_path)
        out = tmp_path / "out.exe"
        argv = ["harden", sample, "-o", str(out)]
        if seed is not None:
            argv += ["--seed", str(seed)]
        assert run_main(argv, capsys)[0] == EXIT_OK
        return sample, str(out)

    def test_verify_exits_zero_on_clean_round_trip(self, tmp_path, capsys):
        sample, out = self._harden_cli(tmp_path, capsys)
        code, stdout, err = run_main(["verify", sample, out], capsys)
        assert code == EXIT_OK
        assert AUTH_REMINDER in stdout
        assert "## verify" in stdout

    def test_custom_seeded_harden_determinism_soft_exits_zero(self, tmp_path, capsys):
        """A non-default-seed harden output fails ONLY the determinism
        assertion (documented best-effort); the command still exits 0."""
        sample, out = self._harden_cli(tmp_path, capsys, seed=42)
        code, stdout, err = run_main(["verify", sample, out], capsys)
        assert code == EXIT_OK
        assert "determinism" in stdout

    def test_mvid_corruption_exits_two(self, tmp_path, capsys):
        """AC8: a parseable-but-corrupt output (input MVID copied back over the
        output's) trips the mvid_differs assertion -> exit 2."""
        from obfuscate.pe import analyze

        sample, out = self._harden_cli(tmp_path, capsys)
        in_pe = analyze(sample)
        out_pe = analyze(out)
        in_off = in_pe["metadata"]["mvid_offset"]
        out_off = out_pe["metadata"]["mvid_offset"]
        assert in_off and out_off
        data = bytearray(Path(out).read_bytes())
        in_data = Path(sample).read_bytes()
        data[out_off:out_off + 16] = in_data[in_off:in_off + 16]
        Path(out).write_bytes(bytes(data))
        report = tmp_path / "report.json"
        code, stdout, err = run_main(["verify", sample, out, "-o", str(report)], capsys)
        assert code == EXIT_FAILURE
        doc = loads(report.read_text(encoding="utf-8"))
        mvid = next(a for a in doc["findings"]["verify"] if a["category"] == "mvid_differs")
        assert mvid["pass"] is False

    def test_missing_inputs_exit_two(self, tmp_path, capsys):
        code, stdout, err = run_main(
            ["verify", str(tmp_path / "bad.exe"), str(tmp_path / "bad2.exe")], capsys
        )
        assert code == EXIT_FAILURE
        assert "obfuscate: error:" in err

    def test_no_defender_forces_skipped_canary(self, tmp_path, capsys, monkeypatch):
        """--no-defender forces the skipped canary state even when the lab env
        var would flip the stubs to lab_required."""
        monkeypatch.setenv("OBFUSCATE_CANARY_LAB", "1")
        sample, out = self._harden_cli(tmp_path, capsys)
        report = tmp_path / "report.json"
        code, stdout, err = run_main(
            ["verify", sample, out, "--no-defender", "-o", str(report)], capsys
        )
        assert code == EXIT_OK
        doc = loads(report.read_text(encoding="utf-8"))
        canary = doc["findings"]["canary"]
        assert canary["amshi"]["status"] == "skipped"
        assert canary["etw"]["status"] == "skipped"

    def test_o_writes_complete_json_report(self, tmp_path, capsys, monkeypatch):
        monkeypatch.delenv("OBFUSCATE_CANARY_LAB", raising=False)
        sample, out = self._harden_cli(tmp_path, capsys)
        report = tmp_path / "report.json"
        code, stdout, err = run_main(["verify", sample, out, "-o", str(report)], capsys)
        assert code == EXIT_OK
        doc = loads(report.read_text(encoding="utf-8"))
        assert doc["command"] == "verify"
        assert doc["authorization_note"]
        findings = doc["findings"]
        assert findings["pe"] is not None
        assert findings["metadata"] is not None
        verify = findings["verify"]
        assert isinstance(verify, list) and verify
        cats = {a["category"] for a in verify}
        assert {
            "pe_intact",
            "layout",
            "mvid_differs",
            "fingerprint_removal",
            "unclaimed_reported",
            "determinism",
        } <= cats
        canary = findings["canary"]
        assert canary["amshi"]["mode"] == "amshi"
        assert canary["etw"]["mode"] == "etw"
        # A plain harden output carries no runtime patch -> canary_mode 'none'.
        assert canary["amshi"]["canary_mode"] == "none"
        assert canary["amshi"]["status"] == "skipped"

    def test_canary_mode_detection(self):
        """R6 mode rule: harden -> 'none'; host+PATCH_MARKER -> 'B'; host
        without (--no-patch baseline) -> 'B baseline'; never 'A'."""
        from obfuscate.cli import _canary_mode
        from obfuscate.verify import PATCH_MARKER

        assert _canary_mode("harden", b"") == "none"
        assert _canary_mode("host", b"garbage" + PATCH_MARKER + b"garbage") == "B"
        assert _canary_mode("host", b"no patch structure here") == "B baseline"


def test_package_never_imports_tests():
    """The installed console script must not reach the test-fixture package.

    A console script's sys.path[0] is the venv Scripts dir, and `tests` is not
    installed, so any `obfuscate/*` module importing `tests.*` would crash the
    entry point (regression: metadata.py used to import the fixture builder).
    Scan the package source for such imports as a static guard.
    """
    import re

    from obfuscate import __file__ as pkg_init

    pkg_dir = Path(pkg_init).parent
    offenders = []
    for py in sorted(pkg_dir.glob("*.py")):
        text = py.read_text(encoding="utf-8")
        if re.search(r"^\s*(from\s+tests|import\s+tests)\b", text, re.MULTILINE):
            offenders.append(py.name)
    assert offenders == [], f"obfuscate/* imports tests package: {offenders}"