"""Self-contained lab canary harness tests (task 33 / AC7, R6 recording).

The lab canary is a deploy-host asset: a self-contained PowerShell script that
is the only measurer of R6 baseline/patched AMSI/ETW suppression.  It must
exist at the repo-root path (never an installed path), parse under the
PowerShell 5.1 AST parser, emit a single JSON document whose keys equal
``verify.CANARY_RECORD_KEYS`` exactly, and only ever make version-scoped claims
('measured on the lab run with <versions>'), never "undetected".
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from obfuscate.verify import CANARY_RECORD_KEYS

CANARY_DIR = Path(__file__).resolve().parents[1] / "obfuscate" / "canary"
CANARY_PS1 = CANARY_DIR / "canary_amsi.ps1"

_PS1 = "canary_amsi.ps1"


def _powershell(*args: str) -> subprocess.CompletedProcess:
    """Run a powershell.exe command (skips orchestration in unit tests)."""
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )


# ---------------------------------------------------------------------------
# Locating the asset (repo-tree path, not an installed path)
# ---------------------------------------------------------------------------

class TestAssetLocation:
    def test_script_exists_at_repo_root_path(self) -> None:
        assert CANARY_PS1.is_file(), f"missing {CANARY_PS1}"

    def test_canary_dir_has_no_init_py(self) -> None:
        # pyproject packages list is ['obfuscate'] only; the canary dir must
        # stay a plain asset dir so `pip install -e .` leaves it out.
        assert not (CANARY_DIR / "__init__.py").exists()
        assert not (CANARY_DIR / "__init__.pyc").exists()

    def test_README_exists(self) -> None:
        assert (CANARY_DIR / "README.md").is_file()


# ---------------------------------------------------------------------------
# PowerShell 5.1 AST parse (ParseInput/ParseFile via the real parser)
# ---------------------------------------------------------------------------

class TestPowerShellParse:
    @pytest.mark.skipif(
        not platform.system().lower().startswith("win"),
        reason="powershell.exe parse requires a Windows host",
    )
    @pytest.mark.skipif(
        shutil.which("powershell") is None,
        reason="powershell.exe not on PATH",
    )
    def test_script_parses_as_powershell_ast(self, tmp_path) -> None:
        # The task pins PowerShell AST parsing via ParseInput: feed the raw
        # script text (read by Python, handed to the parser through a temp
        # file) into Parser::ParseInput and assert zero parse errors plus a
        # non-empty token stream.
        code_path = tmp_path / "canary_code.ps1"
        code_path.write_text(CANARY_PS1.read_text(encoding="utf-8"), encoding="utf-8")
        path = str(code_path).replace("'", "''")
        command = (
            f"$code = [System.IO.File]::ReadAllText('{path}'); "
            "$t = $null; $e = $null; "
            "[System.Management.Automation.Language.Parser]::ParseInput("
            "$code, [ref] $t, [ref] $e) | Out-Null; "
            "if (@($t).Count -eq 0) { exit 2 }; "
            "if ($e.Count -gt 0) { foreach ($err in $e) "
            "{ [Console]::Error.WriteLine($err.Message) }; exit 1 }; "
            "Write-Output ('OK ' + @($t).Count + ' tokens')"
        )
        result = _powershell(command)
        assert result.returncode == 0, (
            f"ParseInput failed with rc={result.returncode}: "
            f"{result.stderr.strip()}"
        )
        assert result.stdout.strip().startswith("OK ")

    def test_script_contains_amsi_test_call_path(self) -> None:
        # The AMSI canary must go through the AMSI test call path, and the
        # optional ETW canary through ntdll's EtwEventWrite.
        text = CANARY_PS1.read_text(encoding="utf-8")
        assert "AmsiInitialize" in text
        assert "AmsiScanBuffer" in text
        assert "EtwEventWrite" in text


# ---------------------------------------------------------------------------
# JSON schema pinning against verify.CANARY_RECORD_KEYS
# ---------------------------------------------------------------------------

def _record_keys_from_source() -> set:
    """Keys of the ``$record`` hashtable literal in the .ps1 source."""
    text = CANARY_PS1.read_text(encoding="utf-8")
    marker = "\n    $record = @{\n"
    start = text.index(marker) + len(marker)
    end = text.index("\n    }\n", start)
    block = text[start:end]
    keys = set()
    for line in block.splitlines():
        line = line.strip()
        if "=" in line:
            keys.add(line.split("=", 1)[0].strip())
    return keys


class TestJsonSchema:
    def test_record_keys_match_canary_record_keys(self) -> None:
        # Task: the JSON keys must match verify.CANARY_RECORD_KEYS exactly.
        keys = _record_keys_from_source()
        assert keys == set(CANARY_RECORD_KEYS)
        assert len(keys) == len(CANARY_RECORD_KEYS)

    def test_record_keys_are_unique_per_schema(self) -> None:
        assert len(set(CANARY_RECORD_KEYS)) == len(CANARY_RECORD_KEYS)

    def test_marker_switch_present_and_no_etw_switch_present(self) -> None:
        text = CANARY_PS1.read_text(encoding="utf-8")
        assert "$NoETW" in text
        assert "$Marker" in text
        assert "$BaselinePath" in text
        assert "$PatchedPath" in text

    def test_host_markers_pinned(self) -> None:
        # Keep the artifact-mode markers in sync with verify.py / host.c.
        text = CANARY_PS1.read_text(encoding="utf-8")
        assert "OBFUSCATE_HOST_V1" in text
        assert "OBFUSCATE_PATCH_V1" in text
        assert "'B baseline'" in text
        assert "'B'" in text

    def test_exit_code_contract_wired(self) -> None:
        text = CANARY_PS1.read_text(encoding="utf-8")
        assert "exit $exitCode" in text
        assert "$exitCode = 1" in text


# ---------------------------------------------------------------------------
# Version-scoped wording; never "undetected"
# ---------------------------------------------------------------------------

class TestWording:
    def test_version_scoped_wording_present(self) -> None:
        text = CANARY_PS1.read_text(encoding="utf-8")
        assert "measured on the lab run with" in text

    def test_never_says_undetected(self) -> None:
        text = CANARY_PS1.read_text(encoding="utf-8").lower()
        assert "undetected" not in text


# ---------------------------------------------------------------------------
# Hermetic runtime: the script actually runs standalone and emits the schema
# ---------------------------------------------------------------------------

def _canary_run(baseline: str, patched: str, marker: str, *extra: str):
    command = (
        "& '" + str(CANARY_PS1).replace("'", "''") + "' " +
        f"-BaselinePath '{baseline}' -PatchedPath '{patched}' " +
        f"-Marker '{marker}' -WaitSeconds 1 " +
        " ".join(extra)
    )
    return _powershell(command)


class TestRuntime:
    @pytest.mark.skipif(
        not platform.system().lower().startswith("win"),
        reason="the harness runs on a Windows deploy-host-condition host",
    )
    @pytest.mark.skipif(
        shutil.which("powershell") is None,
        reason="powershell.exe not on PATH",
    )
    def test_script_runs_and_emits_the_r6_schema(self, tmp_path) -> None:
        # Hermetic placeholders: a real (unpatched) powershell.exe artifact
        # exercises the cross-process probe; a genuinely-patched artifact would
        # come from the lab.  The status is box-conditional -- only the schema,
        # exit code, and wording are asserted here.
        ps = str(
            Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        )
        placeholder_args = "-Arguments '-NoProfile','-Command','Start-Sleep -Seconds 30'"
        result = _canary_run(ps, ps, "obfuscate-unit-marker-x7", placeholder_args)
        assert result.returncode == 0, (
            f"harness failed rc={result.returncode}: {result.stderr.strip()}"
        )
        stdout = result.stdout.strip()
        assert stdout, "no stdout JSON emitted"
        doc = json.loads(stdout)
        assert set(doc.keys()) == set(CANARY_RECORD_KEYS)
        assert len(doc) == len(CANARY_RECORD_KEYS)
        assert doc["mode"] == "amshi"
        assert doc["status"] in ("pass", "fail", "unknown")
        assert "measured on the lab run with" in doc["detail"]
        assert "baseline" in doc and "patched" in doc and "diff" in doc

    @pytest.mark.skipif(
        not platform.system().lower().startswith("win"),
        reason="the harness runs on a Windows deploy-host-condition host",
    )
    @pytest.mark.skipif(
        shutil.which("powershell") is None,
        reason="powershell.exe not on PATH",
    )
    def test_missing_artifact_is_a_harness_failure(self, tmp_path) -> None:
        # Literal path that cannot exist.
        bogus = str(tmp_path / "does_not_exist_9f4c.exe")
        result = _canary_run(bogus, bogus, "obfuscate-unit-marker-x7")
        assert result.returncode != 0
        assert "harness error" in result.stderr.lower()