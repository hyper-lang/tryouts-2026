"""End-to-end CLI tests (spraytask.cli, task 10 / acceptance 1, 2, 4, 10).

The backend runner is swapped for a fake so the flag surface, the validation,
the credential precedence, the report contract and the masking guarantee are
exercised without any impacket network call. The JSON report is written by the
real ``report.write_report`` where the byte-level masking promise is asserted.
"""

import base64
import json
import re

import pytest

from spraytask import cli
from spraytask.backends.base import ALL_STATUSES, BackendResult, Status
from spraytask.creds import MASKED
from spraytask import report as report_mod
from spraytask import runner as runner_mod


NULL_LM = "aad3b435b51404eeaad3b435b51404ee"
RAW_HASH = "0123456789abcdef0123456789abcdef"
NORMALIZED_HASH = f"{NULL_LM}:{RAW_HASH}"
PASSWORD = "S3cret-pw!#zz"

ALL_HELP_TOKENS = [
    "HOSTFILE",
    "--version",
    "-u",
    "--user",
    "-p",
    "--password",
    "-d",
    "--domain",
    "--hash",
    "--command",
    "--ps-command",
    "--ps-file",
    "--task-name",
    "--interval-minutes",
    "--backend",
    "--threads",
    "--try-all",
    "--report",
    "ms-tsch",
    "psexec",
    "wmi",
    "auto",
]


class FakeRunner:
    """A recording Runner stand-in: per-host plan, uniform effective_order."""

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.specs = []
        self.plan = {}

    def run(self, specs):
        self.specs = list(specs)
        results = []
        for spec in self.specs:
            if spec.host in self.plan:
                results.append(self.plan[spec.host])
            else:
                results.append(BackendResult.ok(spec.host, "ms-tsch", "fake ok"))
        return runner_mod.RunSummary(
            results=tuple(results),
            elapsed=0.25,
            counts=runner_mod.count_results(results),
            exit_code=0 if all(r.status == Status.OK for r in results) else 2,
        )

    def effective_order(self, spec):
        if len(spec.action) > 261:
            return ("ms-tsch",)
        return ("ms-tsch", "psexec", "wmi")


def _install(monkeypatch, *, capture_report=True):
    """Swap the runner for a fake; returns (runner, report_spy)."""
    fake = FakeRunner()

    def _factory(**kwargs):
        fake.kwargs.update(kwargs)
        return fake

    monkeypatch.setattr(runner_mod, "Runner", _factory)
    seen = {}

    if capture_report:
        def _record(path, *, run_meta, host_results, summary):
            seen.update(
                path=str(path),
                run_meta=run_meta,
                host_results=host_results,
                summary=summary,
            )
            return str(path)

        monkeypatch.setattr(report_mod, "write_report", _record)
    return fake, seen


def _write_hosts(tmp_path, lines):
    path = tmp_path / "hosts.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def _decode_action(action):
    encoded = action.split()[-1]
    return base64.b64decode(encoded).decode("utf-16-le")


# --- --help documents every flag (acceptance 1) ---------------------------------

def test_help_documents_every_flag():
    help_text = cli.build_parser().format_help()
    for token in ALL_HELP_TOKENS:
        assert token in help_text, f"flag {token!r} not documented in --help"


def test_unknown_flag_exits_1():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--definitely-not-a-flag"])
    assert exc_info.value.code == 1


def test_bare_invocation_prints_help_and_exits_1(capsys):
    assert cli.main([]) == 1
    assert "--version" in capsys.readouterr().out


# --- numeric validation (acceptance 10) ------------------------------------------

def test_interval_minutes_zero_exits_1(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--interval-minutes", "0", "--command", "whoami", "h.txt"])
    assert exc_info.value.code == 1
    assert "interval-minutes" in capsys.readouterr().err


def test_interval_minutes_non_numeric_exits_1():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--interval-minutes", "abc", "--command", "whoami", "h.txt"])
    assert exc_info.value.code == 1


def test_threads_zero_exits_1():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--threads", "0", "--command", "whoami", "h.txt"])
    assert exc_info.value.code == 1


# --- payload modes (R3) -----------------------------------------------------------

def test_command_payload_passed_verbatim_to_specs(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["wc01"])
    code = cli.main(
        ["--command", "whoami /all", "--task-name", "T1", hostfile]
    )
    assert code == 0
    assert [spec.action for spec in fake.specs] == ["whoami /all"]
    assert fake.specs[0].task_name == "T1"


def test_ps_commands_joined_in_order(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["wc01"])
    code = cli.main(
        [
            "--ps-command", "whoami",
            "--ps-command", "Get-Date; ipconfig",
            hostfile,
        ]
    )
    assert code == 0
    action = fake.specs[0].action
    assert action.startswith(
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy "
        "Bypass -EncodedCommand "
    )
    assert _decode_action(action) == "whoami;Get-Date; ipconfig"


def test_ps_file_is_read_locally_one_statement_per_line(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["wc01"])
    ps_file = tmp_path / "script.ps1"
    ps_file.write_text("whoami\nGet-Date\n\n", encoding="utf-8")
    code = cli.main(["--ps-file", str(ps_file), hostfile])
    assert code == 0
    assert _decode_action(fake.specs[0].action) == "whoami;Get-Date"


def test_ps_commands_precede_ps_files(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["wc01"])
    ps_file = tmp_path / "script.ps1"
    ps_file.write_text("Third\n", encoding="utf-8")
    code = cli.main(
        [
            "--ps-command", "First",
            "--ps-file", str(ps_file),
            "--ps-command", "Second",
            hostfile,
        ]
    )
    assert code == 0
    assert _decode_action(fake.specs[0].action) == "First;Second;Third"


def test_command_and_ps_mode_are_mutually_exclusive(monkeypatch, tmp_path):
    _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["wc01"])
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--command", "whoami", "--ps-command", "ipconfig", hostfile])
    assert exc_info.value.code == 1


def test_no_payload_mode_exits_1(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["wc01"])
    with pytest.raises(SystemExit) as exc_info:
        cli.main([hostfile])
    assert exc_info.value.code == 1
    assert fake.specs == []


def test_missing_ps_file_exits_1(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--ps-file", "nope.ps1", "--command", "x", "h.txt"])
    assert exc_info.value.code == 1
    assert "cannot read --ps-file" in capsys.readouterr().err


# --- credential rules (R2) ----------------------------------------------------------

def test_global_password_credential(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["wc01"])
    code = cli.main(["-u", "svc", "-p", PASSWORD, "--command", "whoami", hostfile])
    assert code == 0
    cred = fake.specs[0].cred
    assert cred.user == "svc"
    assert cred.password == PASSWORD
    assert cred.nt_hash is None


def test_global_hash_credential_is_normalized(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["wc01"])
    code = cli.main(["-u", "svc", "--hash", RAW_HASH, "--command", "whoami", hostfile])
    assert code == 0
    cred = fake.specs[0].cred
    assert cred.nt_hash == NORMALIZED_HASH
    assert cred.password is None


def test_user_without_secret_exits_1():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["-u", "svc", "--command", "whoami", "h.txt"])
    assert exc_info.value.code == 1


def test_secret_without_user_exits_1():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["-p", PASSWORD, "--command", "whoami", "h.txt"])
    assert exc_info.value.code == 1


def test_password_and_hash_mutually_exclusive_exits_1():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["-u", "svc", "-p", PASSWORD, "--hash", RAW_HASH,
                  "--command", "whoami", "h.txt"])
    assert exc_info.value.code == 1


def test_invalid_hash_exits_1_and_never_echoes_raw(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["-u", "svc", "--hash", "zzz-not-a-hash",
                  "--command", "whoami", "h.txt"])
    assert exc_info.value.code == 1
    assert "zzz-not-a-hash" not in capsys.readouterr().err


def test_per_host_override_wins_over_global(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["CORP\\alice:TopSecret!@ws01", "ws02"])
    code = cli.main(
        ["-u", "bob", "-p", "GlobalPass", "--command", "whoami", hostfile]
    )
    assert code == 0
    first, second = fake.specs
    assert first.host == "ws01"
    assert first.cred.user == "alice"
    assert first.cred.password == "TopSecret!"
    assert first.cred.domain == "CORP"
    assert second.host == "ws02"
    assert second.cred.user == "bob"
    assert second.cred.password == "GlobalPass"


def test_host_without_override_uses_global_credential(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["ws01", "other:White@ws02"])
    cli.main(["-u", "bob", "-p", "GlobalPass", "--command", "whoami", hostfile])
    assert fake.specs[0].cred.user == "bob"
    assert fake.specs[1].cred.user == "other"
    assert fake.specs[1].cred.password == "White"


# --- task defaults & runner wiring --------------------------------------------------

def test_default_task_name_is_epoch_prefixed(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["wc01"])
    cli.main(["--command", "whoami", hostfile])
    assert re.fullmatch(r"SprayTask_\d+", fake.specs[0].task_name)


def test_backend_auto_passes_no_order_and_pin_passes_single(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["wc01"])
    cli.main(["--command", "whoami", hostfile])
    assert fake.kwargs["order"] is None

    fake, _ = _install(monkeypatch)
    cli.main(["--command", "whoami", "--backend", "psexec", hostfile])
    assert fake.kwargs["order"] == ["psexec"]


def test_try_all_and_threads_flags_reach_runner(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["wc01"])
    cli.main(["--command", "whoami", "--try-all", "--threads", "3", hostfile])
    assert fake.kwargs["try_all"] is True
    assert fake.kwargs["threads"] == 3


def test_interval_and_task_name_reach_specs(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["wc01"])
    cli.main(["--command", "whoami", "--interval-minutes", "9",
              "--task-name", "NamedTask", hostfile])
    spec = fake.specs[0]
    assert spec.interval_minutes == 9
    assert spec.task_name == "NamedTask"


# --- exit codes ----------------------------------------------------------------------

def test_exit_code_0_when_every_host_ok(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["wc01", "wc02"])
    assert cli.main(["--command", "whoami", hostfile]) == 0


def test_exit_code_2_on_any_host_failure_but_report_written(monkeypatch, tmp_path):
    fake, seen = _install(monkeypatch)
    fake.plan["wc02"] = BackendResult(
        "wc02", Status.AUTH_FAILED, "ms-tsch", "login rejected (0xc000006d)"
    )
    hostfile = _write_hosts(tmp_path, ["wc01", "wc02"])
    assert cli.main(["--command", "whoami", hostfile]) == 2
    statuses = [record["status"] for record in seen["host_results"]]
    assert statuses == [Status.OK, Status.AUTH_FAILED]
    assert seen["summary"]["status_counts"]["auth_failed"] == 1


# --- report schema & masking (acceptance 4) -------------------------------------------

def test_report_written_with_pinned_cli_args(monkeypatch, tmp_path):
    fake, seen = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["wc01"])
    cli.main(["-u", "svc", "-p", PASSWORD, "--command", "whoami",
              "--task-name", "T9", "--report", "out.json", hostfile])
    assert seen["path"] == "out.json"
    cli_args = seen["run_meta"]["cli_args"]
    for key in (
        "hostfile", "user", "password", "hash", "domain", "command",
        "task_name", "interval_minutes", "backend", "threads", "report",
        "try_all",
    ):
        assert key in cli_args
    assert cli_args["password"] == PASSWORD  # raw in cli_args; masked by report
    assert seen["summary"]["status_counts"] == {
        status: (1 if status == "ok" else 0) for status in ALL_STATUSES
    }
    records = seen["host_results"]
    assert records[0]["address"] == "wc01"
    assert records[0]["methods"] == ["ms-tsch", "psexec", "wmi"]
    assert records[0]["status"] == Status.OK


def test_report_byte_scan_password_never_on_disk(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch, capture_report=False)
    hostfile = _write_hosts(tmp_path, ["10.0.0.1"])
    report_path = tmp_path / "r-pw.json"
    argv = [
        "-u", "svc", "-p", PASSWORD,
        "--command", f"echo prefix-{PASSWORD}-suffix",
        "--report", str(report_path), hostfile,
    ]
    assert cli.main(argv) == 0
    raw = report_path.read_bytes()
    assert PASSWORD.encode("utf-8") not in raw
    text = report_path.read_text(encoding="utf-8")
    assert MASKED in text
    data = json.loads(text)
    password_index = argv.index(PASSWORD)
    assert data["metadata"]["cli_args"]["password"] == MASKED
    assert data["metadata"]["argv"][password_index] == MASKED
    assert "prefix-" in text and "-suffix" in text


def test_report_byte_scan_hash_never_on_disk(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch, capture_report=False)
    hostfile = _write_hosts(tmp_path, ["10.0.0.2"])
    report_path = tmp_path / "r-hash.json"
    argv = [
        "-u", "svc", "--hash", RAW_HASH,
        "--command", "whoami", "--report", str(report_path), hostfile,
    ]
    assert cli.main(argv) == 0
    raw = report_path.read_bytes()
    for secret in (RAW_HASH, NORMALIZED_HASH):
        assert secret.encode("utf-8") not in raw, f"hash leaked: {secret}"
    data = json.loads(report_path.read_text(encoding="utf-8"))
    assert data["metadata"]["cli_args"]["hash"] == MASKED
    assert data["metadata"]["argv"][argv.index(RAW_HASH)] == MASKED
    assert data["metadata"]["global_credential"] == {
        "domain": "",
        "user": "svc",
        "auth_type": "nt_hash",
    }


# --- host-file strictness (R1) --------------------------------------------------------

def test_malformed_host_line_aborts_and_never_echoes_password(monkeypatch, tmp_path, capsys):
    fake, _ = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["wc01", "alice:pw1!@wc02@extra"])
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["-u", "svc", "-p", PASSWORD, "--command", "whoami", hostfile])
    assert exc_info.value.code == 1
    assert fake.specs == []  # nothing was run
    err = capsys.readouterr().err
    assert "line 2" in err
    assert "must contain exactly one '@'" in err
    assert "pw1!" not in err
    assert PASSWORD not in err


def test_missing_host_file_exits_1(capsys, monkeypatch):
    fake, _ = _install(monkeypatch)
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--command", "whoami", "does-not-exist.txt"])
    assert exc_info.value.code == 1
    assert fake.specs == []
    assert "cannot read host file" in capsys.readouterr().err


def test_empty_host_file_is_a_zero_host_run(monkeypatch, tmp_path):
    fake, _ = _install(monkeypatch)
    hostfile = tmp_path / "empty.txt"
    hostfile.write_text("# no hosts\n\n", encoding="utf-8")
    assert cli.main(["--command", "whoami", str(hostfile)]) == 0
    assert fake.specs == []


# --- stdout never carries secrets -------------------------------------------------------

def test_stdout_never_contains_password(monkeypatch, tmp_path, capsys):
    fake, _ = _install(monkeypatch)
    hostfile = _write_hosts(tmp_path, ["wc01"])
    cli.main(["-u", "svc", "-p", PASSWORD,
              "--command", f"echo {PASSWORD}", hostfile])
    out = capsys.readouterr().out
    assert PASSWORD not in out