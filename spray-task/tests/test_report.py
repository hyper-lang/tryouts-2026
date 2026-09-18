"""Unit tests for the JSON report writer (spraytask.report, R5 / acceptance 4)."""

import json
import os

import pytest

from spraytask.creds import Credential, MASKED
from spraytask.report import DEFAULT_REPORT_PATH, write_report

PASSWORD_SECRET = "s3cret-Pass!#word"
NULL_LM = "aad3b435b51404eeaad3b435b51404ee"
RAW_HASH = "0123456789abcdef0123456789abcdef"
NORMALIZED_HASH = f"{NULL_LM}:{RAW_HASH}"

TS = "2026-09-06T12:00:00+00:00"

CANONICAL_STATUSES = [
    "ok",
    "auth_failed",
    "no_admin",
    "unreachable",
    "payload_too_large",
    "method_error",
    "error",
]

OK_HOST = {
    "address": "10.0.0.1",
    "port": 445,
    "methods": ["ms-tsch"],
    "status": "ok",
    "detail": "",
}


def _cli_args(**overrides):
    args = {
        "hostfile": "hosts.txt",
        "user": "svc",
        "password": PASSWORD_SECRET,
        "domain": "CORP",
        "hash": None,
        "command": "whoami",
        "task_name": "SprayTask_123",
        "interval_minutes": 5,
        "backend": "auto",
        "threads": 10,
        "report": "spray-task-report.json",
        "try_all": False,
    }
    args.update(overrides)
    return args


def _click_run_meta(**overrides):
    meta = {"timestamp": TS, "cli_args": _cli_args()}
    meta.update(overrides)
    return meta


# --- schema shape & stable key order ------------------------------------------


def test_schema_shape_and_stable_key_order(tmp_path):
    path = tmp_path / "report.json"
    host_results = [
        {
            "address": "10.0.0.1",
            "port": 445,
            "methods": ["ms-tsch"],
            "status": "ok",
            "detail": "",
        },
        {
            "address": "ws001",
            "port": None,
            "methods": ["ms-tsch", "psexec"],
            "status": "auth_failed",
            "detail": "SMB login rejected",
        },
    ]
    summary = {
        "status_counts": {"ok": 1, "auth_failed": 1},
        "elapsed_seconds": 3.25,
    }
    write_report(
        path,
        run_meta=_click_run_meta(),
        host_results=host_results,
        summary=summary,
    )

    data = json.loads(path.read_text(encoding="utf-8"))
    assert list(data) == ["metadata", "hosts", "summary"]

    meta = data["metadata"]
    assert list(meta) == ["timestamp", "cli_args", "secrets_masked"]
    assert meta["timestamp"] == TS
    assert meta["secrets_masked"] is True
    assert list(meta["cli_args"]) == list(_cli_args())
    assert meta["cli_args"]["password"] == MASKED
    assert meta["cli_args"]["hash"] is None
    assert meta["cli_args"]["user"] == "svc"

    assert len(data["hosts"]) == 2
    first, second = data["hosts"]
    assert list(first) == ["address", "port", "methods", "status", "detail"]
    assert first == {
        "address": "10.0.0.1",
        "port": 445,
        "methods": ["ms-tsch"],
        "status": "ok",
        "detail": "",
    }
    assert list(second) == ["address", "port", "methods", "status", "detail"]
    assert second["methods"] == ["ms-tsch", "psexec"]
    assert second["status"] == "auth_failed"
    assert second["port"] is None

    assert list(data["summary"]) == ["status_counts", "elapsed_seconds"]
    assert list(data["summary"]["status_counts"]) == CANONICAL_STATUSES
    assert data["summary"]["status_counts"]["ok"] == 1
    assert data["summary"]["status_counts"]["auth_failed"] == 1
    assert data["summary"]["status_counts"]["no_admin"] == 0
    assert data["summary"]["elapsed_seconds"] == 3.25


def test_default_report_path_constant():
    assert DEFAULT_REPORT_PATH == "spray-task-report.json"


# --- masking guarantee --------------------------------------------------------


def test_password_and_hash_never_reach_disk(tmp_path):
    path = tmp_path / "masked.json"
    cli_args = _cli_args(hash=RAW_HASH, command=f"echo {PASSWORD_SECRET}")
    run_meta = {
        "timestamp": TS,
        "cli_args": cli_args,
        "argv": ["spraytask", "-p", PASSWORD_SECRET, "--hash", RAW_HASH, "hosts.txt"],
        "global_credential": Credential(domain="CORP", user="svc", nt_hash=RAW_HASH),
    }
    summary = {"status_counts": {"ok": 1}, "elapsed_seconds": 0.5}
    write_report(
        path,
        run_meta=run_meta,
        host_results=[OK_HOST],
        summary=summary,
    )

    raw = path.read_bytes()
    for secret in (PASSWORD_SECRET, RAW_HASH, NORMALIZED_HASH):
        assert secret.encode("utf-8") not in raw, f"secret leaked in {path.name}"

    text = path.read_text(encoding="utf-8")
    for secret in (PASSWORD_SECRET, RAW_HASH, NORMALIZED_HASH):
        assert secret not in text

    data = json.loads(text)
    assert data["metadata"]["cli_args"]["password"] == MASKED
    assert data["metadata"]["cli_args"]["hash"] == MASKED
    assert data["metadata"]["argv"][2] == MASKED
    assert data["metadata"]["argv"][4] == MASKED
    assert data["metadata"]["global_credential"] == {
        "domain": "CORP",
        "user": "svc",
        "auth_type": "nt_hash",
    }
    assert MASKED in text


def test_substring_scrub_covers_embedded_secret(tmp_path):
    path = tmp_path / "embed.json"
    run_meta = {
        "timestamp": TS,
        "cli_args": _cli_args(command=f"echo prefix-{PASSWORD_SECRET}-suffix"),
    }
    write_report(
        path,
        run_meta=run_meta,
        host_results=[OK_HOST],
        summary={"status_counts": {"ok": 1}, "elapsed_seconds": 0.5},
    )
    text = path.read_text(encoding="utf-8")
    assert PASSWORD_SECRET not in text
    assert "prefix-" in text and "-suffix" in text


def test_redact_applies_to_credential_anywhere(tmp_path):
    path = tmp_path / "cred.json"
    cred = Credential(user="svc", password=PASSWORD_SECRET)
    run_meta = {"timestamp": TS, "cli_args": {}, "creds_snapshot": [cred]}
    write_report(
        path,
        run_meta=run_meta,
        host_results=[OK_HOST],
        summary={"status_counts": {"ok": 1}, "elapsed_seconds": 0.0},
    )
    text = path.read_text(encoding="utf-8")
    assert PASSWORD_SECRET not in text
    data = json.loads(text)
    assert data["metadata"]["creds_snapshot"] == [
        {"domain": "", "user": "svc", "auth_type": "password"}
    ]


# --- aggregation ---------------------------------------------------------------


def test_empty_run_zero_filled_counts(tmp_path):
    path = tmp_path / "empty.json"
    write_report(
        path,
        run_meta=_click_run_meta(),
        host_results=[],
        summary={"status_counts": {}, "elapsed_seconds": 0.0},
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["hosts"] == []
    assert data["summary"]["elapsed_seconds"] == 0.0
    assert data["summary"]["status_counts"] == {
        status: 0 for status in CANONICAL_STATUSES
    }


def test_multi_host_counts_from_records_when_not_provided(tmp_path):
    path = tmp_path / "multi.json"
    statuses = [
        "ok",
        "ok",
        "auth_failed",
        "unreachable",
        "payload_too_large",
        "no_admin",
        "method_error",
        "error",
    ]
    host_results = [
        {
            "address": f"10.0.0.{index}",
            "port": None,
            "methods": ["wmi"],
            "status": status,
            "detail": "",
        }
        for index, status in enumerate(statuses, start=1)
    ]
    write_report(
        path,
        run_meta=_click_run_meta(),
        host_results=host_results,
        summary={"elapsed_seconds": 2.5},
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    counts = data["summary"]["status_counts"]
    assert counts["ok"] == 2
    assert counts["auth_failed"] == 1
    assert counts["no_admin"] == 1
    assert counts["unreachable"] == 1
    assert counts["payload_too_large"] == 1
    assert counts["method_error"] == 1
    assert counts["error"] == 1
    assert data["summary"]["elapsed_seconds"] == 2.5
    assert len(data["hosts"]) == 8


def test_accepted_status_enum_values(tmp_path):
    path = tmp_path / "enum.json"
    write_report(
        path,
        run_meta=_click_run_meta(),
        host_results=[{**OK_HOST, "status": "method_error"}],
        summary={"status_counts": {"ok": 1}, "elapsed_seconds": 1.0},
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["hosts"][0]["status"] == "method_error"


# --- object-shaped host records -------------------------------------------------


class _Result:
    """Attribute-shaped stand-in for a backend attempt outcome."""

    def __init__(self, status, method, detail=""):
        self.status = status
        self.method = method
        self.detail = detail


def test_accepts_object_shaped_host_records(tmp_path):
    path = tmp_path / "results.json"
    results = [
        _Result(status="ok", method="ms-tsch"),
        _Result(status="unreachable", method="psexec", detail="timed out"),
    ]
    write_report(
        path,
        run_meta=_click_run_meta(),
        host_results=results,
        summary={"status_counts": {"ok": 1, "unreachable": 1}, "elapsed_seconds": 1.25},
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    assert [h["status"] for h in data["hosts"]] == ["ok", "unreachable"]
    assert data["hosts"][0]["methods"] == ["ms-tsch"]
    assert data["hosts"][1]["methods"] == ["psexec"]
    assert data["hosts"][1]["detail"] == "timed out"
    assert data["summary"]["status_counts"]["ok"] == 1
    assert data["summary"]["status_counts"]["unreachable"] == 1


def test_real_backend_results_with_status_enum(tmp_path):
    from spraytask.backends.base import BackendResult, Status

    path = tmp_path / "backend.json"
    results = [
        BackendResult(host="10.0.0.1", status=Status.UNREACHABLE, method="ms-tsch",
                      detail="cannot connect: timed out"),
        BackendResult(host="10.0.0.2", status=Status.OK, method="ms-tsch"),
        BackendResult(host="10.0.0.3", status=Status.PAYLOAD_TOO_LARGE, method="psexec",
                      detail="encoded action length 300 exceeds schtasks /TR cap of 261"),
    ]
    summary = {
        "status_counts": {
            Status.UNREACHABLE: 1,
            Status.OK: 1,
            Status.PAYLOAD_TOO_LARGE: 1,
        },
        "elapsed_seconds": 2.0,
    }
    write_report(
        path,
        run_meta=_click_run_meta(),
        host_results=results,
        summary=summary,
    )

    data = json.loads(path.read_text(encoding="utf-8"))
    assert [h["status"] for h in data["hosts"]] == [
        "unreachable",
        "ok",
        "payload_too_large",
    ]
    assert data["hosts"][0]["methods"] == ["ms-tsch"]
    assert data["hosts"][1]["address"] == "10.0.0.2"
    assert data["hosts"][2]["methods"] == ["psexec"]
    assert data["hosts"][0]["detail"].startswith("cannot connect")
    assert data["summary"]["status_counts"]["unreachable"] == 1
    assert data["summary"]["status_counts"]["ok"] == 1
    assert data["summary"]["status_counts"]["payload_too_large"] == 1
    assert data["summary"]["status_counts"]["auth_failed"] == 0


# --- atomic write --------------------------------------------------------------


def test_atomic_write_preserves_previous_report_on_failure(tmp_path, monkeypatch):
    path = tmp_path / "r.json"
    write_report(
        path,
        run_meta=_click_run_meta(),
        host_results=[OK_HOST],
        summary={"status_counts": {"ok": 1}, "elapsed_seconds": 0.5},
    )
    before = path.read_text(encoding="utf-8")

    def boom(src, dst):
        raise OSError("simulated crash mid-replace")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        write_report(
            path,
            run_meta=_click_run_meta(),
            host_results=[],
            summary={"status_counts": {}, "elapsed_seconds": 0.0},
        )
    assert path.read_text(encoding="utf-8") == before
    assert [p for p in tmp_path.iterdir() if p.suffix == ".tmp"] == []


def test_write_replaces_previous_report_and_leaves_no_temp(tmp_path):
    path = tmp_path / "r.json"
    write_report(
        path,
        run_meta=_click_run_meta(),
        host_results=[OK_HOST],
        summary={"status_counts": {"ok": 1}, "elapsed_seconds": 0.5},
    )
    write_report(
        path,
        run_meta=_click_run_meta(),
        host_results=[OK_HOST, OK_HOST],
        summary={"status_counts": {"ok": 2}, "elapsed_seconds": 1.5},
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    assert len(data["hosts"]) == 2
    assert data["summary"]["elapsed_seconds"] == 1.5
    assert [p.name for p in tmp_path.iterdir()] == ["r.json"]


def test_written_file_is_utf8_trailing_newline(tmp_path):
    path = tmp_path / "r.json"
    write_report(
        path,
        run_meta=_click_run_meta(),
        host_results=[OK_HOST],
        summary={"status_counts": {"ok": 1}, "elapsed_seconds": 0.0},
    )
    raw = path.read_bytes()
    assert raw.endswith(b"\n")
    json.loads(raw.decode("utf-8"))  # valid UTF-8 JSON