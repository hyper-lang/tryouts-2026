"""Unit tests for the payload/task-action builder (spraytask.payload, R3)."""

import base64

import pytest

from spraytask import payload


# --- PowerShell action building -------------------------------------------------

def test_powershell_action_is_single_encoded_command_line():
    script = "whoami; whoami /groups"
    action = payload.encode_powershell_action(script)
    assert action.startswith(
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
    )
    encoded = action.split()[-1]
    decoded = base64.b64decode(encoded).decode("utf-16-le")
    assert decoded == script


def test_join_ps_statements_joins_in_order():
    assert payload.join_ps_statements(["a", "b", "c"]) == "a;b;c"
    assert payload.join_ps_statements([]) == ""


def test_build_action_command_command_mode_verbatim():
    cmd = r"C:\Windows\Temp\probe.exe -force"
    assert payload.build_action_command(cmd) == cmd


def test_build_action_command_ps_mode_encoded():
    action = payload.build_action_command(None, ["whoami"])
    assert action.startswith("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ")
    assert "whoami" not in action
    decoded = base64.b64decode(action.split()[-1]).decode("utf-16-le")
    assert decoded == "whoami"


def test_encoded_command_has_no_embedded_quotes_for_schtasks():
    action = payload.build_action_command(None, ['Write-Output "dangerous quotes"'])
    for bad in ('"', "'"):
        assert bad not in action  # quote-free action line survives /TR quoting
    assert " " not in action.split()[-1]  # the -EncodedCommand token is a single word


# --- size cap semantics ---------------------------------------------------------

def test_exceeds_cap_boundaries():
    assert payload.exceeds_cap("x" * 261) is False
    assert payload.exceeds_cap("x" * 262) is True


# --- MS-TSCH Task 2.0 XML -------------------------------------------------------

def test_ms_tsch_xml_has_repetition_trigger():
    xml = payload.build_ms_tsch_xml("whoami /all", 5, start_boundary="2026-01-01T00:00:00")
    assert '<Repetition>' in xml
    assert '<Interval>PT5M</Interval>' in xml
    assert '<StopAtDurationEnd>false</StopAtDurationEnd>' in xml
    assert '<TimeTrigger>' in xml
    assert '<StartBoundary>2026-01-01T00:00:00</StartBoundary>' in xml


def test_ms_tsch_xml_interval_formatting():
    xml = payload.build_ms_tsch_xml("x", 30, start_boundary="2026-01-01T00:00:00")
    assert '<Interval>PT30M</Interval>' in xml


def test_ms_tsch_xml_system_high_principal():
    xml = payload.build_ms_tsch_xml("x", 5, start_boundary="2026-01-01T00:00:00")
    assert '<UserId>S-1-5-18</UserId>' in xml
    assert '<RunLevel>HighestAvailable</RunLevel>' in xml
    assert '<LogonType>Password</LogonType>' in xml


def test_ms_tsch_xml_settings():
    xml = payload.build_ms_tsch_xml("x", 5, start_boundary="2026-01-01T00:00:00")
    assert '<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>' in xml
    assert '<AllowStartOnDemand>true</AllowStartOnDemand>' in xml


def test_ms_tsch_xml_exec_split_command_arguments():
    xml = payload.build_ms_tsch_xml(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Bypass",
        5,
        start_boundary="2026-01-01T00:00:00",
    )
    assert (
        "<Command>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Command>" in xml
    )
    assert "<Arguments>-NoProfile -Bypass</Arguments>" in xml


def test_ms_tsch_xml_embeds_encoded_command_as_single_argument():
    action = payload.encode_powershell_action("whoami")
    xml = payload.build_ms_tsch_xml(action, 5, start_boundary="2026-01-01T00:00:00")
    encoded = action.split()[-1]
    assert "<Command>powershell.exe</Command>" in xml
    assert f"<Arguments>-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}</Arguments>" in xml


def test_ms_tsch_xml_escapes_metacharacters():
    xml = payload.build_ms_tsch_xml(
        'a&b<c>d"e\'f', 5, start_boundary="2026-01-01T00:00:00", task_name="n&<x>"
    )
    assert "&amp;" in xml and "&lt;" in xml and "&gt;" in xml and "&quot;" in xml and "&apos;" in xml
    assert "a&b" not in xml
    assert "n&<x>" not in xml
    root = xml.split("<Task")[-1]
    assert "<Command>a&amp;b&lt;c&gt;d&quot;e&apos;f</Command>" in xml


def test_ms_tsch_xml_has_utf16_declaration():
    xml = payload.build_ms_tsch_xml("x", 5, start_boundary="2026-01-01T00:00:00")
    assert xml.startswith('<?xml version="1.0" encoding="UTF-16"?>')


# --- command line splitting ------------------------------------------------------

def test_split_command_line_basic():
    assert payload.split_command_line("prog -a -b") == ("prog", "-a -b")


def test_split_command_line_single_token():
    assert payload.split_command_line("prog") == ("prog", "")


def test_split_command_line_quoted_path_with_spaces():
    assert payload.split_command_line(r'"C:\Program Files\x.exe" -a') == (
        r"C:\Program Files\x.exe",
        "-a",
    )


def test_split_command_line_empty():
    assert payload.split_command_line("   ") == ("", "")


# --- schtasks.exe templates -----------------------------------------------------

def test_schtasks_create_cmd_shape():
    cmd = payload.schtasks_create_cmd("SprayTask_1", "powershell.exe -EncodedCommand AQ==", 5)
    assert cmd.startswith('schtasks /Create /F /TN "SprayTask_1" /TR "powershell.exe -EncodedCommand AQ==" ')
    assert "/SC MINUTE /MO 5 /RU SYSTEM /RL HIGHEST" in cmd


def test_schtasks_create_cmd_never_uses_it_or_ri():
    cmd = payload.schtasks_create_cmd("t", "a", 5)
    assert "/IT" not in cmd
    assert "/RI" not in cmd
    run = payload.schtasks_run_cmd("t")
    assert run == 'schtasks /Run /TN "t"'


# --- static: payload is embedded, never written to a remote file ----------------

def test_payload_builder_has_no_file_writing_code():
    with open(payload.__file__, encoding="utf-8") as handle:
        text = handle.read()
    for file_construct in ("open(", ".write(", ".write_bytes(", "sftp", "put_file"):
        assert file_construct not in text