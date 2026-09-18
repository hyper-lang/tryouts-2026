"""Unit tests for the spray-task scaffolding: CLI entry point and version guard."""

import pathlib

import pytest

from spraytask import cli

PACKAGE_ROOT = pathlib.Path(cli.__file__).resolve().parent


# --- impacket version parsing ------------------------------------------------

@pytest.mark.parametrize(
    ("version_str", "expected"),
    [
        ("0.13.1", (0, 13, 1)),
        ("0.13.1.dev1", (0, 13, 1)),
        ("0.12.0", (0, 12, 0)),
        ("1.0.0", (1, 0, 0)),
        ("0.13", (0, 13, 0)),
        ("garbage", (0, 0, 0)),
    ],
)
def test_parse_impacket_version(version_str, expected):
    assert cli.parse_impacket_version(version_str) == expected


# --- startup version guard ---------------------------------------------------

def test_warn_when_impacket_too_old(capsys):
    cli.warn_if_impacket_too_old(version=(0, 12, 0))
    err = capsys.readouterr().err
    assert "Warning: impacket 0.12.0 is older than 0.13.0" in err


def test_no_warning_when_impacket_current(capsys):
    cli.warn_if_impacket_too_old(version=(0, 13, 1))
    assert capsys.readouterr().err == ""


def test_guard_warns_but_does_not_raise():
    cli.warn_if_impacket_too_old(version=(0, 12, 0))


# --- --version output --------------------------------------------------------

def test_version_flag_prints_both_versions(capsys):
    assert cli.main(["--version"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("Python ")
    assert "impacket " in out


def test_no_args_prints_help_and_exits_1(capsys):
    assert cli.main([]) == 1
    out = capsys.readouterr().out
    assert "spraytask" in out


def test_unknown_flag_exits_1():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--definitely-not-a-flag"])
    assert exc_info.value.code == 1


def test_help_exits_0(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "--version" in out


def test_old_impacket_warns_but_still_runs(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_impacket_version_raw", lambda: "0.12.0")
    code = cli.main(["--version"])
    captured = capsys.readouterr()
    assert code == 0
    assert "impacket 0.12.0" in captured.out
    assert "older than" in captured.err


# --- static checks -----------------------------------------------------------

def test_no_multiprocessing_process_in_package():
    offenders = []
    for path in PACKAGE_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "multiprocessing" in text and "Process" in text:
            offenders.append(str(path))
    assert offenders == []