"""Unit tests for the WMI backend (spraytask/backends/wmi.py, task 8).

The DCOM layer is swapped for a monkeypatched ``provider_factory`` (the
backend's injection seam) so the connect/login, the R4 size preflight and the
``Win32_Process.Create`` exec flow can be asserted without a live host. Every
exec command must carry the ``cmd.exe /c `` prefix (the fixed
``CreateProcess``-has-no-shell gap from the psexec task), and failure mapping
flows through ``base.classify`` -- this module never buckets raw codes itself.
"""

import socket

import pytest

import spraytask.backends.wmi as wmi
from spraytask.backends.base import (
    CONNECT_TIMEOUT,
    EXEC_TIMEOUT,
    AuthFailedError,
    MethodError,
    NoAdminError,
    Status,
    UnreachableError,
    build_schtasks_commands,
)
from spraytask.creds import Credential

CRED = Credential(user="alice", password="Secret1!")
HOST = "10.0.0.9"

CMD_PREFIX = "cmd.exe /c "


class _CodeError(Exception):
    """An impacket-shaped error carrying only a numeric code."""

    def __init__(self, code):
        super().__init__(f"code 0x{code:08x}")
        self._code = code

    def get_error_code(self):
        return self._code


class _FakeProvider:
    """Answers for ``Win32_Process.Create``; records the calls on its factory."""

    def __init__(self, factory):
        self._factory = factory

    def exec_command(self, command):
        self._factory.executed.append(command)
        if self._factory.exec_errors:
            raise self._factory.exec_errors.pop(0)

    def close(self):
        self._factory.closed = True


class _FakeFactory:
    """A recording ``provider_factory`` with injectable connect/exec faults."""

    def __init__(self, connect_error=None, exec_errors=()):
        self.connect_error = connect_error
        self.exec_errors = list(exec_errors)
        self.connects = []
        self.executed = []
        self.closed = False

    def connect(self, host, cred, *, connect_timeout, exec_timeout):
        self.connects.append(
            (host, cred, connect_timeout, exec_timeout)
        )
        if self.connect_error is not None:
            raise self.connect_error
        return _FakeProvider(self)


def _deploy(factory=None, **overrides):
    kwargs = dict(
        host=HOST,
        port=445,
        cred=CRED,
        task_name="SprayTask_1",
        action="whoami",
        interval_minutes=5,
    )
    kwargs.update(overrides)
    if factory is not None:
        kwargs["provider_factory"] = factory
    return wmi.deploy(**kwargs)


# --- happy path ----------------------------------------------------------------

def test_deploy_executes_create_then_run_with_cmd_prefix(monkeypatch):
    factory = _FakeFactory()
    result = _deploy(factory)
    assert result.status == Status.OK
    assert result.method == "wmi"
    assert result.host == HOST

    expected = [
        CMD_PREFIX + line
        for line in build_schtasks_commands("SprayTask_1", "whoami", 5)
    ]
    assert factory.executed == expected
    create, run = factory.executed
    assert create.startswith(CMD_PREFIX + "schtasks.exe /Create")
    assert run.startswith(CMD_PREFIX + "schtasks.exe /Run")
    for command in factory.executed:
        assert command.startswith(CMD_PREFIX)
        assert "/IT" not in command
        assert "/RI" not in command
    assert "/F" in create
    assert "/SC MINUTE" in create
    assert "/MO 5" in create
    assert "/RU SYSTEM" in create
    assert "/RL HIGHEST" in create
    assert factory.closed


def test_deploy_passes_connect_and_exec_timeouts_to_provider(monkeypatch):
    factory = _FakeFactory()
    result = _deploy(factory, connect_timeout=2.25, exec_timeout=11.5)
    assert result.status == Status.OK
    (host, cred, connect_timeout, exec_timeout) = factory.connects[0]
    assert host == HOST
    assert cred is CRED
    assert connect_timeout == 2.25
    assert exec_timeout == 11.5


def test_default_timeouts_use_base_contract(monkeypatch):
    factory = _FakeFactory()
    result = _deploy(factory)
    assert result.status == Status.OK
    (_, _, connect_timeout, exec_timeout) = factory.connects[0]
    assert connect_timeout == CONNECT_TIMEOUT
    assert exec_timeout == EXEC_TIMEOUT


# --- size preflight (R4: connect first, cap second, both never merged) ---------

def test_oversized_action_reports_payload_too_large_without_exec(monkeypatch):
    factory = _FakeFactory()
    result = _deploy(factory, action="x" * 262)
    assert result.status == Status.PAYLOAD_TOO_LARGE
    assert factory.connects  # the DCOM connect happened first (R4 order)
    assert factory.executed == []  # no Win32_Process.Create was attempted
    assert factory.closed


def test_cap_is_inclusive_at_261_chars(monkeypatch):
    factory = _FakeFactory()
    result = _deploy(factory, action="x" * 261)
    assert result.status == Status.OK
    assert len(factory.executed) == 2


def test_connect_failure_precedes_size_check_even_oversized(monkeypatch):
    factory = _FakeFactory(connect_error=UnreachableError("cannot connect"))
    result = _deploy(factory, action="x" * 400)
    assert result.status == Status.UNREACHABLE
    assert result.detail == "cannot connect"
    assert factory.executed == []
    assert factory.closed is False


# --- failure classification via base.classify ----------------------------------

@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (UnreachableError("cannot connect"), Status.UNREACHABLE),
        (AuthFailedError("login rejected"), Status.AUTH_FAILED),
        (NoAdminError("WMI denied"), Status.NO_ADMIN),
        (socket.timeout("timed out"), Status.UNREACHABLE),
        (ConnectionRefusedError("refused"), Status.UNREACHABLE),
        (PermissionError("denied"), Status.NO_ADMIN),
        (ValueError("odd"), Status.ERROR),
        (MethodError("rpc broke"), Status.METHOD_ERROR),
        (_CodeError(0xC000006D), Status.AUTH_FAILED),
        (_CodeError(0x80070005), Status.NO_ADMIN),
        (_CodeError(0x800706BA), Status.UNREACHABLE),
        (_CodeError(0x80041013), Status.METHOD_ERROR),
    ],
)
def test_connect_failure_mapping(monkeypatch, exc, expected):
    factory = _FakeFactory(connect_error=exc)
    result = _deploy(factory)
    assert result.status == expected
    assert result.method == "wmi"
    assert result.host == HOST
    assert factory.executed == []


def test_connect_message_only_access_denied_is_auth_failed_not_error(monkeypatch):
    dcerpc = pytest.importorskip("impacket.dcerpc.v5.rpcrt")
    exc = dcerpc.DCERPCException("rpc_s_access_denied", None, None)
    factory = _FakeFactory(connect_error=exc)
    result = _deploy(factory)
    assert result.status == Status.AUTH_FAILED
    assert result.detail == "rpc_s_access_denied"
    assert factory.executed == []
    assert factory.closed is False


def test_connect_message_only_server_unavailable_is_unreachable_not_error(monkeypatch):
    dcerpc = pytest.importorskip("impacket.dcerpc.v5.rpcrt")
    exc = dcerpc.DCERPCException("rpc_s_server_unavailable", None, None)
    factory = _FakeFactory(connect_error=exc)
    result = _deploy(factory)
    assert result.status == Status.UNREACHABLE
    assert factory.executed == []
    assert factory.closed is False


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (PermissionError("denied"), Status.NO_ADMIN),
        (ConnectionError("gone"), Status.UNREACHABLE),
        (ValueError("kaboom"), Status.ERROR),
        (_CodeError(0x80070005), Status.NO_ADMIN),
        (_CodeError(0x80041013), Status.METHOD_ERROR),
        (_CodeError(0xC000006D), Status.AUTH_FAILED),
    ],
)
def test_exec_failure_mapping(monkeypatch, exc, expected):
    factory = _FakeFactory(exec_errors=[exc])
    result = _deploy(factory)
    assert result.status == expected
    assert result.method == "wmi"
    assert factory.executed  # the exec was attempted
    assert factory.closed  # still torn down


# --- missing credential --------------------------------------------------------

def test_no_credential_is_status_error_without_connecting(monkeypatch):
    factory = _FakeFactory()
    result = _deploy(factory, cred=None)
    assert result.status == Status.ERROR
    assert "no credential available" in result.detail
    assert factory.connects == []
    assert factory.closed is False


def test_wmi_port_and_namespace_constants():
    assert wmi.WMI_PORT == 135
    assert wmi.WMI_NAMESPACE == "//./root/cimv2"
    assert wmi.METHOD == "wmi"


# --- static acceptance ---------------------------------------------------------

def test_static_no_remote_payload_file_write():
    with open(wmi.__file__, encoding="utf-8") as handle:
        src = handle.read()
    for token in ("putFile", "copyFile", "copyfile", "write_file", "upload"):
        assert token not in src, f"forbidden file-write token {token!r} in wmi"
    assert "import shutil" not in src


def test_static_uses_wmi_dcom_path_no_schtasks_module():
    with open(wmi.__file__, encoding="utf-8") as handle:
        src = handle.read()
    assert "from impacket.dcerpc.v5.dcom import wmi" in src
    assert "Win32_Process" in src
    assert "impacket.dcerpc.v5.schtasks" not in src
    assert "multiprocessing" not in src


def test_static_exec_commands_carry_cmd_exe_prefix():
    with open(wmi.__file__, encoding="utf-8") as handle:
        src = handle.read()
    assert '"cmd.exe /c " + command' in src