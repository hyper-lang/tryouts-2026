"""Unit tests for the MS-TSCH backend (spraytask/backends/ms_tsch.py, task 6).

The RPC helper functions (``hSchRpcRegisterTask`` / ``hSchRpcRun`` on the real
impacket ``tsch`` module) are swapped for a recording fake so the register/run
call shape, the idempotent create->update retry, and the failure-code mapping
can be asserted without a live Windows host. Failure classification is exercised
exactly as it flows through ``base.classify`` -- this module delegates there and
must never bucket NTSTATUS/HRESULT codes itself.
"""

from contextlib import contextmanager

import socket

import pytest
from impacket import nt_errors
from impacket.dcerpc.v5 import tsch as real_tsch
from impacket.smbconnection import SessionError

import spraytask.backends.ms_tsch as ms_tsch
from spraytask.backends.base import (
    CONNECT_TIMEOUT,
    EXEC_TIMEOUT,
    AuthFailedError,
    Status,
    UnreachableError,
)
from spraytask.creds import Credential

CRED = Credential(user="alice", password="Secret1!")
HOST = "10.0.0.5"


class FakeSchRpc:
    """Records RPC calls; every call is routed through the injected helpers."""

    def __init__(self, register_error=None):
        self.calls = []
        self.register_error = register_error
        self.bound = []
        self._connected = True
        self.disconnected = False

    def connect(self):
        self._connected = True

    def bind(self, uuid):
        self.bound.append(uuid)

    def disconnect(self):
        self.disconnected = True

    def register(self, dce, *, path, xml, flags, sddl, logonType, pCreds):
        self.calls.append(("register", path, flags, xml, sddl, logonType, pCreds))
        if self.register_error is not None:
            err, self.register_error = self.register_error, None
            raise err

    def run(self, dce, *, path, **kwargs):
        self.calls.append(("run", path))


def _session_factory(dce):
    @contextmanager
    def _session(*args, **kwargs):
        yield dce

    return _session


def _install_dce(monkeypatch, register_error=None):
    """Swap ``_tsch_session`` for a fake that yields a recording DCE, and wire
    the real ``tsch`` helpers to that DCE so register/run are observable."""
    dce = FakeSchRpc(register_error=register_error)
    monkeypatch.setattr(ms_tsch, "_tsch_session", _session_factory(dce))
    monkeypatch.setattr(ms_tsch.tsch, "hSchRpcRegisterTask", dce.register)
    monkeypatch.setattr(ms_tsch.tsch, "hSchRpcRun", dce.run)
    return dce


def _deploy(**overrides):
    kwargs = dict(
        host=HOST,
        port=445,
        cred=CRED,
        task_name="SprayTask_1",
        action="whoami /all",
        interval_minutes=5,
    )
    kwargs.update(overrides)
    return ms_tsch.deploy(**kwargs)


# --- happy path ------------------------------------------------------------

def test_deploy_registers_create_then_fires_run(monkeypatch):
    dce = _install_dce(monkeypatch)
    result = _deploy()
    assert result.status == Status.OK
    assert result.method == "ms-tsch"
    assert result.host == HOST
    reg = dce.calls[0]
    assert reg[0] == "register"
    assert reg[1] == "\\SprayTask_1"
    assert reg[2] == real_tsch.TASK_CREATE
    assert reg[5] == real_tsch.TASK_LOGON_PASSWORD
    assert reg[6] == ()
    assert "<Interval>PT5M</Interval>" in reg[3]
    assert dce.calls[1] == ("run", "\\SprayTask_1")


def test_deploy_never_preflights_action_size(monkeypatch):
    dce = _install_dce(monkeypatch)
    result = _deploy(action="x" * 5000)
    assert result.status == Status.OK
    assert "x" * 5000 in dce.calls[0][3]


# --- idempotent create -> update retry --------------------------------------

@pytest.mark.parametrize("code", [0x00000050, 0x80030050])
def test_deploy_retries_create_with_update_when_task_already_exists(monkeypatch, code):
    already_exists = real_tsch.DCERPCSessionError(
        error_string="task already exists", error_code=code, packet=None
    )
    dce = _install_dce(monkeypatch, register_error=already_exists)
    result = _deploy()
    assert result.status == Status.OK
    assert [call[0] for call in dce.calls] == ["register", "register", "run"]
    assert dce.calls[0][2] == real_tsch.TASK_CREATE
    assert dce.calls[1][2] == real_tsch.TASK_UPDATE


def test_register_does_not_swallow_unrelated_errors(monkeypatch):
    unrelated = real_tsch.DCERPCSessionError(
        error_string="denied", error_code=0x80070005, packet=None
    )
    dce = _install_dce(monkeypatch, register_error=unrelated)
    result = _deploy()
    assert result.status == Status.NO_ADMIN
    assert len(dce.calls) == 1


# --- failure classification (flows through base.classify) -------------------

@pytest.mark.parametrize(
    "exc, expected",
    [
        (real_tsch.DCERPCSessionError(error_string="denied", error_code=0x80070005, packet=None), Status.NO_ADMIN),
        (real_tsch.DCERPCSessionError(error_string="denied", error_code=0x80041003, packet=None), Status.NO_ADMIN),
        (real_tsch.DCERPCSessionError(error_string="denied", error_code=nt_errors.STATUS_ACCESS_DENIED, packet=None), Status.NO_ADMIN),
        (real_tsch.DCERPCSessionError(error_string="gone", error_code=0x800706BA, packet=None), Status.UNREACHABLE),
        (real_tsch.DCERPCSessionError(error_string="disconnected", error_code=0x80010108, packet=None), Status.METHOD_ERROR),
        (real_tsch.DCERPCSessionError(error_string="op failed", error_code=0x80070003, packet=None), Status.METHOD_ERROR),
        (SessionError(nt_errors.STATUS_ACCESS_DENIED, None), Status.NO_ADMIN),
        (SessionError(nt_errors.STATUS_LOGON_FAILURE, None), Status.AUTH_FAILED),
        (SessionError(0x00000001, None), Status.METHOD_ERROR),
        (ValueError("odd failure"), Status.ERROR),
    ],
)
def test_deploy_maps_register_failures(monkeypatch, exc, expected):
    _install_dce(monkeypatch, register_error=exc)
    result = _deploy()
    assert result.status == expected
    assert result.method == "ms-tsch"
    assert result.host == HOST


def test_deploy_blank_task_name_is_status_error(monkeypatch):
    result = _deploy(task_name="\\\\")
    assert result.status == Status.ERROR


def test_deploy_auth_failed_from_smb_layer(monkeypatch):
    def _connect(**kwargs):
        raise AuthFailedError("login rejected (0xc000006d)")

    monkeypatch.setattr(ms_tsch, "connect_smb", _connect)
    result = _deploy()
    assert result.status == Status.AUTH_FAILED


def test_deploy_unreachable_from_smb_layer(monkeypatch):
    def _connect(**kwargs):
        raise UnreachableError("cannot connect")

    monkeypatch.setattr(ms_tsch, "connect_smb", _connect)
    result = _deploy()
    assert result.status == Status.UNREACHABLE


def test_deploy_socket_timeout_from_smb_layer(monkeypatch):
    def _connect(**kwargs):
        raise socket.timeout("timed out")

    monkeypatch.setattr(ms_tsch, "connect_smb", _connect)
    result = _deploy()
    assert result.status == Status.UNREACHABLE


# --- wiring: base.connect_smb -> SMBTransport -> bind -------------------------

class _FakeConnection:
    def __init__(self):
        self.setTimeout_calls = []
        self.closed = False

    def setTimeout(self, seconds):
        self.setTimeout_calls.append(seconds)

    def close(self):
        self.closed = True


class _FakeSMBSession:
    def __init__(self):
        self.connection = _FakeConnection()
        self.closed = False

    def close(self):
        self.closed = True


class _FakeSMBTransport:
    def __init__(self, dce, **kwargs):
        self.kwargs = kwargs
        self._dce = dce

    def get_dce_rpc(self):
        return self._dce


def test_wiring_uses_atsvc_pipe_binds_tschs_and_sets_timeouts(monkeypatch):
    dce = FakeSchRpc()
    smb = _FakeSMBSession()
    made = []

    def _connect(**kwargs):
        assert kwargs["connect_timeout"] == CONNECT_TIMEOUT
        assert kwargs["exec_timeout"] == EXEC_TIMEOUT
        assert kwargs["host"] == "web01"
        assert kwargs["port"] == 445
        assert kwargs["cred"] is CRED
        return smb

    def _make_transport(**kwargs):
        transport = _FakeSMBTransport(dce, **kwargs)
        made.append(transport)
        return transport

    monkeypatch.setattr(ms_tsch, "connect_smb", _connect)
    monkeypatch.setattr(ms_tsch, "SMBTransport", _make_transport)
    monkeypatch.setattr(ms_tsch.tsch, "hSchRpcRegisterTask", dce.register)
    monkeypatch.setattr(ms_tsch.tsch, "hSchRpcRun", dce.run)

    result = ms_tsch.deploy("web01", 445, CRED, "T", "whoami /all", 5)

    assert result.status == Status.OK
    transport = made[0]
    assert transport.kwargs["filename"] == r"\atsvc"
    assert transport.kwargs["remoteName"] == "web01"
    assert transport.kwargs["remote_host"] == "web01"
    assert transport.kwargs["dstport"] == 445
    assert transport.kwargs["smb_connection"] is smb.connection
    assert smb.connection.setTimeout_calls == [EXEC_TIMEOUT]
    assert dce.bound == [real_tsch.MSRPC_UUID_TSCHS]
    assert dce.disconnected
    assert smb.closed


# --- static: tsch only, no schtasks RPC module, no cap constant ---------------

def test_static_acceptance_uses_tsch_only_and_no_size_preflight():
    with open(ms_tsch.__file__, encoding="utf-8") as handle:
        src = handle.read()
    assert "from impacket.dcerpc.v5 import tsch" in src
    assert "impacket.dcerpc.v5.schtasks" not in src
    assert "SCHTASKS_TR_MAX" not in src
    assert "payload_too_large" not in src
    assert "get_dce_connection" not in src