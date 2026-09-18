"""Unit tests for the psexec-style SMB backend (spraytask/backends/psexec.py).

The backend's SCM plumbing (impacket ``scmr`` / ``\\pipe\\svcctl``) is swapped
for a recording fake, so the service create/start/delete flow, the failure-code
mapping, and the R4 ordering contract can be asserted without a live Windows
host. The shared SMB helper and ``preflight_capped`` run for real (they live in
``base``) with only ``base.connect_smb`` faked, so the R4 ordering tests prove
connect/login -> ADMIN$ probe -> size cap -> SCM delegation end to end.
"""

from impacket import nt_errors, system_errors
from impacket.dcerpc.v5 import scmr as real_scmr
from impacket.smbconnection import SessionError

import spraytask.backends.base as base
import spraytask.backends.psexec as psexec
from spraytask.backends.base import (
    EXEC_TIMEOUT,
    Status,
    UnreachableError,
    build_schtasks_commands,
)
from spraytask.creds import Credential

CRED = Credential(user="alice", password="Secret1!")
HOST = "web01"


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
    return psexec.deploy(**kwargs)


# --- fake SMB session (fed to the real preflight via faked connect_smb) ------

class _FakeConnection:
    def __init__(self, access_error=None):
        self.access_error = access_error
        self.trees = []
        self.closed = False

    def connectTree(self, share):
        if self.access_error is not None:
            raise SessionError(self.access_error, None)
        self.trees.append(share)
        return 1

    def disconnectTree(self, tid):
        self.trees.append(("disconnectTree", tid))

    def close(self):
        self.closed = True


class _FakeSMBSession:
    def __init__(self, conn, host=HOST, port=445):
        self.connection = conn
        self.host = host
        self.port = port
        self.closed = False

    def close(self):
        self.closed = True
        self.connection.close()


def _install_connect(monkeypatch, *, raises=None, access_error=None):
    """Fake ``base.connect_smb`` (keyword-only, like the real one)."""
    state = {"kwargs": None, "session": None}

    def _connect(**kwargs):
        state["kwargs"] = kwargs
        if raises is not None:
            raise raises
        session = _FakeSMBSession(_FakeConnection(access_error=access_error))
        state["session"] = session
        return session

    monkeypatch.setattr(base, "connect_smb", _connect)
    return state


def _install_scm(monkeypatch, *, preflight_returns=None, bind_error=None,
                 stale_exists=False, create_error=None, start_error=None):
    """Fake the svcctl transport + scmr RPC layer; returns a recording spy.

    Optionally stub ``psexec.preflight_capped`` so the SCM layer is reachable
    without a real SMB connection.
    """
    if preflight_returns is not None:
        monkeypatch.setattr(
            psexec, "preflight_capped", lambda **kwargs: preflight_returns
        )
    spy = ScmSpy(
        stale_exists=stale_exists,
        create_error=create_error,
        start_error=start_error,
        bind_error=bind_error,
    )
    monkeypatch.setattr(psexec.transport, "SMBTransport", spy.make_transport)
    for name in (
        "hROpenSCManagerW",
        "hROpenServiceW",
        "hRCreateServiceW",
        "hRStartServiceW",
        "hRQueryServiceStatus",
        "hRControlService",
        "hRDeleteService",
        "hRCloseServiceHandle",
    ):
        monkeypatch.setattr(psexec.scmr, name, getattr(spy, name))
    return spy


class _FakeDCE:
    def __init__(self, bind_error=None):
        self.bound = []
        self.connected = False
        self.disconnected = False
        self.bind_error = bind_error

    def connect(self):
        self.connected = True

    def bind(self, uuid):
        if self.bind_error is not None:
            raise self.bind_error
        self.bound.append(uuid)

    def disconnect(self):
        self.disconnected = True


class ScmSpy:
    """Records every SCM call the backend makes and answers with real handles."""

    def __init__(self, *, stale_exists=False, create_error=None, start_error=None,
                 bind_error=None):
        self.stale_exists = stale_exists
        self.create_error = create_error
        self.start_error = start_error
        self.transports = []
        self.calls = []
        self.created_name = None
        self.sc_handle = 100
        self.svc_handle = 101
        self._bind_error = bind_error

    def make_transport(self, *args, **kwargs):
        transport = _FakeSMBTransport(self, args, kwargs)
        self.transports.append(transport)
        return transport

    # -- scmr fakes (signature-matched to the impacket wrappers) --------------

    def hROpenSCManagerW(self, rpc):
        self.calls.append(("open_scm",))
        return {"lpScHandle": self.sc_handle}

    def hROpenServiceW(self, rpc, lpScManagerHandle, lpServiceName):
        if self.stale_exists:
            self.calls.append(("open_service", lpServiceName))
            return {"lpServiceHandle": 99}
        raise real_scmr.DCERPCSessionError(
            error_string="service does not exist",
            error_code=system_errors.ERROR_SERVICE_DOES_NOT_EXIST,
            packet=None,
        )

    def hRCreateServiceW(self, rpc, lpScManagerHandle, lpServiceName,
                         lpDisplayName, **kwargs):
        self.created_name = lpServiceName
        self.calls.append(("create", lpServiceName, kwargs["lpBinaryPathName"],
                           kwargs.get("dwStartType"), kwargs.get("dwErrorControl")))
        if self.create_error is not None:
            raise self.create_error
        return {"lpServiceHandle": self.svc_handle}

    def hRStartServiceW(self, rpc, lpServiceHandle):
        self.calls.append(("start", lpServiceHandle))
        if self.start_error is not None:
            raise self.start_error

    def hRQueryServiceStatus(self, rpc, lpServiceHandle):
        self.calls.append(("query", lpServiceHandle))
        return {"lpServiceStatus": {"dwCurrentState": real_scmr.SERVICE_STOPPED}}

    def hRControlService(self, rpc, lpServiceHandle, dwControl):
        self.calls.append(("control", lpServiceHandle, dwControl))

    def hRDeleteService(self, rpc, lpServiceHandle):
        self.calls.append(("delete", lpServiceHandle))

    def hRCloseServiceHandle(self, rpc, lpServiceHandle):
        self.calls.append(("close", lpServiceHandle))


class _FakeSMBTransport:
    def __init__(self, spy, args, kwargs):
        self.args = args
        self.kwargs = kwargs
        self._dce = _FakeDCE(bind_error=spy._bind_error)
        self.disconnected = False

    def get_dce_rpc(self):
        return self._dce

    def disconnect(self):
        self.disconnected = True


# --- happy path + SCM wiring ---------------------------------------------------

def test_deploy_happy_path_via_scm_wiring(monkeypatch):
    conn = _FakeConnection()
    session = _FakeSMBSession(conn)
    spy = _install_scm(monkeypatch, preflight_returns=session)

    result = _deploy()

    assert result.status == Status.OK
    assert result.method == "psexec"
    assert result.host == HOST
    transport = spy.transports[0]
    assert transport.args[0] == HOST  # remoteName is the first positional
    assert transport.kwargs["dstport"] == 445
    assert transport.kwargs["filename"] == r"\svcctl"
    assert transport.kwargs["smb_connection"] is conn
    dce = transport._dce
    assert dce.connected
    assert dce.bound == [real_scmr.MSRPC_UUID_SCMR]
    assert spy.created_name.startswith(psexec.SERVICE_NAME_PREFIX)
    assert len(spy.created_name) == len(psexec.SERVICE_NAME_PREFIX) + 8
    expected_command = "cmd.exe /c " + " & ".join(
        build_schtasks_commands("SprayTask_1", "whoami /all", 5)
    )
    assert spy.calls[1][2] == expected_command + "\x00"
    assert "/F" in expected_command
    assert "/SC MINUTE" in expected_command
    assert "/MO 5" in expected_command
    assert "/RU SYSTEM" in expected_command
    assert "/RL HIGHEST" in expected_command
    assert "/IT" not in expected_command
    assert "/RI" not in expected_command
    assert spy.calls[1][3] == real_scmr.SERVICE_DEMAND_START
    assert spy.calls[1][4] == real_scmr.SERVICE_ERROR_IGNORE
    assert ("start", 101) in spy.calls
    assert ("query", 101) in spy.calls
    assert ("delete", 101) in spy.calls
    assert ("close", 101) in spy.calls
    assert ("close", 100) in spy.calls
    assert transport.disconnected
    assert session.closed


def test_deploy_delete_stale_service_before_recreate(monkeypatch):
    spy = _install_scm(
        monkeypatch,
        preflight_returns=_FakeSMBSession(_FakeConnection()),
        stale_exists=True,
    )
    result = _deploy()
    assert result.status == Status.OK
    order = [call[0] for call in spy.calls]
    assert order.index("delete") == 2  # stale removed right after open_scm
    stale = [call for call in spy.calls if call[0] == "delete"][0]
    assert stale[1] == 99


def test_random_service_name_shape():
    name = psexec.random_service_name()
    assert name.startswith(psexec.SERVICE_NAME_PREFIX)
    assert len(name) == len(psexec.SERVICE_NAME_PREFIX) + 8


# --- SCM failure classification -----------------------------------------------

def test_deploy_no_admin_when_scm_create_denied(monkeypatch):
    denied = real_scmr.DCERPCSessionError(
        error_string="access denied", error_code=5, packet=None
    )
    spy = _install_scm(
        monkeypatch,
        preflight_returns=_FakeSMBSession(_FakeConnection()),
        create_error=denied,
    )
    result = _deploy()
    assert result.status == Status.NO_ADMIN
    assert "SCM denied (0x00000005)" in result.detail
    assert ("delete", 101) not in spy.calls
    assert ("start", 101) not in spy.calls


def test_deploy_method_error_on_other_scm_code(monkeypatch):
    odd = real_scmr.DCERPCSessionError(
        error_string="could not interpret", error_code=0x0000113B, packet=None
    )
    _install_scm(
        monkeypatch,
        preflight_returns=_FakeSMBSession(_FakeConnection()),
        create_error=odd,
    )
    result = _deploy()
    assert result.status == Status.METHOD_ERROR
    assert "SCM call failed (0x0000113b)" in result.detail


def test_deploy_method_error_when_svcctl_bind_fails(monkeypatch):
    broken = real_scmr.DCERPCSessionError
    rpc_error = broken(error_string="pipe broken", error_code=6, packet=None)
    _install_scm(
        monkeypatch,
        preflight_returns=_FakeSMBSession(_FakeConnection()),
        bind_error=rpc_error,
    )
    result = _deploy()
    assert result.status == Status.METHOD_ERROR
    assert "SCM call failed (0x00000006)" in result.detail


def test_deploy_cleanup_runs_and_start_denied_maps_to_no_admin(monkeypatch):
    denied = real_scmr.DCERPCSessionError(
        error_string="access denied", error_code=5, packet=None
    )
    spy = _install_scm(
        monkeypatch,
        preflight_returns=_FakeSMBSession(_FakeConnection()),
        start_error=denied,
    )
    result = _deploy()
    assert result.status == Status.NO_ADMIN
    assert ("control", 101, real_scmr.SERVICE_CONTROL_STOP) in spy.calls
    assert ("delete", 101) in spy.calls  # cleanup still ran


def test_deploy_generic_exception_becomes_error(monkeypatch):
    monkeypatch.setattr(
        psexec, "preflight_capped", lambda **kwargs: _FakeSMBSession(_FakeConnection())
    )

    def boom(session, command, exec_timeout):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(psexec, "_exec_via_scm", boom)
    result = _deploy()
    assert result.status == Status.ERROR
    assert "RuntimeError: kaboom" in result.detail


# --- R4 ordering through the real preflight ------------------------------------

def test_r4_unreachable_wins_over_oversized_action(monkeypatch):
    state = _install_connect(
        monkeypatch, raises=UnreachableError("cannot connect")
    )
    called = []
    monkeypatch.setattr(
        psexec, "_exec_via_scm", lambda *a, **k: called.append(a)
    )
    result = _deploy(action="x" * 300, connect_timeout=2.5)
    assert result.status == Status.UNREACHABLE
    assert result.detail == "cannot connect"
    assert state["kwargs"]["connect_timeout"] == 2.5
    assert called == []


def test_r4_no_admin_wins_over_oversized_action(monkeypatch):
    state = _install_connect(monkeypatch, access_error=nt_errors.STATUS_ACCESS_DENIED)
    called = []
    monkeypatch.setattr(
        psexec, "_exec_via_scm", lambda *a, **k: called.append(a)
    )
    result = _deploy(action="x" * 300)
    assert result.status == Status.NO_ADMIN
    assert "ADMIN$ denied (0xc0000022)" in result.detail
    assert state["session"].closed
    assert called == []


def test_r4_admin_probe_logon_rejection_is_auth_failed(monkeypatch):
    state = _install_connect(monkeypatch, access_error=nt_errors.STATUS_LOGON_FAILURE)
    result = _deploy(action="x" * 300)
    assert result.status == Status.AUTH_FAILED
    assert "ADMIN$ rejected (0xc000006d)" in result.detail
    assert state["session"].closed


def test_r4_oversized_action_reports_payload_too_large_after_admin(monkeypatch):
    state = _install_connect(monkeypatch)
    called = []
    monkeypatch.setattr(
        psexec, "_exec_via_scm", lambda *a, **k: called.append(a)
    )
    result = _deploy(action="x" * 300)
    assert result.status == Status.PAYLOAD_TOO_LARGE
    assert "300" in result.detail
    assert "261" in result.detail
    assert state["session"].closed
    assert called == []


def test_r4_cap_is_inclusive_at_261_chars(monkeypatch):
    _install_connect(monkeypatch)
    called = []
    monkeypatch.setattr(
        psexec, "_exec_via_scm", lambda *a, **k: called.append(a)
    )
    result = _deploy(action="x" * 261)
    assert result.status == Status.OK
    assert called  # the SCM step ran


def test_r4_success_probes_admin_then_delegates_scm(monkeypatch):
    state = _install_connect(monkeypatch)
    calls = []

    def record(session, command, exec_timeout):
        calls.append((session, command, exec_timeout))

    monkeypatch.setattr(psexec, "_exec_via_scm", record)
    result = _deploy(connect_timeout=2.5)
    assert result.status == Status.OK
    assert state["kwargs"]["connect_timeout"] == 2.5
    assert calls[0][0] is state["session"]
    expected_command = "cmd.exe /c " + " & ".join(
        build_schtasks_commands("SprayTask_1", "whoami /all", 5)
    )
    assert calls[0][1] == expected_command
    assert calls[0][2] == EXEC_TIMEOUT
    assert state["session"].closed
    assert state["session"].connection.trees[0] == "ADMIN$"
    assert ("disconnectTree", 1) in state["session"].connection.trees


# --- static acceptance ----------------------------------------------------------

def test_static_acceptance_no_upload_uses_svcctl():
    with open(psexec.__file__, encoding="utf-8") as handle:
        src = handle.read()
    assert "from impacket.dcerpc.v5 import scmr, transport" in src
    assert "preflight_capped" in src
    assert "hRCreateServiceW" in src
    assert "serviceinstall" not in src
    assert "impacket.dcerpc.v5.schtasks" not in src
    assert "get_dce_connection" not in src