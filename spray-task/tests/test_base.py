"""Unit tests for the shared backend plumbing (spraytask/backends/base.py).

Covers the R5 status vocabulary, deterministic ``classify`` mapping, the
``BackendResult`` factories, the task-5 SMB helper (``connect_smb``), the
ADMIN$ probe, and the R4 capped-backend preflight ordering.
"""

import errno
import socket

import pytest
from impacket import nmb, nt_errors
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smbconnection import SessionError

from spraytask.backends import base as base_mod
from spraytask.backends.base import (
    ALL_STATUSES,
    CONNECT_TIMEOUT,
    EXEC_TIMEOUT,
    MS_TSCH,
    SMB_DEFAULT_PORT,
    SCHTASKS_TR_MAX_LEN,
    AuthFailedError,
    BackendError,
    BackendResult,
    Error,
    MethodError,
    NoAdminError,
    PayloadTooLargeError,
    SMBSession,
    Status,
    UnreachableError,
    build_schtasks_commands,
    check_payload_size,
    classify,
    connect_smb,
    exception_for_status,
    open_admin_share,
    preflight_capped,
    raise_for,
)
from spraytask.creds import Credential

PASS = Credential(user="alice", password="p@ss!")
HASH = Credential(user="bob", domain="CORP", nt_hash="0123456789abcdef0123456789abcdef")


def _fake_session_error(code):
    """An impacket-smelling ``SessionError`` with ``getErrorCode``."""

    class FakeSessionError(Exception):
        def __init__(self, code):
            self._code = code

        def getErrorCode(self):
            return self._code

    return FakeSessionError(code)


def _fake_dce_error(code):
    """An impacket-smelling DCE session error with ``get_error_code``."""

    class FakeDceError(Exception):
        def __init__(self, code):
            self._code = code

        def get_error_code(self):
            return self._code

    return FakeDceError(code)


# --- statuses / results -----------------------------------------------------

def test_all_statuses_match_r5_enum():
    assert ALL_STATUSES == (
        "ok",
        "auth_failed",
        "no_admin",
        "unreachable",
        "payload_too_large",
        "method_error",
        "error",
    )


def test_status_is_a_str_enum():
    assert Status.OK == "ok"
    assert Status.AUTH_FAILED == "auth_failed"
    assert Status.NO_ADMIN == "no_admin"
    assert Status.UNREACHABLE == "unreachable"
    assert Status.PAYLOAD_TOO_LARGE == "payload_too_large"
    assert Status.METHOD_ERROR == "method_error"
    assert Status.ERROR == "error"
    assert Status("ok") is Status.OK


def test_ms_tsch_label():
    assert MS_TSCH == "ms-tsch"


def test_backend_error_subclass_statuses():
    assert UnreachableError.status is Status.UNREACHABLE
    assert AuthFailedError.status is Status.AUTH_FAILED
    assert NoAdminError.status is Status.NO_ADMIN
    assert PayloadTooLargeError.status is Status.PAYLOAD_TOO_LARGE
    assert MethodError.status is Status.METHOD_ERROR
    assert BackendError.status is Status.ERROR
    assert Error is BackendError
    assert Error.status is Status.ERROR


def test_backend_error_to_result_carries_host_method_detail():
    err = NoAdminError("ADMIN$ denied")
    result = err.to_result("10.0.0.5", "psexec")
    assert result == BackendResult("10.0.0.5", Status.NO_ADMIN, "psexec", "ADMIN$ denied")


def test_backend_result_is_frozen():
    result = BackendResult("10.0.0.5", "ok", "wmi", "done")
    with pytest.raises(AttributeError):
        result.status = "error"  # type: ignore[misc]


def test_backend_result_ok_factory():
    assert BackendResult.ok("10.0.0.5", "psexec", "ran") == BackendResult(
        "10.0.0.5", Status.OK, "psexec", "ran"
    )


def test_backend_result_for_exception_classifies():
    result = BackendResult.for_exception(
        "10.0.0.5", "wmi", ConnectionRefusedError("nothing listening")
    )
    assert result.status is Status.UNREACHABLE
    assert result.detail


def test_backend_result_repr_shows_status_value_not_enum_label():
    result = BackendResult("h", Status.NO_ADMIN, "wmi", "denied")
    assert "status='no_admin'" in repr(result)
    assert "Status.NO_ADMIN" not in repr(result)


# --- classify: BackendError wins ---------------------------------------------

@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (UnreachableError("x"), Status.UNREACHABLE),
        (AuthFailedError("x"), Status.AUTH_FAILED),
        (NoAdminError("x"), Status.NO_ADMIN),
        (PayloadTooLargeError("x"), Status.PAYLOAD_TOO_LARGE),
        (MethodError("x"), Status.METHOD_ERROR),
        (BackendError("x"), Status.ERROR),
    ],
)
def test_classify_backend_error_status_attr_wins(exc, expected):
    assert classify(exc) is expected


# --- classify: socket / OS error classe --------------------------------------

@pytest.mark.parametrize(
    "exc",
    [
        socket.timeout("timed out"),
        socket.gaierror("no such host"),
        ConnectionRefusedError("refused"),
        ConnectionResetError("reset"),
        ConnectionAbortedError("aborted"),
        BrokenPipeError("pipe"),
        PermissionError("permission"),
    ],
)
def test_classify_socket_classes(exc):
    if isinstance(exc, PermissionError):
        assert classify(exc) is Status.NO_ADMIN
    else:
        assert classify(exc) is Status.UNREACHABLE


@pytest.mark.parametrize(
    "errno",
    [
        errno.ECONNREFUSED,
        errno.ECONNRESET,
        errno.ETIMEDOUT,
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
        errno.EPIPE,
    ],
)
def test_classify_oserror_errno_is_unreachable(errno):
    assert classify(OSError(errno, "peer gone")) is Status.UNREACHABLE


def test_classify_plain_oserror_is_error():
    assert classify(OSError("odd")) is Status.ERROR


# --- classify: impacket codes ------------------------------------------------

def test_classify_login_ntstatus_is_auth_failed():
    for code in (
        nt_errors.STATUS_LOGON_FAILURE,
        nt_errors.STATUS_ACCOUNT_LOCKED_OUT,
        nt_errors.STATUS_PASSWORD_EXPIRED,
        nt_errors.STATUS_ACCOUNT_DISABLED,
        nt_errors.STATUS_PASSWORD_MUST_CHANGE,
    ):
        assert classify(_fake_session_error(code)) is Status.AUTH_FAILED, hex(code)
        assert classify(_fake_dce_error(code)) is Status.AUTH_FAILED, hex(code)


def test_classify_access_denied_is_no_admin():
    for code in (nt_errors.STATUS_ACCESS_DENIED, nt_errors.STATUS_PRIVILEGE_NOT_HELD):
        assert classify(_fake_session_error(code)) is Status.NO_ADMIN, hex(code)


def test_classify_transport_ntstatus_is_unreachable():
    for code in (
        nt_errors.STATUS_BAD_NETWORK_NAME,
        nt_errors.STATUS_CONNECTION_REFUSED,
        nt_errors.STATUS_NETWORK_UNREACHABLE,
        nt_errors.STATUS_HOST_UNREACHABLE,
    ):
        assert classify(_fake_session_error(code)) is Status.UNREACHABLE, hex(code)


def test_classify_unknown_ntstatus_is_method_error():
    assert classify(_fake_session_error(nt_errors.STATUS_UNSUCCESSFUL)) is Status.METHOD_ERROR


def test_classify_hresult_access_denied_is_no_admin():
    for code in (0x80070005, 0x80041003, 0x80041062):
        assert classify(_fake_dce_error(code)) is Status.NO_ADMIN, hex(code)


def test_classify_hresult_logon_failure_is_auth_failed():
    assert classify(_fake_dce_error(0x8007052E)) is Status.AUTH_FAILED


def test_classify_hresult_server_unavailable_is_unreachable():
    for code in (0x800706BA, 0x800706BF, 0x800706BE, 0x800706D3, 0x80040111):
        assert classify(_fake_dce_error(code)) is Status.UNREACHABLE, hex(code)


def test_classify_unknown_hresult_is_method_error():
    assert classify(_fake_dce_error(0x80070002)) is Status.METHOD_ERROR


def test_classify_real_dcerpc_error_code_attr():
    exc = DCERPCException("rpc fault", error_code=0x80070005)
    assert classify(exc) is Status.NO_ADMIN
    exc_unknown = DCERPCException("rpc fault", error_code=0x80070002)
    assert classify(exc_unknown) is Status.METHOD_ERROR


def test_classify_dcerpc_could_not_connect_is_unreachable():
    exc = DCERPCException("Could not connect: 10.0.0.9:135 (Connection refused)")
    assert classify(exc) is Status.UNREACHABLE


def test_classify_message_only_access_denied_is_auth_failed():
    exc = DCERPCException("rpc_s_access_denied", None, None)
    assert exc.error_code is None
    assert exc.error_string == "rpc_s_access_denied"
    assert classify(exc) is Status.AUTH_FAILED


def test_classify_message_only_server_unavailable_is_unreachable():
    exc = DCERPCException("rpc_s_server_unavailable", None, None)
    assert exc.error_code is None
    assert classify(exc) is Status.UNREACHABLE


def test_classify_message_only_server_too_busy_is_unreachable():
    exc = DCERPCException("rpc_s_server_too_busy", None, None)
    assert classify(exc) is Status.UNREACHABLE


def test_classify_message_only_unknown_message_is_error():
    exc = DCERPCException("rpc_s_unknown_weirdness", None, None)
    assert classify(exc) is Status.ERROR


def test_classify_win32_access_denied_code_5_is_no_admin():
    exc = DCERPCException("rpc_s_access_denied", 5, None)
    assert classify(exc) is Status.NO_ADMIN


def test_classify_real_smb_session_error():
    assert classify(SessionError(nt_errors.STATUS_LOGON_FAILURE, None)) is Status.AUTH_FAILED
    assert classify(SessionError(nt_errors.STATUS_ACCESS_DENIED, None)) is Status.NO_ADMIN


def test_classify_unknown_exception_is_error():
    assert classify(ValueError("odd")) is Status.ERROR
    assert classify(RuntimeError("boom")) is Status.ERROR


# --- exception_for_status / raise_for ----------------------------------------

def test_exception_for_status_roundtrip():
    assert exception_for_status(Status.AUTH_FAILED) is AuthFailedError
    assert exception_for_status(Status.NO_ADMIN) is NoAdminError
    assert exception_for_status(Status.UNREACHABLE) is UnreachableError
    assert exception_for_status(Status.PAYLOAD_TOO_LARGE) is PayloadTooLargeError
    assert exception_for_status(Status.METHOD_ERROR) is MethodError
    assert exception_for_status(Status.ERROR) is Error


def test_raise_for_raises_matching_class():
    with pytest.raises(AuthFailedError):
        raise_for(Status.AUTH_FAILED, "nope")


# --- connect_smb: transport classification -----------------------------------

def _install_fake_smb(monkeypatch, **behavior):
    created = []

    class FakeSMBConnection:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.login_calls = []
            self.closed = False
            created.append(self)
            if behavior.get("ctor_error"):
                raise behavior["ctor_error"]

        def login(self, user, password, domain, lmhash, nthash):
            self.login_calls.append((user, password, domain, lmhash, nthash))
            if behavior.get("login_error"):
                raise behavior["login_error"]

        def getServerName(self):
            return "FAKESRV"

        def close(self):
            self.closed = True

    monkeypatch.setattr(base_mod, "SMBConnection", FakeSMBConnection)
    return created


def test_connect_smb_success_and_login_args(monkeypatch):
    created = _install_fake_smb(monkeypatch)
    session = connect_smb(host="10.0.0.5", cred=PASS, connect_timeout=3.0, exec_timeout=9.0)
    conn = created[0]
    assert conn.kwargs["remoteName"] == "10.0.0.5"
    assert conn.kwargs["remoteHost"] == "10.0.0.5"
    assert conn.kwargs["sess_port"] == SMB_DEFAULT_PORT
    assert conn.kwargs["timeout"] == 3.0
    assert conn.login_calls == [("alice", "p@ss!", "", "", "")]
    assert session.server_name == "FAKESRV"
    assert session.host == "10.0.0.5"


def test_connect_smb_uses_custom_port_and_hash_creds(monkeypatch):
    created = _install_fake_smb(monkeypatch)
    session = connect_smb(host="web01", port=1445, cred=HASH)
    conn = created[0]
    assert conn.kwargs["sess_port"] == 1445
    lm, nt = HASH.lm_hash, HASH.nthash
    assert conn.login_calls == [("bob", "", "CORP", lm, nt)]
    assert session.port == 1445


def test_connect_smb_unreachable_on_socket_error(monkeypatch):
    _install_fake_smb(monkeypatch, ctor_error=OSError("Connection refused"))
    with pytest.raises(UnreachableError):
        connect_smb(host="10.0.0.5", cred=PASS)


def test_connect_smb_unreachable_on_name_resolution_error(monkeypatch):
    _install_fake_smb(monkeypatch, ctor_error=socket.gaierror("Name or service not known"))
    with pytest.raises(UnreachableError):
        connect_smb(host="no.such.host", cred=PASS)


def test_connect_smb_unreachable_on_timeout(monkeypatch):
    _install_fake_smb(monkeypatch, ctor_error=TimeoutError("timed out"))
    with pytest.raises(UnreachableError):
        connect_smb(host="10.0.0.5", cred=PASS)


def test_connect_smb_unreachable_on_netbios_error(monkeypatch):
    _install_fake_smb(monkeypatch, ctor_error=nmb.NetBIOSError("session failed"))
    with pytest.raises(UnreachableError):
        connect_smb(host="10.0.0.5", cred=PASS)


def test_connect_smb_login_rejection_is_auth_failed(monkeypatch):
    _install_fake_smb(
        monkeypatch,
        login_error=SessionError(nt_errors.STATUS_LOGON_FAILURE, None),
    )
    with pytest.raises(AuthFailedError):
        connect_smb(host="10.0.0.5", cred=PASS)


@pytest.mark.parametrize(
    "code",
    [
        nt_errors.STATUS_ACCOUNT_RESTRICTION,
        nt_errors.STATUS_INVALID_LOGON_HOURS,
        nt_errors.STATUS_INVALID_WORKSTATION,
        nt_errors.STATUS_PASSWORD_EXPIRED,
        nt_errors.STATUS_ACCOUNT_DISABLED,
        nt_errors.STATUS_ACCOUNT_EXPIRED,
        nt_errors.STATUS_PASSWORD_MUST_CHANGE,
        nt_errors.STATUS_ACCOUNT_LOCKED_OUT,
    ],
)
def test_connect_smb_account_statuses_are_auth_failed(monkeypatch, code):
    _install_fake_smb(monkeypatch, login_error=SessionError(code, None))
    with pytest.raises(AuthFailedError):
        connect_smb(host="10.0.0.5", cred=PASS)


def test_connect_smb_unknown_login_error_is_method_error(monkeypatch):
    _install_fake_smb(monkeypatch, login_error=SessionError(nt_errors.STATUS_ACCESS_DENIED, None))
    with pytest.raises(MethodError):
        connect_smb(host="10.0.0.5", cred=PASS)


def test_connect_smb_unexpected_login_failure_is_method_error(monkeypatch):
    _install_fake_smb(monkeypatch, login_error=RuntimeError("odd"))
    with pytest.raises(MethodError):
        connect_smb(host="10.0.0.5", cred=PASS)


def test_connect_smb_without_credential_is_error():
    with pytest.raises(Error):
        connect_smb(host="10.0.0.5")


def test_smb_session_close_swallows_errors():
    class Flaky:
        def getServerName(self):
            return "X"

        def close(self):
            raise OSError("boom")

    session = SMBSession(Flaky(), "h", 445)
    session.close()  # must not raise


# --- open_admin_share --------------------------------------------------------

class _FakeConn:
    def __init__(self, admin="ok"):
        self.admin = admin
        self.disconnected = []

    def connectTree(self, share):
        if self.admin == "denied":
            raise SessionError(nt_errors.STATUS_ACCESS_DENIED, None)
        if self.admin == "logon":
            raise SessionError(nt_errors.STATUS_LOGON_FAILURE, None)
        if self.admin == "boom":
            raise RuntimeError("odd")
        return 7

    def disconnectTree(self, tid):
        self.disconnected.append(tid)

    def getServerName(self):
        return "X"

    def close(self):
        pass


def _session(admin="ok"):
    conn = _FakeConn(admin)
    return SMBSession(conn, "10.0.0.5", 445), conn


def test_open_admin_share_success_disconnects_tree():
    session, conn = _session()
    open_admin_share(session)
    assert conn.disconnected == [7]


def test_open_admin_share_denied_is_no_admin():
    session, _conn = _session("denied")
    with pytest.raises(NoAdminError) as excinfo:
        open_admin_share(session)
    assert "ADMIN$" in excinfo.value.detail


def test_open_admin_share_logon_rejection_is_auth_failed():
    session, _conn = _session("logon")
    with pytest.raises(AuthFailedError):
        open_admin_share(session)


def test_open_admin_share_odd_failure_is_method_error():
    session, _conn = _session("boom")
    with pytest.raises(MethodError):
        open_admin_share(session)


# --- check_payload_size ------------------------------------------------------

def test_check_payload_size_cap_boundaries():
    check_payload_size("x" * SCHTASKS_TR_MAX_LEN)
    with pytest.raises(PayloadTooLargeError) as excinfo:
        check_payload_size("y" * (SCHTASKS_TR_MAX_LEN + 1))
    assert str(SCHTASKS_TR_MAX_LEN) in excinfo.value.detail
    assert "y" not in excinfo.value.detail  # action bytes never echoed


def test_check_payload_size_honours_custom_cap():
    check_payload_size("x" * 10, cap=10)
    with pytest.raises(PayloadTooLargeError):
        check_payload_size("x" * 11, cap=10)


# --- preflight_capped ordering (R4) ------------------------------------------

@pytest.fixture
def fake_pipeline(monkeypatch):
    def install(*, connect_error=None, admin="ok"):
        calls = []

        def fake_connect_smb(**kwargs):
            calls.append(dict(kwargs))
            if connect_error is not None:
                raise connect_error
            conn = _FakeConn(admin)
            port = kwargs.get("port") or 445
            return SMBSession(conn, kwargs.get("host", "10.0.0.5"), port)

        monkeypatch.setattr(base_mod, "connect_smb", fake_connect_smb)
        return calls

    return install


def _oversized():
    return "x" * (SCHTASKS_TR_MAX_LEN + 1)


def test_preflight_unreachable_wins_over_oversized(fake_pipeline):
    fake_pipeline(connect_error=UnreachableError("cannot connect"))
    with pytest.raises(UnreachableError):
        preflight_capped(host="h", port=None, cred=PASS, action=_oversized())


def test_preflight_auth_failed_wins_over_oversized(fake_pipeline):
    fake_pipeline(connect_error=AuthFailedError("login rejected"))
    with pytest.raises(AuthFailedError):
        preflight_capped(host="h", port=None, cred=PASS, action=_oversized())


def test_preflight_no_admin_wins_over_oversized(fake_pipeline):
    fake_pipeline(admin="denied")
    with pytest.raises(NoAdminError):
        preflight_capped(host="h", port=None, cred=PASS, action=_oversized())


def test_preflight_oversized_payload_after_checks_pass(fake_pipeline):
    calls = fake_pipeline()
    with pytest.raises(PayloadTooLargeError):
        preflight_capped(host="h", port=445, cred=PASS, action=_oversized())
    assert calls and calls[0]["port"] == 445


def test_preflight_at_cap_returns_open_session(fake_pipeline):
    fake_pipeline()
    session = preflight_capped(host="h", port=None, cred=PASS, action="x" * SCHTASKS_TR_MAX_LEN)
    assert session.host == "h"


def test_preflight_over_passes_defaults_forward(fake_pipeline):
    calls = fake_pipeline()
    session = preflight_capped(
        host="h",
        port=None,
        cred=PASS,
        action="x" * SCHTASKS_TR_MAX_LEN,
        connect_timeout=2.5,
        exec_timeout=7.5,
    )
    assert session.host == "h"
    assert calls[0]["connect_timeout"] == 2.5
    assert calls[0]["exec_timeout"] == 7.5
    open_admin_share(session)  # session still usable


def test_preflight_closes_session_on_payload_too_large(monkeypatch):
    monkeypatch.setattr(base_mod, "connect_smb", lambda **kw: _session()[0])
    with pytest.raises(PayloadTooLargeError):
        preflight_capped(host="h", port=None, cred=PASS, action=_oversized())


# --- schtasks command builder (R3 cap + shape) ------------------------------

def test_build_schtasks_commands_shape():
    action = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand AAAA"
    create, run = build_schtasks_commands("SprayTask_123", action, 5)
    assert create == (
        'schtasks.exe /Create /F /TN "SprayTask_123" /TR '
        f'"{action}" /SC MINUTE /MO 5 /RU SYSTEM /RL HIGHEST'
    )
    assert run == 'schtasks.exe /Run /TN "SprayTask_123"'
    assert "/IT" not in create and "/IT" not in run
    assert "/RI" not in create and "/RI" not in run


def test_build_schtasks_commands_interval_minutes_propagates():
    create, _run = build_schtasks_commands("T", "x", 1)
    assert "/SC MINUTE /MO 1" in create


def test_schtasks_cap_constant():
    assert SCHTASKS_TR_MAX_LEN == 261
    assert base_mod.SCHTASKS_TR_CAP == 261


def test_timeout_and_defaults():
    assert CONNECT_TIMEOUT == 5.0
    assert EXEC_TIMEOUT == 30.0