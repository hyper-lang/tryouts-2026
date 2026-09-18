"""Shared backend plumbing (R7 layout: ``spraytask/backends/base.py``).

This module is the common floor every backend builds on:

* the R5 result vocabulary -- the :class:`Status` enum, the
  :class:`BackendResult` record, and the :class:`BackendError` taxonomy that
  lets a failure be routed to exactly one status deterministically via
  :func:`classify`;
* the **SMB helper** (:func:`connect_smb` + :class:`SMBSession`), the
  connection/credential check shared by the two SMB 445 backends (MS-TSCH and
  psexec); it classifies transport failures as ``unreachable`` and NTLM login
  rejections as ``auth_failed``;
* the **capped-backend preflight** (:func:`preflight_capped`), which encodes
  the R4 ordering contract ``connect/login -> ADMIN$ -> size cap`` so a
  connectivity or credential-class failure on an SMB host is never masked by
  ``payload_too_large``;
* the ``schtasks.exe`` command-line builder
  (:func:`build_schtasks_commands`) shared by the two capped backends
  (psexec and WMI) together with their documented ``/TR`` cap
  (:data:`SCHTASKS_TR_MAX_LEN`).

Nothing in this module writes files, copies payloads, or touches secret
values beyond handing them straight to impacket at login time.
"""

from __future__ import annotations

import errno
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from impacket import nt_errors, nmb
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smbconnection import SMBConnection, SessionError

from spraytask.creds import Credential

# ---------------------------------------------------------------------------
# R5 status vocabulary
# ---------------------------------------------------------------------------


class Status(str, Enum):
    """The R5 per-attempt status strings.

    A ``str`` enum so ``Status.OK == "ok"`` holds for plain-string
    consumers while the enum keeps the vocabulary closed. Use
    ``status.value`` when serializing.
    """

    OK = "ok"
    AUTH_FAILED = "auth_failed"
    NO_ADMIN = "no_admin"
    UNREACHABLE = "unreachable"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    METHOD_ERROR = "method_error"
    ERROR = "error"


#: The status strings in fixed order, for reports and the console summary.
ALL_STATUSES = tuple(member.value for member in Status)

#: The atomic per-host console/method label of the MS-TSCH backend.
MS_TSCH = "ms-tsch"


@dataclass(frozen=True)
class BackendResult:
    """The outcome of one backend attempt on one host (R5).

    ``status`` is a :class:`Status`, ``method`` names the backend that
    produced the result (``"ms-tsch"`` / ``"psexec"`` / ``"wmi"``), and
    ``detail`` is a short, credential-free explanation for the console line
    and the JSON report.
    """

    host: str
    status: Status
    method: str
    detail: str = ""

    @classmethod
    def ok(cls, host: str, method: str, detail: str = "") -> BackendResult:
        """A successful attempt (R5 ``ok``)."""
        return cls(host, Status.OK, method, detail)

    @classmethod
    def for_exception(
        cls, host: str, method: str, exc: BaseException
    ) -> BackendResult:
        """Classify ``exc`` and build a failure result from it (never raises)."""
        return cls(host, classify(exc), method, _describe(exc))

    def __repr__(self) -> str:
        status = self.status.value if isinstance(self.status, Status) else self.status
        return (
            f"BackendResult(host={self.host!r}, status={status!r}, "
            f"method={self.method!r}, detail={self.detail!r})"
        )


class BackendError(Exception):
    """Failure that maps 1:1 onto a per-attempt status (R5).

    Subclasses pin :attr:`status`; ``detail`` must never contain a password
    or hash (only exception text, NTSTATUS codes, lengths, ...). This class
    itself is the generic ``Status.ERROR`` carrier.
    """

    status = Status.ERROR

    def __init__(self, detail: str = "") -> None:
        super().__init__(detail)
        self.detail = detail

    def to_result(self, host: str, method: str) -> BackendResult:
        return BackendResult(host, self.status, method, self.detail)


#: Generic alias so the taxonomy reads as ``raise Error(...)`` alongside
#: the specific classes below (R5/R7 nomenclature).
Error = BackendError


class UnreachableError(BackendError):
    """Transport timeout, connection refused, or name resolution failure."""

    status = Status.UNREACHABLE


class AuthFailedError(BackendError):
    """NTLM challenge/response rejected at login level."""

    status = Status.AUTH_FAILED


class NoAdminError(BackendError):
    """Login succeeded but the admin endpoint denies access."""

    status = Status.NO_ADMIN


class PayloadTooLargeError(BackendError):
    """Encoded action exceeds the backend's documented cap; terminal."""

    status = Status.PAYLOAD_TOO_LARGE


class MethodError(BackendError):
    """Backend reached but its RPC/exec call failed at the method level."""

    status = Status.METHOD_ERROR


_STATUS_EXCEPTIONS = {
    Status.AUTH_FAILED: AuthFailedError,
    Status.NO_ADMIN: NoAdminError,
    Status.UNREACHABLE: UnreachableError,
    Status.PAYLOAD_TOO_LARGE: PayloadTooLargeError,
    Status.METHOD_ERROR: MethodError,
    Status.ERROR: Error,
}


def exception_for_status(status: Status) -> type[BackendError]:
    """The :class:`BackendError` subclass pinned to ``status``."""
    return _STATUS_EXCEPTIONS[Status(status)]


def raise_for(status: Status, detail: str = "") -> None:
    """Raise the :class:`BackendError` subclass for ``status``."""
    raise exception_for_status(status)(detail)


# ---------------------------------------------------------------------------
# Timeouts (R6)
# ---------------------------------------------------------------------------

#: Default per-host connect timeout, seconds (R6): DNS + TCP handshake.
CONNECT_TIMEOUT = 5.0

#: Default per-host exec timeout, seconds (R6); bounds the SCM start spin
#: and the WMI exec call.
EXEC_TIMEOUT = 30.0

#: Default SMB Connect port when a host line does not carry one (R1).
SMB_DEFAULT_PORT = 445


# ---------------------------------------------------------------------------
# Deterministic exception classification
# ---------------------------------------------------------------------------

#: NTSTATUS codes that mean the supplied credential was rejected (R5
#: ``auth_failed``).
_LOGON_REJECTION_CODES = frozenset(
    {
        nt_errors.STATUS_LOGON_FAILURE,
        nt_errors.STATUS_ACCOUNT_RESTRICTION,
        nt_errors.STATUS_INVALID_LOGON_HOURS,
        nt_errors.STATUS_INVALID_WORKSTATION,
        nt_errors.STATUS_PASSWORD_EXPIRED,
        nt_errors.STATUS_ACCOUNT_DISABLED,
        nt_errors.STATUS_ACCOUNT_EXPIRED,
        nt_errors.STATUS_PASSWORD_MUST_CHANGE,
        nt_errors.STATUS_ACCOUNT_LOCKED_OUT,
    }
)

#: NTSTATUS codes meaning the admin endpoint (or the admin RPC service) said
#: "no".
_ACCESS_DENIED_CODES = frozenset(
    {
        nt_errors.STATUS_ACCESS_DENIED,
        nt_errors.STATUS_PRIVILEGE_NOT_HELD,
    }
)

#: NTSTATUS codes meaning the remote side is gone/unediffable over the wire
#: (``unreachable``).
_UNREACHABLE_NTSTATUS_CODES = frozenset(
    {
        nt_errors.STATUS_BAD_NETWORK_NAME,
        nt_errors.STATUS_CONNECTION_REFUSED,
        nt_errors.STATUS_CONNECTION_ABORTED,
        nt_errors.STATUS_IO_TIMEOUT,
        nt_errors.STATUS_PIPE_BROKEN,
        nt_errors.STATUS_NETWORK_UNREACHABLE,
        nt_errors.STATUS_HOST_UNREACHABLE,
        nt_errors.STATUS_PORT_UNREACHABLE,
    }
)

#: HRESULTs that mean the supplied credential was rejected at the DCOM/WMI
#: level (ERROR_LOGON_FAILURE, ``0x8007052E``).
_AUTH_FAILED_HRESULTS = frozenset({0x8007052E})

#: HRESULTs meaning an admin endpoint denied access: ``E_ACCESSDENIED``
#: (COM), ``WBEM_E_ACCESS_DENIED`` and ``WBEM_E_PRIVILEGE_NOT_HELD`` (WMI).
_NO_ADMIN_HRESULTS = frozenset(
    {
        0x80070005,  # E_ACCESSDENIED
        0x80041003,  # WBEM_E_ACCESS_DENIED
        0x80041062,  # WBEM_E_PRIVILEGE_NOT_HELD
    }
)

#: HRESULTs meaning the server is gone or the RPC channel broke
#: (``unreachable``): RPC_S_SERVER_UNAVAILABLE, RPC_S_SERVER_TOO_BUSY,
#: RPC_S_CALL_FAILED, RPC_S_FAILED, RPC_E_DISCONNECTED.
_UNREACHABLE_HRESULTS = frozenset(
    {
        0x800706BA,
        0x800706BF,
        0x800706BE,
        0x800706D3,
        0x80040111,
    }
)

#: Socket ``errno`` values that mean the peer or the path to it is gone.
_UNREACHABLE_ERRNOS = frozenset(
    {
        errno.ECONNREFUSED,
        errno.ECONNRESET,
        errno.ECONNABORTED,
        errno.ETIMEDOUT,
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
        errno.ENETDOWN,
        errno.EHOSTDOWN,
        errno.EPIPE,
    }
)

#: Win32 error codes meaning the admin endpoint denied access. The most common
#: is ``ERROR_ACCESS_DENIED`` (5), which impacket surfaces as the ``error_code``
#: of a ``DCERPCException('rpc_s_access_denied', 5, None)`` -- a real DCOM/WMI
#: denial. It is a win32 code, distinct from the NTSTATUS ``STATUS_ACCESS_DENIED``
#: (0xC0000022) already in ``_ACCESS_DENIED_CODES``.
_WIN32_ACCESS_DENIED_CODES = frozenset({5})

_AUTH_FAILED_CODES = _LOGON_REJECTION_CODES | _AUTH_FAILED_HRESULTS
_NO_ADMIN_CODES = _ACCESS_DENIED_CODES | _NO_ADMIN_HRESULTS | _WIN32_ACCESS_DENIED_CODES
_UNREACHABLE_CODES = _UNREACHABLE_NTSTATUS_CODES | _UNREACHABLE_HRESULTS

#: ``error_string`` tokens (impacket DCE/RPC status names) that mean the remote
#: side rejected the supplied credential at the logon/DCOM stage (R5
#: ``auth_failed``). impacket's DCOM/WMI path raises a *message-only*
#: ``DCERPCException('rpc_s_access_denied', None, None)`` for a wrong/weak
#: credential, which the code-based branch cannot read.
_MSG_AUTH_TOKENS = (
    "access_denied",
    "access denied",
    "invalid_credentials",
    "invalid credentials",
    "logon_failure",
    "logon failure",
    "credentials_too_large",
)

#: ``error_string`` tokens meaning the server RPC channel is gone, refused, or
#: otherwise unreachable (R5 ``unreachable``), for the same message-only shape.
_MSG_UNREACHABLE_TOKENS = (
    "server_unavailable",
    "server unavailable",
    "server_too_busy",
    "server too busy",
    "server_gone",
    "server gone",
    "call_failed",
    "call failed",
    "network_unreachable",
    "host_unreachable",
    "rem_host_down",
    "connect_timed_out",
    "not_listening",
    "cant_connect",
    "cannot_connect",
)


def _message_exception_status(exc: BaseException) -> Optional[Status]:
    """The status of a *message-only* ``DCERPCException`` (no numeric code).

    impacket sometimes raises ``DCERPCException(error_string, None, None)`` --
    ``error_code``/``packet`` are ``None`` -- which the code-based branch in
    :func:`classify` cannot read; the RPC status string then carries the
    meaning (e.g. ``'rpc_s_access_denied'``). Maps the access-denied family to
    ``auth_failed`` (login-stage DCOM/WMI denial per impacket wmiexec prior
    art) and the server-gone family to ``unreachable``. Returns ``None`` when
    the message names no known family, leaving :func:`classify` to fall through
    to ``error``.
    """
    if not isinstance(exc, DCERPCException):
        return None
    text = str(exc)
    if text.startswith("Could not connect"):
        return Status.UNREACHABLE
    error_string = getattr(exc, "error_string", None)
    if not isinstance(error_string, str):
        return None
    lowered = error_string.lower()
    if any(token in lowered for token in _MSG_AUTH_TOKENS):
        return Status.AUTH_FAILED
    if any(token in lowered for token in _MSG_UNREACHABLE_TOKENS):
        return Status.UNREACHABLE
    return None


def _error_code(exc: BaseException) -> Optional[int]:
    """The numeric error code an impacket-ish exception carries, if any.

    ``smbconnection.SessionError`` exposes ``getErrorCode()``; the DCE
    ``DCERPCSessionError`` flavors expose ``get_error_code()`` or a plain
    ``error_code`` attribute.
    """
    for getter_name in ("getErrorCode", "get_error_code"):
        getter = getattr(exc, getter_name, None)
        if callable(getter):
            try:
                value = getter()
            except Exception:
                continue
            if isinstance(value, int):
                return value
    value = getattr(exc, "error_code", None)
    if isinstance(value, int):
        return value
    return None


def classify(exc: BaseException) -> Status:
    """Map an exception to exactly one :class:`Status` (deterministic, R5).

    Precedence:

    #. a :class:`BackendError` wins with its pinned status;
    #. socket connectivity classes (timeout, name resolution, connection
       refused/reset, broken pipe, network unreachable) -> ``unreachable``;
    #. ``PermissionError`` -> ``no_admin``;
    #. an impacket-style exception with a recognized NTSTATUS/HRESULT code ->
       ``auth_failed`` / ``no_admin`` / ``unreachable``;
    #. any other RPC-level exception with a code -> ``method_error``;
    #. a code-less ``DCERPCException`` whose ``error_string`` names the
       access-denied family -> ``auth_failed``, or the server-gone family ->
       ``unreachable``;
    #. anything else -> ``error``.
    """
    if isinstance(exc, BackendError):
        return exc.status
    if isinstance(exc, (socket.timeout, socket.gaierror)):
        return Status.UNREACHABLE
    if isinstance(exc, PermissionError):
        return Status.NO_ADMIN
    if isinstance(exc, (ConnectionError, BrokenPipeError)):
        return Status.UNREACHABLE
    if isinstance(exc, OSError) and exc.errno in _UNREACHABLE_ERRNOS:
        return Status.UNREACHABLE

    code = _error_code(exc)
    if code is not None:
        if code in _AUTH_FAILED_CODES:
            return Status.AUTH_FAILED
        if code in _NO_ADMIN_CODES:
            return Status.NO_ADMIN
        if code in _UNREACHABLE_CODES:
            return Status.UNREACHABLE
        return Status.METHOD_ERROR

    message_status = _message_exception_status(exc)
    if message_status is not None:
        return message_status
    return Status.ERROR


def _describe(exc: BaseException, limit: int = 300) -> str:
    """A short, secret-free detail line for a failure."""
    text = str(exc).strip()
    if not text:
        text = type(exc).__name__
    return text[:limit]


def _first_line(text: str) -> str:
    line = text.splitlines()[0].strip() if text else ""
    return line[:200]


# ---------------------------------------------------------------------------
# The SMB helper (shared connection/credential checks)
# ---------------------------------------------------------------------------


class SMBSession:
    """An authenticated SMB session for backend use.

    Wraps the impacket :class:`SMBConnection` so the 445 backends share one
    connect/authenticate path and one teardown path. ``server_name`` is the
    target's server name as reported by SMB; it is best-effort and may be
    ``None``.
    """

    def __init__(self, connection: SMBConnection, host: str, port: int) -> None:
        self.connection = connection
        self.host = host
        self.port = port
        self.server_name: Optional[str] = None
        try:
            self.server_name = connection.getServerName()
        except Exception:
            self.server_name = None

    def close(self) -> None:
        """Log off and release the socket. Never raises."""
        try:
            self.connection.close()
        except Exception:
            pass


def connect_smb(
    *,
    host: str,
    port: Optional[int] = None,
    cred: Optional[Credential] = None,
    connect_timeout: float = CONNECT_TIMEOUT,
    exec_timeout: float = EXEC_TIMEOUT,
) -> SMBSession:
    """Open and authenticate an SMB session to ``host:port`` (task-5 helper).

    This is the shared connection/credential check used by the SMB 445
    backends. Failure classification is deterministic:

    * non-credentialed request / transport / name-resolution failures ->
      :class:`UnreachableError`;
    * NTLM login rejection -> :class:`AuthFailedError`;
    * protocol-level trouble after the socket is up -> :class:`MethodError`.

    ``exec_timeout`` is accepted for signature uniformity with the backend
    callables; the session socket is governed by ``connect_timeout``.
    Raises :class:`UnreachableError`, :class:`AuthFailedError`,
    :class:`MethodError`, or (missing credential) :class:`Error`.
    """
    if cred is None:
        raise Error("no credential available for host")
    connect_port = SMB_DEFAULT_PORT if port is None else port
    connection: Optional[SMBConnection] = None
    try:
        connection = SMBConnection(
            remoteName=host,
            remoteHost=host,
            sess_port=connect_port,
            timeout=connect_timeout,
        )
    except (socket.timeout, OSError) as exc:
        raise UnreachableError(f"cannot connect: {_first_line(str(exc))}") from exc
    except nmb.NetBIOSError as exc:
        raise UnreachableError(f"SMB session failed: {_first_line(str(exc))}") from exc
    except Exception as exc:
        # A closed/protocol-odd endpoint makes itself known after the socket
        # is up; that is a method-level outcome, not a transport one.
        raise MethodError(
            f"SMB negotiation failed: {type(exc).__name__}: {_first_line(str(exc))}"
        ) from exc

    try:
        connection.login(
            cred.user,
            cred.password or "",
            cred.domain or "",
            cred.lm_hash or "",
            cred.nthash or "",
        )
    except SessionError as exc:
        _drop(connection)
        code = exc.getErrorCode()
        if code in _LOGON_REJECTION_CODES:
            raise AuthFailedError(f"login rejected (0x{code:08x})") from exc
        raise MethodError(f"SMB login failed (0x{code:08x})") from exc
    except Exception as exc:
        _drop(connection)
        raise MethodError(
            f"SMB login failed: {type(exc).__name__}: {_first_line(str(exc))}"
        ) from exc

    return SMBSession(connection, host, connect_port)


def _drop(connection: SMBConnection) -> None:
    try:
        connection.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Capped-backend preflight (R4 ordering)
# ---------------------------------------------------------------------------

#: Documented ``schtasks.exe`` action cap: a ``/TR`` value longer than this is
#: rejected. The ``powershell.exe`` + ``-EncodedCommand`` prefix is ~70 chars
#: and base64 inflates UTF-16 input ~2.7x, so these backends carry at most
#: ~70 bytes of real PowerShell.
SCHTASKS_TR_MAX_LEN = 261

#: Alias used by the R4 preflight helper default.
SCHTASKS_TR_CAP = SCHTASKS_TR_MAX_LEN


def open_admin_share(session: SMBSession) -> None:
    """Probe ADMIN$ to separate ``no_admin`` from later method failures."""
    try:
        tid = session.connection.connectTree("ADMIN$")
    except Exception as exc:
        code = _error_code(exc)
        if code in _LOGON_REJECTION_CODES:
            raise AuthFailedError(f"ADMIN$ rejected (0x{code:08x})") from exc
        if code is not None:
            raise NoAdminError(f"ADMIN$ denied (0x{code:08x})") from exc
        raise MethodError(
            f"ADMIN$ probe failed: {type(exc).__name__}: {_first_line(str(exc))}"
        ) from exc
    try:
        session.connection.disconnectTree(tid)
    except Exception:
        pass


def check_payload_size(action: str, cap: int = SCHTASKS_TR_MAX_LEN) -> None:
    """Raise :class:`PayloadTooLargeError` when ``action`` exceeds ``cap``.

    Only the length and the cap appear in the message; the action itself is
    never echoed (R5 masking).
    """
    if len(action) > cap:
        raise PayloadTooLargeError(
            f"encoded action length {len(action)} exceeds schtasks /TR cap of {cap}"
        )


def preflight_capped(
    *,
    host: str,
    port: Optional[int],
    cred: Optional[Credential],
    action: str,
    cap: int = SCHTASKS_TR_MAX_LEN,
    connect_timeout: float = CONNECT_TIMEOUT,
    exec_timeout: float = EXEC_TIMEOUT,
) -> SMBSession:
    """R4 ordering for an SMB-based capped backend, in one call.

    Order is fixed: transport + login (``unreachable`` / ``auth_failed``),
    then the ADMIN$ admin check (``no_admin``), then the size preflight
    (``payload_too_large``) -- so a connectivity/credential-class failure is
    never masked by the cap (R4 acceptance 7). Raises the matching
    :class:`BackendError` on failure and returns an open
    :class:`SMBSession` on success (the caller owns closing it).
    """
    session = connect_smb(
        host=host,
        port=port,
        cred=cred,
        connect_timeout=connect_timeout,
        exec_timeout=exec_timeout,
    )
    try:
        open_admin_share(session)
        check_payload_size(action, cap)
    except BackendError:
        session.close()
        raise
    return session


# ---------------------------------------------------------------------------
# schtasks.exe command lines for the capped backends (R3)
# ---------------------------------------------------------------------------

def build_schtasks_commands(
    task_name: str, action: str, interval_minutes: int
) -> list[str]:
    """The ``schtasks.exe`` create+run pair that installs a repeating SYSTEM
    task and fires it immediately (R3).

    Deliberately excludes ``/IT`` (interactive-only contradicts a SYSTEM
    "run whether logged on" task) and ``/RI`` (invalid with ``/SC MINUTE``).
    ``/RU SYSTEM`` + ``/RL HIGHEST`` make the task run as SYSTEM; ``/F`` makes
    re-deployment idempotent (same-name task overwritten); ``/SC MINUTE
    /MO N`` repeats every N minutes.
    """
    create = (
        f'schtasks.exe /Create /F /TN "{task_name}" /TR "{action}" '
        f"/SC MINUTE /MO {interval_minutes} /RU SYSTEM /RL HIGHEST"
    )
    run = f'schtasks.exe /Run /TN "{task_name}"'
    return [create, run]


# ---------------------------------------------------------------------------
# TCP preflight (DCOM/WMI uses this instead of the SMB helper)
# ---------------------------------------------------------------------------

def probe_tcp(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> None:
    """Best-effort TCP probe that turns connectivity-class failures into
    :class:`UnreachableError` (used by the WMI/DCOM path, which has no SMB).
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except Exception as exc:
        if isinstance(exc, (socket.gaierror, socket.timeout, ConnectionError)):
            raise UnreachableError(
                f"{host}:{port}: {_first_line(str(exc))}"
            ) from exc
        if isinstance(exc, OSError) and exc.errno in _UNREACHABLE_ERRNOS:
            raise UnreachableError(
                f"{host}:{port}: {_first_line(str(exc))}"
            ) from exc
        raise