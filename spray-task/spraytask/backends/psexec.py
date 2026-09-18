"""psexec-style SMB service-exec backend (``spraytask/backends/psexec.py``).

Second member of the backend chain, still over SMB 445. It delegates the
connect/login/ADMIN$/size-preflight sequence to
:func:`spraytask.backends.base.preflight_capped` so its connection, credential,
and cap semantics are identical to the other capped backend's -- then executes
the ``schtasks.exe`` create+run pair built by
:func:`spraytask.backends.base.build_schtasks_commands` as a scratch service
via the Service Control Manager (the impacket ``scmr`` / ``\\pipe\\svcctl``
path bound to the already-authenticated SMB session). Services run as
LocalSystem, so the exec token is SYSTEM.

Capped backend: the task action is embedded in the ``/TR`` value and
``schtasks.exe`` rejects values longer than
:data:`SCHTASKS_TR_MAX_LEN` characters. The R4 preflight runs the size check
*after* the connectivity/credential checks (unreachable, auth_failed,
no_admin) and *before* any SCM call, so an unreachable or non-admin host is
never misreported as ``payload_too_large`` (R3/R4 acceptance 7).

No supporting file is ever uploaded or referenced: the entire payload lives
as the ``/TR`` string of the task definition the service exec registers.
"""

from __future__ import annotations

import time
from random import SystemRandom
from string import ascii_letters, digits

from impacket import system_errors
from impacket.dcerpc.v5 import scmr, transport
from impacket.smbconnection import SessionError

from spraytask.backends.base import (
    CONNECT_TIMEOUT,
    EXEC_TIMEOUT,
    SMBSession,
    BackendError,
    BackendResult,
    MethodError,
    NoAdminError,
    Status,
    build_schtasks_commands,
    preflight_capped,
)

#: Label used in :class:`BackendResult` and thus the console/JSON method field.
METHOD = "psexec"

_rng = SystemRandom()
_SERVICE_NAME_CHARS = ascii_letters + digits
#: Random scratch-service name; only the class of the value matters, so the
#: test suite can assert on it without knowing the exact string.
SERVICE_NAME_PREFIX = "SprayTaskSvc"


def random_service_name() -> str:
    """A random local service name for the transient SCM service."""
    return SERVICE_NAME_PREFIX + "".join(_rng.choices(_SERVICE_NAME_CHARS, k=8))


def deploy(
    host: str,
    port: int,
    cred,
    task_name: str,
    action: str,
    interval_minutes: int,
    *,
    connect_timeout: float = CONNECT_TIMEOUT,
    exec_timeout: float = EXEC_TIMEOUT,
) -> BackendResult:
    """Deploy the task by running ``schtasks.exe`` as SYSTEM via the SCM.

    Attempt order within a host (R3/R4): shared SMB connect+login
    (``unreachable`` / ``auth_failed``), ADMIN$ probe (``no_admin``), size
    preflight (``payload_too_large``, no SCM call), then the service exec
    (``ok`` / ``no_admin`` / ``method_error`` / ``error``). Returns a
    :class:`BackendResult`; never raises.
    """
    session: SMBSession | None = None
    try:
        session = preflight_capped(
            host=host,
            port=port,
            cred=cred,
            action=action,
            connect_timeout=connect_timeout,
            exec_timeout=exec_timeout,
        )
        # SCM launches a service via CreateProcess, which does not interpret
        # `&`; the create+run pair must ride in a shell for the sequence to
        # actually execute (the stale task form used the same cmd.exe /c wrap).
        command = "cmd.exe /c " + " & ".join(
            build_schtasks_commands(task_name, action, interval_minutes)
        )
        _exec_via_scm(session, command, exec_timeout)
        return BackendResult.ok(
            host, METHOD, "task created and triggered via SCM service exec"
        )
    except BackendError as exc:
        return BackendResult(host, exc.status, METHOD, exc.detail)
    except Exception as exc:
        return BackendResult(
            host, Status.ERROR, METHOD, f"{type(exc).__name__}: {exc}"
        )
    finally:
        if session is not None:
            session.close()


# -- SCM plumbing -------------------------------------------------------

def _exec_via_scm(session: SMBSession, command: str, exec_timeout: float) -> None:
    """Create, start, await, and delete a transient service (R3 psexec)."""
    rpc_transport = transport.SMBTransport(
            session.host,
            dstport=session.port,
            filename=r"\svcctl",
            smb_connection=session.connection,
        )
    rpc = None
    sc_handle = None
    svc_handle = None
    try:
        rpc = rpc_transport.get_dce_rpc()
        rpc.connect()
        rpc.bind(scmr.MSRPC_UUID_SCMR)
        service_name = random_service_name()
        sc_handle = scmr.hROpenSCManagerW(rpc)["lpScHandle"]
        _drop_stale_service(rpc, sc_handle, service_name)
        svc_handle = scmr.hRCreateServiceW(
            rpc,
            sc_handle,
            service_name,
            service_name,
            lpBinaryPathName=command + "\x00",
            dwStartType=scmr.SERVICE_DEMAND_START,
            dwErrorControl=scmr.SERVICE_ERROR_IGNORE,
        )["lpServiceHandle"]
        try:
            scmr.hRStartServiceW(rpc, svc_handle)
            _wait_for_stop(rpc, svc_handle, exec_timeout)
        finally:
            _cleanup_service(rpc, svc_handle)
    except scmr.DCERPCSessionError as exc:
        raise _classify_scm_error(exc) from exc
    except (transport.DCERPCException, SessionError) as exc:
        raise _classify_transport_error(exc) from exc
    except Exception as exc:
        raise MethodError(
            f"SCM exec failed: {type(exc).__name__}: {exc}"
        ) from exc
    finally:
        for handle in (svc_handle, sc_handle):
            if handle is not None:
                _best_effort(lambda: scmr.hRCloseServiceHandle(rpc, handle))
        try:
            rpc_transport.disconnect()
        except Exception:
            pass


def _drop_stale_service(rpc, sc_handle, service_name: str) -> None:
    """Remove a same-named leftover service so create is idempotent."""
    try:
        stale = scmr.hROpenServiceW(rpc, sc_handle, service_name)[
            "lpServiceHandle"
        ]
    except scmr.DCERPCSessionError as exc:
        if exc.get_error_code() == system_errors.ERROR_SERVICE_DOES_NOT_EXIST:
            return
        raise
    try:
        scmr.hRDeleteService(rpc, stale)
    finally:
        _best_effort(lambda: scmr.hRCloseServiceHandle(rpc, stale))


def _wait_for_stop(rpc, svc_handle, exec_timeout: float) -> None:
    """Wait for the scratch service to reach STOPPED so its schtasks
    output finished before we delete it. On timeout we still clean up."""
    deadline = time.monotonic() + exec_timeout
    while True:
        response = scmr.hRQueryServiceStatus(rpc, svc_handle)
        state = response["lpServiceStatus"]["dwCurrentState"]
        if state == scmr.SERVICE_STOPPED:
            return
        if time.monotonic() >= deadline:
            return
        time.sleep(0.1)


def _cleanup_service(rpc, svc_handle) -> None:
    """Best-effort stop + delete so no scratch service is left behind."""
    _best_effort(lambda: scmr.hRControlService(rpc, svc_handle, scmr.SERVICE_CONTROL_STOP))
    _best_effort(lambda: scmr.hRDeleteService(rpc, svc_handle))


def _classify_scm_error(exc: scmr.DCERPCSessionError) -> BackendError:
    code = exc.get_error_code()
    if code == system_errors.ERROR_ACCESS_DENIED:
        return NoAdminError(f"SCM denied (0x{code:08x})")
    return MethodError(f"SCM call failed (0x{code:08x})")


def _classify_transport_error(exc: Exception) -> BackendError:
    """Errors from binding/starting the svcctl pipe over the live session."""
    code = None
    getter = getattr(exc, "get_error_code", None)
    if getter is not None:
        try:
            code = getter()
        except Exception:
            code = None
    if code is not None and code == system_errors.ERROR_ACCESS_DENIED:
        return NoAdminError(f"svcctl denied (0x{code:08x})")
    if code is not None:
        return MethodError(f"svcctl RPC failed (0x{code:08x})")
    return MethodError(f"svcctl RPC failed: {type(exc).__name__}: {exc}")


def _best_effort(fn) -> None:
    try:
        fn()
    except Exception:
        pass