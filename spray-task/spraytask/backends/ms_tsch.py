"""MS-TSCH backend: native Task Scheduler RPC over SMB 445 (R4, primary backend).

Binds ``ncacn_np:\\pipe\\atsvc`` on the authenticated SMB session (impacket
``dcerpc.v5.tsch``) -- the login/tree connection goes through the shared task-5
SMB helper :func:`spraytask.backends.base.connect_smb` -- and registers a
repeating SYSTEM task via ``SchRpcRegisterTask`` with hand-built Task 2.0 XML,
then fires the first run explicitly via ``SchRpcRun`` (registration alone does
not run the task).

Task name is embedded in the RPC ``path`` (e.g. ``\\SprayTask_1234567890``),
not a separate argument; ``TASK_CREATE`` (=2) is used on first deploy and
``TASK_UPDATE`` (=4) overwrites an existing same-name task idempotently (there
is no ``TASK_CREATE_OR_UPDATE`` constant in impacket 0.13.1). An already-exists
HRESULT on create (ERROR_FILE_EXISTS / STG_E_FILEALREADYEXISTS, low 16 bits
``0x0050``) triggers the update retry.

Payloads of any size are carried inline as separate Command/Arguments XML
elements over RPC; there is no ``schtasks.exe`` ``/TR`` cap here, so this
backend performs **no size preflight** (R3). Failures are mapped onto the
shared status vocabulary by :func:`spraytask.backends.base.classify`,
the single classification source of truth -- this module never buckets error
codes itself.

Imports only ``impacket.dcerpc.v5.tsch``; the non-existent ``schtasks`` RPC
module is never referenced (acceptance 9).
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from impacket.dcerpc.v5 import tsch
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.transport import SMBTransport

from spraytask.backends.base import (
    CONNECT_TIMEOUT,
    EXEC_TIMEOUT,
    BackendResult,
    connect_smb,
)
from spraytask.creds import Credential
from spraytask.payload import build_ms_tsch_xml

#: Label recorded in :class:`BackendResult` and thus the console/JSON method field.
METHOD = "ms-tsch"

#: Named pipe to bind (impacket's transport factory strips the ``\\pipe\\`` prefix).
_ATSVIC_PIPE = r"\atsvc"

#: Low 16 bits of the HRESULT SchRpcRegisterTask returns under TASK_CREATE when
#: a task with the same name already exists (ERROR_FILE_EXISTS = 0x00000050 and
#: STG_E_FILEALREADYEXISTS = 0x80030050 both end in 0x0050).
_ALREADY_EXISTS_LOW = 0x0050


def normalize_task_path(task_name: str) -> str:
    """Task path with a single leading backslash (root folder), no trailing slash."""
    name = task_name.strip("\\")
    if not name:
        raise ValueError("task name must not be blank")
    return "\\" + name


def _register(
    dce: object,
    path: str,
    xml: str,
    flags: int,
) -> None:
    tsch.hSchRpcRegisterTask(
        dce,
        path=path,
        xml=xml,
        flags=flags,
        sddl=NULL,
        logonType=tsch.TASK_LOGON_PASSWORD,
        pCreds=(),
    )


def register_idempotent(dce: object, path: str, xml: str) -> None:
    """Register the task, overwriting an existing same-name task in place.

    First deploy uses ``TASK_CREATE``; when the remote reports that the task
    already exists, the call is retried with ``TASK_UPDATE`` so repeated runs of
    the tool are idempotent (R3). Any other error propagates to the caller.
    """
    try:
        _register(dce, path, xml, tsch.TASK_CREATE)
    except tsch.DCERPCSessionError as exc:
        if (exc.error_code or 0) & 0xFFFF == _ALREADY_EXISTS_LOW:
            _register(dce, path, xml, tsch.TASK_UPDATE)
        else:
            raise


@contextmanager
def _tsch_session(
    host: str,
    port: int,
    cred: Credential,
    connect_timeout: float,
    exec_timeout: float,
) -> Iterator[object]:
    """An RPC connection bound to the Task Scheduler service on the authenticated SMB session."""
    smb = None
    dce = None
    try:
        smb = connect_smb(
            host=host,
            port=port,
            cred=cred,
            connect_timeout=connect_timeout,
            exec_timeout=exec_timeout,
        )
        smb.connection.setTimeout(exec_timeout)
        transport = SMBTransport(
            remoteName=host,
            dstport=port,
            filename=_ATSVIC_PIPE,
            remote_host=host,
            smb_connection=smb.connection,
        )
        dce = transport.get_dce_rpc()
        dce.connect()
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        yield dce
    finally:
        if dce is not None:
            try:
                dce.disconnect()
            except Exception:
                pass
        if smb is not None:
            smb.close()


def deploy(
    host: str,
    port: int,
    cred: Credential,
    task_name: str,
    action: str,
    interval_minutes: int,
    *,
    connect_timeout: float = CONNECT_TIMEOUT,
    exec_timeout: float = EXEC_TIMEOUT,
) -> BackendResult:
    """Register a repeating SYSTEM task and fire its first run via MS-TSCH.

    ``action`` is the already-embedded single command line (R3). No size
    preflight exists in this backend: arbitrary-size payloads ride inline over
    RPC (R3/R4). Returns a :class:`BackendResult`; never raises. The ``Status``
    is produced by :func:`spraytask.backends.base.classify` on any failure.
    """
    try:
        task_path = normalize_task_path(task_name)
        xml = build_ms_tsch_xml(action, interval_minutes, task_name=task_path)
        with _tsch_session(host, port, cred, connect_timeout, exec_timeout) as dce:
            register_idempotent(dce, task_path, xml)
            tsch.hSchRpcRun(dce, path=task_path)
    except Exception as exc:
        return BackendResult.for_exception(host, METHOD, exc)
    return BackendResult.ok(
        host,
        METHOD,
        f"registered repeating SYSTEM task {task_path} and started it",
    )