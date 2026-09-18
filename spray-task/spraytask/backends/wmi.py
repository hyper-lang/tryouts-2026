"""WMI backend over DCOM (``spraytask/backends/wmi.py``).

Third member of the backend chain, over the distinct transport: DCOM RPC
(port 135 + a dynamic high port), NOT SMB 445. It connects to ``root\\cimv2``
via ``IWbemLevel1Login`` (impacket ``dcom/wmi``), then executes the
``schtasks.exe`` create+run pair built by
:func:`spraytask.backends.base.build_schtasks_commands` through
``Win32_Process.Create`` (the wmiexec-style exec path). The exec token is the
authenticated admin; SYSTEM comes from the task's ``/RU SYSTEM`` principal,
which an admin is permitted to register.

Capped backend with R4 ordering over the DCOM path: TCP probe + DCOM
connect/login (``unreachable`` / ``auth_failed`` / ``no_admin`` / the size
check (``payload_too_large``, no ``ExecMethod`` call) / the WMI exec
(``no_admin`` / ``method_error``). This deliberately re-implements the
ordering instead of reusing the SMB-bound ``preflight_capped`` (R4, task 8).
Every exec command is prefixed with ``cmd.exe /c `` (the wmiexec convention):
``Win32_Process.Create`` launches via ``CreateProcess``, which has no shell, so
the prefix keeps a multi-command ``&`` chain from collapsing into junk
arguments. A pure string prefix -- it never changes the ``/TR`` quoting and
writes no remote file.

No supporting file is ever written remotely: the entire payload lives as the
``/TR`` string of the task definition the exec registers.
"""

from __future__ import annotations

from typing import Optional

from impacket.dcerpc.v5 import dcomrt
from impacket.dcerpc.v5.dcom import wmi as _wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection, INTERFACE
from impacket.dcerpc.v5.dtypes import NULL

from spraytask.backends.base import (
    CONNECT_TIMEOUT,
    EXEC_TIMEOUT,
    BackendError,
    BackendResult,
    Error,
    Status,
    build_schtasks_commands,
    check_payload_size,
    classify,
    probe_tcp,
)
from spraytask.creds import Credential

#: Label used in :class:`BackendResult` and thus the console/JSON method field.
METHOD = "wmi"

#: Fixed DCOM endpoint mapper port; ``host:port`` in the host file is the SMB
#: port, so the WMI backend always uses 135.
WMI_PORT = 135

#: Root WMI namespace with Win32_Process, the exec class (R4).
WMI_NAMESPACE = "//./root/cimv2"


def _describe(exc: BaseException, limit: int = 300) -> str:
    """A short, secret-free detail line for a failure."""
    text = str(exc).strip()
    if not text:
        text = type(exc).__name__
    return text[:limit]


class WmiProvider:
    """A live impacket DCOM/WMI session executing ``Win32_Process.Create``.

    Connect flow: TCP probe of port 135, ``DCOMConnection`` (portmap bind over
    ``ncacn_ip_tcp``), ``CoCreateInstanceEx(WbemLevel1Login)``, then
    ``IWbemLevel1Login.NTLMLogin`` to ``root\\cimv2``. The class is
    monkeypatch-friendly: backends accept an injectable ``provider_factory``,
    so tests swap this for a fake with the same ``connect``/``exec_command``/
    ``close`` shape.
    """

    def __init__(
        self, dcom: dcomrt.DCOMConnection, services: object, host: str
    ) -> None:
        self._dcom = dcom
        self._services = services
        self.host = host

    @classmethod
    def connect(
        cls,
        host: str,
        cred: Optional[Credential],
        *,
        connect_timeout: float = CONNECT_TIMEOUT,
        exec_timeout: float = EXEC_TIMEOUT,
    ) -> "WmiProvider":
        """Open and authenticate a WMI session to ``host`` (port 135)."""
        if cred is None:
            raise Error("no credential available for host")
        probe_tcp(host, WMI_PORT, connect_timeout)
        dcom = DCOMConnection(
            host,
            cred.user,
            cred.password or "",
            cred.domain or "",
            cred.lm_hash or "",
            cred.nthash or "",
        )
        try:
            iinterface = dcom.CoCreateInstanceEx(
                _wmi.CLSID_WbemLevel1Login, _wmi.IID_IWbemLevel1Login
            )
            login = _wmi.IWbemLevel1Login(iinterface)
            services = login.NTLMLogin(WMI_NAMESPACE, NULL, NULL)
            login.RemRelease()
        except BaseException:
            dcom.disconnect()
            raise
        provider = cls(dcom, services, host)
        provider._apply_timeouts(exec_timeout)
        return provider

    def exec_command(self, command: str) -> None:
        """Run one command line through ``Win32_Process.Create``."""
        win32_process, _ = self._services.GetObject("Win32_Process")
        win32_process.Create(command, NULL, NULL)

    def close(self) -> None:
        """Tear down the DCOM connection. Never raises."""
        try:
            self._dcom.disconnect()
        except Exception:
            pass

    def _apply_timeouts(self, exec_timeout: float) -> None:
        """Best-effort exec-timeout enforcement on the DCOM socket(s).

        The WMI transport opens a dynamic high port whose transport defaults
        to a long connect timeout and no recv timeout; pin both to
        ``exec_timeout`` so a dead peer cannot hang a host slot indefinitely
        (R6). Swallows every error -- timeout tuning must never break a
        healthy session.
        """
        dces = []
        try:
            dces.append(self._dcom.get_dce_rpc())
        except Exception:
            pass
        for connections in INTERFACE.CONNECTIONS.get(self.host, {}).values():
            for entry in connections.values():
                try:
                    dces.append(entry["dce"])
                except (KeyError, TypeError):
                    continue
        for dce in dces:
            try:
                transport = dce.get_rpc_transport()
                transport.get_socket().settimeout(exec_timeout)
            except Exception:
                continue


def deploy(
    host: str,
    port: Optional[int],
    cred: Optional[Credential],
    task_name: str,
    action: str,
    interval_minutes: int,
    *,
    connect_timeout: float = CONNECT_TIMEOUT,
    exec_timeout: float = EXEC_TIMEOUT,
    provider_factory=None,
) -> BackendResult:
    """Register a repeating SYSTEM task and fire its first run via WMI.

    ``action`` is the already-embedded single command line (R3); it must
    respect the 261-char ``schtasks.exe`` cap (the runner only reaches this
    backend for capped size, but the check is enforced here over the DCOM
    path too). ``port`` is accepted for a uniform backend signature but not
    used (DCOM always targets port 135).

    Attempt order (R4): DCOM connect+login first, then the size preflight
    (``payload_too_large`` with no exec call), then the create+run exec pair.
    Returns a :class:`BackendResult`; never raises.
    """
    provider = None
    try:
        if cred is None:
            raise Error("no credential available for host")
        factory = provider_factory or WmiProvider
        provider = factory.connect(
            host,
            cred,
            connect_timeout=connect_timeout,
            exec_timeout=exec_timeout,
        )
        check_payload_size(action)
        for command in build_schtasks_commands(
            task_name, action, interval_minutes
        ):
            provider.exec_command("cmd.exe /c " + command)
    except Exception as exc:
        return BackendResult(host, classify(exc), METHOD, _describe(exc))
    finally:
        if provider is not None:
            try:
                provider.close()
            except Exception:
                pass
    return BackendResult(
        host,
        Status.OK,
        METHOD,
        f"registered repeating SYSTEM task {task_name} and started it",
    )