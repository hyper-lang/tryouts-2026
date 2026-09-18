"""Payload and task-action builder (R3): command vs PowerShell, size caps, MS-TSCH XML.

Two mutually exclusive payload modes are normalized into a single task action
command line:

* ``--command`` is used verbatim as the action.
* PowerShell sequence statements (inline ``--ps-command`` and/or local
  ``--ps-file``) are joined in order with ``;``; the joined script is embedded
  in the action as ``powershell.exe -NoProfile -NonInteractive -ExecutionPolicy
  Bypass -EncodedCommand <b64>`` where ``<b64>`` is the UTF-16LE base64 of the
  script.

In either mode the entire payload is EMBEDDED IN THE TASK ACTION as a single
command line; nobody may copy or write a script/payload file to the remote host.

The hard size limit is that of ``schtasks.exe``: a ``/TR`` value longer than
``SCHTASKS_TR_MAX`` (261) characters is rejected, which caps the psexec/WMI
backends. The MS-TSCH backend has no such cap (Command/Arguments are separate
XML elements carried inline over RPC), so it performs no size preflight.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Optional, Sequence

#: Documented schtasks.exe /TR maximum length.
SCHTASKS_TR_MAX = 261

POWERSHELL_EXE = "powershell.exe"
#: PowerShell invocation prefix for the embedded action (R3 embedding technique).
POWERSHELL_ARGS = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand"

XML_HEADER = '<?xml version="1.0" encoding="UTF-16"?>\n'


def join_ps_statements(statements: Sequence[str]) -> str:
    """Join PowerShell statements in order with ``;`` into one script."""
    return ";".join(statements)


def encode_powershell_action(script: str) -> str:
    """Embed a PowerShell script as a single ``powershell.exe -EncodedCommand`` line."""
    encoded = b64encode_utf16(script)
    return f"{POWERSHELL_EXE} {POWERSHELL_ARGS} {encoded}"


def b64encode_utf16(script: str) -> str:
    """UTF-16LE base64 of a script (the ``-EncodedCommand`` value)."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def build_action_command(
    command: Optional[str], ps_statements: Sequence[str] = ()
) -> str:
    """The single task-action command line for the requested payload mode.

    ``command`` wins verbatim when given; otherwise the PowerShell sequence is
    encoded into a single ``-EncodedCommand`` line (PS mode). Exactly one mode
    is required; violating that is a CLI (validation) concern, not this module's.
    """
    if command is not None:
        return command
    return encode_powershell_action(join_ps_statements(ps_statements))


def exceeds_cap(action: str, cap: int = SCHTASKS_TR_MAX) -> bool:
    """True when the encoded action exceeds a backend's documented cap (R3)."""
    return len(action) > cap


# --- MS-TSCH Task 2.0 XML -----------------------------------------------------

def repetition_interval(interval_minutes: int) -> str:
    """ISO 8601 duration for a repeating trigger, e.g. ``PT5M``."""
    return f"PT{int(interval_minutes)}M"


def xml_escape(text: str) -> str:
    """Escape the five XML metacharacters ``& < > \" '`` for text or attribute."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def split_command_line(action: str) -> tuple[str, str]:
    """Split an action line into ``(Command, Arguments)`` for the Exec element.

    A leading double-quoted token (path with spaces) is taken verbatim as the
    Command; otherwise the first whitespace-delimited token is the Command and
    the remainder the Arguments. Deterministic and free of shell parsing.
    """
    stripped = action.strip()
    if not stripped:
        return "", ""
    if stripped.startswith('"'):
        end = stripped.find('"', 1)
        if end != -1:
            return stripped[1:end], stripped[end + 1 :].strip()
    first, sep, rest = stripped.partition(" ")
    if not sep:
        return stripped, ""
    return first, rest.strip()


def _utc_now_ts() -> str:
    """Current UTC time in the Task Scheduler ``YYYY-MM-DDTHH:MM:SS`` form."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def build_ms_tsch_xml(
    action: str,
    interval_minutes: int,
    start_boundary: Optional[str] = None,
    task_name: str = "",
) -> str:
    """Hand-crafted Task 2.0 XML for the MS-TSCH backend (R3 design note).

    The repetition must be an explicit trigger block: a ``<TimeTrigger>``
    wrapping ``<Repetition><Interval>PT{N}M</Interval><StopAtDurationEnd>false
    </StopAtDurationEnd></Repetition>``. The principal is SYSTEM (S-1-5-18) at
    run level ``HIGHEST`` with the "run whether user is logged on" logon type.
    ``MultipleInstancesPolicy`` is ``IgnoreNew`` and ``AllowStartOnDemand`` is
    ``true`` so an explicit ``SchRpcRun`` can fire the first run (registration
    alone does not run the task). Command and Arguments are separate,
    XML-escaped ``<Exec>`` elements.
    """
    command, arguments = split_command_line(action)
    interval = repetition_interval(interval_minutes)
    start = start_boundary if start_boundary is not None else _utc_now_ts()
    title = xml_escape(task_name.strip("\\")) if task_name.strip("\\") else "spray-task"
    return (
        f"{XML_HEADER}"
        f"<Task version=\"1.2\" "
        f"xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
        f"  <RegistrationInfo>\n"
        f"    <Date>{start}</Date>\n"
        f"    <Author>spray-task</Author>\n"
        f"    <Description>spray-task deployment of {title}</Description>\n"
        f"  </RegistrationInfo>\n"
        f"  <Triggers>\n"
        f"    <TimeTrigger>\n"
        f"      <StartBoundary>{start}</StartBoundary>\n"
        f"      <Enabled>true</Enabled>\n"
        f"      <Repetition>\n"
        f"        <Interval>{interval}</Interval>\n"
        f"        <StopAtDurationEnd>false</StopAtDurationEnd>\n"
        f"      </Repetition>\n"
        f"    </TimeTrigger>\n"
        f"  </Triggers>\n"
        f"  <Principals>\n"
        f"    <Principal id=\"Author\">\n"
        f"      <UserId>S-1-5-18</UserId>\n"
        f"      <LogonType>Password</LogonType>\n"
        f"      <RunLevel>HighestAvailable</RunLevel>\n"
        f"    </Principal>\n"
        f"  </Principals>\n"
        f"  <Settings>\n"
        f"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
        f"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
        f"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
        f"    <AllowHardTerminate>true</AllowHardTerminate>\n"
        f"    <StartWhenAvailable>false</StartWhenAvailable>\n"
        f"    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n"
        f"    <IdleSettings>\n"
        f"      <StopOnIdleEnd>true</StopOnIdleEnd>\n"
        f"      <RestartOnIdle>false</RestartOnIdle>\n"
        f"    </IdleSettings>\n"
        f"    <AllowStartOnDemand>true</AllowStartOnDemand>\n"
        f"    <Enabled>true</Enabled>\n"
        f"    <Hidden>false</Hidden>\n"
        f"    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n"
        f"    <WakeToRun>false</WakeToRun>\n"
        f"    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n"
        f"    <Priority>7</Priority>\n"
        f"  </Settings>\n"
        f"  <Actions Context=\"Author\">\n"
        f"    <Exec>\n"
        f"      <Command>{xml_escape(command)}</Command>\n"
        f"      <Arguments>{xml_escape(arguments)}</Arguments>\n"
        f"    </Exec>\n"
        f"  </Actions>\n"
        f"</Task>\n"
    )


# --- schtasks.exe command templates (psexec/WMI backends) ---------------------

def schtasks_create_cmd(task_name: str, action: str, interval_minutes: int) -> str:
    """schtasks.exe create line for the capped backends (R3 design note).

    ``/SC MINUTE /MO <N>`` is the repetition; ``/RU SYSTEM /RL HIGHEST`` the
    principal. ``/IT`` (interactive-only) and ``/RI`` (invalid with MINUTE)
    are deliberately never used.
    """
    return (
        f'schtasks /Create /F /TN "{task_name}" /TR "{action}" '
        f"/SC MINUTE /MO {int(interval_minutes)} /RU SYSTEM /RL HIGHEST"
    )


def schtasks_run_cmd(task_name: str) -> str:
    """schtasks.exe line that fires the first run after create."""
    return f'schtasks /Run /TN "{task_name}"'