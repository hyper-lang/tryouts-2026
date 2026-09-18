"""Backend implementations for the spray-task runner.

The chain, in default order: ``ms-tsch`` (native Task Scheduler RPC over the
SMB 445 session), ``psexec`` (schtasks.exe via a scratch SCM service over SMB
445, 261-char cap), and ``wmi`` (schtasks.exe via DCOM 135 / ``Win32_Process``
exec, 261-char cap). ``auto`` is the runner's chain, defined in
``spraytask.runner``.
"""