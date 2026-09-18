"""Command-line entry point for spray-task (task 10, full flag surface).

Wires the epic's front-to-back flow: host-file parsing (R1), global/per-host
credentials (R2), payload building (R3), the backend chain (R4), the
concurrent runner (R6) and the masked JSON report (R5, exit codes 0/1/2).
Validation happens before any network call; every misuse exits 1, a run where
every host deployed exits 0, and any per-host failure exits 2 (the per-host
console lines, the summary and the JSON report are still produced).

``spraytask.hosts``/``creds``/``payload``/``report`` are imported at module
load (all impacket-free); ``spraytask.runner`` -- which pulls in impacket via
``backends.base`` -- is imported lazily inside :func:`main` so ``--version``/
``--help`` keep working even on a box where impacket is not importable (the
runtime guard's only job is to warn, not to hard-fail).
"""

from __future__ import annotations

import argparse
import platform
import sys
import time
from importlib.metadata import PackageNotFoundError, version as _distribution_version
from typing import List, Optional, Sequence, Tuple

try:
    import impacket
except ImportError:  # pragma: no cover - environment error, not exercised by tests
    impacket = None

from spraytask import hosts, payload
from spraytask.creds import Credential, parse_nt_hash, resolve_for_host
from spraytask.report import DEFAULT_REPORT_PATH

IMPAKET_MIN_VERSION: Tuple[int, int, int] = (0, 13, 0)

#: ``--backend`` choices (R4): pin one method, or run the auto chain.
BACKEND_CHOICES: Tuple[str, ...] = ("ms-tsch", "psexec", "wmi", "auto")

#: Minimum allowed values for the CLI-validated numeric flags.
MIN_INTERVAL_MINUTES = 1
MIN_THREADS = 1

#: Default task name prefix when ``--task-name`` is not given (R3).
TASK_NAME_PREFIX = "SprayTask_"


def parse_impacket_version(version_str: str) -> Tuple[int, int, int]:
    """Parse an impacket version string into a comparable (major, minor, patch) tuple.

    Trailing pre-release/development labels are ignored: ``"0.13.1"`` and
    ``"0.13.1.dev1"`` both parse to ``(0, 13, 1)``. A string with no leading
    digits yields ``(0, 0, 0)``.
    """
    parts: list[int] = []
    for raw in version_str.split("."):
        digits = "".join(ch for ch in raw if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    while len(parts) < 3:
        parts.append(0)
    return (parts[0], parts[1], parts[2])


def _impacket_version_raw() -> Optional[str]:
    """Return the installed impacket version string, or None when undeterminable.

    impacket does not expose a module-level ``__version__``; the installed
    version comes from distribution metadata (``importlib.metadata``).
    """
    if impacket is None:
        return None
    try:
        return _distribution_version("impacket")
    except PackageNotFoundError:
        return None


def warn_if_impacket_too_old(version: Optional[Tuple[int, int, int]] = None) -> None:
    """Emit a startup warning (never a hard fail) when impacket is too old.

    The guard is deliberately permissive: when it cannot determine the
    installed impacket (missing package, unparseable version) it warns rather
    than raising, so ``--version`` and startup keep working.
    """
    actual = version
    if actual is None:
        raw = _impacket_version_raw()
        if raw is None:
            print(
                "Warning: impacket is not installed (declared dependency).",
                file=sys.stderr,
            )
            return
        actual = parse_impacket_version(raw)
    if actual < IMPAKET_MIN_VERSION:
        shown = ".".join(str(part) for part in actual)
        minimum = ".".join(str(part) for part in IMPAKET_MIN_VERSION)
        print(
            f"Warning: impacket {shown} is older than {minimum}; "
            "0.13.x+ is required for Python 3.13 support.",
            file=sys.stderr,
        )


def _print_versions() -> None:
    print(f"Python {platform.python_version()}")
    raw = _impacket_version_raw()
    if raw is None:
        print("impacket <not installed>")
    else:
        print(f"impacket {raw}")


class _SprayTaskArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that exits with usage-status 1 on errors (project contract)."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def default_task_name() -> str:
    """``SprayTask_<epoch>``, the task name when ``--task-name`` is absent (R3)."""
    return f"{TASK_NAME_PREFIX}{int(time.time())}"


def read_ps_file(path: str) -> List[str]:
    """Read a LOCAL ``--ps-file``: one statement per line, blank lines skipped.

    Deliberately ``utf-8`` (not ``utf-8-sig``): a UTF-8 BOM at the start of a
    statement file is an accepted edge (see ``ralph/memory.md``). Only local
    files are read; nothing is ever copied to the remote host (R3).
    """
    with open(path, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


def collect_ps_statements(
    ps_commands: Sequence[str], ps_files: Sequence[str]
) -> List[str]:
    """All PowerShell statements in order: each ``--ps-command`` (stripped,
    non-blank), then each ``--ps-file``'s lines, files in the given order.

    Raises ``OSError``/``UnicodeError`` when a local statement file cannot be
    read; the caller turns that into a usage error.
    """
    statements: List[str] = []
    for raw in ps_commands:
        statement = raw.strip()
        if statement:
            statements.append(statement)
    for path in ps_files:
        statements.extend(read_ps_file(path))
    return statements


def validate_payload_mode(
    command: Optional[str], ps_statements: Sequence[str]
) -> str:
    """Exactly one of ``--command`` / PowerShell mode, then build the action.

    Returns the single task-action command line (R3). Raises ``ValueError``
    with a secret-free message on misuse; the caller turns that into a usage
    error (exit 1). ``--command`` is stripped for the emptiness check but the
    surviving (stripped) text is what becomes the action.
    """
    command = command.strip() if command is not None else None
    if command is not None and ps_statements:
        raise ValueError(
            "--command and PowerShell mode (--ps-command/--ps-file) are "
            "mutually exclusive; give exactly one payload mode"
        )
    if command is None and not ps_statements:
        raise ValueError(
            "a payload is required: --command, or --ps-command/--ps-file"
        )
    if command == "":
        raise ValueError("--command must not be empty")
    statements = ps_statements if command is None else ()
    return payload.build_action_command(command=command, ps_statements=statements)


def build_global_credential(
    user: Optional[str],
    password: Optional[str],
    hash_raw: Optional[str],
    domain: Optional[str],
) -> Optional[Credential]:
    """The global credential from CLI flags, or None when none were given.

    Consistency is validated first (``-u`` required with a secret, exactly one
    of ``-p``/``--hash``, never both); secrets are never echoed in an error.
    Raises ``ValueError`` on misuse.
    """
    user = (user or "").strip()
    provided = bool(user or password is not None or hash_raw is not None)
    if not provided:
        return None
    if not user:
        raise ValueError(
            "-u/--user is required when supplying -p/--password or --hash"
        )
    has_password = password is not None
    has_hash = hash_raw is not None
    if has_password and has_hash:
        raise ValueError("-p/--password and --hash are mutually exclusive")
    if not has_password and not has_hash:
        raise ValueError(
            "-u/--user requires exactly one of -p/--password or --hash"
        )
    nt = None
    if has_hash:
        try:
            nt = parse_nt_hash(hash_raw)
        except ValueError:
            raise ValueError(
                "invalid --hash: must be a 32-hex NT hash or a "
                "'<lm32hex>:<nt32hex>' pair"
            ) from None
    return Credential(
        domain=domain or "", user=user, password=password, nt_hash=nt
    )


def override_credential(entry: hosts.HostEntry) -> Optional[Credential]:
    """Convert a host-file override into a :class:`spraytask.creds.Credential`.

    Per-host file overrides only ever carry a password (R1 grammar), never a
    hash.
    """
    if entry.credential is None:
        return None
    file_cred = entry.credential
    return Credential(
        domain=file_cred.domain or "",
        user=file_cred.username,
        password=file_cred.password,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = _SprayTaskArgumentParser(
        prog="spraytask",
        description=(
            "Remote scheduled-task sprayer: registers a SYSTEM-privileged, "
            "repeating scheduled task on remote Windows hosts. Authorized use "
            "only, on systems with explicit permission to test."
        ),
    )
    parser.add_argument(
        "hostfile",
        nargs="?",
        metavar="HOSTFILE",
        help=(
            "List of target hosts, one per line; blank and '#' lines are "
            "ignored. A line is 'host', 'host:port', '[v6]', '[v6]:port', or "
            "a per-host credential override '[domain\\]user:password@host[:port]'."
        ),
    )

    creds = parser.add_argument_group("credentials (applied to every backend)")
    creds.add_argument(
        "-u", "--user", metavar="USER", help="Global account name (R2)."
    )
    creds.add_argument(
        "-p",
        "--password",
        metavar="PASSWORD",
        help=(
            "Global account password. Never echoed in output or reports. "
            "Mutually exclusive with --hash."
        ),
    )
    creds.add_argument(
        "-d", "--domain", metavar="DOMAIN", help="Global account domain (optional)."
    )
    creds.add_argument(
        "--hash",
        metavar="HASH",
        help=(
            "NT hash for pass-the-hash, "
            "'aad3b435b51404eeaad3b435b51404ee:<NTLM>' or a bare 32-hex NT "
            "hash. Mutually exclusive with --password."
        ),
    )

    payload_group = parser.add_argument_group("payload (exactly one mode required)")
    payload_group.add_argument(
        "--command",
        metavar="CMD",
        help="Full command line the task executes as SYSTEM (verbatim action).",
    )
    payload_group.add_argument(
        "--ps-command",
        metavar="STATEMENT",
        action="append",
        default=[],
        help=(
            "One PowerShell statement; repeatable. Statements are joined in "
            "order with ';' and embedded via powershell.exe -EncodedCommand."
        ),
    )
    payload_group.add_argument(
        "--ps-file",
        metavar="PATH",
        action="append",
        default=[],
        help=(
            "LOCAL text file read by this tool, one PowerShell statement per "
            "line; repeatable. Never copied to the remote host."
        ),
    )

    task = parser.add_argument_group("task specification")
    task.add_argument(
        "--task-name",
        metavar="NAME",
        default=None,
        help=f"Scheduled-task name (default: {TASK_NAME_PREFIX}<epoch>).",
    )
    task.add_argument(
        "--interval-minutes",
        metavar="N",
        type=int,
        default=5,
        help="Repeat interval in minutes, >= 1 (default: 5, indefinite).",
    )

    run = parser.add_argument_group("runner / reporting")
    run.add_argument(
        "--backend",
        metavar="BACKEND",
        choices=BACKEND_CHOICES,
        default="auto",
        help=(
            "Pin one backend or use auto fallback (default: auto, order "
            "ms-tsch -> psexec -> wmi on each host)."
        ),
    )
    run.add_argument(
        "--threads",
        metavar="N",
        type=int,
        default=10,
        help="Concurrent host workers (default: 10).",
    )
    run.add_argument(
        "--try-all",
        action="store_true",
        help=(
            "Keep trying backends past ok/auth_failed instead of stopping a "
            "host's chain at the first terminal status."
        ),
    )
    run.add_argument(
        "--report",
        metavar="PATH",
        default=DEFAULT_REPORT_PATH,
        help=f"JSON report path (default: {DEFAULT_REPORT_PATH}).",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print the Python interpreter and impacket versions and exit.",
    )
    return parser


def _report_host_errors(path: str, host_errors) -> None:
    """One stderr line per malformed host line, WITHOUT echoing the raw line.

    The raw override line can contain ``user:password@host`` (R1 grammar);
    echoing it would leak a password to stderr. Line number + reason still
    satisfy R1's "reported, not silently dropped".
    """
    for error in host_errors:
        print(f"{path}: line {error.line_no}: {error.reason}", file=sys.stderr)


def main(argv: Optional[Sequence[str]] = None) -> int:
    warn_if_impacket_too_old()  # never a hard fail (R7/acceptance 12)
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        _print_versions()
        return 0
    if args.hostfile is None:
        parser.print_help()
        return 1
    if args.interval_minutes < MIN_INTERVAL_MINUTES:
        parser.error(
            f"--interval-minutes must be >= {MIN_INTERVAL_MINUTES} "
            f"(got {args.interval_minutes})"
        )
    if args.threads < MIN_THREADS:
        parser.error(f"--threads must be >= {MIN_THREADS} (got {args.threads})")

    try:
        ps_statements = collect_ps_statements(args.ps_command, args.ps_file)
    except (OSError, UnicodeError) as exc:
        parser.error(f"cannot read --ps-file: {exc}")
    try:
        action = validate_payload_mode(args.command, ps_statements)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        global_cred = build_global_credential(
            args.user, args.password, args.hash, args.domain
        )
    except ValueError as exc:
        parser.error(str(exc))

    try:
        from spraytask import runner
    except ImportError:
        print(
            "spraytask: impacket (declared dependency) could not be imported; "
            "install with `pip install -e .`",
            file=sys.stderr,
        )
        return 1

    try:
        entries, host_errors = hosts.load_host_file(args.hostfile)
    except OSError as exc:
        parser.error(f"cannot read host file {args.hostfile!r}: {exc}")
    if host_errors:
        _report_host_errors(args.hostfile, host_errors)
        parser.error(f"{len(host_errors)} malformed host line(s) in {args.hostfile}")

    overrides = {
        entry.address: override_credential(entry)
        for entry in entries
        if entry.credential is not None
    }
    task_name = args.task_name or default_task_name()

    specs = []
    for entry in entries:
        cred = resolve_for_host(entry.address, overrides, global_cred)
        specs.append(
            runner.DeploySpec(
                host=entry.address,
                action=action,
                task_name=task_name,
                interval_minutes=args.interval_minutes,
                cred=cred,
                port=entry.port,
            )
        )

    order = None if args.backend == "auto" else [args.backend]
    r = runner.Runner(order=order, threads=args.threads, try_all=args.try_all)
    summary = r.run(specs)

    host_records = []
    for spec, result in zip(specs, summary.results):
        host_records.append(
            {
                "address": spec.host,
                "port": spec.port,
                "methods": list(r.effective_order(spec)),
                "status": result.status,
                "detail": result.detail,
            }
        )
    cli_args = {
        "hostfile": args.hostfile,
        "user": args.user,
        "password": args.password,
        "hash": args.hash,
        "domain": args.domain,
        "command": args.command,
        "task_name": task_name,
        "interval_minutes": args.interval_minutes,
        "backend": args.backend,
        "threads": args.threads,
        "report": args.report,
        "try_all": bool(args.try_all),
    }
    run_meta: dict = {"cli_args": cli_args, "global_credential": global_cred}
    if argv is not None:
        run_meta["argv"] = list(argv)
    try:
        from spraytask import report as report_mod

        report_mod.write_report(
            args.report,
            run_meta=run_meta,
            host_results=host_records,
            summary={
                "status_counts": summary.counts,
                "elapsed_seconds": summary.elapsed,
            },
        )
    except OSError as exc:
        print(
            f"spraytask: cannot write report {args.report!r}: {exc}",
            file=sys.stderr,
        )
        return 1
    return summary.exit_code


if __name__ == "__main__":
    sys.exit(main())