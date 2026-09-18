"""Per-host orchestration: backend chain, threading, console output (R9).

The runner is the coordination layer between the CLI (which produces one
:class:`DeploySpec` per host) and the per-host backend callables. It owns the
backend chain and its rules:

* auto chain order ``ms-tsch`` (primary) -> ``psexec`` -> ``wmi``, or a single
  pinned backend when the CLI passes ``--backend``;
* terminal vs. fall-through: ``ok`` and ``payload_too_large`` always end a
  host; ``auth_failed`` ends it too unless ``--try-all`` relaxes it; the
  connectivity/privilege/method classes (``no_admin``, ``unreachable``,
  ``method_error``, ``error``) fall through to the next backend;
* the R3 cap rule: when the encoded action exceeds ``SCHTASKS_TR_MAX_LEN``,
  auto mode attempts only the uncapped ``ms-tsch`` backend, so a later capped
  backend can never replace an earlier connectivity reading with a size error;
* a uniform, never-overridden ``connect_timeout``/``exec_timeout`` pair, one
  host per ``ThreadPoolExecutor`` worker, a per-attempt deadline that aborts an
  overrunning backend as ``error``, and one locked, atomic console line per
  host plus a summary line;
* exit status ``0`` when every host ended ``ok``, ``2`` otherwise.

Every backend is called with the same keyword set
``(host, port, cred, task_name, action, interval_minutes, connect_timeout,
exec_timeout)``, matching the actual ``deploy`` signatures in the three backend
modules. Nothing here writes payload files, prints credentials, or calls
impacket directly.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Mapping, Optional, Sequence

from spraytask.backends.base import (
    ALL_STATUSES,
    CONNECT_TIMEOUT,
    EXEC_TIMEOUT,
    SCHTASKS_TR_MAX_LEN,
    BackendResult,
    Status,
)
from spraytask.creds import Credential

#: Default chain order, primary first (R4/R9).
AUTO_ORDER: tuple[str, ...] = ("ms-tsch", "psexec", "wmi")

#: Backends whose embedded-action cap (schtasks ``/TR``) can reject an
#: oversized payload (R3); auto mode skips them for oversized actions.
CAPPED_BACKENDS: frozenset[str] = frozenset(("psexec", "wmi"))

#: Worker pool size when the CLI does not pass ``--threads``.
DEFAULT_THREADS = 10

#: Statuses that end a host's chain by default and are relaxed by ``--try-all``.
#: ``payload_too_large`` is terminal in every mode.
TRY_ALL_RELAXES: frozenset[str] = frozenset(
    (Status.OK.value, Status.AUTH_FAILED.value)
)

BackendCallable = Callable[..., BackendResult]


@dataclass(frozen=True)
class DeploySpec:
    """Everything the runner knows about one host for one deployment (R9).

    ``action`` is the already-embedded single command line that becomes the
    ``/TR`` value of ``schtasks.exe`` (a ``powershell.exe ... -EncodedCommand``
    line or a plain ``--command``). The timeouts are deliberately **not** on
    the spec: the runner enforces one uniform pair for every host, so a host
    file or CLI can never override them per-host.
    """

    host: str
    action: str
    task_name: str
    interval_minutes: int
    cred: Optional[Credential] = None
    port: Optional[int] = None


def default_backends() -> dict[str, BackendCallable]:
    """The real backend callables keyed by method label (lazy import)."""
    from spraytask.backends.ms_tsch import deploy as deploy_ms_tsch
    from spraytask.backends.psexec import deploy as deploy_psexec
    from spraytask.backends.wmi import deploy as deploy_wmi

    return {
        "ms-tsch": deploy_ms_tsch,
        "psexec": deploy_psexec,
        "wmi": deploy_wmi,
    }


def _coerce_backend(backend: object) -> BackendCallable:
    """Normalize a backend to a uniform keyword-callable.

    Accepts either a callable or an object exposing an instance method
    ``run(**kwargs)``.
    """
    runner = getattr(backend, "run", None)
    if callable(runner):
        return runner
    if callable(backend):
        return backend
    raise TypeError(
        f"backend must be callable or expose run(...), "
        f"got {type(backend).__name__}"
    )


def _call_kwargs(
    spec: DeploySpec,
    connect_timeout: float,
    exec_timeout: float,
) -> dict:
    """The uniform keyword set passed to every backend call."""
    return {
        "host": spec.host,
        "port": spec.port,
        "cred": spec.cred,
        "task_name": spec.task_name,
        "action": spec.action,
        "interval_minutes": spec.interval_minutes,
        "connect_timeout": connect_timeout,
        "exec_timeout": exec_timeout,
    }


def _status_value(status: object) -> str:
    """The plain status string from a :class:`Status` member or a raw string.

    ``Status`` is a ``str``-subclass enum, so ``isinstance(value, str)`` is
    true for its members but ``str(member)`` still renders as ``Status.OK``;
    we must prefer the explicit ``.value`` attribute whenever one exists.
    """
    value = getattr(status, "value", None)
    if value is not None:
        return value
    return status


@dataclass(frozen=True)
class RunSummary:
    """Aggregated outcome of one ``Runner.run`` over all hosts.

    ``results`` are one :class:`BackendResult` per host in input order,
    ``counts`` the tally by status string over :data:`ALL_STATUSES`,
    ``elapsed`` the wall-clock seconds, and ``exit_code`` 0 when every host
    ended ``ok``.
    """

    results: tuple[BackendResult, ...]
    elapsed: float
    counts: Mapping[str, int]
    exit_code: int


def count_results(results: Sequence[BackendResult]) -> dict[str, int]:
    """Tally results by status string (unknown statuses are still counted)."""
    counts = {status: 0 for status in ALL_STATUSES}
    for result in results:
        key = _status_value(result.status)
        counts[key] = counts.get(key, 0) + 1
    return counts


def format_host_line(host: str, result: BackendResult) -> str:
    """One console line per host: ``host  status  method [ detail]``."""
    line = f"{host}  {_status_value(result.status)}  {result.method}"
    if result.detail:
        line += f"  {result.detail}"
    return line


def format_summary_line(summary: RunSummary) -> str:
    """The trailing aggregate line with per-status counts and exit code."""
    counts = "  ".join(
        f"{status}={summary.counts.get(status, 0)}" for status in ALL_STATUSES
    )
    return f"done in {summary.elapsed:.1f}s  {counts}  exit={summary.exit_code}"


@dataclass
class _Attempt:
    """One backend call running in its own thread so a deadline can bound it."""

    method: str
    fn: BackendCallable
    kwargs: dict
    result: Optional[BackendResult] = None
    _thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run,
            name=f"spraytask:{self.method}",
            daemon=True,
        )
        self._thread.start()

    def _run(self) -> None:
        try:
            self.result = self.fn(**self.kwargs)
        except Exception as exc:
            self.result = BackendResult(
                self.kwargs["host"],
                Status.ERROR,
                self.method,
                f"{type(exc).__name__}: {exc}",
            )

    def join(self, timeout: float) -> bool:
        """Wait up to ``timeout`` seconds; True when still running afterwards."""
        assert self._thread is not None
        self._thread.join(timeout)
        return self._thread.is_alive()


class Runner:
    """Runs the backend chain over a list of :class:`DeploySpec` hosts.

    ``backends`` maps method labels onto backends (a callable or an object
    with ``run(**kwargs)``); default is :func:`default_backends`. ``order``
    defaults to auto (the full :data:`AUTO_ORDER` chain with the cap rule);
    passing an explicit order pins the run to exactly those backends.
    ``connect_timeout``/``exec_timeout`` are uniform across every host and
    never overridden per-host.
    """

    def __init__(
        self,
        backends: Optional[Mapping[str, object]] = None,
        order: Optional[Sequence[str]] = None,
        threads: int = DEFAULT_THREADS,
        try_all: bool = False,
        connect_timeout: float = CONNECT_TIMEOUT,
        exec_timeout: float = EXEC_TIMEOUT,
        out: Callable[[str], None] = print,
    ) -> None:
        source = backends if backends is not None else default_backends()
        self._callbacks: dict[str, BackendCallable] = {
            name: _coerce_backend(backend) for name, backend in source.items()
        }
        if order is None:
            self._order: Sequence[str] = AUTO_ORDER
            self._auto = True
        else:
            missing = [name for name in order if name not in self._callbacks]
            if missing:
                raise ValueError(
                    f"backend(s) not registered: {', '.join(missing)}"
                )
            self._order = tuple(order)
            self._auto = False
        self._threads = max(1, int(threads))
        self.try_all = bool(try_all)
        self._connect_timeout = float(connect_timeout)
        self._exec_timeout = float(exec_timeout)
        self._out = out
        self._write_lock = threading.Lock()

    def effective_order(self, spec: DeploySpec) -> tuple[str, ...]:
        """Per-host chain: cap-aware auto, or the pinned order as given.

        In auto mode an action longer than ``SCHTASKS_TR_MAX_LEN`` drops every
        capped backend, leaving only the uncapped ``ms-tsch``. A pinned order
        (``--backend``) never rewrites the chain, so a pinned capped backend
        still runs and can report ``payload_too_large`` from its own preflight.
        """
        order = self._order
        if self._auto and len(spec.action) > SCHTASKS_TR_MAX_LEN:
            order = tuple(
                name for name in order if name not in CAPPED_BACKENDS
            )
        return order

    def _is_terminal(self, status: str) -> bool:
        if status == Status.PAYLOAD_TOO_LARGE.value:
            return True
        if not self.try_all and status in TRY_ALL_RELAXES:
            return True
        return False

    def _run_host(self, spec: DeploySpec) -> BackendResult:
        deadline = self._connect_timeout + self._exec_timeout
        final: Optional[BackendResult] = None
        for method in self.effective_order(spec):
            callback = self._callbacks.get(method)
            if callback is None:
                continue
            attempt = _Attempt(
                method,
                callback,
                _call_kwargs(spec, self._connect_timeout, self._exec_timeout),
            )
            attempt.start()
            attempt.join(deadline)
            if attempt.result is None:
                result = BackendResult(
                    spec.host,
                    Status.ERROR,
                    method,
                    f"aborted: exceeded {deadline:.1f}s "
                    "(connect_timeout + exec_timeout)",
                )
            else:
                result = attempt.result
            final = result
            if self._is_terminal(_status_value(result.status)):
                break
        assert final is not None
        return final

    def _run_host_emitting(self, spec: DeploySpec) -> BackendResult:
        result = self._run_host(spec)
        self._emit(format_host_line(spec.host, result))
        return result

    def _emit(self, line: str) -> None:
        with self._write_lock:
            self._out(line)

    def run(self, specs: Sequence[DeploySpec]) -> RunSummary:
        """Run all hosts concurrently and return the aggregate :class:`RunSummary`."""
        start = time.monotonic()
        spec_list = list(specs)
        results: list[BackendResult] = []
        if spec_list:
            with ThreadPoolExecutor(max_workers=self._threads) as pool:
                futures = [
                    pool.submit(self._run_host_emitting, spec)
                    for spec in spec_list
                ]
                for future in futures:
                    results.append(future.result())
        elapsed = time.monotonic() - start
        counts = count_results(results)
        exit_code = 0 if all(
            _status_value(r.status) == Status.OK.value for r in results
        ) else 2
        summary = RunSummary(
            results=tuple(results),
            elapsed=elapsed,
            counts=counts,
            exit_code=exit_code,
        )
        self._emit(format_summary_line(summary))
        return summary


def run(
    specs: Sequence[DeploySpec],
    backends: Optional[Mapping[str, object]] = None,
    order: Optional[Sequence[str]] = None,
    threads: int = DEFAULT_THREADS,
    try_all: bool = False,
    connect_timeout: float = CONNECT_TIMEOUT,
    exec_timeout: float = EXEC_TIMEOUT,
    out: Callable[[str], None] = print,
) -> RunSummary:
    """Module-level convenience over :class:`Runner`."""
    return Runner(
        backends=backends,
        order=order,
        threads=threads,
        try_all=try_all,
        connect_timeout=connect_timeout,
        exec_timeout=exec_timeout,
        out=out,
    ).run(specs)