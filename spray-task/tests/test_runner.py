"""Runner chain/threading/console-output tests (spraytask.runner, task 9).

Every test drives the runner with fake backends; no network or impacket call
is made. Fakes record the keyword calls so acceptance is asserted by the
exact arguments the runner passes to each backend.
"""

from __future__ import annotations

import inspect
import re
import threading
import time

from spraytask.backends.base import (
    CONNECT_TIMEOUT,
    EXEC_TIMEOUT,
    SCHTASKS_TR_MAX_LEN,
    BackendResult,
    Status,
)
from spraytask import runner
from spraytask.payload import encode_powershell_action


def spec(
    host: str,
    action: str = "powershell.exe -x",
    task_name: str = "SprayTask_test",
    interval_minutes: int = 5,
) -> runner.DeploySpec:
    return runner.DeploySpec(
        host=host,
        action=action,
        task_name=task_name,
        interval_minutes=interval_minutes,
    )


class FakeBackend:
    """Recorded callable backend: per-host plan, optional barrier/block/delay."""

    def __init__(
        self,
        method: str,
        plan: dict | None = None,
        barrier: threading.Barrier | None = None,
        block: threading.Event | None = None,
        delay: float = 0.0,
    ) -> None:
        self.method = method
        self.plan = plan if plan is not None else {}
        self.barrier = barrier
        self.block = block
        self.delay = delay
        self.calls: list[dict] = []

    def run(self, **kwargs) -> BackendResult:
        if self.block is not None:
            self.block.wait(60)
        if self.barrier is not None:
            self.barrier.wait(timeout=15)
        if self.delay:
            time.sleep(self.delay)
        self.calls.append(kwargs)
        if kwargs["host"] in self.plan:
            return self.plan[kwargs["host"]]
        return BackendResult.ok(kwargs["host"], self.method, detail="fake ok")


def res(status, method: str, host: str = "wc01", detail: str = "") -> BackendResult:
    return BackendResult(host=host, status=status, method=method, detail=detail)


def ok_r(method: str, host: str = "wc01") -> BackendResult:
    return BackendResult.ok(host, method, detail="fake ok")


def test_auto_order_is_primary_first():
    assert runner.AUTO_ORDER == ("ms-tsch", "psexec", "wmi")


def test_default_pool_size_is_ten():
    assert runner.DEFAULT_THREADS == 10


def test_ok_on_primary_stops_chain():
    ms = FakeBackend("ms-tsch", {"wc01": res(Status.NO_ADMIN, "ms-tsch")})
    ps = FakeBackend("psexec", {"wc01": ok_r("psexec")})
    requests = [spec("wc01")]
    summary = runner.run(requests, backends={"ms-tsch": ms, "psexec": ps})
    assert len(summary.results) == 1
    result = summary.results[0]
    assert result.status == Status.OK
    assert result.method == "psexec"
    assert len(ms.calls) == len(requests)
    assert len(ps.calls) == len(requests)
    assert summary.exit_code == 0


def test_ok_on_primary_is_terminal_without_try_all():
    ms = FakeBackend("ms-tsch", {"wc01": ok_r("ms-tsch")})
    ps = FakeBackend("psexec", {"wc01": ok_r("psexec")})
    summary = runner.run(
        [spec("wc01")], backends={"ms-tsch": ms, "psexec": ps}
    )
    assert summary.results[0].status == Status.OK
    assert summary.results[0].method == "ms-tsch"
    assert ms.calls
    assert ps.calls == []


def test_auth_failed_is_terminal_without_try_all():
    ms = FakeBackend(
        "ms-tsch", {"wc01": res(Status.AUTH_FAILED, "ms-tsch")}
    )
    ps = FakeBackend("psexec", {"wc01": ok_r("psexec")})
    summary = runner.run(
        [spec("wc01")], backends={"ms-tsch": ms, "psexec": ps}
    )
    result = summary.results[0]
    assert result.status == Status.AUTH_FAILED
    assert result.method == "ms-tsch"
    assert ps.calls == []
    assert summary.exit_code == 2


def test_try_all_continues_after_ok():
    ms = FakeBackend("ms-tsch", {"wc01": ok_r("ms-tsch")})
    ps = FakeBackend("psexec", {"wc01": ok_r("psexec")})
    summary = runner.run(
        [spec("wc01")],
        backends={"ms-tsch": ms, "psexec": ps},
        try_all=True,
    )
    assert len(ms.calls) == 1
    assert len(ps.calls) == 1
    result = summary.results[0]
    assert result.status == Status.OK
    assert result.method == "psexec"


def test_try_all_relaxes_auth_failed():
    ms = FakeBackend(
        "ms-tsch", {"wc01": res(Status.AUTH_FAILED, "ms-tsch")}
    )
    ps = FakeBackend("psexec", {"wc01": ok_r("psexec")})
    summary = runner.run(
        [spec("wc01")],
        backends={"ms-tsch": ms, "psexec": ps},
        try_all=True,
    )
    assert len(ms.calls) == 1
    assert len(ps.calls) == 1
    result = summary.results[0]
    assert result.status == Status.OK
    assert result.method == "psexec"


def test_connectivity_and_method_classes_fall_through():
    ms = FakeBackend("ms-tsch", {"wc01": res(Status.UNREACHABLE, "ms-tsch")})
    ps = FakeBackend(
        "psexec", {"wc01": res(Status.METHOD_ERROR, "psexec")}
    )
    wm = FakeBackend("wmi", {"wc01": ok_r("wmi")})
    summary = runner.run(
        [spec("wc01")],
        backends={"ms-tsch": ms, "psexec": ps, "wmi": wm},
    )
    result = summary.results[0]
    assert result.status == Status.OK
    assert result.method == "wmi"
    assert len(ms.calls) == 1
    assert len(ps.calls) == 1
    assert len(wm.calls) == 1


def test_no_admin_falls_through():
    ms = FakeBackend("ms-tsch", {"wc01": res(Status.NO_ADMIN, "ms-tsch")})
    ps = FakeBackend("psexec", {"wc01": ok_r("psexec")})
    summary = runner.run(
        [spec("wc01")], backends={"ms-tsch": ms, "psexec": ps}
    )
    assert summary.results[0].method == "psexec"
    assert summary.results[0].status == Status.OK


def test_all_fail_keeps_last_method_and_exit_2():
    ms = FakeBackend("ms-tsch", {"wc01": res(Status.ERROR, "ms-tsch")})
    ps = FakeBackend("psexec", {"wc01": res(Status.ERROR, "psexec")})
    summary = runner.run(
        [spec("wc01")], backends={"ms-tsch": ms, "psexec": ps}
    )
    result = summary.results[0]
    assert result.status == Status.ERROR
    assert result.method == "psexec"
    assert summary.exit_code == 2
    assert summary.counts[Status.ERROR.value] == 1


def test_exit_code_zero_when_every_host_ok():
    ms = FakeBackend(
        "ms-tsch",
        {"wc01": ok_r("ms-tsch"), "wc02": ok_r("ms-tsch")},
    )
    summary = runner.run(
        [spec("wc01"), spec("wc02")], backends={"ms-tsch": ms}
    )
    assert summary.exit_code == 0


def test_exit_code_two_when_any_host_failed():
    ms = FakeBackend(
        "ms-tsch",
        {"wc01": ok_r("ms-tsch"), "wc02": res(Status.ERROR, "ms-tsch")},
    )
    summary = runner.run(
        [spec("wc01"), spec("wc02")], backends={"ms-tsch": ms}
    )
    assert summary.exit_code == 2


def test_cap_aware_auto_runs_only_uncapped_for_oversized_payload():
    long_action = "x" * (SCHTASKS_TR_MAX_LEN + 10)
    ms = FakeBackend("ms-tsch", {"wc01": ok_r("ms-tsch")})
    ps = FakeBackend("psexec", {"wc01": ok_r("psexec")})
    wm = FakeBackend("wmi", {"wc01": ok_r("wmi")})
    summary = runner.run(
        [spec("wc01", action=long_action)],
        backends={"ms-tsch": ms, "psexec": ps, "wmi": wm},
    )
    result = summary.results[0]
    assert result.status == Status.OK
    assert result.method == "ms-tsch"
    assert ps.calls == []
    assert wm.calls == []


def test_cap_aware_connectivity_wins_over_size_rejection():
    long_action = "x" * (SCHTASKS_TR_MAX_LEN + 10)
    ms = FakeBackend("ms-tsch", {"wc01": res(Status.UNREACHABLE, "ms-tsch")})
    ps = FakeBackend("psexec", {"wc01": ok_r("psexec")})
    summary = runner.run(
        [spec("wc01", action=long_action)],
        backends={"ms-tsch": ms, "psexec": ps},
    )
    result = summary.results[0]
    assert result.status == Status.UNREACHABLE
    assert result.method == "ms-tsch"
    assert ps.calls == []


def test_pinned_capped_backend_can_report_payload_too_large():
    long_action = "x" * (SCHTASKS_TR_MAX_LEN + 10)
    ps = FakeBackend(
        "psexec",
        {"wc01": res(Status.PAYLOAD_TOO_LARGE, "psexec", detail="over /TR cap")},
    )
    summary = runner.run(
        [spec("wc01", action=long_action)],
        backends={"psexec": ps},
        order=["psexec"],
    )
    result = summary.results[0]
    assert result.status == Status.PAYLOAD_TOO_LARGE
    assert result.method == "psexec"
    assert len(ps.calls) == 1
    assert summary.exit_code == 2


def test_payload_too_large_is_terminal_even_with_try_all():
    ms = FakeBackend(
        "ms-tsch", {"wc01": res(Status.PAYLOAD_TOO_LARGE, "ms-tsch")}
    )
    ps = FakeBackend("psexec", {"wc01": ok_r("psexec")})
    summary = runner.run(
        [spec("wc01")],
        backends={"ms-tsch": ms, "psexec": ps},
        try_all=True,
    )
    result = summary.results[0]
    assert result.status == Status.PAYLOAD_TOO_LARGE
    assert ps.calls == []


def test_pinned_order_skips_other_backends():
    ms = FakeBackend("ms-tsch", {"wc01": ok_r("ms-tsch")})
    ps = FakeBackend(
        "psexec", {"wc01": res(Status.PAYLOAD_TOO_LARGE, "psexec")}
    )
    summary = runner.run(
        [spec("wc01", action="x" * (SCHTASKS_TR_MAX_LEN + 10))],
        backends={"ms-tsch": ms, "psexec": ps},
        order=["ms-tsch"],
    )
    assert summary.results[0].method == "ms-tsch"
    assert ps.calls == []


def test_unknown_backend_order_raises_at_construction():
    ms = FakeBackend("ms-tsch", {"wc01": ok_r("ms-tsch")})
    try:
        runner.Runner(backends={"ms-tsch": ms}, order=["bogus"])
    except ValueError as exc:
        assert "bogus" in str(exc)
    else:
        raise AssertionError("expected ValueError for unknown backend")


def test_backend_must_be_callable_or_have_run():
    try:
        runner.Runner(backends={"ms-tsch": object()})
    except TypeError as exc:
        assert "run" in str(exc)
    else:
        raise AssertionError("expected TypeError for a non-backend object")


def test_uniform_keywords_passed_to_every_backend():
    captured: list[dict] = []

    def record(**kwargs) -> BackendResult:
        captured.append(kwargs)
        return BackendResult.ok(kwargs["host"], "ms-tsch")

    request = spec("wc01")
    summary = runner.run(
        [request], backends={"ms-tsch": record}
    )
    call = captured[0]
    assert call["host"] == "wc01"
    assert call["port"] is None
    assert call["cred"] is None
    assert call["task_name"] == "SprayTask_test"
    assert call["action"] == "powershell.exe -x"
    assert call["interval_minutes"] == 5
    assert call["connect_timeout"] == CONNECT_TIMEOUT
    assert call["exec_timeout"] == EXEC_TIMEOUT
    assert summary.results[0].status == Status.OK


def test_uniform_timeouts_are_never_overridden_per_host():
    got: list[tuple] = []

    def record(**kwargs) -> BackendResult:
        got.append((kwargs["connect_timeout"], kwargs["exec_timeout"]))
        return BackendResult.ok(kwargs["host"], "ms-tsch")

    # Spec-level timeouts do not exist; the runner's uniform values are used.
    summary = runner.run(
        [spec("wc01"), spec("wc02")],
        backends={"ms-tsch": record},
        connect_timeout=1.0,
        exec_timeout=2.0,
    )
    assert got == [(1.0, 2.0), (1.0, 2.0)]


def test_powershell_action_embedded_verbatim_passthrough():
    action = encode_powershell_action("whoami; ipconfig")
    captured: list[str] = []

    def record(**kwargs) -> BackendResult:
        captured.append(kwargs["action"])
        return BackendResult.ok(kwargs["host"], "ms-tsch")

    runner.run([spec("wc01", action=action)], backends={"ms-tsch": record})
    assert captured == [action]
    assert (
        action.startswith(
            "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy "
            "Bypass -EncodedCommand "
        )
    )


def test_overrunning_backend_is_aborted_as_error():
    blocked = threading.Event()
    ms = FakeBackend("ms-tsch", block=blocked)
    started = time.monotonic()
    summary = runner.run(
        [spec("wc01")], backends={"ms-tsch": ms},
        connect_timeout=0.05, exec_timeout=0.2,
    )
    elapsed = time.monotonic() - started
    result = summary.results[0]
    assert result.status == Status.ERROR
    assert result.method == "ms-tsch"
    assert "aborted" in result.detail
    assert summary.exit_code == 2
    assert elapsed < 5.0


def test_backend_that_raises_reports_error():
    def boom(**kwargs) -> BackendResult:
        raise RuntimeError("backend exploded")

    summary = runner.run([spec("wc01")], backends={"ms-tsch": boom})
    result = summary.results[0]
    assert result.status == Status.ERROR
    assert "RuntimeError" in result.detail
    assert summary.exit_code == 2


def test_threaded_hosts_prove_concurrency_with_barrier():
    barrier = threading.Barrier(4)

    def sync_run(**kwargs) -> BackendResult:
        barrier.wait(timeout=15)
        return BackendResult.ok(kwargs["host"], "ms-tsch", detail=kwargs["host"])

    hosts = ["wc01", "wc02", "wc03", "wc04"]
    started = time.monotonic()
    summary = runner.run(
        [spec(host) for host in hosts],
        backends={"ms-tsch": sync_run},
        threads=4,
        connect_timeout=0.1, exec_timeout=1.0,
    )
    elapsed = time.monotonic() - started
    # The barrier could only be released if all four host attempts were running
    # at once; a sequential executor would deadlock until the attempt deadline
    # and produce error results instead of ok.
    assert [r.status for r in summary.results] == [Status.OK] * 4
    assert [r.detail for r in summary.results] == hosts
    assert elapsed < 10.0


def test_results_keep_input_order_despite_completion_order():
    def slow(**kwargs) -> BackendResult:
        time.sleep({"wc01": 0.3, "wc02": 0.15, "wc03": 0.0}[kwargs["host"]])
        return BackendResult.ok(kwargs["host"], "ms-tsch", detail=kwargs["host"])

    requests = [spec("wc01"), spec("wc02"), spec("wc03")]
    summary = runner.run(requests, backends={"ms-tsch": slow})
    assert [r.detail for r in summary.results] == ["wc01", "wc02", "wc03"]


def test_host_lines_are_single_atomic_lines():
    lines: list[str] = []
    hosts = [f"host{i}" for i in range(8)]
    plan = {host: BackendResult.ok(host, "ms-tsch", detail=f"seeded {i}") for i, host in enumerate(hosts)}
    ms = FakeBackend("ms-tsch", plan)
    summary = runner.run(
        [spec(host) for host in hosts],
        backends={"ms-tsch": ms},
        out=lines.append,
    )
    host_lines = [line for line in lines if not line.startswith("done in ")]
    summary_line = [line for line in lines if line.startswith("done in ")]
    assert len(host_lines) == len(hosts)
    assert len(summary_line) == 1
    pattern = re.compile(r"^(host\d)\s+\S+\s+\S+(?:\s.*)?$")
    for line in host_lines:
        assert pattern.match(line), f"garbled or malformed line: {line!r}"
    seen = {pattern.match(line).group(1) for line in host_lines}
    assert seen == set(hosts)
    assert summary.exit_code == 0


def test_empty_specs_emit_summary_only():
    lines: list[str] = []
    runner.run([], backends={}, out=lines.append)
    assert len(lines) == 1
    assert lines[0].startswith("done in ")


def test_format_host_line_with_and_without_detail():
    assert (
        runner.format_host_line("wc01", BackendResult.ok("wc01", "ms-tsch", "registered"))
        == "wc01  ok  ms-tsch  registered"
    )
    assert (
        runner.format_host_line("wc01", BackendResult("wc01", Status.OK, "ms-tsch"))
        == "wc01  ok  ms-tsch"
    )


def test_format_summary_line():
    counts = runner.count_results([BackendResult.ok("wc01", "ms-tsch")])
    summary = runner.RunSummary(
        results=(BackendResult.ok("wc01", "ms-tsch"),),
        elapsed=1.5,
        counts=counts,
        exit_code=0,
    )
    assert (
        runner.format_summary_line(summary)
        == "done in 1.5s  ok=1  auth_failed=0  no_admin=0  unreachable=0  payload_too_large=0  method_error=0  error=0  exit=0"
    )


def test_default_backends_cover_the_whole_auto_chain():
    backends = runner.default_backends()
    assert set(backends) == set(runner.AUTO_ORDER)
    for name, callable_ in backends.items():
        assert callable(callable_)


def test_static_no_remote_payload_file_write():
    source = inspect.getsource(runner)
    for token in ("putFile", "copyFile", "copyfile", "write_file", "upload", "open("):
        assert token not in source, f"forbidden file-write token {token!r} in runner"
    assert "import shutil" not in source