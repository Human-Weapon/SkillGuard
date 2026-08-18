"""Regression tests for SG2-002 (P2): a descendant process that inherits
stdout/stderr from the target CommandRunner launches can keep those pipes
open long after the DIRECT child has exited, defeating the configured
timeout -- proc.wait() on the direct child returns normally, but the
reader threads draining stdout/stderr then block waiting for EOF that
never comes (because the descendant, not tracked or killed on the
normal-exit path, keeps the write end open).

These use real subprocess descendants (tests/fixtures/
parent_exits_descendant_holds_pipe.py), not mocks, per the audit's
required test quality bar."""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path

import psutil
import pytest

from skillguard.dynamic.runner import CommandRunner, EnvironmentPolicy, TargetOutcome

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE = FIXTURES / "parent_exits_descendant_holds_pipe.py"

# Generous but bounded: proves the WHOLE call returns well before the
# holder's own 120s sleep would naturally end it, not just "eventually".
_MAX_ACCEPTABLE_RUNTIME_SECONDS = 20.0
_TIMEOUT = 2.0


def _extract_pid(stdout: str, label: str) -> int:
    match = re.search(rf"{label}=(\d+)", stdout)
    assert match is not None, f"{label} never reported; stdout={stdout!r}"
    return int(match.group(1))


def _wait_until_gone(*pids: int, seconds: float = 8.0) -> list[int]:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        still_alive = [p for p in pids if psutil.pid_exists(p)]
        if not still_alive:
            return []
        time.sleep(0.2)
    return [p for p in pids if psutil.pid_exists(p)]


class TestDescendantHeldPipeVariants:
    @pytest.mark.parametrize("mode", ["both", "stdout", "stderr"])
    def test_child_holds_pipe_after_parent_exits(self, tmp_path, mode):
        """Variants B/C/D: parent exits early, child holds stdout, stderr,
        or both."""
        started = time.monotonic()
        result = CommandRunner().run(
            [sys.executable, str(FIXTURE), mode, "child"],
            cwd=tmp_path,
            timeout=_TIMEOUT,
            env_policy=EnvironmentPolicy(),
        )
        elapsed = time.monotonic() - started

        assert elapsed < _MAX_ACCEPTABLE_RUNTIME_SECONDS, (
            f"run() blocked for {elapsed:.1f}s -- the configured {_TIMEOUT}s timeout "
            "did not bound the whole execution lifecycle"
        )
        assert result.outcome == TargetOutcome.EXITED
        child_pid = _extract_pid(result.stdout, "CHILD_PID")
        still_alive = _wait_until_gone(child_pid)
        assert still_alive == [], f"descendant-held-pipe process(es) survived: {still_alive}"

    def test_grandchild_holds_pipe_after_parent_and_child_exit(self, tmp_path):
        """Variant E: the pipe-holder is a GRANDCHILD of the direct child,
        not the direct child itself -- both intermediate processes exit
        quickly."""
        started = time.monotonic()
        result = CommandRunner().run(
            [sys.executable, str(FIXTURE), "both", "grandchild"],
            cwd=tmp_path,
            timeout=_TIMEOUT,
            env_policy=EnvironmentPolicy(),
        )
        elapsed = time.monotonic() - started

        assert elapsed < _MAX_ACCEPTABLE_RUNTIME_SECONDS, (
            f"run() blocked for {elapsed:.1f}s with a grandchild holding the pipe"
        )
        assert result.outcome == TargetOutcome.EXITED
        child_pid = _extract_pid(result.stdout, "CHILD_PID")
        grandchild_pid = _extract_pid(result.stdout, "GRANDCHILD_PID")
        still_alive = _wait_until_gone(child_pid, grandchild_pid)
        assert still_alive == [], f"descendant-held-pipe process(es) survived: {still_alive}"

    def test_large_output_with_descendant_held_pipe_still_bounded_and_captured(self, tmp_path):
        """Variant F: large output plus a descendant-held pipe -- output
        captured so far must still be bounded/returned promptly, not
        lost or blocked on indefinitely."""
        big_output_fixture = tmp_path / "big_then_hold.py"
        big_output_fixture.write_text(
            "import subprocess, sys, time\n"
            "print('x' * 500_000, flush=True)\n"
            "holder = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
            "print(f'CHILD_PID={holder.pid}', flush=True)\n"
        )
        started = time.monotonic()
        result = CommandRunner(max_output_bytes=1_000_000).run(
            [sys.executable, str(big_output_fixture)],
            cwd=tmp_path,
            timeout=_TIMEOUT,
            env_policy=EnvironmentPolicy(),
        )
        elapsed = time.monotonic() - started

        assert elapsed < _MAX_ACCEPTABLE_RUNTIME_SECONDS
        assert result.outcome == TargetOutcome.EXITED
        assert "x" * 100 in result.stdout  # some of the large output was retained
        child_pid = _extract_pid(result.stdout, "CHILD_PID")
        still_alive = _wait_until_gone(child_pid)
        assert still_alive == [], f"descendant-held-pipe process(es) survived: {still_alive}"

    def test_parent_itself_times_out_still_cleans_up_descendant(self, tmp_path):
        """Variant A: the direct parent ALSO stays alive past the
        timeout (not just a descendant) -- the pre-existing
        TIMED_OUT path, kept green alongside the new normal-exit path."""
        fixture = tmp_path / "parent_and_child_both_sleep.py"
        fixture.write_text(
            "import subprocess, sys, time\n"
            "holder = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
            "print(f'CHILD_PID={holder.pid}', flush=True)\n"
            "time.sleep(120)\n"
        )
        started = time.monotonic()
        result = CommandRunner().run(
            [sys.executable, str(fixture)],
            cwd=tmp_path,
            timeout=_TIMEOUT,
            env_policy=EnvironmentPolicy(),
        )
        elapsed = time.monotonic() - started

        assert elapsed < _MAX_ACCEPTABLE_RUNTIME_SECONDS
        assert result.outcome == TargetOutcome.TIMED_OUT
        child_pid = _extract_pid(result.stdout, "CHILD_PID")
        still_alive = _wait_until_gone(child_pid)
        assert still_alive == [], f"descendant process(es) survived: {still_alive}"


class TestNoLeakedStateAfterReturn:
    def test_no_leftover_processes_across_repeated_runs(self, tmp_path):
        """No processes left behind after test teardown, across several
        runs in a row (regression against the tracker/kill_pids plumbing
        leaking state between calls)."""
        seen_pids: list[int] = []
        for _ in range(3):
            result = CommandRunner().run(
                [sys.executable, str(FIXTURE), "both", "child"],
                cwd=tmp_path,
                timeout=_TIMEOUT,
                env_policy=EnvironmentPolicy(),
            )
            assert result.outcome == TargetOutcome.EXITED
            seen_pids.append(_extract_pid(result.stdout, "CHILD_PID"))

        still_alive = _wait_until_gone(*seen_pids)
        assert still_alive == [], f"processes leaked across repeated runs: {still_alive}"
