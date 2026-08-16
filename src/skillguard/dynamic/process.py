"""Best-effort process-tree observation and forceful process-tree
termination.

Process enumeration is inherently racy: a process can start and exit
between one enumeration call and the next, or deny access to an
unprivileged observer. Every psutil call in this module is wrapped so a
NoSuchProcess/AccessDenied/ZombieProcess never propagates out and crashes
the observer -- see spec sections 46-48.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import psutil

from skillguard.redaction import scrub_text


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    ppid: int | None
    name: str
    cmdline_redacted: tuple[str, ...]
    seen_at_monotonic: float
    exit_code: int | None = None


def _safe_name(proc: psutil.Process) -> str:
    try:
        return proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "<unknown>"


def _safe_ppid(proc: psutil.Process) -> int | None:
    try:
        return proc.ppid()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def _safe_cmdline(proc: psutil.Process, *, redact_values: list[str]) -> tuple[str, ...]:
    try:
        parts = proc.cmdline()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return ()
    redacted = []
    for part in parts:
        scrubbed, _ = scrub_text(part, redact_values)
        redacted.append(scrubbed)
    return tuple(redacted)


def snapshot_tree(root_pid: int, *, redact_values: list[str] | None = None) -> list[ProcessRecord]:
    """Best-effort snapshot of ``root_pid`` and all of its current
    descendants. Never raises for individual-process races."""
    redact_values = redact_values or []
    records: list[ProcessRecord] = []
    now = time.monotonic()
    try:
        root = psutil.Process(root_pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return records
    procs = [root]
    try:
        procs.extend(root.children(recursive=True))
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    for proc in procs:
        try:
            pid = proc.pid
        except Exception:  # noqa: BLE001
            continue
        records.append(
            ProcessRecord(
                pid=pid,
                ppid=_safe_ppid(proc),
                name=_safe_name(proc),
                cmdline_redacted=_safe_cmdline(proc, redact_values=redact_values),
                seen_at_monotonic=now,
            )
        )
    return records


def kill_tree(root_pid: int, *, timeout: float = 5.0) -> None:
    """Terminate ``root_pid`` and every descendant it has at call time.
    Used to enforce process-tree timeout semantics: killing only the direct
    child leaves any grandchildren (e.g. a shell spawning a sleeping
    Python child) running as orphans, which this function prevents."""
    try:
        root = psutil.Process(root_pid)
    except psutil.NoSuchProcess:
        return
    try:
        children = root.children(recursive=True)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        children = []
    targets = [*children, root]
    for proc in targets:
        try:
            proc.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    _gone, alive = psutil.wait_procs(targets, timeout=timeout)
    for proc in alive:
        try:
            proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    psutil.wait_procs(alive, timeout=timeout)


class ProcessMonitor:
    """Polls a process tree on a background thread until stopped.

    If the polling loop itself raises (a bug, not an expected per-process
    race), the exception is captured and re-raised from :meth:`join` --
    monitor failure must never be silently swallowed into a COMPLETE
    result (spec section 49).
    """

    def __init__(self, root_pid: int, *, poll_interval: float, redact_values: list[str] | None = None) -> None:
        self._root_pid = root_pid
        self._poll_interval = poll_interval
        self._redact_values = redact_values or []
        self._records: dict[int, ProcessRecord] = {}
        self._stop = False
        self._error: BaseException | None = None
        self._thread = None

    def start(self) -> None:
        import threading

        self._thread = threading.Thread(target=self._run, daemon=True, name="skillguard-process-monitor")
        self._thread.start()

    def _run(self) -> None:
        try:
            while not self._stop:
                for record in snapshot_tree(self._root_pid, redact_values=self._redact_values):
                    self._records[record.pid] = record
                time.sleep(self._poll_interval)
            for record in snapshot_tree(self._root_pid, redact_values=self._redact_values):
                self._records[record.pid] = record
        except BaseException as exc:  # noqa: BLE001
            self._error = exc

    def stop_and_join(self, *, timeout: float = 10.0) -> list[ProcessRecord]:
        self._stop = True
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                self._error = self._error or RuntimeError("process monitor thread did not stop in time")
        if self._error is not None:
            raise self._error
        return list(self._records.values())
