"""Best-effort process-tree observation and forceful process-tree
termination.

Process enumeration is inherently racy: a process can start and exit
between one enumeration call and the next, or deny access to an
unprivileged observer. Every psutil call in this module is wrapped so a
NoSuchProcess/AccessDenied/ZombieProcess never propagates out and crashes
the observer -- see spec sections 46-48.
"""

from __future__ import annotations

import contextlib
import sys
import time
from dataclasses import dataclass

import psutil

from skillguard.redaction import scrub_text

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:  # pragma: no cover - exercised only on Windows CI
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    _JobObjectExtendedLimitInformation = 9

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
            ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_void_p),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            (n, ctypes.c_uint64)
            for n in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    class ProcessTreeJob:
        """A Windows Job Object that every descendant of the assigned
        process automatically joins (standard Win32 behavior: a process
        running under a job propagates membership to any child it
        creates). This is what makes whole-tree termination
        deterministic instead of racy: polling ``psutil`` for the
        current process tree can only find a descendant while the ppid
        chain to it is still intact, which breaks the instant an
        intermediate process exits -- exactly the SG2-002 scenario
        (parent exits quickly, a descendant it spawned keeps a pipe
        open). ``TerminateJobObject`` reaches every job member in one
        call regardless of that chain.

        ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` is set so that even an
        unclean shutdown of SkillGuard itself (crash, unhandled
        exception before ``close()`` runs) still tears down every
        process in the job once this handle's last reference goes away.
        """

        def __init__(self) -> None:
            handle = _kernel32.CreateJobObjectW(None, None)
            if not handle:
                raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
            self._handle: int | None = handle
            info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            _kernel32.SetInformationJobObject(
                self._handle,
                _JobObjectExtendedLimitInformation,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )

        def assign(self, process_handle: int) -> None:
            if self._handle is None or not _kernel32.AssignProcessToJobObject(
                self._handle, process_handle
            ):
                raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")

        def terminate(self, exit_code: int = 1) -> None:
            if self._handle is not None:
                with contextlib.suppress(OSError):
                    _kernel32.TerminateJobObject(self._handle, exit_code)

        def close(self) -> None:
            if self._handle is not None:
                with contextlib.suppress(OSError):
                    _kernel32.CloseHandle(self._handle)
                self._handle = None

        def __enter__(self) -> ProcessTreeJob:
            return self

        def __exit__(self, *exc_info: object) -> None:
            self.close()


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
    with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
        procs.extend(root.children(recursive=True))
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


def kill_pids(pids, *, timeout: float = 5.0) -> frozenset[int]:
    """Terminate every process in ``pids`` directly, addressed by PID.

    This never walks a live process tree to discover what to kill -- it
    only kills PIDs the caller already knows about. That matters when the
    caller tracked descendants over the course of a run (see
    ``CommandRunner`` in ``runner.py``): by the time cleanup runs, an
    intermediate process may have already exited, which breaks
    ppid-based tree-walking (``psutil.Process(root_pid).children()``) for
    any of ITS descendants that got reparented away as a result (SG2-002
    in docs/audits). Killing by a previously-recorded PID set is
    unaffected by that. ``CommandRunner`` also uses a process
    group/Job Object as its PRIMARY, non-racy cleanup mechanism (see
    ``ProcessTreeJob``); this remains as a supplementary, best-effort
    layer for whatever PIDs a polling tracker still managed to observe.

    Returns the subset of ``pids`` that could not be confirmed dead
    after both a ``terminate()`` and a follow-up ``kill()`` attempt, each
    given up to ``timeout`` seconds. This matters beyond diagnostics: on
    POSIX, a descendant that called ``setsid()`` before this runs may
    already have left both the process group ``os.killpg()`` targets AND
    (if reparented, e.g. via a double-fork) the ppid chain the polling
    tracker discovers PIDs through in the first place (SG-R3 seam B in
    docs/audits) -- SkillGuard is explicitly not a sandbox and cannot
    guarantee containment against that, but it must never silently
    report a run as fully cleaned up when a tracked PID demonstrably
    was not. Callers must surface a non-empty return value as an honest
    incompleteness signal, not swallow it.
    """
    targets = []
    for pid in set(pids):
        with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
            targets.append(psutil.Process(pid))
    for proc in targets:
        with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
            proc.terminate()
    _gone, alive = psutil.wait_procs(targets, timeout=timeout)
    for proc in alive:
        with contextlib.suppress(psutil.NoSuchProcess, psutil.AccessDenied):
            proc.kill()
    _gone2, still_alive = psutil.wait_procs(alive, timeout=timeout)
    return frozenset(proc.pid for proc in still_alive)


class ProcessMonitor:
    """Polls a process tree on a background thread until stopped.

    If the polling loop itself raises (a bug, not an expected per-process
    race), the exception is captured and re-raised from :meth:`join` --
    monitor failure must never be silently swallowed into a COMPLETE
    result (spec section 49).
    """

    def __init__(
        self, root_pid: int, *, poll_interval: float, redact_values: list[str] | None = None
    ) -> None:
        self._root_pid = root_pid
        self._poll_interval = poll_interval
        self._redact_values = redact_values or []
        self._records: dict[int, ProcessRecord] = {}
        self._stop = False
        self._error: BaseException | None = None
        self._thread = None

    def start(self) -> None:
        import threading

        self._thread = threading.Thread(
            target=self._run, daemon=True, name="skillguard-process-monitor"
        )
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
                self._error = self._error or RuntimeError(
                    "process monitor thread did not stop in time"
                )
        if self._error is not None:
            raise self._error
        return list(self._records.values())
