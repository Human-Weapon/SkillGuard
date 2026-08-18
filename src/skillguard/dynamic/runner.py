"""The dynamic command execution contract.

A target command is always: an argv list, ``shell=False``, an explicit
cwd, an explicit timeout, and an explicit environment policy. There is no
"pass a shell string" mode -- see spec sections 42-44 and SECURITY.md. This
is the only place in SkillGuard that starts a target process.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType

from skillguard.dynamic.process import ProcessMonitor, kill_pids
from skillguard.errors import DynamicAnalysisError, ValidationError
from skillguard.validation import (
    materialize_iterable,
    validate_finite_number,
    validate_non_negative_int,
)

_IS_WINDOWS = sys.platform == "win32"
if _IS_WINDOWS:  # pragma: no cover - exercised only on Windows CI
    from skillguard.dynamic.process import ProcessTreeJob

_DEFAULT_MAX_OUTPUT_BYTES = 2_000_000

# Grace period for descendant-held-pipe cleanup, applied ONCE, on top of
# (not carved out of) the caller's configured timeout -- see SG2-002 in
# docs/audits. This bounds the combined stdout+stderr reader-thread drain
# after the process tree has already been killed, not the target's own
# execution time.
_CLEANUP_ALLOWANCE_SECONDS = 5.0
_TRACKER_POLL_INTERVAL_SECONDS = 0.2


class EnvMode(str, Enum):
    MINIMAL = "MINIMAL"
    ALLOWLIST = "ALLOWLIST"
    EXPLICIT = "EXPLICIT"


@dataclass(frozen=True)
class EnvironmentPolicy:
    """How the target process's environment is constructed.

    MINIMAL: only the OS-functionality variables needed for a process to
    run at all (PATH, SystemRoot on Windows, HOME on POSIX, etc).
    ALLOWLIST: MINIMAL plus caller-named variables forwarded from the
    parent environment by name (values not specified by the caller).
    EXPLICIT: exactly the caller-supplied key/value pairs, nothing forwarded.

    In no mode is the full parent environment forwarded automatically.
    """

    mode: EnvMode = EnvMode.MINIMAL
    allowlist_names: frozenset[str] = frozenset()
    explicit_vars: MappingProxyType = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        if not isinstance(self.mode, EnvMode):
            raise ValidationError(f"env mode must be an EnvMode, got {self.mode!r}")
        object.__setattr__(self, "allowlist_names", frozenset(self.allowlist_names))
        object.__setattr__(self, "explicit_vars", MappingProxyType(dict(self.explicit_vars)))

    def build(self) -> dict[str, str]:
        if self.mode == EnvMode.EXPLICIT:
            return dict(self.explicit_vars)
        keep = {"PATH"}
        if sys.platform == "win32":
            keep |= {
                "SystemRoot",
                "SYSTEMROOT",
                "WINDIR",
                "COMSPEC",
                "PATHEXT",
                "TEMP",
                "TMP",
                "USERPROFILE",
            }
        else:
            keep |= {"HOME", "LANG", "LC_ALL", "TMPDIR", "USER"}
        if self.mode == EnvMode.ALLOWLIST:
            keep |= set(self.allowlist_names)
        return {k: os.environ[k] for k in keep if k in os.environ}


class TargetOutcome(str, Enum):
    EXITED = "EXITED"
    TIMED_OUT = "TIMED_OUT"
    OBSERVER_FAILED = "OBSERVER_FAILED"


@dataclass(frozen=True)
class CommandResult:
    outcome: TargetOutcome
    pid: int | None
    exit_code: int | None
    stdout: str
    stdout_truncated: bool
    stdout_encoding_lossy: bool
    stderr: str
    stderr_truncated: bool
    stderr_encoding_lossy: bool
    duration_seconds: float


class CommandRunner:
    def __init__(self, *, max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES) -> None:
        self.max_output_bytes = validate_non_negative_int(max_output_bytes, name="max_output_bytes")

    def run(
        self,
        argv: object,
        *,
        cwd: Path,
        timeout: float,
        env_policy: EnvironmentPolicy | None = None,
        on_pid_available=None,
    ) -> CommandResult:
        argv_tuple = materialize_iterable(argv, name="argv")
        if not argv_tuple:
            raise ValidationError("argv must not be empty")
        for item in argv_tuple:
            if not isinstance(item, str):
                raise ValidationError(
                    f"argv items must be str, got {type(item).__name__}: {item!r}"
                )
        validate_finite_number(timeout, name="timeout", allow_zero=False)
        if not isinstance(cwd, Path) or not cwd.is_dir():
            raise ValidationError(f"cwd must be an existing directory, got {cwd!r}")

        env_policy = env_policy or EnvironmentPolicy()
        env = env_policy.build()

        # Whole-tree cleanup must not depend on discovering descendants by
        # walking the process tree from proc.pid AFTER something has
        # already happened: a descendant's ppid chain back to proc.pid
        # breaks the instant proc (or any intermediate process) exits,
        # which is exactly the SG2-002 scenario (a target that spawns a
        # descendant and exits quickly, leaving the descendant holding
        # inherited stdout/stderr open). POSIX gets this for free via a
        # new session/process group (killing the group reaches every
        # member regardless of ppid); Windows gets the equivalent via a
        # Job Object, which every descendant automatically joins at
        # creation time -- see ProcessTreeJob's docstring in process.py.
        popen_kwargs: dict[str, object] = {
            "cwd": str(cwd),
            "env": env,
            "shell": False,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": False,
        }
        job = None
        if _IS_WINDOWS:
            job = ProcessTreeJob()
        else:
            popen_kwargs["start_new_session"] = True

        start = time.monotonic()
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv list, shell=False by contract
                list(argv_tuple), **popen_kwargs
            )
        except OSError as exc:
            if job is not None:
                job.close()
            raise DynamicAnalysisError(
                f"failed to start target command {argv_tuple!r}: {exc}"
            ) from exc

        if job is not None:
            # As close to Popen() returning as possible: a descendant the
            # target spawns before this line would not inherit job
            # membership. In practice this window is microseconds of pure
            # Python overhead; the psutil-based tracker below remains as
            # defense-in-depth for whatever it still manages to catch.
            with contextlib.suppress(OSError):
                job.assign(int(proc._handle))  # noqa: SLF001 - only way to get the raw HANDLE

        stdout_capture = _BoundedStreamCapture(proc.stdout, self.max_output_bytes)
        stderr_capture = _BoundedStreamCapture(proc.stderr, self.max_output_bytes)
        stdout_capture.start()
        stderr_capture.start()

        # Supplementary descendant tracking (evidence/defense-in-depth):
        # unlike the group/job mechanism above, this IS racy (a fast-
        # exiting parent can come and go between polls), so it is not
        # relied on alone for the correctness property SG2-002 requires.
        tracker = ProcessMonitor(proc.pid, poll_interval=_TRACKER_POLL_INTERVAL_SECONDS)
        tracker.start()
        try:
            remaining = max(0.0, timeout - (time.monotonic() - start))
            if on_pid_available is not None:
                try:
                    on_pid_available(proc.pid)
                except BaseException as exc:  # noqa: BLE001 - target must not survive setup errors
                    raise DynamicAnalysisError(
                        f"dynamic observer setup failed for target pid {proc.pid}: {exc}"
                    ) from exc

            proc.wait(timeout=remaining)
            outcome = TargetOutcome.EXITED
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            outcome = TargetOutcome.TIMED_OUT
            exit_code = None
        finally:
            # ALWAYS kill the full process tree here -- on the normal-exit
            # path too, not just on timeout. A direct child can exit
            # (making proc.wait() return successfully) while a descendant
            # it spawned keeps running and keeps holding the inherited
            # pipe open; without this, that descendant was simply never
            # cleaned up, and the reader threads below could block
            # waiting for EOF far past the configured timeout.
            if job is not None:
                job.terminate()
            else:
                with contextlib.suppress(OSError, ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
            tracked_pids = _stop_tracker_best_effort(tracker)
            kill_pids([proc.pid, *tracked_pids], timeout=2.0)
            _join_and_close(
                proc, stdout_capture, stderr_capture, allowance=_CLEANUP_ALLOWANCE_SECONDS
            )
            if job is not None:
                job.close()

        duration = time.monotonic() - start
        stdout_out, stdout_trunc, stdout_lossy = stdout_capture.result()
        stderr_out, stderr_trunc, stderr_lossy = stderr_capture.result()

        return CommandResult(
            outcome=outcome,
            pid=proc.pid,
            exit_code=exit_code,
            stdout=stdout_out,
            stdout_truncated=stdout_trunc,
            stdout_encoding_lossy=stdout_lossy,
            stderr=stderr_out,
            stderr_truncated=stderr_trunc,
            stderr_encoding_lossy=stderr_lossy,
            duration_seconds=duration,
        )


class _BoundedStreamCapture:
    """Drain a subprocess pipe continuously while retaining only a byte cap."""

    def __init__(self, stream, max_bytes: int) -> None:
        self._stream = stream
        self._max_bytes = max_bytes
        self._buffer = bytearray()
        self.truncated = False
        self._thread = threading.Thread(target=self._drain, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _drain(self) -> None:
        try:
            while True:
                chunk = self._stream.read(65_536)
                if not chunk:
                    return
                remaining = self._max_bytes - len(self._buffer)
                if remaining > 0:
                    self._buffer.extend(chunk[:remaining])
                if len(chunk) > max(remaining, 0):
                    self.truncated = True
        except (OSError, ValueError):
            # The parent closes a pipe after a timed-out or setup-failed
            # process. Captured bytes up to that point remain valid.
            return

    def join(self, timeout: float = 5.0) -> None:
        self._thread.join(timeout=timeout)

    def close(self) -> None:
        with contextlib.suppress(OSError, ValueError):
            self._stream.close()

    def result(self) -> tuple[str, bool, bool]:
        """Returns ``(text, truncated, encoding_lossy)``. ``text`` is
        always a safely-decodable str -- invalid UTF-8 bytes are replaced
        with U+FFFD rather than raising -- but when that happened,
        ``encoding_lossy`` is True so the caller can record that this was
        NOT necessarily a byte-for-byte-faithful observation (SG2-006 in
        docs/audits): silently decoding-and-moving-on would let a run
        with genuinely corrupted/binary output still report COMPLETE.
        Decoding the full accumulated buffer in one call (not per
        65536-byte read() chunk -- see _drain) means a valid multibyte
        UTF-8 character split across two reads is reassembled before
        decoding and is never mistaken for invalid input here.
        """
        encoded = bytes(self._buffer)
        text = encoded.decode("utf-8", errors="replace")
        lossy = "�" in text
        # A replacement character can encode to more bytes than the sliced
        # input. Keep the public contract byte-based even for invalid
        # UTF-8. This second pass uses errors="ignore", not "replace": a
        # partial multibyte sequence left dangling right at the max_bytes
        # cut point would otherwise decode to ANOTHER replacement
        # character that can itself be >1 byte, which could push the
        # result back over max_bytes again (non-convergent). `lossy` was
        # already captured from the first, full decode above, so this
        # step dropping a boundary-truncated fragment doesn't need to
        # re-check it -- that fragment loss is exactly what `truncated`
        # already communicates.
        if len(text.encode("utf-8")) > self._max_bytes:
            text = text.encode("utf-8")[: self._max_bytes].decode("utf-8", errors="ignore")
        return text, self.truncated, lossy


def _stop_tracker_best_effort(tracker: ProcessMonitor) -> set[int]:
    """Stop the descendant tracker and return every PID it ever recorded.
    Cleanup must proceed even if the tracker thread itself failed --
    whatever PIDs it managed to record before failing are still worth
    killing; a tracker failure must never suppress the process-tree
    cleanup this exists to enable."""
    try:
        records = tracker.stop_and_join(timeout=2.0)
        return {r.pid for r in records}
    except BaseException:  # noqa: BLE001 - best-effort cleanup, never fatal here
        return set(getattr(tracker, "_records", {}))


def _join_and_close(
    proc,
    stdout_capture: _BoundedStreamCapture,
    stderr_capture: _BoundedStreamCapture,
    *,
    allowance: float,
) -> None:
    """Drain and close both streams within a single, bounded allowance
    (shared across both, not ``allowance`` each) -- the process tree has
    already been killed by this point, so a cooperative descendant's
    pipe write-end is already closing; this just bounds how long we wait
    for that to finish being observed (SG2-002)."""
    deadline = time.monotonic() + allowance
    stdout_capture.join(timeout=max(0.0, deadline - time.monotonic()))
    stderr_capture.join(timeout=max(0.0, deadline - time.monotonic()))
    stdout_capture.close()
    stderr_capture.close()
    with contextlib.suppress(OSError, ValueError):
        proc.stdout.close()
    with contextlib.suppress(OSError, ValueError):
        proc.stderr.close()
    with contextlib.suppress(subprocess.TimeoutExpired, OSError):
        proc.wait(timeout=max(0.0, deadline - time.monotonic()))
