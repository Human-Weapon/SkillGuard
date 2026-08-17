"""The dynamic command execution contract.

A target command is always: an argv list, ``shell=False``, an explicit
cwd, an explicit timeout, and an explicit environment policy. There is no
"pass a shell string" mode -- see spec sections 42-44 and SECURITY.md. This
is the only place in SkillGuard that starts a target process.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType

from skillguard.dynamic.process import kill_tree
from skillguard.errors import DynamicAnalysisError, ValidationError
from skillguard.validation import (
    materialize_iterable,
    validate_finite_number,
    validate_non_negative_int,
)

_DEFAULT_MAX_OUTPUT_BYTES = 2_000_000


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
    stderr: str
    stderr_truncated: bool
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

        start = time.monotonic()
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv list, shell=False by contract
                list(argv_tuple),
                cwd=str(cwd),
                env=env,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
            )
        except OSError as exc:
            raise DynamicAnalysisError(
                f"failed to start target command {argv_tuple!r}: {exc}"
            ) from exc

        if on_pid_available is not None:
            on_pid_available(proc.pid)

        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            outcome = TargetOutcome.EXITED
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            kill_tree(proc.pid)
            try:
                stdout, stderr = proc.communicate(timeout=5.0)
            except subprocess.TimeoutExpired:
                stdout, stderr = "", ""
            outcome = TargetOutcome.TIMED_OUT
            exit_code = None
        duration = time.monotonic() - start

        stdout_out, stdout_trunc = _cap(stdout, self.max_output_bytes)
        stderr_out, stderr_trunc = _cap(stderr, self.max_output_bytes)

        return CommandResult(
            outcome=outcome,
            pid=proc.pid,
            exit_code=exit_code,
            stdout=stdout_out,
            stdout_truncated=stdout_trunc,
            stderr=stderr_out,
            stderr_truncated=stderr_trunc,
            duration_seconds=duration,
        )


def _cap(text: str, max_bytes: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text, False
    return encoded[:max_bytes].decode("utf-8", errors="ignore"), True
