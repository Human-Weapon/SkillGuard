"""Public exception hierarchy for SkillGuard.

External callers should only need to catch :class:`SkillGuardError` and,
where finer handling is useful, the specific subclasses below. Internal
Python exceptions (KeyError, JSONDecodeError, etc.) must never cross a
public API boundary unwrapped.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from skillguard.dynamic.observer import DynamicResult


class SkillGuardError(Exception):
    """Base class for all errors raised by the public SkillGuard API."""


class ConfigurationError(SkillGuardError):
    """A configuration object was constructed with invalid settings."""


class ValidationError(SkillGuardError):
    """A caller-supplied value failed input validation."""


class PathSecurityError(SkillGuardError):
    """A path operation would escape a bound root or violate containment."""


class ScanError(SkillGuardError):
    """Base class for errors raised while performing a scan."""


class StaticAnalysisError(ScanError):
    """Static analysis could not proceed for a reason other than a single
    file's parse failure (which is recorded as an incompleteness reason,
    not raised)."""


class DynamicAnalysisError(ScanError):
    """Dynamic analysis could not be started or configured."""


class ObservationError(SkillGuardError):
    """A runtime observer (process/filesystem/network/git) failed."""


class PersistenceError(SkillGuardError):
    """Base class for result-store read/write errors."""


class CorruptResultError(PersistenceError):
    """Persisted result data exists but does not match the expected schema."""


class PolicyError(SkillGuardError):
    """A policy document is invalid or could not be evaluated."""


class SourceMutationError(ObservationError):
    """The original source workspace changed while a dynamic run against an
    isolated copy of it was in progress. Static/dynamic source must never be
    mutated by SkillGuard itself; this indicates something else did.

    A source mutation can be discovered AFTER a dynamic run has already
    completed and produced a fully-formed ``DynamicResult`` -- e.g. the
    target timed out, or its output was truncated or contained invalid
    UTF-8, and only then did the integrity check notice the original
    source had also been modified. Both facts are security-relevant and
    neither may silently hide the other (SG3-003 in docs/audits): the
    completed result is attached here as ``partial_result`` rather than
    discarded, so a caller that catches this exception can still recover
    and surface it, while the exception itself still makes the mutation
    unmistakable and prevents the run from being treated as a clean
    success. ``partial_result`` is ``None`` when no run completed before
    the mutation was raised (e.g. observer setup itself failed)."""

    def __init__(self, message: str, *, partial_result: DynamicResult | None = None) -> None:
        super().__init__(message)
        self.partial_result = partial_result
