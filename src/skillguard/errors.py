"""Public exception hierarchy for SkillGuard.

External callers should only need to catch :class:`SkillGuardError` and,
where finer handling is useful, the specific subclasses below. Internal
Python exceptions (KeyError, JSONDecodeError, etc.) must never cross a
public API boundary unwrapped.
"""

from __future__ import annotations


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
    mutated by SkillGuard itself; this indicates something else did."""
