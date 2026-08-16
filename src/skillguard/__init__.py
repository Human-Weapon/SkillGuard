"""SkillGuard: security and behavior auditor for AI skills, plugins, and agents.

SkillGuard combines static analysis (AST-aware, never executes target code)
with optional dynamic behavior observation (executes a caller-specified
command and watches what it does) to help answer: does this skill/plugin's
observed behavior match what it declares?

SkillGuard never claims a target is "safe" or "secure" -- see the module
docstrings in :mod:`skillguard.report` and SECURITY.md for why.
"""

from skillguard._version import __version__
from skillguard.errors import (
    ConfigurationError,
    CorruptResultError,
    DynamicAnalysisError,
    ObservationError,
    PathSecurityError,
    PersistenceError,
    PolicyError,
    ScanError,
    SkillGuardError,
    StaticAnalysisError,
    ValidationError,
)
from skillguard.models import (
    AnalysisStatus,
    Confidence,
    Evidence,
    Finding,
    FindingSource,
    PolicyDisposition,
    Severity,
)

__all__ = [
    "__version__",
    "SkillGuardError",
    "ConfigurationError",
    "ValidationError",
    "ScanError",
    "StaticAnalysisError",
    "DynamicAnalysisError",
    "ObservationError",
    "PersistenceError",
    "CorruptResultError",
    "PolicyError",
    "PathSecurityError",
    "Finding",
    "Evidence",
    "Severity",
    "Confidence",
    "FindingSource",
    "AnalysisStatus",
    "PolicyDisposition",
]
