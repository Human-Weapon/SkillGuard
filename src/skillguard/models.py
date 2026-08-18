"""Immutable domain models: Finding, Evidence, and the enums that describe
audit state.

All public dataclasses here are frozen *and* deep-normalize any
caller-supplied mutable containers (list/dict/set) into immutable
equivalents (tuple/MappingProxyType/frozenset) at construction time, via
:func:`deep_freeze`. A frozen dataclass whose fields still hold a mutable
``dict``/``list`` reference is not actually immutable -- the caller can
mutate the object through that reference after construction -- so this
normalization is load-bearing, not decorative.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any

from skillguard.redaction import redact_secret_like_patterns


def deep_freeze(value: Any) -> Any:
    if isinstance(value, MappingProxyType):
        return value
    if isinstance(value, dict):
        return MappingProxyType({k: deep_freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(deep_freeze(v) for v in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(deep_freeze(v) for v in value)
    return value


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def weight(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class FindingSource(str, Enum):
    STATIC = "STATIC"
    DYNAMIC = "DYNAMIC"
    POLICY = "POLICY"


class AnalysisStatus(str, Enum):
    COMPLETE = "COMPLETE"
    ANALYSIS_INCOMPLETE = "ANALYSIS_INCOMPLETE"
    FAILED = "FAILED"


class PolicyDisposition(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    BLOCK = "BLOCK"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class EvidenceKind(str, Enum):
    STATIC_AST = "STATIC_AST"
    STATIC_PATTERN = "STATIC_PATTERN"
    MANIFEST = "MANIFEST"
    PROCESS = "PROCESS"
    FILESYSTEM = "FILESYSTEM"
    NETWORK = "NETWORK"
    GIT = "GIT"
    SECRET_CANARY = "SECRET_CANARY"
    POLICY = "POLICY"


class IncompletenessReason(str, Enum):
    FILE_LIMIT_REACHED = "FILE_LIMIT_REACHED"
    BYTE_LIMIT_REACHED = "BYTE_LIMIT_REACHED"
    UNREADABLE_FILE = "UNREADABLE_FILE"
    PYTHON_PARSE_ERROR = "PYTHON_PARSE_ERROR"
    PROCESS_PERMISSION_DENIED = "PROCESS_PERMISSION_DENIED"
    NETWORK_OBSERVER_PARTIAL = "NETWORK_OBSERVER_PARTIAL"
    MONITOR_FAILURE = "MONITOR_FAILURE"
    OUTPUT_TRUNCATED = "OUTPUT_TRUNCATED"
    UNSUPPORTED_CAPABILITY = "UNSUPPORTED_CAPABILITY"
    MAX_DEPTH_REACHED = "MAX_DEPTH_REACHED"
    REPARSE_POINT_SKIPPED = "REPARSE_POINT_SKIPPED"
    SPECIAL_FILE_SKIPPED = "SPECIAL_FILE_SKIPPED"
    MANIFEST_PARSE_ERROR = "MANIFEST_PARSE_ERROR"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    UNEXPECTED_FILE_ERROR = "UNEXPECTED_FILE_ERROR"
    ROOT_CHANGED = "ROOT_CHANGED"
    FILE_CHANGED_DURING_READ = "FILE_CHANGED_DURING_READ"
    UNSUPPORTED_ENCODING = "UNSUPPORTED_ENCODING"
    OUTPUT_ENCODING_LOSS = "OUTPUT_ENCODING_LOSS"
    PROCESS_CLEANUP_INCOMPLETE = "PROCESS_CLEANUP_INCOMPLETE"


@dataclass(frozen=True)
class Evidence:
    kind: EvidenceKind
    source: str
    summary: str
    origin: str
    timestamp: str | None = None
    details: MappingProxyType = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        # This is the single shared redaction boundary for every Evidence
        # record, regardless of which observer/scanner constructed it --
        # summary/origin/details can all carry target-controlled text
        # (a path, an argv entry, a joined list of skipped paths), and a
        # secret-shaped substring anywhere in them must never reach a
        # persisted artifact or the CLI unredacted (SG2-004 in docs/audits).
        object.__setattr__(self, "summary", redact_secret_like_patterns(self.summary))
        object.__setattr__(self, "origin", redact_secret_like_patterns(self.origin))
        frozen_details = deep_freeze(self.details)
        object.__setattr__(
            self,
            "details",
            MappingProxyType(
                {
                    k: (redact_secret_like_patterns(v) if isinstance(v, str) else v)
                    for k, v in frozen_details.items()
                }
            ),
        )


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: str
    source: FindingSource
    confidence: Confidence
    recommendation: str
    evidence_ids: tuple[str, ...] = ()
    file_path: str | None = None
    line: int | None = None
    column: int | None = None
    observed_capability: str | None = None
    declared_capability: str | None = None
    suppressed: bool = False
    suppression_reason: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_ids", deep_freeze(self.evidence_ids))
        # Same redaction boundary as Evidence, applied here for the same
        # reason: file_path/description can both carry a target-controlled
        # path or exception-message fragment (SG2-004 in docs/audits).
        object.__setattr__(self, "description", redact_secret_like_patterns(self.description))
        if self.file_path is not None:
            object.__setattr__(self, "file_path", redact_secret_like_patterns(self.file_path))

    def sort_key(self) -> tuple:
        return (
            -self.severity.weight,
            self.rule_id,
            self.file_path or "",
            self.line if self.line is not None else -1,
            self.title,
        )


def sort_findings(findings: list[Finding]) -> tuple[Finding, ...]:
    return tuple(sorted(findings, key=Finding.sort_key))
