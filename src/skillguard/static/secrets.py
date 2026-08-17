"""Conservative static secret detection.

Detects likely hard-coded secret material by pattern, never by importing or
executing target code. Raw secret values are never included in the
returned findings -- see :mod:`skillguard.redaction`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from skillguard.models import Finding, FindingSource
from skillguard.redaction import redact_details
from skillguard.static import rules

_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")

_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    (
        "generic_bearer_jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
)

_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|api[_-]?key|secret|token|access[_-]?key)\b\s*[:=]\s*"
    r"['\"]([^'\"\n]{6,200})['\"]"
)


@dataclass
class SecretScanResult:
    findings: list[Finding]


def _finding(rule_def, *, line: int, value: str, kind: str) -> Finding:
    details = redact_details(value, kind=kind)
    return Finding(
        rule_id=rule_def.rule_id,
        title=rule_def.title,
        description=(
            f"{rule_def.title} ({kind}, length={details['length']}, "
            f"prefix={details['prefix']}, sha256_prefix={details['sha256_prefix']})"
        ),
        severity=rule_def.default_severity,
        category=rule_def.category,
        source=FindingSource.STATIC,
        confidence=rule_def.default_confidence,
        recommendation=rule_def.recommendation,
        line=line,
    )


class SecretScanner:
    def __init__(self, *, enable_entropy: bool = False, entropy_threshold: float = 4.3) -> None:
        self.enable_entropy = enable_entropy
        self.entropy_threshold = entropy_threshold

    def scan_text(self, *, relative_path: str, text: str) -> SecretScanResult:
        findings: list[Finding] = []
        lines = text.splitlines()
        for i, line in enumerate(lines, start=1):
            if _PRIVATE_KEY_RE.search(line):
                f = _finding(
                    rules.SG_SECRET_001, line=i, value=line.strip(), kind="private_key_block"
                )
                findings.append(_with_path(f, relative_path))
                continue
            for token_kind, pattern in _TOKEN_PATTERNS:
                m = pattern.search(line)
                if m:
                    f = _finding(rules.SG_SECRET_002, line=i, value=m.group(0), kind=token_kind)
                    findings.append(_with_path(f, relative_path))
            m = _ASSIGNMENT_RE.search(line)
            if m:
                f = _finding(
                    rules.SG_SECRET_003,
                    line=i,
                    value=m.group(2),
                    kind=f"assignment:{m.group(1).lower()}",
                )
                findings.append(_with_path(f, relative_path))
            if self.enable_entropy:
                findings.extend(
                    self._entropy_findings(relative_path=relative_path, line_no=i, line=line)
                )
        return SecretScanResult(findings=findings)

    def _entropy_findings(self, *, relative_path: str, line_no: int, line: str) -> list[Finding]:
        results: list[Finding] = []
        for candidate in re.findall(r"['\"]([A-Za-z0-9+/_=\-]{20,})['\"]", line):
            if _shannon_entropy(candidate) >= self.entropy_threshold:
                f = _finding(
                    rules.SG_SECRET_004, line=line_no, value=candidate, kind="high_entropy_literal"
                )
                results.append(_with_path(f, relative_path))
        return results


def _with_path(finding: Finding, relative_path: str) -> Finding:
    from dataclasses import replace

    return replace(finding, file_path=relative_path)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    import math
    from collections import Counter

    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
