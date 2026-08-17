"""Top-level static scan orchestration: walk the target, classify each
file, and dispatch to the AST/manifest/secret scanners.

Never imports or executes anything in the scan target -- only reads bytes
and, for recognized text formats, parses them (ast.parse / tomllib.loads /
json.loads).
"""

from __future__ import annotations

from dataclasses import dataclass

from skillguard.capabilities import Capability
from skillguard.errors import ObservationError, ValidationError
from skillguard.models import (
    AnalysisStatus,
    Evidence,
    EvidenceKind,
    Finding,
    FindingSource,
    sort_findings,
)
from skillguard.paths import BoundRoot, WalkLimits, open_walk_entry, walk_tree
from skillguard.static import manifests, rules
from skillguard.static.python_ast import PythonAstScanner
from skillguard.static.secrets import SecretScanner
from skillguard.validation import validate_non_negative_int

_PY_AST = PythonAstScanner()


@dataclass(frozen=True)
class StaticScanConfig:
    max_files: int = 5000
    max_total_bytes: int = 200_000_000
    max_file_bytes: int = 5_000_000
    max_depth: int = 64
    enable_entropy_secrets: bool = False

    def __post_init__(self) -> None:
        validate_non_negative_int(self.max_files, name="max_files")
        validate_non_negative_int(self.max_total_bytes, name="max_total_bytes")
        validate_non_negative_int(self.max_file_bytes, name="max_file_bytes")
        validate_non_negative_int(self.max_depth, name="max_depth")
        if not isinstance(self.enable_entropy_secrets, bool):
            raise ValidationError("enable_entropy_secrets must be a bool")


@dataclass(frozen=True)
class StaticScanResult:
    status: AnalysisStatus
    target: str
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    capabilities_observed: frozenset[Capability]
    files_scanned: int
    incompleteness_reasons: tuple[str, ...]


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def _decode_text(data: bytes) -> str | None:
    if _is_binary(data):
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None


class StaticScanner:
    def __init__(self, config: StaticScanConfig | None = None) -> None:
        self.config = config or StaticScanConfig()
        self._secret_scanner = SecretScanner(enable_entropy=self.config.enable_entropy_secrets)

    def scan(self, target: object) -> StaticScanResult:
        root = BoundRoot.bind(target, label="scan target")
        limits = WalkLimits(
            max_files=self.config.max_files,
            max_total_bytes=self.config.max_total_bytes,
            max_file_bytes=self.config.max_file_bytes,
            max_depth=self.config.max_depth,
        )
        outcome = walk_tree(root, limits)

        findings: list[Finding] = []
        evidence: list[Evidence] = []
        capabilities: set[Capability] = set()
        reasons: set[str] = set(outcome.incompleteness_reasons)

        for rel in outcome.reparse_points_skipped:
            rule = rules.SG_PATH_001
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    description=f"{rule.title}: {rel}",
                    severity=rule.default_severity,
                    category=rule.category,
                    source=FindingSource.STATIC,
                    confidence=rule.default_confidence,
                    recommendation=rule.recommendation,
                    file_path=rel,
                )
            )

        files_scanned = 0
        for entry in outcome.entries:
            if entry.size_bytes > limits.max_file_bytes:
                reasons.add("FILE_TOO_LARGE")
                continue
            try:
                self._scan_one(entry, findings, evidence, capabilities, reasons)
                files_scanned += 1
            except ObservationError as exc:
                reasons.add("FILE_CHANGED_DURING_READ")
                evidence.append(
                    Evidence(
                        kind=EvidenceKind.STATIC_PATTERN,
                        source="StaticScanner",
                        summary=f"file changed before a stable read: {entry.relative_posix}: {exc}",
                        origin=entry.relative_posix,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - one bad file must not kill the scan
                reasons.add("UNEXPECTED_FILE_ERROR")
                evidence.append(
                    Evidence(
                        kind=EvidenceKind.STATIC_PATTERN,
                        source="StaticScanner",
                        summary=f"unexpected error scanning {entry.relative_posix}: {exc}",
                        origin=entry.relative_posix,
                    )
                )

        status = AnalysisStatus.COMPLETE if not reasons else AnalysisStatus.ANALYSIS_INCOMPLETE
        return StaticScanResult(
            status=status,
            target=str(root.resolved),
            findings=sort_findings(findings),
            evidence=tuple(evidence),
            capabilities_observed=frozenset(capabilities),
            files_scanned=files_scanned,
            incompleteness_reasons=tuple(sorted(reasons)),
        )

    def _scan_one(
        self,
        entry,
        findings: list[Finding],
        evidence: list[Evidence],
        capabilities: set[Capability],
        reasons: set[str],
    ) -> None:
        name = entry.relative_posix.rsplit("/", 1)[-1]
        with open_walk_entry(entry) as fh:
            data = fh.read()
        text = _decode_text(data)
        if text is None:
            if not _is_binary(data):
                reasons.add("UNSUPPORTED_ENCODING")
            return  # binary: no content-level scan, not an error

        if name.endswith(".py"):
            result = _PY_AST.scan_source(relative_path=entry.relative_posix, source=text)
            findings.extend(result.findings)
            evidence.extend(result.evidence)
            capabilities.update(result.capabilities)
            if not result.parse_ok:
                reasons.add("PYTHON_PARSE_ERROR")
        elif name == "pyproject.toml":
            result = manifests.scan_pyproject(relative_path=entry.relative_posix, text=text)
            findings.extend(result.findings)
            if not result.parse_ok:
                reasons.add("MANIFEST_PARSE_ERROR")
        elif name == "package.json":
            result = manifests.scan_package_json(relative_path=entry.relative_posix, text=text)
            findings.extend(result.findings)
            if not result.parse_ok:
                reasons.add("MANIFEST_PARSE_ERROR")
        elif name.startswith("requirements") and name.endswith(".txt"):
            result = manifests.scan_requirements(relative_path=entry.relative_posix, text=text)
            findings.extend(result.findings)
            if not result.parse_ok:
                reasons.add("MANIFEST_PARSE_ERROR")

        secret_result = self._secret_scanner.scan_text(
            relative_path=entry.relative_posix, text=text
        )
        findings.extend(secret_result.findings)
        if secret_result.findings:
            capabilities.add(Capability.SECRETS_ACCESS)
