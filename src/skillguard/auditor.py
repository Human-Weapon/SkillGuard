"""Top-level orchestration: run static analysis, optionally dynamic
observation, compare declared vs. observed capabilities, and evaluate
policy -- sequentially, in that order. v0.1.0 audits exactly one target at
a time (see spec section 91 on why concurrency is out of scope for now).
"""

from __future__ import annotations

import platform
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from skillguard._version import __version__
from skillguard.capabilities import (
    Capability,
    CapabilityComparison,
    CapabilityManifest,
    compare_capabilities,
)
from skillguard.dynamic.observer import DynamicObserver, DynamicResult, DynamicRunConfig
from skillguard.errors import SkillGuardError
from skillguard.models import AnalysisStatus, Evidence, Finding, sort_findings
from skillguard.paths import BoundRoot
from skillguard.policy import Policy, PolicyEngine, PolicyResult, apply_suppressions, default_policy
from skillguard.static.scanner import StaticScanConfig, StaticScanner, StaticScanResult


def combine_statuses(*statuses: AnalysisStatus | None) -> AnalysisStatus:
    present = [s for s in statuses if s is not None]
    if not present:
        return AnalysisStatus.ANALYSIS_INCOMPLETE
    if any(s == AnalysisStatus.FAILED for s in present):
        return AnalysisStatus.FAILED
    if any(s == AnalysisStatus.ANALYSIS_INCOMPLETE for s in present):
        return AnalysisStatus.ANALYSIS_INCOMPLETE
    return AnalysisStatus.COMPLETE


@dataclass(frozen=True)
class AuditConfig:
    static: StaticScanConfig = field(default_factory=StaticScanConfig)
    dynamic: DynamicRunConfig | None = None
    capability_manifest: CapabilityManifest | None = None
    policy: Policy = field(default_factory=default_policy)


@dataclass(frozen=True)
class AuditResult:
    audit_id: str
    status: AnalysisStatus
    target: str
    generated_at: str
    skillguard_version: str
    python_version: str
    platform: str
    static: StaticScanResult | None
    dynamic: DynamicResult | None
    capability_comparison: CapabilityComparison
    policy_result: PolicyResult
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    incompleteness_reasons: tuple[str, ...]
    failure_reasons: tuple[str, ...]


class SkillGuardAuditor:
    def __init__(self, config: AuditConfig | None = None) -> None:
        self.config = config or AuditConfig()

    def audit(self, target: object, *, audit_id: str | None = None) -> AuditResult:
        audit_id = audit_id or uuid.uuid4().hex
        root = BoundRoot.bind(target, label="scan target")

        static_result: StaticScanResult | None = None
        dynamic_result: DynamicResult | None = None
        failure_reasons: list[str] = []

        try:
            static_result = StaticScanner(self.config.static).scan(root.resolved)
        except SkillGuardError as exc:
            failure_reasons.append(f"static analysis failed: {exc}")

        if self.config.dynamic is not None:
            try:
                dynamic_result = DynamicObserver(self.config.dynamic).run(root)
            except SkillGuardError as exc:
                failure_reasons.append(f"dynamic analysis failed: {exc}")

        observed: set[Capability] = set()
        if static_result is not None:
            observed |= static_result.capabilities_observed
        if dynamic_result is not None:
            observed |= dynamic_result.capabilities_observed

        declared = (
            self.config.capability_manifest.declared
            if self.config.capability_manifest
            else frozenset()
        )
        comparison = compare_capabilities(declared=declared, observed=frozenset(observed))

        raw_findings = static_result.findings if static_result is not None else ()
        findings = apply_suppressions(raw_findings, self.config.policy.suppressions)

        evidence: list[Evidence] = []
        if static_result is not None:
            evidence.extend(static_result.evidence)
        if dynamic_result is not None:
            evidence.extend(dynamic_result.evidence)

        incompleteness: set[str] = set()
        if static_result is not None:
            incompleteness.update(static_result.incompleteness_reasons)
        if dynamic_result is not None:
            incompleteness.update(dynamic_result.incompleteness_reasons)

        status = combine_statuses(
            static_result.status if static_result is not None else None,
            dynamic_result.status if dynamic_result is not None else None,
        )
        if failure_reasons:
            status = AnalysisStatus.FAILED

        policy_result = PolicyEngine().evaluate(
            policy=self.config.policy,
            findings=findings,
            capability_comparison=comparison,
            analysis_status=status,
        )

        return AuditResult(
            audit_id=audit_id,
            status=status,
            target=str(root.resolved),
            generated_at=datetime.now(timezone.utc).isoformat(),
            skillguard_version=__version__,
            python_version=sys.version.split()[0],
            platform=platform.platform(),
            static=static_result,
            dynamic=dynamic_result,
            capability_comparison=comparison,
            policy_result=policy_result,
            findings=sort_findings(list(findings)),
            evidence=tuple(evidence),
            incompleteness_reasons=tuple(sorted(incompleteness)),
            failure_reasons=tuple(failure_reasons),
        )
