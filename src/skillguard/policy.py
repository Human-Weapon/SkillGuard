"""Small, explicit, data-only policy engine.

A Finding is evidence. A Policy decides whether that evidence is
acceptable. Keeping these separate avoids collapsing "network capability
observed" straight into "malicious" -- see docs/decisions/0004-capability-semantics.md.

Policy conditions are data (an enum tag plus parameters), never executable
predicates, so a policy document loaded from JSON/YAML can never run
arbitrary code (see spec section 68 / SG-POLICY threat model note in
SECURITY.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from skillguard.capabilities import Capability, CapabilityComparison
from skillguard.errors import PolicyError
from skillguard.models import AnalysisStatus, Finding, PolicyDisposition, Severity

SCHEMA_VERSION = 1


class PolicyAction(str, Enum):
    WARN = "WARN"
    BLOCK = "BLOCK"


class ConditionType(str, Enum):
    UNDECLARED_CAPABILITY_OBSERVED = "UNDECLARED_CAPABILITY_OBSERVED"
    CAPABILITY_OBSERVED = "CAPABILITY_OBSERVED"
    MIN_STATIC_SEVERITY = "MIN_STATIC_SEVERITY"
    ANALYSIS_INCOMPLETE = "ANALYSIS_INCOMPLETE"


@dataclass(frozen=True)
class PolicyCondition:
    type: ConditionType
    capabilities: frozenset[Capability] = field(default_factory=frozenset)
    min_severity: Severity | None = None


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    description: str
    action: PolicyAction
    condition: PolicyCondition


@dataclass(frozen=True)
class Suppression:
    rule_id: str
    reason: str
    scope_path: str | None = None


@dataclass(frozen=True)
class Policy:
    schema_version: int
    rules: tuple[PolicyRule, ...] = ()
    suppressions: tuple[Suppression, ...] = ()
    require_complete_analysis: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.schema_version, bool) or not isinstance(self.schema_version, int):
            raise PolicyError(
                f"policy schema_version must be an int, got {type(self.schema_version).__name__}"
            )
        if self.schema_version != SCHEMA_VERSION:
            raise PolicyError(f"unsupported policy schema_version: {self.schema_version}")
        if not isinstance(self.require_complete_analysis, bool):
            raise PolicyError("policy require_complete_analysis must be a bool")

    @classmethod
    def from_dict(cls, data: dict) -> Policy:
        if not isinstance(data, dict):
            raise PolicyError("policy document must be a JSON object")
        try:
            schema_version = data["schema_version"]
        except KeyError as exc:
            raise PolicyError("policy document missing 'schema_version'") from exc
        if isinstance(schema_version, bool) or not isinstance(schema_version, int):
            raise PolicyError("policy 'schema_version' must be an int")
        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise PolicyError("policy 'rules' must be a list")
        rules = []
        for raw_rule in raw_rules:
            rules.append(_parse_rule(raw_rule))
        raw_suppressions = data.get("suppressions", [])
        if not isinstance(raw_suppressions, list):
            raise PolicyError("policy 'suppressions' must be a list")
        suppressions = []
        for raw_supp in raw_suppressions:
            if not isinstance(raw_supp, dict):
                raise PolicyError("each suppression must be a JSON object")
            rule_id = raw_supp.get("rule_id")
            reason = raw_supp.get("reason")
            scope_path = raw_supp.get("scope_path")
            if not isinstance(rule_id, str) or not rule_id:
                raise PolicyError("suppression 'rule_id' must be a non-empty string")
            if not isinstance(reason, str) or not reason:
                raise PolicyError("suppression 'reason' must be a non-empty string")
            if scope_path is not None and not isinstance(scope_path, str):
                raise PolicyError("suppression 'scope_path' must be a string or null")
            suppressions.append(Suppression(rule_id=rule_id, reason=reason, scope_path=scope_path))
        require_complete_analysis = data.get("require_complete_analysis", False)
        if not isinstance(require_complete_analysis, bool):
            raise PolicyError("policy 'require_complete_analysis' must be a bool")
        return cls(
            schema_version=schema_version,
            rules=tuple(rules),
            suppressions=tuple(suppressions),
            require_complete_analysis=require_complete_analysis,
        )


def _parse_rule(raw: dict) -> PolicyRule:
    if not isinstance(raw, dict):
        raise PolicyError("each policy rule must be a JSON object")
    try:
        rule_id = raw["rule_id"]
        description = raw["description"]
        action = PolicyAction(raw["action"])
        raw_cond = raw["condition"]
    except (KeyError, ValueError, TypeError) as exc:
        raise PolicyError(f"invalid policy rule: {exc}") from exc
    if not isinstance(rule_id, str) or not rule_id:
        raise PolicyError("policy rule 'rule_id' must be a non-empty string")
    if not isinstance(description, str):
        raise PolicyError("policy rule 'description' must be a string")
    if not isinstance(raw_cond, dict):
        raise PolicyError("policy rule 'condition' must be a JSON object")
    try:
        cond_type = ConditionType(raw_cond["type"])
    except (KeyError, ValueError, TypeError) as exc:
        raise PolicyError(f"invalid policy condition: {exc}") from exc
    raw_capabilities = raw_cond.get("capabilities", [])
    if not isinstance(raw_capabilities, list):
        raise PolicyError("policy condition 'capabilities' must be a list")
    try:
        capabilities = frozenset(Capability(c) for c in raw_capabilities)
    except (ValueError, TypeError) as exc:
        raise PolicyError(f"invalid capability in policy condition: {exc}") from exc
    try:
        min_severity = Severity(raw_cond["min_severity"]) if "min_severity" in raw_cond else None
    except (ValueError, TypeError) as exc:
        raise PolicyError(f"invalid severity in policy condition: {exc}") from exc
    return PolicyRule(
        rule_id=rule_id,
        description=description,
        action=action,
        condition=PolicyCondition(
            type=cond_type, capabilities=capabilities, min_severity=min_severity
        ),
    )


def default_policy() -> Policy:
    """Review-oriented default: nothing is auto-blocked, everything powerful
    is surfaced for human review. See spec section 66."""
    return Policy(
        schema_version=SCHEMA_VERSION, rules=(), suppressions=(), require_complete_analysis=False
    )


def example_strict_policy() -> Policy:
    """An example strict policy, provided separately from the default so a
    caller opts in explicitly rather than being silently blocked."""
    return Policy(
        schema_version=SCHEMA_VERSION,
        rules=(
            PolicyRule(
                rule_id="deny-undeclared-network",
                description="Block if network.outbound was observed but not declared.",
                action=PolicyAction.BLOCK,
                condition=PolicyCondition(
                    type=ConditionType.UNDECLARED_CAPABILITY_OBSERVED,
                    capabilities=frozenset({Capability.NETWORK_OUTBOUND}),
                ),
            ),
            PolicyRule(
                rule_id="deny-package-install",
                description="Block if packages.install was observed.",
                action=PolicyAction.BLOCK,
                condition=PolicyCondition(
                    type=ConditionType.CAPABILITY_OBSERVED,
                    capabilities=frozenset({Capability.PACKAGES_INSTALL}),
                ),
            ),
            PolicyRule(
                rule_id="deny-critical-static-findings",
                description="Block on any non-suppressed CRITICAL static finding.",
                action=PolicyAction.BLOCK,
                condition=PolicyCondition(
                    type=ConditionType.MIN_STATIC_SEVERITY, min_severity=Severity.CRITICAL
                ),
            ),
        ),
        suppressions=(),
        require_complete_analysis=True,
    )


@dataclass(frozen=True)
class PolicyRuleOutcome:
    rule_id: str
    action: PolicyAction
    triggered: bool
    reason: str
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyResult:
    disposition: PolicyDisposition
    outcomes: tuple[PolicyRuleOutcome, ...]
    analysis_status: AnalysisStatus


def apply_suppressions(
    findings: tuple[Finding, ...], suppressions: tuple[Suppression, ...]
) -> tuple[Finding, ...]:
    """Mark matching findings as suppressed. Never removes a finding --
    suppressed findings must remain visible in machine-readable output with
    suppressed=true (spec section 67)."""
    from dataclasses import replace

    if not suppressions:
        return findings
    result = []
    for f in findings:
        match = next(
            (
                s
                for s in suppressions
                if (s.rule_id == "*" or s.rule_id == f.rule_id)
                and (s.scope_path is None or s.scope_path == f.file_path)
            ),
            None,
        )
        if match:
            result.append(replace(f, suppressed=True, suppression_reason=match.reason))
        else:
            result.append(f)
    return tuple(result)


class PolicyEngine:
    def evaluate(
        self,
        *,
        policy: Policy,
        findings: tuple[Finding, ...],
        capability_comparison: CapabilityComparison,
        analysis_status: AnalysisStatus,
    ) -> PolicyResult:
        outcomes: list[PolicyRuleOutcome] = []
        active_findings = [f for f in findings if not f.suppressed]

        for rule in policy.rules:
            triggered, reason, refs = self._check(
                rule.condition, active_findings, capability_comparison
            )
            outcomes.append(
                PolicyRuleOutcome(
                    rule_id=rule.rule_id,
                    action=rule.action,
                    triggered=triggered,
                    reason=reason,
                    evidence_refs=refs,
                )
            )

        if policy.require_complete_analysis and analysis_status != AnalysisStatus.COMPLETE:
            outcomes.append(
                PolicyRuleOutcome(
                    rule_id="require-complete-analysis",
                    action=PolicyAction.WARN,
                    triggered=True,
                    reason=f"analysis status is {analysis_status.value}, not COMPLETE",
                    evidence_refs=(),
                )
            )

        disposition = self._disposition(outcomes, policy=policy, analysis_status=analysis_status)
        return PolicyResult(
            disposition=disposition, outcomes=tuple(outcomes), analysis_status=analysis_status
        )

    def _disposition(
        self, outcomes: list[PolicyRuleOutcome], *, policy: Policy, analysis_status: AnalysisStatus
    ) -> PolicyDisposition:
        triggered = [o for o in outcomes if o.triggered]
        if any(o.action == PolicyAction.BLOCK for o in triggered):
            return PolicyDisposition.BLOCK
        if policy.require_complete_analysis and analysis_status != AnalysisStatus.COMPLETE:
            return PolicyDisposition.REVIEW_REQUIRED
        if any(o.action == PolicyAction.WARN for o in triggered):
            return PolicyDisposition.WARN
        return PolicyDisposition.PASS

    def _check(
        self, condition: PolicyCondition, findings: list[Finding], comparison: CapabilityComparison
    ) -> tuple[bool, str, tuple[str, ...]]:
        if condition.type == ConditionType.UNDECLARED_CAPABILITY_OBSERVED:
            hits = comparison.undeclared_observed & (
                condition.capabilities or comparison.undeclared_observed
            )
            if hits:
                return (
                    True,
                    f"undeclared observed capabilities: {sorted(c.value for c in hits)}",
                    tuple(c.value for c in hits),
                )
            return False, "no matching undeclared observed capability", ()

        if condition.type == ConditionType.CAPABILITY_OBSERVED:
            hits = comparison.observed & (condition.capabilities or comparison.observed)
            if hits:
                return (
                    True,
                    f"observed capabilities: {sorted(c.value for c in hits)}",
                    tuple(c.value for c in hits),
                )
            return False, "no matching observed capability", ()

        if condition.type == ConditionType.MIN_STATIC_SEVERITY:
            assert condition.min_severity is not None
            hits = [f for f in findings if f.severity.weight >= condition.min_severity.weight]
            if hits:
                return (
                    True,
                    f"{len(hits)} finding(s) at or above {condition.min_severity.value}",
                    tuple(f.rule_id for f in hits),
                )
            return False, "no findings at or above threshold", ()

        if condition.type == ConditionType.ANALYSIS_INCOMPLETE:
            return False, "checked separately via require_complete_analysis", ()

        raise PolicyError(f"unknown condition type: {condition.type}")
