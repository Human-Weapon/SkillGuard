"""Policy engine scenarios: declared+observed, undeclared+observed,
declared-but-not-observed, suppression, incomplete-analysis handling."""

from __future__ import annotations

from skillguard.capabilities import Capability, compare_capabilities
from skillguard.models import (
    AnalysisStatus,
    Confidence,
    Finding,
    FindingSource,
    PolicyDisposition,
    Severity,
)
from skillguard.policy import (
    ConditionType,
    Policy,
    PolicyAction,
    PolicyCondition,
    PolicyEngine,
    PolicyRule,
    Suppression,
    apply_suppressions,
    default_policy,
    example_strict_policy,
)


def _finding(rule_id: str, severity: Severity, *, suppressed: bool = False) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="t",
        description="d",
        severity=severity,
        category="c",
        source=FindingSource.STATIC,
        confidence=Confidence.HIGH,
        recommendation="r",
        suppressed=suppressed,
    )


class TestCapabilityComparison:
    def test_undeclared_observed(self):
        comp = compare_capabilities(
            declared=frozenset({Capability.FILESYSTEM_READ}),
            observed=frozenset({Capability.FILESYSTEM_READ, Capability.NETWORK_OUTBOUND}),
        )
        assert comp.undeclared_observed == frozenset({Capability.NETWORK_OUTBOUND})

    def test_declared_not_observed_is_not_absence_claim(self):
        comp = compare_capabilities(
            declared=frozenset({Capability.NETWORK_OUTBOUND}),
            observed=frozenset(),
        )
        assert comp.declared_not_observed == frozenset({Capability.NETWORK_OUTBOUND})
        # the type itself carries no "is absent" flag -- callers must not
        # infer one; this test just pins the field's actual meaning.

    def test_environment_read_is_marked_unsupported_observation(self):
        comp = compare_capabilities(declared=frozenset(), observed=frozenset())
        assert Capability.ENVIRONMENT_READ in comp.unsupported_observation


class TestPolicyEvaluation:
    def test_default_policy_never_blocks(self):
        comp = compare_capabilities(
            declared=frozenset(),
            observed=frozenset({Capability.NETWORK_OUTBOUND, Capability.PACKAGES_INSTALL}),
        )
        findings = (_finding("SG-X-001", Severity.CRITICAL),)
        result = PolicyEngine().evaluate(
            policy=default_policy(),
            findings=findings,
            capability_comparison=comp,
            analysis_status=AnalysisStatus.COMPLETE,
        )
        assert result.disposition == PolicyDisposition.PASS

    def test_strict_policy_blocks_undeclared_network(self):
        comp = compare_capabilities(
            declared=frozenset(), observed=frozenset({Capability.NETWORK_OUTBOUND})
        )
        result = PolicyEngine().evaluate(
            policy=example_strict_policy(),
            findings=(),
            capability_comparison=comp,
            analysis_status=AnalysisStatus.COMPLETE,
        )
        assert result.disposition == PolicyDisposition.BLOCK
        triggered = [o for o in result.outcomes if o.triggered]
        assert any(o.rule_id == "deny-undeclared-network" for o in triggered)

    def test_strict_policy_passes_declared_network(self):
        comp = compare_capabilities(
            declared=frozenset({Capability.NETWORK_OUTBOUND}),
            observed=frozenset({Capability.NETWORK_OUTBOUND}),
        )
        result = PolicyEngine().evaluate(
            policy=example_strict_policy(),
            findings=(),
            capability_comparison=comp,
            analysis_status=AnalysisStatus.COMPLETE,
        )
        assert result.disposition == PolicyDisposition.PASS

    def test_min_severity_rule_blocks_on_critical_finding(self):
        comp = compare_capabilities(declared=frozenset(), observed=frozenset())
        findings = (_finding("SG-X-001", Severity.CRITICAL),)
        result = PolicyEngine().evaluate(
            policy=example_strict_policy(),
            findings=findings,
            capability_comparison=comp,
            analysis_status=AnalysisStatus.COMPLETE,
        )
        assert result.disposition == PolicyDisposition.BLOCK

    def test_suppressed_finding_does_not_trigger_min_severity(self):
        comp = compare_capabilities(declared=frozenset(), observed=frozenset())
        findings = apply_suppressions(
            (_finding("SG-X-001", Severity.CRITICAL),),
            (Suppression(rule_id="SG-X-001", reason="reviewed, accepted"),),
        )
        assert findings[0].suppressed is True
        result = PolicyEngine().evaluate(
            policy=example_strict_policy(),
            findings=findings,
            capability_comparison=comp,
            analysis_status=AnalysisStatus.COMPLETE,
        )
        assert result.disposition != PolicyDisposition.BLOCK

    def test_suppression_never_removes_finding_from_output(self):
        findings = apply_suppressions(
            (_finding("SG-X-001", Severity.HIGH),), (Suppression(rule_id="SG-X-001", reason="ok"),)
        )
        assert len(findings) == 1
        assert findings[0].suppressed is True
        assert findings[0].suppression_reason == "ok"

    def test_require_complete_analysis_prevents_pass_when_incomplete(self):
        policy = Policy(schema_version=1, rules=(), require_complete_analysis=True)
        comp = compare_capabilities(declared=frozenset(), observed=frozenset())
        result = PolicyEngine().evaluate(
            policy=policy,
            findings=(),
            capability_comparison=comp,
            analysis_status=AnalysisStatus.ANALYSIS_INCOMPLETE,
        )
        assert result.disposition == PolicyDisposition.REVIEW_REQUIRED

    def test_block_dominates_warn(self):
        policy = Policy(
            schema_version=1,
            rules=(
                PolicyRule(
                    rule_id="warn-rule",
                    description="warn",
                    action=PolicyAction.WARN,
                    condition=PolicyCondition(
                        type=ConditionType.CAPABILITY_OBSERVED,
                        capabilities=frozenset({Capability.FILESYSTEM_WRITE}),
                    ),
                ),
                PolicyRule(
                    rule_id="block-rule",
                    description="block",
                    action=PolicyAction.BLOCK,
                    condition=PolicyCondition(
                        type=ConditionType.CAPABILITY_OBSERVED,
                        capabilities=frozenset({Capability.NETWORK_OUTBOUND}),
                    ),
                ),
            ),
        )
        comp = compare_capabilities(
            declared=frozenset(),
            observed=frozenset({Capability.FILESYSTEM_WRITE, Capability.NETWORK_OUTBOUND}),
        )
        result = PolicyEngine().evaluate(
            policy=policy,
            findings=(),
            capability_comparison=comp,
            analysis_status=AnalysisStatus.COMPLETE,
        )
        assert result.disposition == PolicyDisposition.BLOCK

    def test_policy_traceability_every_block_has_a_reason(self):
        comp = compare_capabilities(
            declared=frozenset(), observed=frozenset({Capability.NETWORK_OUTBOUND})
        )
        result = PolicyEngine().evaluate(
            policy=example_strict_policy(),
            findings=(),
            capability_comparison=comp,
            analysis_status=AnalysisStatus.COMPLETE,
        )
        for outcome in result.outcomes:
            if outcome.triggered:
                assert outcome.reason
                if outcome.action == PolicyAction.BLOCK:
                    assert (
                        outcome.evidence_refs
                        or "static" in outcome.reason.lower()
                        or "observed" in outcome.reason.lower()
                    )
