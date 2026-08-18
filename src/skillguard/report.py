"""Serialization of an :class:`~skillguard.auditor.AuditResult` into the
machine-readable JSON artifacts and the human-readable Markdown report.

Language rule (spec section 4 / 80 / 128): SkillGuard never claims a target
is "safe" or "secure", and never claims an absence of a finding proves an
absence of the underlying behavior. Only phrasing like "no matching issue
was detected by the analyses that completed" is used here. If you are
editing this file, keep it that way.
"""

from __future__ import annotations

from skillguard.auditor import AuditResult
from skillguard.models import Evidence, Finding
from skillguard.redaction import redact_secret_like_patterns as _redact

_PROHIBITED_PHRASES = (
    "is safe",
    "is secure",
    "guaranteed safe",
    "100% safe",
    "proves secure",
    "no malicious behavior exists",
    "never writes outside",
    "proves absence",
)


def finding_to_dict(f: Finding) -> dict:
    return {
        "rule_id": f.rule_id,
        "title": f.title,
        "description": f.description,
        "severity": f.severity.value,
        "category": f.category,
        "source": f.source.value,
        "confidence": f.confidence.value,
        "recommendation": f.recommendation,
        "evidence_ids": list(f.evidence_ids),
        "file_path": f.file_path,
        "line": f.line,
        "column": f.column,
        "observed_capability": f.observed_capability,
        "declared_capability": f.declared_capability,
        "suppressed": f.suppressed,
        "suppression_reason": f.suppression_reason,
    }


def evidence_to_dict(e: Evidence) -> dict:
    return {
        "kind": e.kind.value,
        "source": e.source,
        "summary": e.summary,
        "origin": e.origin,
        "timestamp": e.timestamp,
        "details": dict(e.details),
    }


def audit_to_dict(result: AuditResult) -> dict:
    """Every target-controlled string reaching this dict is redacted here,
    at the serialization boundary -- not only inside Finding/Evidence
    (SG3-001 in docs/audits): result.target, dynamic filesystem diff
    paths, and incompleteness/failure reason strings (which can embed an
    exception message that itself contains a path, e.g. "static analysis
    failed: <PathSecurityError with a path in it>") are all
    target-controlled or target-influenced text that must not carry a
    secret-shaped substring into a persisted or machine-readable
    artifact just because it never passed through a Finding/Evidence
    object."""
    static = result.static
    dynamic = result.dynamic
    return {
        "audit_id": result.audit_id,
        "status": result.status.value,
        "target": _redact(result.target),
        "generated_at": result.generated_at,
        "skillguard_version": result.skillguard_version,
        "python_version": result.python_version,
        "platform": result.platform,
        "static": None
        if static is None
        else {
            "status": static.status.value,
            "files_scanned": static.files_scanned,
            "finding_count": len(static.findings),
            "capabilities_observed": sorted(c.value for c in static.capabilities_observed),
            "incompleteness_reasons": list(static.incompleteness_reasons),
        },
        "dynamic": None
        if dynamic is None
        else {
            "status": dynamic.status.value,
            "outcome": dynamic.command_result.outcome.value,
            "exit_code": dynamic.command_result.exit_code,
            "duration_seconds": dynamic.command_result.duration_seconds,
            "capabilities_observed": sorted(c.value for c in dynamic.capabilities_observed),
            "incompleteness_reasons": list(dynamic.incompleteness_reasons),
            "probable_canary_exposure": dynamic.probable_canary_exposure,
            "filesystem_created": [_redact(p) for p in dynamic.filesystem_diff.created],
            "filesystem_modified": [_redact(p) for p in dynamic.filesystem_diff.modified],
            "filesystem_deleted": [_redact(p) for p in dynamic.filesystem_diff.deleted],
        },
        "capabilities": {
            "declared": sorted(c.value for c in result.capability_comparison.declared),
            "observed": sorted(c.value for c in result.capability_comparison.observed),
            "undeclared_observed": sorted(
                c.value for c in result.capability_comparison.undeclared_observed
            ),
            "declared_not_observed": sorted(
                c.value for c in result.capability_comparison.declared_not_observed
            ),
            "unsupported_observation": sorted(
                c.value for c in result.capability_comparison.unsupported_observation
            ),
        },
        "policy": {
            "disposition": result.policy_result.disposition.value,
            "outcomes": [
                {
                    "rule_id": o.rule_id,
                    "action": o.action.value,
                    "triggered": o.triggered,
                    "reason": _redact(o.reason),
                    "evidence_refs": list(o.evidence_refs),
                }
                for o in result.policy_result.outcomes
            ],
        },
        "incompleteness_reasons": list(result.incompleteness_reasons),
        "failure_reasons": [_redact(r) for r in result.failure_reasons],
        "finding_count": len(result.findings),
    }


def render_markdown(result: AuditResult) -> str:
    lines: list[str] = []
    lines.append(f"# SkillGuard audit report: {result.audit_id}")
    lines.append("")
    lines.append(f"- Target: `{_redact(result.target)}`")
    lines.append(f"- Analysis status: **{result.status.value}**")
    lines.append(f"- Policy disposition: **{result.policy_result.disposition.value}**")
    lines.append(f"- Generated: {result.generated_at}")
    lines.append(
        f"- SkillGuard {result.skillguard_version}, Python {result.python_version}, {result.platform}"
    )
    lines.append("")
    lines.append(
        "> SkillGuard does not claim this target is safe or secure. Findings below reflect "
        "issues matched by the analyses that completed; absence of a finding is not evidence "
        "of absence of the underlying behavior."
    )
    lines.append("")

    if result.incompleteness_reasons:
        lines.append("## Analysis incompleteness")
        lines.append("")
        for reason in result.incompleteness_reasons:
            lines.append(f"- {reason}")
        lines.append("")

    if result.failure_reasons:
        lines.append("## Failures")
        lines.append("")
        for reason in result.failure_reasons:
            lines.append(f"- {reason}")
        lines.append("")

    lines.append("## Static findings")
    lines.append("")
    if not result.findings:
        lines.append("No matching issue was detected by the analyses that completed.")
    else:
        lines.append("| Severity | Rule | File | Line | Title | Suppressed |")
        lines.append("|---|---|---|---|---|---|")
        for f in result.findings:
            lines.append(
                f"| {f.severity.value} | {f.rule_id} | {f.file_path or ''} | {f.line or ''} | "
                f"{f.title} | {'yes' if f.suppressed else 'no'} |"
            )
    lines.append("")

    lines.append("## Capabilities")
    lines.append("")
    comp = result.capability_comparison
    lines.append(f"- Declared: {sorted(c.value for c in comp.declared) or 'none'}")
    lines.append(f"- Observed: {sorted(c.value for c in comp.observed) or 'none'}")
    lines.append(
        f"- Undeclared but observed: {sorted(c.value for c in comp.undeclared_observed) or 'none'}"
    )
    lines.append(
        f"- Declared but not observed: {sorted(c.value for c in comp.declared_not_observed) or 'none'}"
    )
    lines.append(
        "  (declared-not-observed does not mean the capability is absent -- only that no "
        "supported observation mechanism saw evidence of it in this run)"
    )
    lines.append("")

    lines.append("## Policy")
    lines.append("")
    if not result.policy_result.outcomes:
        lines.append("No policy rules were configured.")
    else:
        for o in result.policy_result.outcomes:
            mark = "TRIGGERED" if o.triggered else "clear"
            lines.append(f"- `{o.rule_id}` ({o.action.value}): {mark} -- {o.reason}")
    lines.append("")

    if result.dynamic is not None:
        d = result.dynamic
        lines.append("## Dynamic observation")
        lines.append("")
        lines.append(f"- Outcome: {d.command_result.outcome.value}")
        lines.append(f"- Exit code: {d.command_result.exit_code}")
        lines.append(f"- Duration: {d.command_result.duration_seconds:.2f}s")
        lines.append(
            f"- Filesystem: {len(d.filesystem_diff.created)} created, "
            f"{len(d.filesystem_diff.modified)} modified, {len(d.filesystem_diff.deleted)} deleted"
        )
        lines.append(f"- Network connections observed: {len(d.network_records)}")
        lines.append(f"- Probable canary exposure observed: {d.probable_canary_exposure}")
        lines.append("")

    lines.append("## Limitations")
    lines.append("")
    lines.append(
        "- Dynamic analysis executes caller-selected code and is not a sandbox. See SECURITY.md."
    )
    lines.append(
        "- Process/network observation is best-effort and polling-based; very short-lived "
        "activity between polls may not be observed."
    )
    lines.append("- Environment-variable reads are not observable at runtime in v0.1.0.")
    lines.append("")

    return "\n".join(lines)
