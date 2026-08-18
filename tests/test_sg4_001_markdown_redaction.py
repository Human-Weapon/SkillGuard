"""RED/GREEN regression for SG4-001: Markdown is an independent output boundary."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import replace

from skillguard.auditor import AuditConfig, SkillGuardAuditor
from skillguard.persistence import ResultStore
from skillguard.policy import PolicyAction, PolicyResult, PolicyRuleOutcome
from skillguard.report import audit_to_dict, finding_to_dict, render_markdown


def _token(suffix: str) -> str:
    return "AKIA" + suffix.ljust(16, "Z")[:16].upper()


def test_markdown_redacts_failure_and_policy_reasons_end_to_end(tmp_path):
    failure_token = _token("FAILURE")
    policy_token = _token("POLICY")
    target = tmp_path / "target"
    target.mkdir()

    baseline = SkillGuardAuditor(AuditConfig()).audit(target, audit_id="sg4-001")
    policy_outcome = PolicyRuleOutcome(
        rule_id="probe",
        action=PolicyAction.BLOCK,
        triggered=True,
        reason=f"denied path /tmp/{policy_token}/payload",
    )
    result = replace(
        baseline,
        failure_reasons=(f"failed path /tmp/{failure_token}/payload",),
        policy_result=PolicyResult(
            disposition=baseline.policy_result.disposition,
            outcomes=(policy_outcome,),
            analysis_status=baseline.policy_result.analysis_status,
        ),
    )

    markdown = render_markdown(result)
    assert failure_token not in markdown
    assert policy_token not in markdown
    assert markdown.count("[REDACTED:") >= 2

    audit = audit_to_dict(result)
    store = ResultStore(tmp_path / "results")
    location = store.save(
        result.audit_id,
        audit=audit,
        findings=[finding_to_dict(f) for f in result.findings],
        capabilities=audit["capabilities"],
        evidence=[],
        report_markdown=markdown,
    )
    persisted = location.report_md.read_text(encoding="utf-8")
    assert failure_token not in persisted
    assert policy_token not in persisted

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "skillguard.cli",
            "report",
            str(store.root.resolved),
            result.audit_id,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0
    assert failure_token not in proc.stdout
    assert policy_token not in proc.stdout
