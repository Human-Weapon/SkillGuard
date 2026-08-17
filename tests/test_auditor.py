"""End-to-end SkillGuardAuditor tests: status combination, capability
comparison wiring, and target-failure vs. observer-failure distinction."""

from __future__ import annotations

import sys

from skillguard.auditor import AuditConfig, SkillGuardAuditor, combine_statuses
from skillguard.capabilities import Capability, CapabilityManifest
from skillguard.dynamic.observer import DynamicRunConfig
from skillguard.models import AnalysisStatus
from skillguard.static.scanner import StaticScanConfig


class TestCombineStatuses:
    def test_all_complete_is_complete(self):
        assert (
            combine_statuses(AnalysisStatus.COMPLETE, AnalysisStatus.COMPLETE)
            == AnalysisStatus.COMPLETE
        )

    def test_any_incomplete_dominates_complete(self):
        assert (
            combine_statuses(AnalysisStatus.COMPLETE, AnalysisStatus.ANALYSIS_INCOMPLETE)
            == AnalysisStatus.ANALYSIS_INCOMPLETE
        )

    def test_any_failed_dominates_everything(self):
        assert (
            combine_statuses(AnalysisStatus.FAILED, AnalysisStatus.COMPLETE)
            == AnalysisStatus.FAILED
        )

    def test_none_present_is_incomplete_not_complete(self):
        assert combine_statuses(None, None) == AnalysisStatus.ANALYSIS_INCOMPLETE


class TestSkillGuardAuditorStaticOnly:
    def test_audit_without_dynamic_config_skips_dynamic(self, tmp_path):
        (tmp_path / "a.py").write_text("eval('1')\n")
        result = SkillGuardAuditor(AuditConfig(static=StaticScanConfig())).audit(tmp_path)
        assert result.dynamic is None
        assert result.static is not None
        assert result.status == AnalysisStatus.COMPLETE

    def test_capability_comparison_flags_undeclared_dynamic_code(self, tmp_path):
        (tmp_path / "a.py").write_text("eval(input())\n")
        manifest = CapabilityManifest.from_dict({"schema_version": 1, "capabilities": []})
        config = AuditConfig(static=StaticScanConfig(), capability_manifest=manifest)
        result = SkillGuardAuditor(config).audit(tmp_path)
        assert Capability.DYNAMIC_CODE_EXECUTE in result.capability_comparison.undeclared_observed


class TestSkillGuardAuditorWithDynamic:
    def test_target_nonzero_exit_is_not_a_skillguard_failure(self, tmp_path):
        """A target failing (exit 1) is evidence about the target, not a
        SkillGuard failure -- spec sections 87-88."""
        (tmp_path / "a.py").write_text("x = 1\n")
        dynamic = DynamicRunConfig(
            argv=(sys.executable, "-c", "import sys; sys.exit(1)"), timeout=15
        )
        config = AuditConfig(static=StaticScanConfig(), dynamic=dynamic)
        result = SkillGuardAuditor(config).audit(tmp_path)
        assert result.status == AnalysisStatus.COMPLETE
        assert result.dynamic.command_result.exit_code == 1
        assert not result.failure_reasons

    def test_target_timeout_marks_outcome_not_failure(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n")
        dynamic = DynamicRunConfig(
            argv=(sys.executable, "-c", "import time; time.sleep(30)"), timeout=1.0
        )
        config = AuditConfig(static=StaticScanConfig(), dynamic=dynamic)
        result = SkillGuardAuditor(config).audit(tmp_path)
        assert result.dynamic.command_result.outcome.value == "TIMED_OUT"
        assert not result.failure_reasons

    def test_audit_id_is_stable_when_provided(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n")
        result = SkillGuardAuditor(AuditConfig()).audit(tmp_path, audit_id="fixed-id-123")
        assert result.audit_id == "fixed-id-123"
