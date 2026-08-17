"""Targeted tests for error/edge branches not exercised by the main
scenario-driven test files: type validation, byte limits, permission
errors, policy document parsing, and markdown report rendering."""

from __future__ import annotations

import pytest

from skillguard.errors import PathSecurityError, PolicyError, ValidationError
from skillguard.paths import BoundRoot, WalkLimits, is_reparse_point, walk_tree
from skillguard.policy import ConditionType, Policy, PolicyAction
from skillguard.report import render_markdown
from skillguard.static.manifests import scan_pyproject
from skillguard.static.secrets import SecretScanner


class TestPathsEdgeCases:
    def test_bind_rejects_non_path_type(self):
        with pytest.raises(ValidationError):
            BoundRoot.bind(12345)

    def test_bind_output_rejects_non_path_type(self):
        with pytest.raises(ValidationError):
            BoundRoot.bind_output(12345)

    def test_is_reparse_point_false_for_missing_path(self, tmp_path):
        assert is_reparse_point(tmp_path / "does-not-exist") is False

    def test_require_contains_raises_for_escaping_path(self, tmp_path):
        root_dir = tmp_path / "root"
        root_dir.mkdir()
        outside = tmp_path / "outside.txt"
        outside.write_text("x")
        root = BoundRoot.bind(root_dir)
        with pytest.raises(PathSecurityError):
            root.require_contains(outside)

    def test_total_byte_limit_truncates(self, tmp_path):
        for i in range(5):
            (tmp_path / f"f{i}.txt").write_bytes(b"x" * 100)
        root = BoundRoot.bind(tmp_path)
        outcome = walk_tree(
            root, WalkLimits(max_files=100, max_total_bytes=250, max_file_bytes=1000, max_depth=10)
        )
        assert "BYTE_LIMIT_REACHED" in outcome.incompleteness_reasons
        assert len(outcome.entries) < 5

    def test_unreadable_subdirectory_recorded_not_fatal(self, tmp_path, monkeypatch):
        sub = tmp_path / "locked"
        sub.mkdir()
        (tmp_path / "ok.txt").write_text("fine")

        import os as os_mod

        real_scandir = os_mod.scandir

        def flaky_scandir(path):
            if str(path) == str(sub):
                raise PermissionError("simulated permission denied")
            return real_scandir(path)

        monkeypatch.setattr(os_mod, "scandir", flaky_scandir)
        root = BoundRoot.bind(tmp_path)
        outcome = walk_tree(
            root,
            WalkLimits(max_files=100, max_total_bytes=10**6, max_file_bytes=10**6, max_depth=10),
        )
        assert "UNREADABLE_FILE" in outcome.incompleteness_reasons
        assert any(e.relative_posix == "ok.txt" for e in outcome.entries)


class TestPolicyDocumentParsing:
    def test_from_dict_parses_full_document(self):
        doc = {
            "schema_version": 1,
            "require_complete_analysis": True,
            "rules": [
                {
                    "rule_id": "r1",
                    "description": "d",
                    "action": "BLOCK",
                    "condition": {
                        "type": "CAPABILITY_OBSERVED",
                        "capabilities": ["network.outbound"],
                    },
                }
            ],
            "suppressions": [{"rule_id": "SG-X-001", "reason": "reviewed", "scope_path": "a.py"}],
        }
        policy = Policy.from_dict(doc)
        assert policy.require_complete_analysis is True
        assert policy.rules[0].action == PolicyAction.BLOCK
        assert policy.rules[0].condition.type == ConditionType.CAPABILITY_OBSERVED
        assert policy.suppressions[0].scope_path == "a.py"

    def test_from_dict_rejects_non_dict(self):
        with pytest.raises(PolicyError):
            Policy.from_dict([1, 2, 3])  # type: ignore[arg-type]

    def test_from_dict_rejects_missing_schema_version(self):
        with pytest.raises(PolicyError):
            Policy.from_dict({"rules": []})

    def test_from_dict_rejects_invalid_action(self):
        with pytest.raises(PolicyError):
            Policy.from_dict(
                {
                    "schema_version": 1,
                    "rules": [
                        {
                            "rule_id": "r1",
                            "description": "d",
                            "action": "NOT_AN_ACTION",
                            "condition": {"type": "CAPABILITY_OBSERVED"},
                        }
                    ],
                }
            )

    def test_from_dict_rejects_suppression_missing_reason(self):
        with pytest.raises(PolicyError):
            Policy.from_dict({"schema_version": 1, "suppressions": [{"rule_id": "x"}]})

    def test_wrong_schema_version_rejected_at_construction(self):
        with pytest.raises(PolicyError):
            Policy(schema_version=2)


class TestSecretScannerEntropy:
    def test_entropy_detection_when_enabled(self):
        scanner = SecretScanner(enable_entropy=True, entropy_threshold=3.0)
        result = scanner.scan_text(relative_path="a.py", text='token = "kX9mQ2pL7vN4bR8jW1zQ7"\n')
        assert any(f.rule_id == "SG-SECRET-004" for f in result.findings)

    def test_entropy_detection_disabled_by_default(self):
        scanner = SecretScanner()
        result = scanner.scan_text(relative_path="a.py", text='x = "kX9$mQ2#pL7@vN4!zzzzzzz"\n')
        assert not any(f.rule_id == "SG-SECRET-004" for f in result.findings)


class TestManifestUrlDependency:
    def test_direct_url_dependency_detected(self):
        text = '[project]\nname = "x"\nversion = "0"\ndependencies = ["pkg @ https://example.com/pkg.whl"]\n'
        result = scan_pyproject(relative_path="pyproject.toml", text=text)
        assert any(f.rule_id == "SG-MANIFEST-001" for f in result.findings)

    def test_local_path_dependency_detected(self):
        text = '[project]\nname = "x"\nversion = "0"\ndependencies = ["./vendor/pkg"]\n'
        result = scan_pyproject(relative_path="pyproject.toml", text=text)
        assert any(f.rule_id == "SG-MANIFEST-003" for f in result.findings)


class TestReportRendering:
    def test_render_markdown_full_audit_with_dynamic(self, tmp_path):
        import sys

        from skillguard.auditor import AuditConfig, SkillGuardAuditor
        from skillguard.dynamic.observer import DynamicRunConfig
        from skillguard.static.scanner import StaticScanConfig

        (tmp_path / "a.py").write_text("eval('1')\nimport socket\n")
        dynamic = DynamicRunConfig(argv=(sys.executable, "-c", "print('hi')"), timeout=15)
        config = AuditConfig(static=StaticScanConfig(), dynamic=dynamic)
        result = SkillGuardAuditor(config).audit(tmp_path)
        md = render_markdown(result)
        assert "SkillGuard audit report" in md
        assert "Dynamic observation" in md
        assert "Static findings" in md
        assert "Capabilities" in md
        assert "Policy" in md

    def test_render_markdown_no_findings_uses_honest_language(self, tmp_path):
        from skillguard.auditor import AuditConfig, SkillGuardAuditor

        (tmp_path / "a.py").write_text("x = 1\n")
        result = SkillGuardAuditor(AuditConfig()).audit(tmp_path)
        md = render_markdown(result)
        assert "no matching issue was detected" in md.lower()
        assert "does not claim this target is safe or secure" in md.lower()
