"""Unit tests for the centralized redaction module, plus a documentation
sweep for prohibited absolute-safety claims (spec section 128)."""

from __future__ import annotations

from pathlib import Path

from skillguard.redaction import fingerprint, redact_details, safe_prefix, scrub_text

REPO_ROOT = Path(__file__).parent.parent

_PROHIBITED_PHRASES = (
    "is 100% safe",
    "guaranteed safe",
    "guaranteed to be safe",
    "proves secure",
    "proves this is secure",
    "no malicious behavior exists",
    "this software is secure",
)

_DOC_FILES = ["README.md", "SECURITY.md", "CHANGELOG.md", "CONTRIBUTING.md"]


class TestFingerprint:
    def test_deterministic(self):
        assert fingerprint("secret-value") == fingerprint("secret-value")

    def test_different_values_differ(self):
        assert fingerprint("a") != fingerprint("b")

    def test_short_hex(self):
        assert len(fingerprint("anything")) == 12


class TestSafePrefix:
    def test_short_value_fully_masked(self):
        assert safe_prefix("ab") == "***"

    def test_long_value_only_shows_prefix(self):
        result = safe_prefix("abcdefghijklmnop")
        assert result == "abcd***"
        assert "efgh" not in result


class TestRedactDetails:
    def test_never_contains_raw_value(self):
        secret = "sk-realistictokenvalue1234567890"
        details = redact_details(secret, kind="test_kind")
        rendered = str(dict(details))
        assert secret not in rendered
        assert details["type"] == "test_kind"


class TestScrubText:
    def test_replaces_all_occurrences(self):
        text = "before SECRET123 middle SECRET123 after"
        scrubbed, truncated = scrub_text(text, ["SECRET123"])
        assert "SECRET123" not in scrubbed
        assert scrubbed.count("[REDACTED:") == 2
        assert truncated is False

    def test_longer_secret_scrubbed_before_shorter_substring(self):
        text = "value=ABCDEF-LONG-TOKEN-XYZ"
        scrubbed, _ = scrub_text(text, ["ABCDEF-LONG-TOKEN-XYZ", "TOKEN"])
        assert "TOKEN" not in scrubbed
        assert "ABCDEF" not in scrubbed

    def test_truncation_flagged(self):
        scrubbed, truncated = scrub_text("x" * 1000, [], max_len=100)
        assert len(scrubbed) == 100
        assert truncated is True

    def test_empty_secrets_list_is_noop(self):
        scrubbed, truncated = scrub_text("hello world", [])
        assert scrubbed == "hello world"
        assert truncated is False


class TestEndToEndSecretRedaction:
    def test_secret_never_appears_in_any_persisted_artifact(self, tmp_path):
        """Spec section 79/118 (letter M of the self-adversarial pass): a
        secret detected by the static scanner must not appear in any of
        the real persisted output files written by the real ResultStore,
        not just in the in-memory Finding object."""
        import json as json_mod

        from skillguard.auditor import AuditConfig, SkillGuardAuditor
        from skillguard.persistence import ResultStore
        from skillguard.report import audit_to_dict, finding_to_dict, render_markdown

        secret_value = "AKIAABCDEFGHIJKLMNOP"
        target = tmp_path / "target"
        target.mkdir()
        (target / "leak.py").write_text(f'aws_key = "{secret_value}"\n')

        result = SkillGuardAuditor(AuditConfig()).audit(target)
        assert any(f.rule_id == "SG-SECRET-002" for f in result.findings)

        output = tmp_path / "output"
        store = ResultStore(output)
        loc = store.save(
            result.audit_id,
            audit=audit_to_dict(result),
            findings=[finding_to_dict(f) for f in result.findings],
            capabilities=audit_to_dict(result)["capabilities"],
            evidence=[],
            report_markdown=render_markdown(result),
        )

        for artifact in (loc.audit_json, loc.findings_json, loc.capabilities_json, loc.report_md):
            text = artifact.read_text(encoding="utf-8")
            assert secret_value not in text, f"raw secret leaked into {artifact}"
            if artifact.suffix == ".json":
                json_mod.loads(text)  # also prove it's still valid JSON


class TestDocumentationHonesty:
    def test_no_prohibited_absolute_safety_claims(self):
        violations = []
        for name in _DOC_FILES:
            path = REPO_ROOT / name
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8").lower()
            for phrase in _PROHIBITED_PHRASES:
                if phrase in text:
                    violations.append((name, phrase))
        assert violations == [], f"prohibited absolute-safety language found: {violations}"
