"""Regression tests for SG3-001 (P2, third Daybreak adversarial audit):
Round 2's SG2-004 fix redacted secret-shaped path/filename content in
Finding/Evidence, but several serialization and CLI output paths never
route through those two models -- AuditResult.target, dynamic filesystem
diff paths, and CLI exception messages leaked secret-shaped substrings
verbatim into audit.json, report.md, JSON stdout, and validation-error
stderr.

Uses DISTINCT, runtime-constructed (not literal-contiguous, to avoid
tripping GitHub push-protection the way Round 2's first attempt did)
synthetic AWS-access-key-shaped tokens in: the target root's own name, a
dynamically created file, a dynamically modified file, a dynamically
deleted file, a nested directory, and an expected-domain-error path.
Exercises the real SkillGuardAuditor, audit_to_dict, render_markdown,
ResultStore, and the real CLI (installed module invocation), then
greps every artifact and stream for the raw tokens.
"""

from __future__ import annotations

import json
import subprocess
import sys

from skillguard.auditor import AuditConfig, SkillGuardAuditor
from skillguard.dynamic.observer import DynamicRunConfig
from skillguard.dynamic.runner import EnvironmentPolicy
from skillguard.persistence import ResultStore
from skillguard.report import audit_to_dict, finding_to_dict, render_markdown

CLI = [sys.executable, "-m", "skillguard.cli"]


def _token(suffix: str) -> str:
    """A synthetic, pattern-matching (not real) AWS-access-key-shaped
    token, built by concatenation so no single literal in this file's
    source matches GitHub's secret-scanning push protection."""
    return "AKIA" + suffix.ljust(16, "Z")[:16].upper()


TOKEN_ROOT = _token("ROOTNAME01")
TOKEN_CREATED = _token("CREATED002")
TOKEN_MODIFIED = _token("MODIFIED03")
TOKEN_DELETED = _token("DELETED004")
TOKEN_NESTED = _token("NESTEDDIR5")
TOKEN_ERRORPATH = _token("ERRORPATH6")

ALL_TOKENS = (
    TOKEN_ROOT,
    TOKEN_CREATED,
    TOKEN_MODIFIED,
    TOKEN_DELETED,
    TOKEN_NESTED,
    TOKEN_ERRORPATH,
)


def _assert_no_raw_tokens(haystack: str, *, context: str) -> None:
    for token in ALL_TOKENS:
        assert token not in haystack, f"raw token {token!r} leaked in {context}"


class TestFullPipelineRedaction:
    def test_target_and_dynamic_filesystem_paths_redacted_everywhere(self, tmp_path):
        target = tmp_path / f"skill_{TOKEN_ROOT}_dir"
        target.mkdir()
        nested = target / f"pkg_{TOKEN_NESTED}"
        nested.mkdir()
        (nested / "a.py").write_text("x = 1\n")
        to_modify = target / f"modify_{TOKEN_MODIFIED}.txt"
        to_modify.write_text("before")
        to_delete = target / f"delete_{TOKEN_DELETED}.txt"
        to_delete.write_text("gone soon")

        script = (
            "import pathlib;"
            f"pathlib.Path('create_{TOKEN_CREATED}.txt').write_text('new');"
            f"pathlib.Path('modify_{TOKEN_MODIFIED}.txt').write_text('after');"
            f"pathlib.Path('delete_{TOKEN_DELETED}.txt').unlink()"
        )
        dynamic_config = DynamicRunConfig(
            argv=(sys.executable, "-c", script),
            timeout=15.0,
            env_policy=EnvironmentPolicy(),
            observe_network=False,
            observe_git=False,
        )
        config = AuditConfig(dynamic=dynamic_config)
        result = SkillGuardAuditor(config).audit(target)

        assert result.dynamic is not None
        # Sanity: the real paths DID contain the tokens before redaction
        # (otherwise this test would vacuously pass).
        assert any(TOKEN_CREATED in p for p in result.dynamic.filesystem_diff.created)
        assert any(TOKEN_MODIFIED in p for p in result.dynamic.filesystem_diff.modified)
        assert any(TOKEN_DELETED in p for p in result.dynamic.filesystem_diff.deleted)

        audit_dict = audit_to_dict(result)
        markdown = render_markdown(result)
        json_blob = json.dumps(audit_dict, indent=2, sort_keys=True)

        for label, text in (
            ("audit_to_dict JSON", json_blob),
            ("render_markdown output", markdown),
        ):
            _assert_no_raw_tokens(text, context=label)

        store = ResultStore(tmp_path / "out")
        loc = store.save(
            result.audit_id,
            audit=audit_dict,
            findings=[finding_to_dict(f) for f in result.findings],
            capabilities=audit_dict["capabilities"],
            evidence=[
                {
                    "kind": e.kind.value,
                    "source": e.source,
                    "summary": e.summary,
                    "origin": e.origin,
                    "timestamp": e.timestamp,
                    "details": dict(e.details),
                }
                for e in result.evidence
            ],
            report_markdown=markdown,
        )
        for artifact_path in (
            loc.audit_json,
            loc.findings_json,
            loc.evidence_json,
            loc.capabilities_json,
            loc.report_md,
        ):
            _assert_no_raw_tokens(
                artifact_path.read_text(encoding="utf-8"), context=str(artifact_path.name)
            )

    def test_expected_domain_error_message_redacted_in_stderr_and_json(self, tmp_path):
        missing = tmp_path / f"missing_{TOKEN_ERRORPATH}_target"

        proc_stderr = subprocess.run(
            CLI + ["scan", str(missing)], capture_output=True, text=True, timeout=30
        )
        assert proc_stderr.returncode != 0
        _assert_no_raw_tokens(proc_stderr.stderr, context="human stderr")
        _assert_no_raw_tokens(proc_stderr.stdout, context="human stdout")

        proc_json = subprocess.run(
            CLI + ["scan", str(missing), "--json"], capture_output=True, text=True, timeout=30
        )
        assert proc_json.returncode != 0
        _assert_no_raw_tokens(proc_json.stdout, context="JSON stdout")
        parsed = json.loads(proc_json.stdout)
        assert parsed["ok"] is False
        assert "error" in parsed


class TestRedactionCollisionHandling:
    def test_two_different_tokens_stay_distinguishable_after_redaction(self, tmp_path):
        target_a = tmp_path / f"skill_{TOKEN_ROOT}"
        target_a.mkdir()
        target_b = tmp_path / f"skill_{TOKEN_CREATED}"
        target_b.mkdir()

        result_a = SkillGuardAuditor(AuditConfig()).audit(target_a)
        result_b = SkillGuardAuditor(AuditConfig()).audit(target_b)

        redacted_a = audit_to_dict(result_a)["target"]
        redacted_b = audit_to_dict(result_b)["target"]

        assert TOKEN_ROOT not in redacted_a
        assert TOKEN_CREATED not in redacted_b
        # Different secrets must not collapse into the same redacted
        # marker -- each carries its own fingerprint.
        assert redacted_a != redacted_b
        assert "[REDACTED:" in redacted_a
        assert "[REDACTED:" in redacted_b
