"""Regression tests for SG2-004 (P2): secret-like content embedded in a
TARGET-CONTROLLED filename/path (not file content) could be persisted
raw, because AB-001's redaction only covered the specific manifest-text
spots being scanned as *content* -- a same-shaped secret moved into a
path component skipped that boundary entirely.

These use a REAL file on disk whose name contains a synthetic (fake but
pattern-matching) secret token -- not a mock of the redaction logic --
and check every persisted/user-facing artifact SkillGuard produces:
findings.json, evidence.json, report.md, and the in-memory Finding/
Evidence objects themselves (which is what feeds --json stdout too).
"""

from __future__ import annotations

import json

from skillguard.auditor import AuditConfig, SkillGuardAuditor
from skillguard.dynamic.workspace import DynamicWorkspace
from skillguard.models import Confidence, Evidence, EvidenceKind, Finding, FindingSource, Severity
from skillguard.paths import BoundRoot
from skillguard.persistence import ResultStore
from skillguard.report import audit_to_dict, finding_to_dict, render_markdown
from skillguard.static.scanner import StaticScanner

# A synthetic, pattern-matching (not real) AWS-shaped access key ID --
# matches SecretScanner's own AKIA[0-9A-Z]{16} shape so it exercises the
# exact same detection boundary a real credential would. Built by
# concatenation (not a single contiguous literal) so this test fixture
# itself doesn't trip GitHub push-protection secret scanning, which
# cannot distinguish a synthetic pattern-shaped value from a real one.
FAKE_SECRET = "AKIA" + "ABCDEFGHIJKLMNOP"


def _assert_not_present(haystack: str) -> None:
    assert FAKE_SECRET not in haystack


class TestFilenameSecretRedactionEndToEnd:
    def test_secret_like_filename_not_in_finding_file_path(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        secret_file = target / f"prefix_{FAKE_SECRET}_suffix.py"
        secret_file.write_text("import os\nos.system('whoami')\n")
        (target / "normal.py").write_text("y = 2\n")

        result = StaticScanner().scan(target)

        matching = [f for f in result.findings if f.file_path and "prefix_" in f.file_path]
        assert matching, "expected at least one finding referencing the secret-named file"
        for finding in matching:
            _assert_not_present(finding.file_path)
            _assert_not_present(finding.description)
            assert "[REDACTED:" in finding.file_path

    def test_secret_like_directory_name_not_in_finding_file_path(self, tmp_path):
        target = tmp_path / "target"
        nested = target / f"dir_{FAKE_SECRET}_name"
        nested.mkdir(parents=True)
        (nested / "inner.py").write_text("import os\nos.system('whoami')\n")

        result = StaticScanner().scan(target)

        matching = [f for f in result.findings if f.file_path and "dir_" in f.file_path]
        assert matching, "expected at least one finding referencing the secret-named directory"
        for finding in matching:
            _assert_not_present(finding.file_path)
            assert "[REDACTED:" in finding.file_path

    def test_secret_like_nested_path_not_in_finding_or_evidence(self, tmp_path):
        target = tmp_path / "target"
        deep = target / "a" / "b" / f"c_{FAKE_SECRET}"
        deep.mkdir(parents=True)
        (deep / "payload.py").write_text("import os\nos.system('x')\n")

        result = StaticScanner().scan(target)
        matching = [f for f in result.findings if f.file_path and "payload.py" in f.file_path]
        assert matching, "expected at least one finding referencing the nested secret path"
        for finding in matching:
            _assert_not_present(finding.file_path)
            assert "[REDACTED:" in finding.file_path
        for ev in result.evidence:
            _assert_not_present(ev.summary)
            _assert_not_present(ev.origin)
            for v in ev.details.values():
                if isinstance(v, str):
                    _assert_not_present(v)

    def test_secret_like_filename_not_in_persisted_artifacts(self, tmp_path):
        """Sweep audit.json/findings.json/evidence.json/report.md -- the
        actual bytes written to disk via the real SkillGuardAuditor +
        ResultStore + render_markdown path (mirrors cli.py's
        _save_and_print exactly), not just the in-memory objects."""
        target = tmp_path / "target"
        target.mkdir()
        (target / f"payload_{FAKE_SECRET}.py").write_text("import os\nos.system('rm -rf /')\n")

        result = SkillGuardAuditor(AuditConfig()).audit(target)

        store = ResultStore(tmp_path / "out")
        loc = store.save(
            result.audit_id,
            audit=audit_to_dict(result),
            findings=[finding_to_dict(f) for f in result.findings],
            capabilities=audit_to_dict(result)["capabilities"],
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
            report_markdown=render_markdown(result),
        )

        assert any(f.file_path for f in result.findings), (
            "expected at least one finding with a file_path"
        )
        assert "[REDACTED:" in loc.findings_json.read_text(encoding="utf-8")

        for artifact_path in (loc.findings_json, loc.evidence_json, loc.report_md, loc.audit_json):
            _assert_not_present(artifact_path.read_text(encoding="utf-8"))

        # Round-trip through JSON too, in case something upstream escaped
        # the marker in a way that hid a raw substring match.
        findings_raw = json.loads(loc.findings_json.read_text(encoding="utf-8"))
        _assert_not_present(json.dumps(findings_raw))
        _assert_not_present(json.dumps(audit_to_dict(result)))


class TestWorkspaceCopyReparseEvidenceRedaction:
    def test_reparse_points_skipped_paths_redacted_in_evidence_details(self, tmp_path):
        """The 'paths' detail on the workspace-reparse evidence record
        (observer.py) joins target-controlled relative paths directly --
        confirm a secret-shaped one there is also redacted."""
        import sys

        if sys.platform != "win32":
            import pytest

            pytest.skip("Windows junction semantics")
        import subprocess

        source = tmp_path / "source"
        source.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()

        link_name = f"escape_{FAKE_SECRET}"
        link = source / link_name
        made = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
            capture_output=True,
            text=True,
        )
        if made.returncode != 0:
            import pytest

            pytest.skip("could not create a real junction in this environment")

        root = BoundRoot.bind(source)
        with DynamicWorkspace(root) as ws:
            # ws.reparse_points_skipped itself is internal bookkeeping,
            # not output -- it legitimately holds the raw path (it's not
            # persisted or shown to the user directly). The point at
            # which it becomes user-facing is exactly where it gets
            # wrapped into an Evidence record, as observer.py does.
            assert any(link_name in p for p in ws.reparse_points_skipped)
            ev = Evidence(
                kind=EvidenceKind.FILESYSTEM,
                source="DynamicWorkspace",
                summary=f"symlink(s) skipped: {', '.join(ws.reparse_points_skipped)}",
                origin="dynamic.workspace",
                details={"paths": ",".join(ws.reparse_points_skipped)},
            )
            assert "[REDACTED:" in ev.summary
            assert "[REDACTED:" in ev.details["paths"]
            _assert_not_present(ev.summary)
            _assert_not_present(ev.details["paths"])


class TestRedactionPreservesDistinguishability:
    def test_two_different_secrets_get_different_fingerprints(self):
        other_secret = "AKIA" + "ZYXWVUTSRQPONMLK"
        f1 = Finding(
            rule_id="SG-TEST-001",
            title="t",
            description=f"leaked path prefix_{FAKE_SECRET}.py",
            severity=Severity.HIGH,
            category="test",
            source=FindingSource.STATIC,
            confidence=Confidence.HIGH,
            recommendation="r",
            file_path=f"prefix_{FAKE_SECRET}.py",
        )
        f2 = Finding(
            rule_id="SG-TEST-001",
            title="t",
            description=f"leaked path prefix_{other_secret}.py",
            severity=Severity.HIGH,
            category="test",
            source=FindingSource.STATIC,
            confidence=Confidence.HIGH,
            recommendation="r",
            file_path=f"prefix_{other_secret}.py",
        )
        assert f1.file_path != f2.file_path
        assert FAKE_SECRET not in f1.file_path
        assert other_secret not in f2.file_path
