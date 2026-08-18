"""Regression tests for SG3-002 (P2, third Daybreak adversarial audit):
main()'s SkillGuardError handler always printed a human "error: ..."
line to stderr regardless of --json, so a JSON-capable command
(scan/run/audit) invoked with --json produced EMPTY stdout on an
expected domain failure (missing target, invalid output root, invalid
policy, invalid dynamic argv, a runtime-start failure) -- breaking the
documented "json.loads(stdout) always succeeds in --json mode" contract
SG2-005 established for the success/policy-block/incomplete paths.

Uses the real installed CLI as a subprocess, not cli.main() in-process,
matching the audit's own reproduction and the project's established test
quality bar for this contract."""

from __future__ import annotations

import json
import subprocess
import sys

CLI = [sys.executable, "-m", "skillguard.cli"]


def _run_cli(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(CLI + args, capture_output=True, text=True, timeout=30, **kwargs)


class TestJsonErrorContractAcrossSubcommands:
    def test_scan_missing_target_json_produces_error_document(self, tmp_path):
        proc = _run_cli(["scan", str(tmp_path / "does-not-exist"), "--json"])
        assert proc.returncode != 0
        parsed = json.loads(proc.stdout)
        assert parsed["ok"] is False
        assert parsed["error"]["type"]
        assert parsed["error"]["exit_code"] == proc.returncode

    def test_scan_invalid_output_root_json_produces_error_document(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("x = 1\n")
        bad_output = tmp_path / "not_a_dir"
        bad_output.write_text("existing file, not a directory")

        proc = _run_cli(["scan", str(target), "--output", str(bad_output), "--json"])
        assert proc.returncode != 0
        parsed = json.loads(proc.stdout)
        assert parsed["ok"] is False

    def test_scan_invalid_policy_json_produces_error_document(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        bad_policy = tmp_path / "policy.json"
        bad_policy.write_text('{"schema_version": "not-an-int"}')

        proc = _run_cli(["scan", str(target), "--policy", str(bad_policy), "--json"])
        assert proc.returncode != 0
        parsed = json.loads(proc.stdout)
        assert parsed["ok"] is False

    def test_audit_invalid_capabilities_json_produces_error_document(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        bad_caps = tmp_path / "caps.json"
        bad_caps.write_text('{"not": "a valid manifest"}')

        proc = _run_cli(["audit", str(target), "--capabilities", str(bad_caps), "--json"])
        assert proc.returncode != 0
        parsed = json.loads(proc.stdout)
        assert parsed["ok"] is False

    def test_run_missing_command_after_dashdash_json_produces_error_document(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        proc = _run_cli(["run", str(target), "--json", "--timeout", "5"])
        assert proc.returncode != 0
        parsed = json.loads(proc.stdout)
        assert parsed["ok"] is False

    def test_run_invalid_working_directory_json_produces_error_document(self, tmp_path):
        proc = _run_cli(
            [
                "run",
                str(tmp_path / "no-such-target"),
                "--json",
                "--timeout",
                "5",
                "--",
                sys.executable,
                "-c",
                "print('hi')",
            ]
        )
        assert proc.returncode != 0
        parsed = json.loads(proc.stdout)
        assert parsed["ok"] is False

    def test_audit_missing_target_json_produces_error_document(self, tmp_path):
        proc = _run_cli(["audit", str(tmp_path / "missing"), "--json"])
        assert proc.returncode != 0
        parsed = json.loads(proc.stdout)
        assert parsed["ok"] is False

    def test_no_traceback_ever_appears_on_stdout_in_json_mode(self, tmp_path):
        proc = _run_cli(["scan", str(tmp_path / "missing"), "--json"])
        assert "Traceback" not in proc.stdout
        assert "Traceback" not in proc.stderr
        json.loads(proc.stdout)  # must still be pure, parseable JSON

    def test_stdout_not_empty_in_json_error_mode(self, tmp_path):
        """The exact regression the audit named: stdout must not be
        empty just because the command failed before doing any work."""
        proc = _run_cli(["scan", str(tmp_path / "missing"), "--json"])
        assert proc.stdout.strip() != ""


class TestSuccessAndPolicyPathsStillGreen:
    """Confirm the fix is additive -- the SG2-005 contract for
    success/policy-block/incomplete paths is unaffected."""

    def test_scan_success_json_still_pure_json(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("x = 1\n")
        proc = _run_cli(["scan", str(target), "--json"])
        assert proc.returncode == 0
        parsed = json.loads(proc.stdout)
        assert parsed["status"] in ("COMPLETE", "ANALYSIS_INCOMPLETE")

    def test_debug_flag_still_reraises_instead_of_json(self, tmp_path):
        proc = _run_cli(["--debug", "scan", str(tmp_path / "missing"), "--json"])
        assert proc.returncode != 0
        assert "Traceback" in proc.stderr
