"""Regression tests for SG2-005 (P2): using --json together with
--output could write a normal human "wrote results to ..." banner line
to stdout, before or around the JSON document -- corrupting the
machine-readable stream for anything doing `json.loads(stdout)`.

These invoke the REAL CLI as a subprocess (python -m skillguard.cli),
exactly as an external tool consuming SkillGuard's output would, per
the audit's required test quality bar -- not cli.main() called in
process."""

from __future__ import annotations

import json
import subprocess
import sys

CLI = [sys.executable, "-m", "skillguard.cli"]


def _run_cli(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(CLI + args, capture_output=True, text=True, timeout=30, **kwargs)


class TestJsonStdoutIsPureJson:
    def test_scan_json_with_output_stdout_is_pure_json(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("x = 1\n")
        out_dir = tmp_path / "out"

        proc = _run_cli(["scan", str(target), "--output", str(out_dir), "--json"])

        assert proc.returncode in (0, 3), proc.stderr
        parsed = json.loads(proc.stdout)  # raises if anything but pure JSON
        assert parsed["status"] in ("COMPLETE", "ANALYSIS_INCOMPLETE")
        # The banner still gets printed -- to stderr, not stdout.
        assert "wrote results to" in proc.stderr

    def test_scan_json_without_output_stdout_is_pure_json(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("x = 1\n")

        proc = _run_cli(["scan", str(target), "--json"])

        assert proc.returncode in (0, 3), proc.stderr
        json.loads(proc.stdout)

    def test_audit_json_with_output_stdout_is_pure_json(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("import socket\n")
        out_dir = tmp_path / "out"

        proc = _run_cli(["audit", str(target), "--output", str(out_dir), "--json"])

        assert proc.returncode in (0, 3), proc.stderr
        parsed = json.loads(proc.stdout)
        assert "status" in parsed
        assert "wrote results to" in proc.stderr

    def test_run_json_with_output_stdout_is_pure_json(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        out_dir = tmp_path / "out"

        proc = _run_cli(
            [
                "run",
                str(target),
                "--output",
                str(out_dir),
                "--json",
                "--timeout",
                "15",
                "--",
                sys.executable,
                "-c",
                "print('hi')",
            ]
        )

        assert proc.returncode in (0, 1), proc.stderr
        parsed = json.loads(proc.stdout)
        assert "status" in parsed
        assert "wrote results to" in proc.stderr

    def test_policy_block_json_with_output_stdout_still_pure_json(self, tmp_path):
        """A BLOCK policy disposition changes the exit code but must not
        change the "stdout is pure JSON" contract. Uses a static-only
        MIN_STATIC_SEVERITY condition against a real credential-shaped
        finding, so this runs without --dynamic."""
        target = tmp_path / "target"
        target.mkdir()
        # Synthetic, pattern-shaped (not real) credential, built by
        # concatenation so this fixture doesn't trip GitHub push-protection
        # secret scanning itself.
        fake_key = "AKIA" + "ABCDEFGHIJKLMNOP"
        (target / "a.py").write_text(f"AWS_KEY = '{fake_key}'\n")
        policy_path = tmp_path / "policy.json"
        policy_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "rules": [
                        {
                            "rule_id": "block-high-severity",
                            "description": "block any HIGH+ severity finding",
                            "condition": {
                                "type": "MIN_STATIC_SEVERITY",
                                "min_severity": "HIGH",
                            },
                            "action": "BLOCK",
                        }
                    ],
                }
            )
        )
        out_dir = tmp_path / "out"

        proc = _run_cli(
            [
                "audit",
                str(target),
                "--policy",
                str(policy_path),
                "--output",
                str(out_dir),
                "--json",
            ]
        )

        assert proc.returncode == 3, proc.stderr
        parsed = json.loads(proc.stdout)
        assert parsed["policy"]["disposition"] == "BLOCK"

    def test_invalid_config_error_does_not_corrupt_stdout(self, tmp_path):
        """A clean ValidationError (e.g. a target that does not exist)
        must not print a traceback or partial JSON to stdout -- stdout
        should be empty (or, if anything, still valid JSON), with the
        error on stderr."""
        proc = _run_cli(["scan", str(tmp_path / "does-not-exist"), "--json"])

        assert proc.returncode != 0
        assert "Traceback" not in proc.stdout
        if proc.stdout.strip():
            json.loads(proc.stdout)
        assert "error" in proc.stderr.lower() or "Traceback" not in proc.stderr


class TestNonJsonModeUnaffected:
    def test_scan_without_json_still_prints_banner_to_stdout(self, tmp_path):
        """Confirm the fix is --json-specific: the interactive
        (non-machine-readable) mode keeps printing the banner to stdout
        as before, unchanged."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("x = 1\n")
        out_dir = tmp_path / "out"

        proc = _run_cli(["scan", str(target), "--output", str(out_dir)])

        assert proc.returncode in (0, 3), proc.stderr
        assert "wrote results to" in proc.stdout
