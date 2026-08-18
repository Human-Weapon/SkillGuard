"""CLI tests: argv/`--` boundary safety, exit codes, and command wiring.
Calls skillguard.cli.main() in-process (no shell involved) so shell
metacharacters in test arguments are exercised as literal argv items."""

from __future__ import annotations

import json
import sys

import pytest

from skillguard import cli
from skillguard.errors import PathSecurityError


def test_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])
    assert exc_info.value.code == 0
    assert "skillguard" in capsys.readouterr().out


def test_version_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--version"])
    assert exc_info.value.code == 0


def test_rules_command_lists_rule_ids(capsys):
    code = cli.main(["rules"])
    assert code == 0
    out = capsys.readouterr().out
    assert "SG-PY-001" in out
    assert "SG-SECRET-001" in out


def test_scan_json_output_is_valid_json(tmp_path, capsys):
    (tmp_path / "a.py").write_text("eval('1')\n")
    code = cli.main(["scan", str(tmp_path), "--json"])
    assert code == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["status"] == "COMPLETE"
    assert data["finding_count"] >= 1


def test_scan_missing_target_reports_clean_error_not_traceback(tmp_path, capsys):
    missing = tmp_path / "does-not-exist"
    code = cli.main(["scan", str(missing)])
    assert code == 2
    err = capsys.readouterr().err
    assert "error:" in err
    assert "Traceback" not in err


def test_run_without_dynamic_command_is_a_clean_error(tmp_path, capsys):
    (tmp_path / "a.py").write_text("x = 1\n")
    code = cli.main(["run", str(tmp_path), "--timeout", "5"])
    assert code == 2
    err = capsys.readouterr().err
    assert "error:" in err


@pytest.mark.parametrize("dangerous_arg", ["a;b", "a|b", "a&&b", "a$(b)", "a`b`"])
def test_dash_dash_boundary_preserves_literal_argv(tmp_path, capsys, dangerous_arg):
    """Everything after `--` must reach the target process as a literal
    argv item, never interpreted by a shell."""
    (tmp_path / "a.py").write_text("x = 1\n")
    code = cli.main(
        [
            "run",
            str(tmp_path),
            "--timeout",
            "15",
            "--json",
            "--",
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1])",
            dangerous_arg,
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert out["dynamic"]["exit_code"] == 0
    assert code == 0


def test_validate_manifest_accepts_valid_document(tmp_path, capsys):
    manifest = tmp_path / "caps.json"
    manifest.write_text(json.dumps({"schema_version": 1, "capabilities": ["filesystem.read"]}))
    code = cli.main(["validate-manifest", str(manifest)])
    assert code == 0
    assert "valid" in capsys.readouterr().out


def test_validate_manifest_rejects_unknown_capability(tmp_path, capsys):
    manifest = tmp_path / "caps.json"
    manifest.write_text(
        json.dumps({"schema_version": 1, "capabilities": ["not.a.real.capability"]})
    )
    code = cli.main(["validate-manifest", str(manifest)])
    assert code == 2
    assert "error:" in capsys.readouterr().err


def test_audit_with_capabilities_and_policy_files(tmp_path, capsys):
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.py").write_text("import socket\n")
    caps_file = tmp_path / "caps.json"
    caps_file.write_text(json.dumps({"schema_version": 1, "capabilities": []}))
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "rules": [
                    {
                        "rule_id": "block-net",
                        "description": "block undeclared network",
                        "action": "BLOCK",
                        "condition": {
                            "type": "UNDECLARED_CAPABILITY_OBSERVED",
                            "capabilities": ["network.outbound"],
                        },
                    }
                ],
            }
        )
    )
    code = cli.main(
        [
            "audit",
            str(target),
            "--capabilities",
            str(caps_file),
            "--policy",
            str(policy_file),
            "--json",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert out["policy"]["disposition"] == "BLOCK"
    assert code == 3


def test_audit_dynamic_without_command_is_clean_error(tmp_path, capsys):
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.py").write_text("x = 1\n")
    code = cli.main(["audit", str(target), "--dynamic"])
    assert code == 2
    assert "error:" in capsys.readouterr().err


def test_report_missing_result_is_clean_error(tmp_path, capsys):
    output = tmp_path / "output"
    output.mkdir()
    code = cli.main(["report", str(output), "nonexistent-id"])
    assert code == 2
    err = capsys.readouterr().err
    assert "error:" in err
    assert "Traceback" not in err


def test_report_with_corrupt_audit_json_is_rejected_even_though_report_md_is_valid(
    tmp_path, capsys
):
    """save() writes audit.json/findings.json/.../report.md as separate
    atomic replacements, not one multi-file transaction, so they can go
    out of sync independently. `report` must not present report.md's
    content as if it were verified just because that one file parses --
    it must check the backing audit.json too."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.py").write_text("x = 1\n")
    output = tmp_path / "output"

    code = cli.main(["scan", str(target), "--output", str(output), "--json"])
    assert code == 0
    captured0 = capsys.readouterr()
    # SG2-005: --json stdout is pure JSON; the banner goes to stderr.
    assert "wrote results to" in captured0.err
    data = json.loads(captured0.out)
    audit_id = data["audit_id"]

    # Simulate audit.json becoming corrupt (e.g. a crash/disk issue between
    # its write and report.md's) while report.md remains intact and valid.
    audit_json = output / audit_id / "audit.json"
    assert audit_json.exists()
    report_md = output / audit_id / "report.md"
    assert report_md.exists()
    original_report = report_md.read_text(encoding="utf-8")
    audit_json.write_text("not valid json {{{", encoding="utf-8")

    code2 = cli.main(["report", str(output), audit_id])
    assert code2 == 2
    captured = capsys.readouterr()
    assert "error:" in captured.err
    assert "Traceback" not in captured.err
    # and the (now-unverifiable) report content must not have been printed
    assert original_report not in captured.out


def test_output_as_existing_file_rejected_before_dynamic_command_runs(tmp_path, capsys):
    """Spec section 111/23 (letter V of the self-adversarial pass): an
    invalid --output must be caught before a potentially expensive (and,
    for --dynamic, code-executing) audit runs at all."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.py").write_text("x = 1\n")
    bad_output = tmp_path / "not_a_directory"
    bad_output.write_text("existing file, not a directory")
    marker = tmp_path / "SHOULD_NOT_EXIST"

    code = cli.main(
        [
            "run",
            str(target),
            "--output",
            str(bad_output),
            "--timeout",
            "15",
            "--",
            sys.executable,
            "-c",
            f"from pathlib import Path; Path(r'{marker}').write_text('ran')",
        ]
    )
    assert code == 2
    assert "error:" in capsys.readouterr().err
    assert not marker.exists(), "the dynamic command ran even though --output was invalid"


def test_debug_flag_reraises_instead_of_printing_error(tmp_path):
    missing = tmp_path / "does-not-exist"
    with pytest.raises(PathSecurityError):
        cli.main(["--debug", "scan", str(missing)])


def test_scan_and_output_then_report_round_trip(tmp_path, capsys):
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.py").write_text("x = 1\n")
    output = tmp_path / "output"

    code = cli.main(["scan", str(target), "--output", str(output), "--json"])
    assert code == 0
    captured = capsys.readouterr()
    # SG2-005: --json stdout is pure JSON; the banner goes to stderr.
    assert "wrote results to" in captured.err
    data = json.loads(captured.out)
    audit_id = data["audit_id"]

    code2 = cli.main(["report", str(output), audit_id])
    assert code2 == 0
    report_out = capsys.readouterr().out
    assert "SkillGuard audit report" in report_out
