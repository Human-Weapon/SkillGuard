"""RED/GREEN regression for SG4-002: successful persistence banners are output too."""

from __future__ import annotations

import json
import subprocess
import sys


def _token(suffix: str) -> str:
    return "AKIA" + suffix.ljust(16, "Z")[:16].upper()


def test_successful_output_banner_redacts_path_in_human_and_json_modes(tmp_path):
    token = _token("OUTPUT")
    target = tmp_path / "target"
    target.mkdir()
    (target / "safe.py").write_text("x = 1\n", encoding="utf-8")

    human_output = tmp_path / f"human_{token}"
    human = subprocess.run(
        [
            sys.executable,
            "-m",
            "skillguard.cli",
            "scan",
            str(target),
            "--output",
            str(human_output),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert human.returncode == 0
    assert token not in human.stdout
    assert token not in human.stderr
    assert "[REDACTED:" in human.stdout

    json_output = tmp_path / f"json_{token}"
    machine = subprocess.run(
        [
            sys.executable,
            "-m",
            "skillguard.cli",
            "scan",
            str(target),
            "--output",
            str(json_output),
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert machine.returncode == 0
    json.loads(machine.stdout)
    assert token not in machine.stdout
    assert token not in machine.stderr
    assert "[REDACTED:" in machine.stderr
