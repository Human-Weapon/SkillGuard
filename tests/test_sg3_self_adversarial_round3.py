"""Self-adversarial pass, Round 3 (third Daybreak adversarial audit
brief, section 49-equivalent list of required combinations): scenarios
explicitly named as required checks before this round can be considered
ready for a fourth audit, that were not already covered by an SG3-00x
finding's own dedicated regression file.

Each class here targets one named combination:
- redaction through the --output + --json combo (not just --json alone)
- source mutation combined with TWO simultaneous completed-run facts
  at once (not just one at a time, which the SG3-003 regressions cover)
- a legitimate U+FFFD landing at/near the output byte cap (encoding
  loss must stay False even though truncation is True)
- genuinely invalid UTF-8 surviving alongside truncation in the same
  captured stream (both flags independently True)
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from skillguard.dynamic.observer import DynamicObserver, DynamicRunConfig
from skillguard.dynamic.runner import EnvironmentPolicy, TargetOutcome
from skillguard.paths import BoundRoot

CLI = [sys.executable, "-m", "skillguard.cli"]


def _run_cli(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(CLI + args, capture_output=True, text=True, timeout=30, **kwargs)


def _run(target_dir: Path, argv: list[str], **kwargs):
    root = BoundRoot.bind(target_dir)
    config = DynamicRunConfig(
        argv=tuple(argv),
        timeout=kwargs.pop("timeout", 15.0),
        env_policy=kwargs.pop("env_policy", EnvironmentPolicy()),
        **kwargs,
    )
    return DynamicObserver(config).run(root)


def _token(suffix: str) -> str:
    return "AKIA" + suffix.ljust(16, "Z")[:16].upper()


TOKEN = _token("R3ADVERSAR1")


class TestRedactionSurvivesJsonPlusOutputCombo:
    def test_missing_target_json_and_output_together_leak_nothing(self, tmp_path):
        """A domain error (missing target) with BOTH --json and a valid
        --output directory given at once: no result files should be
        written at all (the error happens before SkillGuardAuditor.audit
        returns), and the secret-shaped target path must not leak into
        stdout, stderr, or anything written under --output."""
        missing = tmp_path / f"missing_{TOKEN}_target"
        output_dir = tmp_path / "results"
        output_dir.mkdir()

        proc = _run_cli(["scan", str(missing), "--output", str(output_dir), "--json"])

        assert proc.returncode != 0
        assert TOKEN not in proc.stdout
        assert TOKEN not in proc.stderr
        parsed = json.loads(proc.stdout)
        assert parsed["ok"] is False

        written = list(output_dir.rglob("*"))
        for path in written:
            if path.is_file():
                assert TOKEN not in path.read_text(encoding="utf-8", errors="replace")
                assert TOKEN not in path.name


class TestMutationPlusTwoSimultaneousFacts:
    def test_mutation_timeout_and_truncation_all_three_observable(self, tmp_path, monkeypatch):
        """Not just mutation-plus-one-fact (SG3-003's own regressions):
        a run that BOTH times out AND has its output truncated, with a
        source mutation discovered on top of that. All three must
        remain visible on the resulting partial_result."""
        import skillguard.dynamic.observer as observer_mod
        from skillguard.errors import SourceMutationError

        target = tmp_path / "target"
        target.mkdir()
        original = target / "original.txt"
        original.write_text("untouched")

        real_runner_run = observer_mod.CommandRunner.run

        def mutate_after_run(self, *args, **kwargs):
            result = real_runner_run(self, *args, **kwargs)
            original.write_text("MUTATED-BY-TARGET")
            return result

        monkeypatch.setattr(observer_mod.CommandRunner, "run", mutate_after_run)

        script = (
            "import sys, time; sys.stdout.write('x' * 5000); sys.stdout.flush(); time.sleep(30)"
        )
        with pytest.raises(SourceMutationError) as exc_info:
            _run(
                target,
                [sys.executable, "-c", script],
                timeout=1.0,
                max_output_bytes=100,
            )

        partial = exc_info.value.partial_result
        assert partial is not None
        assert partial.command_result.outcome == TargetOutcome.TIMED_OUT
        assert partial.command_result.stdout_truncated is True
        assert "OUTPUT_TRUNCATED" in partial.incompleteness_reasons


class TestFfdNearCapAndInvalidUtf8WithTruncationCombos:
    def test_legitimate_fffd_exactly_at_truncation_cap_not_encoding_lossy(self, tmp_path):
        """A legitimate, valid literal U+FFFD (3 bytes: EF BF BD) landing
        so the output cap truncates the stream partway through OTHER
        content but the U+FFFD itself is fully retained: truncated must
        be True, encoding_lossy must stay False (SG3-004 + SG3-003
        interaction: truncation must never be conflated with encoding
        loss even when both facts are present in the same run)."""
        target = tmp_path / "target"
        target.mkdir()
        script = (
            "import sys; "
            "sys.stdout.buffer.write(b'\\xef\\xbf\\xbd' + b'x' * 5000); "
            "sys.stdout.buffer.flush()"
        )
        result = _run(target, [sys.executable, "-c", script], max_output_bytes=10)

        assert result.command_result.stdout_truncated is True
        assert result.command_result.stdout_encoding_lossy is False
        assert "OUTPUT_TRUNCATED" in result.incompleteness_reasons
        assert "OUTPUT_ENCODING_LOSS" not in result.incompleteness_reasons

    def test_invalid_utf8_byte_survives_alongside_truncation(self, tmp_path):
        """A genuinely invalid byte early in the stream, followed by
        enough additional output to trigger truncation: both
        OUTPUT_ENCODING_LOSS and OUTPUT_TRUNCATED must be independently
        True -- one must not suppress or substitute for the other."""
        target = tmp_path / "target"
        target.mkdir()
        script = (
            "import sys; sys.stdout.buffer.write(b'\\xff' + b'y' * 5000); sys.stdout.buffer.flush()"
        )
        result = _run(target, [sys.executable, "-c", script], max_output_bytes=10)

        assert result.command_result.stdout_truncated is True
        assert result.command_result.stdout_encoding_lossy is True
        assert "OUTPUT_TRUNCATED" in result.incompleteness_reasons
        assert "OUTPUT_ENCODING_LOSS" in result.incompleteness_reasons
