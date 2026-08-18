"""Regression tests for SG3-003 (P2, third Daybreak adversarial audit):

DynamicObserver.run() called ws.verify_source_unchanged() and, on a
mutation, raised SourceMutationError -- discarding whatever fully-formed
DynamicResult _run_inner() had just produced. A run can complete with its
own security-relevant facts (TIMED_OUT, OUTPUT_TRUNCATED,
OUTPUT_ENCODING_LOSS, MONITOR_FAILURE) at the exact same time the source
mutation is discovered; the old code made those two facts mutually
exclusive -- whichever the caller learned about, it lost the other.

SourceMutationError now carries the completed DynamicResult as
``partial_result`` when one was produced before the mutation was
detected, and SkillGuardAuditor.audit() recovers it so the resulting
AuditResult.dynamic still exposes those facts even though the overall
audit is (correctly) forced to AnalysisStatus.FAILED by the mutation.

Each test forces a REAL mutation of the original protected source (not
the workspace copy) via the same production seam SG2-003's regressions
use (wrapping CommandRunner.run to mutate immediately after the real
call returns), combined with a REAL condition that produces the second
fact under test.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from skillguard.auditor import AuditConfig, SkillGuardAuditor
from skillguard.dynamic import process as process_mod
from skillguard.dynamic.observer import DynamicObserver, DynamicRunConfig
from skillguard.dynamic.runner import EnvironmentPolicy, TargetOutcome
from skillguard.errors import SourceMutationError
from skillguard.models import AnalysisStatus
from skillguard.paths import BoundRoot

FIXTURES = Path(__file__).parent / "fixtures"


def _run(target_dir: Path, argv: list[str], **kwargs) -> object:
    root = BoundRoot.bind(target_dir)
    config = DynamicRunConfig(
        argv=tuple(argv),
        timeout=kwargs.pop("timeout", 15.0),
        env_policy=kwargs.pop("env_policy", EnvironmentPolicy()),
        **kwargs,
    )
    return DynamicObserver(config).run(root)


def _mutate_after_real_run(observer_mod, original: Path):
    """Wrap CommandRunner.run so the mutation happens immediately after
    the REAL run completes and returned a real, fully-formed
    CommandResult -- not before, and not via a fake/short-circuited
    result -- matching the SG2-003 regression seam."""
    real_runner_run = observer_mod.CommandRunner.run

    def mutate_after_run(self, *args, **kwargs):
        result = real_runner_run(self, *args, **kwargs)
        original.write_text("MUTATED-BY-TARGET")
        return result

    return mutate_after_run


class TestMutationPlusTimeoutBothFactsSurvive:
    def test_mutation_and_timeout_both_observable_on_exception(self, tmp_path, monkeypatch):
        import skillguard.dynamic.observer as observer_mod

        target = tmp_path / "target"
        target.mkdir()
        original = target / "original.txt"
        original.write_text("untouched")

        monkeypatch.setattr(
            observer_mod.CommandRunner, "run", _mutate_after_real_run(observer_mod, original)
        )

        with pytest.raises(SourceMutationError) as exc_info:
            _run(
                target,
                [sys.executable, "-c", "import time; time.sleep(30)"],
                timeout=1.0,
            )

        partial = exc_info.value.partial_result
        assert partial is not None
        assert partial.command_result.outcome == TargetOutcome.TIMED_OUT

    def test_mutation_and_timeout_both_observable_via_auditor(self, tmp_path, monkeypatch):
        """The same scenario, but through the public SkillGuardAuditor
        API: the resulting AuditResult must stay FAILED (mutation is
        unmistakably security-relevant) while still exposing the
        completed run's own TIMED_OUT fact via .dynamic."""
        import skillguard.dynamic.observer as observer_mod

        target = tmp_path / "target"
        target.mkdir()
        original = target / "original.txt"
        original.write_text("untouched")

        monkeypatch.setattr(
            observer_mod.CommandRunner, "run", _mutate_after_real_run(observer_mod, original)
        )

        dynamic_config = DynamicRunConfig(
            argv=(sys.executable, "-c", "import time; time.sleep(30)"),
            timeout=1.0,
            env_policy=EnvironmentPolicy(),
        )
        result = SkillGuardAuditor(AuditConfig(dynamic=dynamic_config)).audit(target)

        assert result.status == AnalysisStatus.FAILED
        assert any("dynamic analysis failed" in r for r in result.failure_reasons)
        assert result.dynamic is not None
        assert result.dynamic.command_result.outcome == TargetOutcome.TIMED_OUT


class TestMutationPlusTruncationBothFactsSurvive:
    def test_mutation_and_stdout_truncation_both_observable(self, tmp_path, monkeypatch):
        import skillguard.dynamic.observer as observer_mod

        target = tmp_path / "target"
        target.mkdir()
        original = target / "original.txt"
        original.write_text("untouched")

        monkeypatch.setattr(
            observer_mod.CommandRunner, "run", _mutate_after_real_run(observer_mod, original)
        )

        with pytest.raises(SourceMutationError) as exc_info:
            _run(
                target,
                [sys.executable, "-c", "import sys; sys.stdout.write('x' * 5000)"],
                max_output_bytes=100,
            )

        partial = exc_info.value.partial_result
        assert partial is not None
        assert partial.command_result.stdout_truncated is True
        assert "OUTPUT_TRUNCATED" in partial.incompleteness_reasons

    def test_mutation_and_stderr_truncation_both_observable(self, tmp_path, monkeypatch):
        import skillguard.dynamic.observer as observer_mod

        target = tmp_path / "target"
        target.mkdir()
        original = target / "original.txt"
        original.write_text("untouched")

        monkeypatch.setattr(
            observer_mod.CommandRunner, "run", _mutate_after_real_run(observer_mod, original)
        )

        with pytest.raises(SourceMutationError) as exc_info:
            _run(
                target,
                [sys.executable, "-c", "import sys; sys.stderr.write('y' * 5000)"],
                max_output_bytes=100,
            )

        partial = exc_info.value.partial_result
        assert partial is not None
        assert partial.command_result.stderr_truncated is True
        assert "OUTPUT_TRUNCATED" in partial.incompleteness_reasons


class TestMutationPlusEncodingLossBothFactsSurvive:
    def test_mutation_and_invalid_utf8_both_observable(self, tmp_path, monkeypatch):
        import skillguard.dynamic.observer as observer_mod

        target = tmp_path / "target"
        target.mkdir()
        original = target / "original.txt"
        original.write_text("untouched")

        monkeypatch.setattr(
            observer_mod.CommandRunner, "run", _mutate_after_real_run(observer_mod, original)
        )

        with pytest.raises(SourceMutationError) as exc_info:
            _run(
                target,
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.buffer.write(b'\\xff\\xfe'); sys.stdout.buffer.flush()",
                ],
            )

        partial = exc_info.value.partial_result
        assert partial is not None
        assert partial.command_result.stdout_encoding_lossy is True
        assert "OUTPUT_ENCODING_LOSS" in partial.incompleteness_reasons


class TestMutationPlusMonitorFailureBothFactsSurvive:
    def test_mutation_and_process_monitor_failure_both_observable(self, tmp_path, monkeypatch):
        """Distinct from SG2-003's existing 'monitor failure' regressions:
        those only prove SourceMutationError is still raised. This proves
        the MONITOR_FAILURE fact captured inside _run_inner (which does
        NOT raise -- it's caught and recorded as an incompleteness
        reason/evidence, see observer.py) survives on partial_result too."""
        import skillguard.dynamic.observer as observer_mod

        target = tmp_path / "target"
        target.mkdir()
        original = target / "original.txt"
        original.write_text("untouched")

        monkeypatch.setattr(
            observer_mod.CommandRunner, "run", _mutate_after_real_run(observer_mod, original)
        )

        def boom(self, *, timeout=10.0):
            raise RuntimeError("simulated process monitor failure")

        monkeypatch.setattr(process_mod.ProcessMonitor, "stop_and_join", boom)

        with pytest.raises(SourceMutationError) as exc_info:
            _run(target, [sys.executable, "-c", "print('hi')"])

        partial = exc_info.value.partial_result
        assert partial is not None
        assert "MONITOR_FAILURE" in partial.incompleteness_reasons
        assert any("process monitor failed" in e.summary for e in partial.evidence)


class TestNoPartialResultWhenRunInnerNeverCompleted:
    def test_monitor_setup_failure_leaves_partial_result_none(self, tmp_path, monkeypatch):
        """When _run_inner itself raises (never produces a DynamicResult),
        there is nothing to attach -- partial_result must stay None, not
        a half-built or fabricated object."""
        target = tmp_path / "target"
        target.mkdir()
        original = target / "original.txt"
        original.write_text("untouched")

        def boom_start(self) -> None:
            original.write_text("MUTATED-BY-TARGET")
            raise RuntimeError("simulated monitor setup failure")

        monkeypatch.setattr(process_mod.ProcessMonitor, "start", boom_start)

        with pytest.raises(SourceMutationError) as exc_info:
            _run(target, [sys.executable, "-c", "import time; time.sleep(5)"], timeout=5.0)

        assert exc_info.value.partial_result is None


class TestCliRunExitCodeStaysNonZeroOnMutation:
    def test_run_command_exit_code_nonzero_despite_clean_target_exit(self, tmp_path, monkeypatch):
        """Even though result.dynamic is now populated with the target's
        own (clean) TargetOutcome.EXITED on a mutation-plus-otherwise-
        successful run, `skillguard run` must not report success -- the
        mutation is unmistakably security-relevant regardless of what the
        target's own process did (SG3-003)."""
        import skillguard.cli as cli_mod
        import skillguard.dynamic.observer as observer_mod

        target = tmp_path / "target"
        target.mkdir()
        original = target / "original.txt"
        original.write_text("untouched")

        monkeypatch.setattr(
            observer_mod.CommandRunner, "run", _mutate_after_real_run(observer_mod, original)
        )

        code = cli_mod.main(
            [
                "run",
                str(target),
                "--timeout",
                "15",
                "--",
                sys.executable,
                "-c",
                "print('hi')",
            ]
        )
        assert code != 0
