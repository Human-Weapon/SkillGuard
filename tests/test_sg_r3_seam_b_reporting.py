"""Regression test for the reporting half of SG-R3 seam B (third Daybreak
adversarial audit): when a tracked descendant PID cannot be confirmed
terminated after cleanup (most plausibly because it escaped this run's
process-group/Job containment, e.g. via POSIX setsid() -- see
tests/test_sg_r3_seam_b_setsid_escape.py for the real POSIX race this
covers), the run must never silently read as COMPLETE. This is the
deterministic half of that fix: it does not depend on winning any real
OS-level race, and runs on every platform (Windows included, since the
wiring from CommandRunner.run() through DynamicObserver to
incompleteness_reasons/evidence is platform-agnostic)."""

from __future__ import annotations

import sys
from pathlib import Path

from skillguard.dynamic.observer import DynamicObserver, DynamicRunConfig
from skillguard.dynamic.runner import EnvironmentPolicy
from skillguard.models import IncompletenessReason
from skillguard.paths import BoundRoot

FIXTURES = Path(__file__).parent / "fixtures"


def _run(target_dir: Path, argv: list[str], **kwargs):
    root = BoundRoot.bind(target_dir)
    config = DynamicRunConfig(
        argv=tuple(argv),
        timeout=kwargs.pop("timeout", 15.0),
        env_policy=kwargs.pop("env_policy", EnvironmentPolicy()),
        **kwargs,
    )
    return DynamicObserver(config).run(root)


class TestUnterminatedDescendantReportedHonestly:
    def test_unterminated_descendant_pid_forces_incomplete_not_complete(
        self, tmp_path, monkeypatch
    ):
        """Force kill_pids() (via the reference CommandRunner.run() holds
        on it) to report a PID it could not confirm terminated, and
        confirm DynamicObserver surfaces PROCESS_CLEANUP_INCOMPLETE and
        matching evidence instead of letting the run read as COMPLETE."""
        import skillguard.dynamic.runner as runner_mod

        real_kill_pids = runner_mod.kill_pids

        def lying_kill_pids(pids, *, timeout=5.0):
            real_kill_pids(pids, timeout=timeout)
            return frozenset({999999})

        monkeypatch.setattr(runner_mod, "kill_pids", lying_kill_pids)

        target = tmp_path / "target"
        target.mkdir()
        result = _run(target, [sys.executable, "-c", "print('hi')"])

        assert result.command_result.unterminated_descendant_pids == (999999,)
        assert (
            IncompletenessReason.PROCESS_CLEANUP_INCOMPLETE.value in result.incompleteness_reasons
        )
        assert any("could not be confirmed terminated" in e.summary for e in result.evidence)

    def test_all_descendants_confirmed_terminated_does_not_set_the_reason(self, tmp_path):
        """Baseline: the ordinary, successful-cleanup case (already
        exercised implicitly by every other dynamic test, but asserted
        directly here) must NOT spuriously set
        PROCESS_CLEANUP_INCOMPLETE."""
        target = tmp_path / "target"
        target.mkdir()
        result = _run(target, [sys.executable, "-c", "print('hi')"])

        assert result.command_result.unterminated_descendant_pids == ()
        assert (
            IncompletenessReason.PROCESS_CLEANUP_INCOMPLETE.value
            not in result.incompleteness_reasons
        )
