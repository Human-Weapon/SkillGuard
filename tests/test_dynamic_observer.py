"""End-to-end DynamicObserver tests: workspace source protection, canary
redaction, filesystem diff, local-loopback network observation, and git
observation -- all against the real production code paths."""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

from skillguard.capabilities import Capability
from skillguard.dynamic import process as process_mod
from skillguard.dynamic.observer import DynamicObserver, DynamicRunConfig
from skillguard.dynamic.runner import EnvironmentPolicy
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


class TestReparsePointsSurfacedEndToEnd:
    @pytest.mark.skipif(sys.platform != "win32", reason="Windows junction semantics")
    def test_junction_in_source_is_skipped_and_reported_not_silently_ignored(self, tmp_path):
        import subprocess

        target = tmp_path / "target"
        target.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "SECRET.txt").write_text("outside content")
        (target / "normal.py").write_text("x = 1\n")

        link = target / "escape"
        made = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(outside)],
            capture_output=True,
            text=True,
            shell=False,
        )
        if made.returncode != 0:
            pytest.skip("could not create a real junction in this environment")

        result = _run(target, [sys.executable, "-c", "print('hi')"])

        assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE
        assert "REPARSE_POINT_SKIPPED" in result.incompleteness_reasons
        assert any(e.origin == "dynamic.workspace" for e in result.evidence)


class TestSourceProtection:
    def test_original_source_is_never_modified(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        original = target / "original.txt"
        original.write_text("untouched")

        result = _run(
            target,
            [
                sys.executable,
                "-c",
                "from pathlib import Path; Path('new_in_copy.txt').write_text('copy only')",
            ],
        )
        assert original.read_text() == "untouched"
        assert not (target / "new_in_copy.txt").exists()
        # The workspace copy itself is cleaned up after the run (temp-dir
        # hygiene); what's actually load-bearing is that the write was
        # observed to have happened in the copy, not the source -- which
        # the filesystem diff proves without needing the copy to persist.
        assert "new_in_copy.txt" in result.filesystem_diff.created


class TestFilesystemObservation:
    def test_created_file_is_reported(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "seed.txt").write_text("seed")
        result = _run(
            target,
            [sys.executable, "-c", "from pathlib import Path; Path('created.txt').write_text('x')"],
        )
        assert "created.txt" in result.filesystem_diff.created
        assert Capability.FILESYSTEM_WRITE in result.capabilities_observed

    def test_no_writes_means_no_filesystem_write_capability(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "seed.txt").write_text("seed")
        result = _run(target, [sys.executable, "-c", "print('no writes here')"])
        assert result.filesystem_diff.created == ()
        assert Capability.FILESYSTEM_WRITE not in result.capabilities_observed


class TestCanaryRedaction:
    def test_canary_in_stdout_is_detected_and_redacted(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        canary = "SKILLGUARD-CANARY-abc123XYZ"
        result = _run(
            target,
            [sys.executable, str(FIXTURES / "print_canary.py"), canary],
            canaries=(canary,),
        )
        assert result.probable_canary_exposure is True
        assert canary not in result.command_result.stdout
        assert "[REDACTED:" in result.command_result.stdout

    def test_no_canary_means_no_exposure_flag(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        result = _run(
            target,
            [sys.executable, "-c", "print('nothing sensitive')"],
            canaries=("unused-canary",),
        )
        assert result.probable_canary_exposure is False


class TestProcessSpawnObservation:
    def test_child_process_yields_process_spawn_capability(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        # The child sleeps briefly so it's still alive for at least one poll
        # of the process monitor -- a child that exits instantly (e.g. `pass`)
        # can come and go between polls on fast CI runners, which would make
        # this test measure poll timing instead of the actual capability
        # detection logic.
        result = _run(
            target,
            [
                sys.executable,
                "-c",
                "import subprocess, sys; subprocess.run([sys.executable, '-c', 'import time; time.sleep(0.5)'])",
            ],
            poll_interval=0.02,
        )
        assert Capability.PROCESS_SPAWN in result.capabilities_observed


class TestNetworkObservation:
    def test_loopback_connection_is_observed(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        accepted = []

        def accept_once():
            try:
                conn, _addr = server.accept()
                conn.recv(16)
                accepted.append(True)
                conn.close()
            except OSError:
                pass

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()
        try:
            result = _run(
                target,
                [sys.executable, str(FIXTURES / "tcp_client.py"), str(port)],
                poll_interval=0.05,
                timeout=15.0,
            )
        finally:
            thread.join(timeout=5.0)
            server.close()

        assert Capability.NETWORK_OUTBOUND in result.capabilities_observed
        assert len(result.network_records) > 0


class TestGitObservation:
    def test_head_change_is_detected_as_git_write(self, tmp_path):
        pytest.importorskip("shutil")
        import shutil
        import subprocess

        if shutil.which("git") is None:
            pytest.skip("git is not installed")

        target = tmp_path / "target"
        target.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=target, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=target, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=target, check=True)
        (target / "a.txt").write_text("a")
        subprocess.run(["git", "add", "."], cwd=target, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=target, check=True)

        script = (
            "import subprocess; "
            "subprocess.run(['git', 'commit', '--allow-empty', '-q', '-m', 'second'], check=True)"
        )
        result = _run(target, [sys.executable, "-c", script])
        assert result.git_diff is not None
        assert result.git_diff.head_changed is True
        assert Capability.GIT_WRITE in result.capabilities_observed


class TestSourceIntegrityRunsOnEveryCompletionPath:
    """SG2-003: source-integrity verification must run on every dynamic
    completion path, not only the success path -- an observer/monitor
    failure must never be able to make a mutated source look
    integrity-clean by preventing verify_source_unchanged() from running.
    Each test forces a REAL mutation of the original protected source
    (not the workspace copy) via a hook on a real production seam, and a
    REAL failure of the observer/monitor named, then asserts the
    mutation is still detected (SourceMutationError raised)."""

    def test_mutation_detected_despite_process_monitor_failure(self, tmp_path, monkeypatch):
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

        def boom(self, *, timeout=10.0):
            raise RuntimeError("simulated process monitor failure")

        monkeypatch.setattr(process_mod.ProcessMonitor, "stop_and_join", boom)

        with pytest.raises(SourceMutationError):
            _run(target, [sys.executable, "-c", "print('hi')"])

    def test_mutation_detected_despite_network_monitor_failure(self, tmp_path, monkeypatch):
        import skillguard.dynamic.network as network_mod
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

        def boom(self, *, timeout=10.0):
            raise RuntimeError("simulated network monitor failure")

        monkeypatch.setattr(network_mod.NetworkMonitor, "stop_and_join", boom)

        with pytest.raises(SourceMutationError):
            _run(target, [sys.executable, "-c", "print('hi')"], observe_network=True)

    def test_mutation_detected_despite_filesystem_observer_failure(self, tmp_path, monkeypatch):
        """The 'after' FilesystemObserver.snapshot() call is NOT wrapped
        in any try/except in _run_inner -- before the SG2-003 fix, this
        exact exception would propagate straight out of DynamicObserver
        .run(), skipping verify_source_unchanged() entirely."""
        import skillguard.dynamic.observer as observer_mod
        from skillguard.errors import SourceMutationError

        target = tmp_path / "target"
        target.mkdir()
        original = target / "original.txt"
        original.write_text("untouched")

        real_snapshot = observer_mod.FilesystemObserver.snapshot
        call_count = {"n": 0}

        def flaky_snapshot(self):
            call_count["n"] += 1
            if call_count["n"] == 2:
                original.write_text("MUTATED-BY-TARGET")
                raise RuntimeError("simulated filesystem observer failure")
            return real_snapshot(self)

        monkeypatch.setattr(observer_mod.FilesystemObserver, "snapshot", flaky_snapshot)

        with pytest.raises(SourceMutationError) as exc_info:
            _run(target, [sys.executable, "-c", "print('hi')"])
        assert "simulated filesystem observer failure" in str(exc_info.value)

    def test_mutation_detected_despite_monitor_setup_failure(self, tmp_path, monkeypatch):
        """Monitor exception during SETUP (not runtime): ProcessMonitor
        .start() itself raises. This propagates through the on_pid
        callback, through CommandRunner.run() as a wrapped
        DynamicAnalysisError, and out of _run_inner entirely -- another
        path that used to skip verify_source_unchanged() completely."""
        from skillguard.errors import SourceMutationError

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
        assert "simulated monitor setup failure" in str(exc_info.value)

    def test_mutation_alone_without_any_observer_failure_still_detected(
        self, tmp_path, monkeypatch
    ):
        """Baseline: confirm the success-path behavior (already correct
        before this fix) is unchanged."""
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
        with pytest.raises(SourceMutationError):
            _run(target, [sys.executable, "-c", "print('hi')"])


class TestMonitorFailurePropagation:
    def test_process_monitor_failure_forces_incomplete_not_complete(self, tmp_path, monkeypatch):
        """Spec section 49 (letter H of the self-adversarial pass): if the
        process monitor thread dies, the run must not silently report
        COMPLETE. This drives the real DynamicObserver.run() end-to-end
        with a genuinely failing monitor, not a mock of the status field."""

        def boom(self, *, timeout=10.0):
            raise RuntimeError("simulated process monitor failure")

        monkeypatch.setattr(process_mod.ProcessMonitor, "stop_and_join", boom)

        target = tmp_path / "target"
        target.mkdir()
        result = _run(target, [sys.executable, "-c", "print('hi')"])

        assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE
        assert "MONITOR_FAILURE" in result.incompleteness_reasons
