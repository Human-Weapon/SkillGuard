"""Regression tests for AB-001..AB-013 (first independent adversarial audit,
b96a65e, verdict D -- NOT RELEASE READY) and ADD-001/ADD-002 (found during
remediation). See docs/audits/first-adversarial-audit.md.

These tests deliberately exercise public production seams with real files
and real subprocesses. Races use deterministic replacement hooks (a
monkeypatched walk_tree/observer callback that performs the filesystem
replacement at the exact right moment) so they prove the production
identity/handle checks close the race rather than depending on scheduler
timing to win it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from skillguard.capabilities import CapabilityManifest, compare_capabilities
from skillguard.dynamic.filesystem import FilesystemObserver
from skillguard.dynamic.observer import DynamicObserver, DynamicRunConfig
from skillguard.dynamic.runner import CommandRunner, EnvironmentPolicy
from skillguard.dynamic.workspace import DynamicWorkspace
from skillguard.errors import (
    CorruptResultError,
    DynamicAnalysisError,
    ObservationError,
    PathSecurityError,
    PersistenceError,
    PolicyError,
    ValidationError,
)
from skillguard.models import AnalysisStatus
from skillguard.paths import BoundRoot, WalkLimits, WalkOutcome, open_walk_entry
from skillguard.paths import walk_tree as real_walk_tree
from skillguard.persistence import ResultStore, atomic_write_json, load_json_strict
from skillguard.policy import (
    ConditionType,
    Policy,
    PolicyAction,
    PolicyCondition,
    PolicyEngine,
    PolicyRule,
)
from skillguard.static.scanner import StaticScanner

WINDOWS = sys.platform == "win32"


def _make_junction(link: Path, target: Path) -> bool:
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        text=True,
        shell=False,
    )
    return result.returncode == 0


class TestManifestAndStaticReadBoundaries:
    def test_lifecycle_script_is_not_persisted_verbatim(self, tmp_path):
        token = "npm-secret-token-DO-NOT-PERSIST-123456"
        (tmp_path / "package.json").write_text('{"scripts": {"postinstall": "echo ' + token + '"}}')

        result = StaticScanner().scan(tmp_path)
        finding = next(f for f in result.findings if f.rule_id == "SG-MANIFEST-005")
        assert token not in finding.description

    def test_static_read_replacement_is_incomplete_and_does_not_scan_outside(
        self, tmp_path, monkeypatch
    ):
        target = tmp_path / "target"
        target.mkdir()
        source_file = target / "payload.py"
        source_file.write_text("x = 1\n")
        outside = tmp_path / "outside.py"
        outside.write_text("eval('OUTSIDE_SENTINEL')\n")

        import skillguard.static.scanner as scanner_mod

        def replace_after_walk(root, limits):
            outcome = real_walk_tree(root, limits)
            source_file.unlink()
            os.link(outside, source_file)
            return outcome

        monkeypatch.setattr(scanner_mod, "walk_tree", replace_after_walk)
        result = StaticScanner().scan(target)

        assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE
        assert "FILE_CHANGED_DURING_READ" in result.incompleteness_reasons
        assert all("OUTSIDE_SENTINEL" not in f.description for f in result.findings)


class TestRootAndWorkspaceBoundaries:
    @pytest.mark.skipif(WINDOWS, reason="POSIX executable-bit semantics")
    def test_copy_preserves_executable_mode(self, tmp_path):
        source = tmp_path / "source"
        source.mkdir()
        executable = source / "run.sh"
        executable.write_text("#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)

        with DynamicWorkspace(BoundRoot.bind(source)) as workspace:
            assert workspace.path.joinpath("run.sh").stat().st_mode & 0o111

    @pytest.mark.skipif(not WINDOWS, reason="requires Windows junction semantics")
    def test_root_replacement_is_reported_by_walk(self, tmp_path):
        real_root = tmp_path / "real-root"
        real_root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "outside-sentinel.py").write_text("eval('outside')\n")

        root = BoundRoot.bind(real_root)
        import shutil

        shutil.rmtree(real_root)
        if not _make_junction(real_root, outside):
            pytest.skip("could not create a real junction in this environment")

        outcome = real_walk_tree(
            root,
            WalkLimits(max_files=100, max_total_bytes=10**6, max_file_bytes=10**6, max_depth=10),
        )
        assert outcome.entries == ()
        assert "ROOT_CHANGED" in outcome.incompleteness_reasons

    def test_partial_copy_failure_removes_temporary_parent(self, tmp_path, monkeypatch):
        source = tmp_path / "source"
        source.mkdir()
        (source / "a.txt").write_text("source")
        root = BoundRoot.bind(source)

        import skillguard.dynamic.workspace as workspace_mod

        def partial_copy(_root, destination):
            destination.mkdir(parents=True)
            (destination / "leaked-secret.txt").write_text("synthetic-secret")
            raise OSError("simulated copy failure")

        monkeypatch.setattr(workspace_mod, "_safe_copy_tree", partial_copy)
        with pytest.raises(ObservationError):
            DynamicWorkspace(root, parent_dir=tmp_path)

        assert not list(tmp_path.glob("skillguard-ws-parent-*/workspace/leaked-secret.txt"))

    def test_file_replacement_during_copy_fails_closed(self, tmp_path, monkeypatch):
        source = tmp_path / "source"
        source.mkdir()
        source_file = source / "payload.txt"
        source_file.write_text("inside")
        outside = tmp_path / "outside.txt"
        outside.write_text("OUTSIDE_SENTINEL")
        root = BoundRoot.bind(source)

        import skillguard.dynamic.workspace as workspace_mod

        call_count = 0

        def replace_after_fingerprint(root_arg, limits):
            nonlocal call_count
            call_count += 1
            outcome = real_walk_tree(root_arg, limits)
            if call_count == 2:
                source_file.unlink()
                os.link(outside, source_file)
            return outcome

        monkeypatch.setattr(workspace_mod, "walk_tree", replace_after_fingerprint)
        with pytest.raises(ObservationError):
            DynamicWorkspace(root, parent_dir=tmp_path)

        assert not list(tmp_path.glob("skillguard-ws-parent-*"))

    def test_copy_and_fingerprint_limits_are_the_same_contract(self):
        import skillguard.dynamic.workspace as workspace_mod

        assert workspace_mod._FINGERPRINT_LIMITS == workspace_mod._COPY_LIMITS

    def test_result_id_validation_rejects_non_windows_forms(self, tmp_path):
        root = BoundRoot.bind_output(tmp_path / "out")
        with pytest.raises(ValidationError):
            root.resolve_result_id(None)  # type: ignore[arg-type]
        with pytest.raises(PathSecurityError):
            root.resolve_result_id("C:/absolute")
        with pytest.raises(PathSecurityError):
            root.resolve_result_id("bad<name")

    @pytest.mark.skipif(not WINDOWS, reason="Windows case-insensitive aliases")
    def test_result_id_rejects_existing_case_alias(self, tmp_path):
        root = BoundRoot.bind_output(tmp_path / "out")
        (root.resolved / "already-there").mkdir()
        with pytest.raises(PathSecurityError):
            root.resolve_result_id("ALREADY-THERE")

    def test_path_helpers_fail_closed_on_unusual_stat_results(self, tmp_path, monkeypatch):
        import skillguard.paths as paths_mod

        target = tmp_path / "target"
        target.mkdir()
        (target / "a.txt").write_text("a")
        entry = real_walk_tree(
            BoundRoot.bind(target),
            WalkLimits(max_files=10, max_total_bytes=100, max_file_bytes=100, max_depth=2),
        ).entries[0]

        monkeypatch.setattr(paths_mod.os.path, "islink", lambda _path: True)
        assert paths_mod.is_reparse_point(entry.absolute_path) is True

        monkeypatch.setattr(paths_mod.os.path, "islink", lambda _path: False)
        monkeypatch.setattr(
            paths_mod.os, "lstat", lambda _path: SimpleNamespace(st_file_attributes=None)
        )
        assert paths_mod.is_reparse_point(entry.absolute_path) is False

        monkeypatch.setattr(paths_mod.os, "stat", lambda _path: (_ for _ in ()).throw(OSError()))
        assert paths_mod._identity(entry.absolute_path) is None

    def test_bound_root_unknown_identity_is_not_verified(self, tmp_path):
        root = BoundRoot(
            label="root",
            configured=tmp_path,
            resolved=tmp_path,
            _identity_snapshot=None,
        )
        assert root.verify_unchanged() is False

    def test_open_walk_entry_rejects_replacement_and_open_failures(self, tmp_path, monkeypatch):
        import skillguard.paths as paths_mod

        target = tmp_path / "target"
        target.mkdir()
        source = target / "a.txt"
        source.write_text("a")
        entry = real_walk_tree(
            BoundRoot.bind(target),
            WalkLimits(max_files=10, max_total_bytes=100, max_file_bytes=100, max_depth=2),
        ).entries[0]

        monkeypatch.setattr(paths_mod, "is_reparse_point", lambda _path: True)
        with pytest.raises(ObservationError):
            open_walk_entry(entry)

        monkeypatch.setattr(paths_mod, "is_reparse_point", lambda _path: False)
        monkeypatch.setattr(paths_mod.os, "lstat", lambda _path: (_ for _ in ()).throw(OSError()))
        with pytest.raises(ObservationError):
            open_walk_entry(entry)

        monkeypatch.setattr(paths_mod.os, "lstat", os.lstat)
        monkeypatch.setattr(paths_mod.os, "open", lambda *_args: (_ for _ in ()).throw(OSError()))
        with pytest.raises(ObservationError):
            open_walk_entry(entry)

    def test_open_walk_entry_rejects_non_regular_handle(self, tmp_path, monkeypatch):
        import skillguard.paths as paths_mod

        target = tmp_path / "target"
        target.mkdir()
        (target / "a.txt").write_text("a")
        entry = real_walk_tree(
            BoundRoot.bind(target),
            WalkLimits(max_files=10, max_total_bytes=100, max_file_bytes=100, max_depth=2),
        ).entries[0]
        real_fstat = paths_mod.os.fstat
        monkeypatch.setattr(
            paths_mod.os,
            "fstat",
            lambda _fd: SimpleNamespace(st_mode=0, st_dev=0, st_ino=0, st_ctime_ns=0),
        )
        with pytest.raises(ObservationError):
            open_walk_entry(entry)
        monkeypatch.setattr(paths_mod.os, "fstat", real_fstat)


class TestIdentityCheckWindowsCtimeJitter:
    """SG-R1-NEW-001 (found during implementer review of the Codex export,
    not in the original AB-* findings): the first identity-checked
    open_walk_entry() implementation compared st_ctime_ns for *exact*
    equality between a walk-time os.lstat() and a later os.fstat() on the
    opened handle. On this Windows host, an ordinary, completely untouched
    file's ctime as reported by a directory-entry/lstat query and by
    fstat() on an already-opened handle can differ by roughly up to 60ms --
    observed consistently for files written via a lock-file-then-rename
    pattern (exactly how `git config` writes `.git/config`). That made
    open_walk_entry() (and therefore static reads, workspace copying, and
    content fingerprinting) fail closed on completely legitimate,
    unmodified files at a real, reproducible rate -- not a security hole,
    but a reliability defect serious enough to make normal scans flaky.

    A first fix widened `identity_matches()` itself to a multi-second
    ctime tolerance. That broke real Ubuntu CI: it also loosened
    `BoundRoot.verify_unchanged()`, whose whole job is catching a root
    directory deleted and immediately replaced (real tmpfs inode-reuse
    behavior), and a fast enough replacement now landed inside the
    tolerance window undetected. `identity_matches()` stayed exact, and a
    new `handle_identity_matches()` -- used *only* for the specific
    lstat-vs-open-handle-fstat comparison in `open_walk_entry()` -- carries
    the (much narrower, 150ms) tolerance instead. These tests prove three
    things: an ordinary file is not spuriously rejected, a real replacement
    is still caught, and the general identity comparison used for root-swap
    detection stayed exact.
    """

    def test_ordinary_file_is_stable_across_repeated_checks(self, tmp_path):
        """Regression for the flake: previously failed intermittently
        (observed roughly 40% of runs) with an exact-equality ctime
        comparison. Repeats several times because a single pass could pass
        by chance even with the old, flaky comparison."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.py").write_text("aws_key = AKIAABCDEFGHIJKLMNOP\n")

        for _ in range(10):
            entry = real_walk_tree(
                BoundRoot.bind(target),
                WalkLimits(max_files=10, max_total_bytes=1000, max_file_bytes=1000, max_depth=5),
            ).entries[0]
            with open_walk_entry(entry) as fh:
                assert fh.read().startswith(b"aws_key")

    def test_git_config_style_lock_and_rename_file_is_stable(self, tmp_path):
        """The specific scenario that surfaced the jitter: a file written
        via git's write-lockfile-then-rename pattern, read back through the
        full StaticScanner (walk -> open_walk_entry) shortly afterward."""
        import shutil

        if shutil.which("git") is None:
            pytest.skip("git is not installed")

        target = tmp_path / "target"
        target.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=target, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=target, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=target, check=True)

        from skillguard.static.scanner import StaticScanner

        for _ in range(5):
            result = StaticScanner().scan(target)
            assert "FILE_CHANGED_DURING_READ" not in result.incompleteness_reasons

    def test_real_replacement_is_still_rejected_despite_wide_ctime_tolerance(self, tmp_path):
        """The tolerance must not swallow a genuine replacement: device and
        inode still have to match exactly, so a file replaced by a
        different one (different inode) is still caught."""
        target = tmp_path / "target"
        target.mkdir()
        source_file = target / "payload.txt"
        source_file.write_text("original")
        outside = tmp_path / "outside.txt"
        outside.write_text("REPLACED_CONTENT")

        entry = real_walk_tree(
            BoundRoot.bind(target),
            WalkLimits(max_files=10, max_total_bytes=1000, max_file_bytes=1000, max_depth=5),
        ).entries[0]

        source_file.unlink()
        os.link(outside, source_file)

        with pytest.raises(ObservationError):
            open_walk_entry(entry)

    def test_identity_matches_is_exact_not_tolerant(self):
        """The general comparator (root-swap detection, filesystem-snapshot
        diffing, open_walk_entry's pre-open check) must stay exact -- this
        is what a fast Linux tmpfs inode-reuse root-swap depends on to be
        caught at all."""
        from skillguard.paths import identity_matches

        assert identity_matches((1, 2, 1_000), (1, 2, 1_000)) is True
        assert identity_matches((1, 2, 1_000), (1, 2, 1_001)) is False
        assert identity_matches((1, 2, 1_000), (9, 2, 1_000)) is False
        assert identity_matches((1, 2, 1_000), (1, 9, 1_000)) is False

    def test_handle_identity_matches_tolerates_ctime_but_not_device_or_inode(self):
        """Only the narrow, open-handle-specific comparator gets slack, and
        only on ctime -- device/inode remain exact even here."""
        from skillguard.paths import handle_identity_matches

        assert handle_identity_matches((1, 2, 1_000), (1, 2, 1_000)) is True
        assert handle_identity_matches((1, 2, 1_000), (1, 2, 1_000 + 149_000_000)) is True
        assert handle_identity_matches((1, 2, 1_000), (1, 2, 1_000 + 200_000_000)) is False
        assert handle_identity_matches((1, 2, 1_000), (9, 2, 1_000)) is False
        assert handle_identity_matches((1, 2, 1_000), (1, 9, 1_000)) is False

    def test_root_swap_detection_stays_exact_after_the_narrowed_fix(self, tmp_path):
        """The regression this whole class exists to prevent: prove the
        real Linux CI failure mode (fast delete-and-recreate at the same
        path) is still caught by the general (exact) comparator, not just
        asserted about in the abstract."""
        target = tmp_path / "root"
        target.mkdir()
        root = BoundRoot.bind_output(target)
        assert root.verify_unchanged() is True

        import shutil

        shutil.rmtree(target)
        target.mkdir()  # new directory, same path, possibly-reused inode
        assert root.verify_unchanged() is False


class TestRootChangedDuringWalk:
    def test_walk_tree_marks_root_changed_during_recursion(self, tmp_path, monkeypatch):
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.txt").write_text("a")
        root = BoundRoot.bind(target)
        states = iter((True, False))
        monkeypatch.setattr(BoundRoot, "verify_unchanged", lambda _root: next(states))
        outcome = real_walk_tree(
            root,
            WalkLimits(max_files=10, max_total_bytes=100, max_file_bytes=100, max_depth=2),
        )
        assert "ROOT_CHANGED" in outcome.incompleteness_reasons

    def test_workspace_surfaces_special_file_omissions(self, tmp_path, monkeypatch):
        import skillguard.dynamic.workspace as workspace_mod

        source = tmp_path / "source"
        source.mkdir()
        root = BoundRoot.bind(source)
        outcome = WalkOutcome(
            entries=(),
            reparse_points_skipped=(),
            unreadable_paths=(),
            special_files_skipped=("device",),
            incompleteness_reasons=("SPECIAL_FILE_SKIPPED",),
        )
        monkeypatch.setattr(workspace_mod, "walk_tree", lambda _root, _limits: outcome)
        with DynamicWorkspace(root) as workspace:
            assert "SPECIAL_FILE_SKIPPED" in workspace.incompleteness_reasons


class TestDynamicCompletenessAndLifecycle:
    @pytest.mark.skipif(WINDOWS, reason="POSIX special-file semantics")
    def test_dynamic_special_file_omission_is_incomplete(self, tmp_path):
        os.mkfifo(tmp_path / "fifo")
        result = DynamicObserver(
            DynamicRunConfig(
                argv=(sys.executable, "-c", "print('hi')"),
                timeout=15,
                observe_network=False,
                observe_git=False,
            )
        ).run(BoundRoot.bind(tmp_path))
        assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE
        assert "SPECIAL_FILE_SKIPPED" in result.incompleteness_reasons

    @pytest.mark.skipif(not WINDOWS, reason="requires Windows junction semantics")
    def test_target_created_junction_marks_dynamic_analysis_incomplete(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        outside = target / "outside"
        outside.mkdir()
        (outside / "seed.txt").write_text("seed")
        script = (
            "import subprocess; "
            "subprocess.run(['cmd', '/c', 'mklink', '/J', 'escape', 'outside'], "
            "check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)"
        )

        result = DynamicObserver(
            DynamicRunConfig(
                argv=(sys.executable, "-c", script),
                timeout=15,
                observe_network=False,
                observe_git=False,
            )
        ).run(BoundRoot.bind(target))

        assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE
        assert "REPARSE_POINT_SKIPPED" in result.incompleteness_reasons

    def test_output_truncation_marks_dynamic_analysis_incomplete(self, tmp_path):
        result = DynamicObserver(
            DynamicRunConfig(
                argv=(sys.executable, "-c", "print('x' * 100000)"),
                timeout=15,
                max_output_bytes=1000,
                observe_network=False,
                observe_git=False,
            )
        ).run(BoundRoot.bind(tmp_path))

        assert result.command_result.stdout_truncated is True
        assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE
        assert "OUTPUT_TRUNCATED" in result.incompleteness_reasons

    def test_monitor_setup_failure_kills_target_and_wraps_error(self, tmp_path):
        pid: dict[str, int] = {}

        def fail_setup(value: int) -> None:
            pid["value"] = value
            raise RuntimeError("monitor setup failed")

        with pytest.raises(DynamicAnalysisError):
            CommandRunner().run(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                cwd=tmp_path,
                timeout=15,
                env_policy=EnvironmentPolicy(),
                on_pid_available=fail_setup,
            )

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not psutil.pid_exists(pid["value"]):
                break
            time.sleep(0.1)
        assert not psutil.pid_exists(pid["value"])

    def test_dynamic_monitor_setup_rolls_back_partial_start(self, tmp_path, monkeypatch):
        import skillguard.dynamic.observer as observer_mod

        def fail_network_start(_monitor):
            raise RuntimeError("network monitor setup failed")

        monkeypatch.setattr(observer_mod.NetworkMonitor, "start", fail_network_start)
        with pytest.raises(DynamicAnalysisError):
            DynamicObserver(
                DynamicRunConfig(
                    argv=(sys.executable, "-c", "import time; time.sleep(30)"),
                    timeout=15,
                    observe_git=False,
                )
            ).run(BoundRoot.bind(tmp_path))

    def test_network_monitor_stop_failure_forces_incomplete(self, tmp_path, monkeypatch):
        import skillguard.dynamic.observer as observer_mod

        monkeypatch.setattr(observer_mod.NetworkMonitor, "start", lambda _monitor: None)

        def fail_network_stop(_monitor):
            raise RuntimeError("network monitor stop failed")

        monkeypatch.setattr(observer_mod.NetworkMonitor, "stop_and_join", fail_network_stop)
        result = DynamicObserver(
            DynamicRunConfig(
                argv=(sys.executable, "-c", "print('hi')"),
                timeout=15,
                observe_git=False,
            )
        ).run(BoundRoot.bind(tmp_path))
        assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE
        assert "MONITOR_FAILURE" in result.incompleteness_reasons

    def test_filesystem_snapshot_marks_vanished_and_replaced_entries(self, tmp_path, monkeypatch):
        import skillguard.dynamic.filesystem as filesystem_mod

        target = tmp_path / "target"
        target.mkdir()
        source = target / "a.txt"
        source.write_text("a")
        root = BoundRoot.bind(target)
        outcome = real_walk_tree(
            root,
            WalkLimits(max_files=10, max_total_bytes=100, max_file_bytes=100, max_depth=2),
        )
        observer = FilesystemObserver(scope=target)

        monkeypatch.setattr(
            filesystem_mod,
            "walk_tree",
            lambda _root, _limits: replace(
                outcome, entries=(replace(outcome.entries[0], identity=(0, 0, 0)),)
            ),
        )
        snapshot = observer.snapshot()
        assert "FILE_CHANGED_DURING_READ" in snapshot.incompleteness_reasons

        source.unlink()
        missing_outcome = replace(outcome, entries=outcome.entries)
        monkeypatch.setattr(filesystem_mod, "walk_tree", lambda _root, _limits: missing_outcome)
        missing_snapshot = observer.snapshot()
        assert "FILE_CHANGED_DURING_READ" in missing_snapshot.incompleteness_reasons

    def test_bounded_capture_handles_pipe_errors_and_invalid_utf8(self):
        import skillguard.dynamic.runner as runner_mod

        class BrokenStream:
            def read(self, _size):
                raise OSError("closed")

            def close(self):
                return None

        broken = runner_mod._BoundedStreamCapture(BrokenStream(), 10)
        broken.start()
        broken.join()
        assert broken.result() == ("", False)

        class InvalidStream:
            def __init__(self):
                self._done = False

            def read(self, _size):
                if self._done:
                    return b""
                self._done = True
                return b"\xff"

            def close(self):
                return None

        invalid = runner_mod._BoundedStreamCapture(InvalidStream(), 1)
        invalid.start()
        invalid.join()
        text, truncated = invalid.result()
        assert len(text.encode("utf-8")) <= 1
        assert truncated is False

    def test_runner_rejects_invalid_working_directory_and_start(self, tmp_path):
        with pytest.raises(ValidationError):
            CommandRunner().run(
                [sys.executable, "-c", "pass"],
                cwd=tmp_path / "missing",
                timeout=15,
                env_policy=EnvironmentPolicy(),
            )
        with pytest.raises(DynamicAnalysisError):
            CommandRunner().run(
                [str(tmp_path / "not-an-executable")],
                cwd=tmp_path,
                timeout=15,
                env_policy=EnvironmentPolicy(),
            )


class TestValidationAndPersistenceBoundaries:
    def test_invalid_utf8_is_incomplete(self, tmp_path):
        (tmp_path / "invalid.py").write_bytes(b"# invalid\n\xff\xfe\n")
        result = StaticScanner().scan(tmp_path)
        assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE
        assert "UNSUPPORTED_ENCODING" in result.incompleteness_reasons

    @pytest.mark.parametrize(
        "document",
        [
            {"schema_version": 1, "rules": [None]},
            {"schema_version": 1, "require_complete_analysis": "false"},
            {"schema_version": True},
        ],
    )
    def test_malformed_policy_is_always_policy_error(self, document):
        with pytest.raises(PolicyError):
            Policy.from_dict(document)

    def test_programmatic_policy_rejects_non_bool_completion_flag(self):
        with pytest.raises(PolicyError):
            Policy(schema_version=1, require_complete_analysis=1)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "document",
        [
            {"schema_version": 1, "rules": {}},
            {"schema_version": 1, "suppressions": {}},
            {"schema_version": 1, "suppressions": [None]},
            {"schema_version": 1, "suppressions": [{"rule_id": 1, "reason": "x"}]},
            {"schema_version": 1, "suppressions": [{"rule_id": "r", "reason": 1}]},
            {
                "schema_version": 1,
                "suppressions": [{"rule_id": "r", "reason": "x", "scope_path": 1}],
            },
        ],
    )
    def test_policy_container_and_suppression_types_are_rejected(self, document):
        with pytest.raises(PolicyError):
            Policy.from_dict(document)

    @pytest.mark.parametrize(
        "rule",
        [
            {"rule_id": 1, "description": "d", "action": "WARN", "condition": {}},
            {"rule_id": "r", "description": 1, "action": "WARN", "condition": {}},
            {"rule_id": "r", "description": "d", "action": "WARN", "condition": None},
            {
                "rule_id": "r",
                "description": "d",
                "action": "WARN",
                "condition": {"type": "CAPABILITY_OBSERVED", "capabilities": {}},
            },
            {
                "rule_id": "r",
                "description": "d",
                "action": "WARN",
                "condition": {"type": "CAPABILITY_OBSERVED", "capabilities": [None]},
            },
            {
                "rule_id": "r",
                "description": "d",
                "action": "WARN",
                "condition": {"type": "CAPABILITY_OBSERVED", "min_severity": "NOPE"},
            },
        ],
    )
    def test_policy_rule_field_types_are_rejected(self, rule):
        with pytest.raises(PolicyError):
            Policy.from_dict({"schema_version": 1, "rules": [rule]})

    def test_policy_warn_and_analysis_incomplete_conditions_have_trace(self):
        policy = Policy(
            schema_version=1,
            rules=(
                PolicyRule(
                    rule_id="warn",
                    description="warn",
                    action=PolicyAction.WARN,
                    condition=PolicyCondition(type=ConditionType.CAPABILITY_OBSERVED),
                ),
                PolicyRule(
                    rule_id="incomplete",
                    description="incomplete",
                    action=PolicyAction.WARN,
                    condition=PolicyCondition(type=ConditionType.ANALYSIS_INCOMPLETE),
                ),
            ),
        )
        comparison = compare_capabilities(declared=frozenset(), observed=frozenset())
        result = PolicyEngine().evaluate(
            policy=policy,
            findings=(),
            capability_comparison=comparison,
            analysis_status=AnalysisStatus.COMPLETE,
        )
        assert result.disposition.value == "PASS"
        assert any(
            o.reason == "checked separately via require_complete_analysis" for o in result.outcomes
        )

    @pytest.mark.parametrize(
        "document",
        [
            {"schema_version": True, "capabilities": []},
            {"schema_version": 1, "capabilities": [None]},
            {"schema_version": 1, "capabilities": [], "constraints": []},
        ],
    )
    def test_capability_manifest_types_are_rejected(self, document):
        with pytest.raises(ValidationError):
            CapabilityManifest.from_dict(document)

    def test_corrupt_sibling_artifact_is_rejected(self, tmp_path):
        store = ResultStore(tmp_path / "out")
        store.save(
            "run-1",
            audit={"audit_id": "run-1", "status": "COMPLETE"},
            findings=[],
            capabilities={},
            evidence=[],
            report_markdown="# report\n",
        )
        store.location_for("run-1").findings_json.write_text("not json")
        with pytest.raises(CorruptResultError):
            store.load("run-1")

    def test_result_id_rejects_windows_alias_forms(self, tmp_path):
        root = ResultStore(tmp_path / "out").root
        for bad_id in (".", "foo.", "foo ", "CON.txt", "NUL.log"):
            with pytest.raises(PathSecurityError):
                root.resolve_result_id(bad_id)

    def test_strict_json_rejects_nonfinite_and_invalid_utf8(self, tmp_path):
        path = tmp_path / "value.json"
        with pytest.raises(PersistenceError):
            atomic_write_json(path, {"value": float("nan")})
        with pytest.raises(PersistenceError):
            atomic_write_json(path, {"value": object()})
        path.write_text('{"value": NaN}')
        with pytest.raises(CorruptResultError):
            load_json_strict(path)
        path.write_bytes(b"\xff")
        with pytest.raises(CorruptResultError):
            load_json_strict(path)

    def test_persistence_rejects_mixed_or_invalid_artifacts(self, tmp_path):
        store = ResultStore(tmp_path / "out")
        store.save(
            "run-1",
            audit={"audit_id": "run-1", "status": "COMPLETE"},
            findings=[],
            capabilities={},
            evidence=[],
            report_markdown="# report\n",
        )
        loc = store.location_for("run-1")

        loc.report_md.write_text("tampered")
        with pytest.raises(CorruptResultError):
            store.load("run-1")

        store.save(
            "run-1",
            audit={"audit_id": "run-1", "status": "COMPLETE"},
            findings=[],
            capabilities={},
            evidence=[],
            report_markdown="# report\n",
        )
        audit = json.loads(loc.audit_json.read_text())
        audit["audit_id"] = "other"
        loc.audit_json.write_text(json.dumps(audit))
        with pytest.raises(CorruptResultError):
            store.load("run-1")

        store.save(
            "run-1",
            audit={"audit_id": "run-1", "status": "COMPLETE"},
            findings=[],
            capabilities={},
            evidence=[],
            report_markdown="# report\n",
        )
        audit = json.loads(loc.audit_json.read_text())
        audit.pop("artifact_hashes")
        loc.audit_json.write_text(json.dumps(audit))
        with pytest.raises(CorruptResultError):
            store.load("run-1")

    def test_persistence_rejects_sibling_schema_and_report_absence(self, tmp_path):
        store = ResultStore(tmp_path / "out")
        store.save(
            "run-1",
            audit={"audit_id": "run-1", "status": "COMPLETE"},
            findings=[],
            capabilities={},
            evidence=[],
            report_markdown="# report\n",
        )
        loc = store.location_for("run-1")
        loc.findings_json.write_text('{"schema_version": 999, "findings": []}')
        with pytest.raises(CorruptResultError):
            store.load("run-1")

        store.save(
            "run-1",
            audit={"audit_id": "run-1", "status": "COMPLETE"},
            findings=[],
            capabilities={},
            evidence=[],
            report_markdown="# report\n",
        )
        loc.capabilities_json.write_text('{"schema_version": 1}')
        with pytest.raises(CorruptResultError):
            store.load("run-1")

        store.save(
            "run-1",
            audit={"audit_id": "run-1", "status": "COMPLETE"},
            findings=[],
            capabilities={},
            evidence=[],
            report_markdown="# report\n",
        )
        loc.report_md.unlink()
        with pytest.raises(CorruptResultError):
            store.load("run-1")

        store.save(
            "run-1",
            audit={"audit_id": "run-1", "status": "COMPLETE"},
            findings=[{"rule_id": "missing-other-fields"}],
            capabilities={},
            evidence=[],
            report_markdown="# report\n",
        )
        with pytest.raises(CorruptResultError):
            store.load("run-1")

    def test_persistence_rejects_invalid_save_inputs_and_atomic_report_failure(
        self, tmp_path, monkeypatch
    ):
        store = ResultStore(tmp_path / "out")
        with pytest.raises(PersistenceError):
            store.save(
                "run-1",
                audit=None,  # type: ignore[arg-type]
                findings=[],
                capabilities={},
                evidence=[],
                report_markdown="",
            )
        with pytest.raises(PersistenceError):
            store.save(
                "run-1",
                audit={"audit_id": "run-1", "status": "COMPLETE"},
                findings=[],
                capabilities={},
                evidence=[],
                report_markdown=None,  # type: ignore[arg-type]
            )

        import skillguard.persistence as persistence_mod

        def fail_replace(*_args):
            raise OSError("replace failed")

        monkeypatch.setattr(persistence_mod.os, "replace", fail_replace)
        with pytest.raises(OSError):
            persistence_mod._atomic_write_text(tmp_path / "report.md", "report")
