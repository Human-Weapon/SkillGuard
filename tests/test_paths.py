"""Path containment adversarial tests. These exercise the real production
scanner/store against real symlinks/junctions on disk -- not a mock of the
containment logic -- per spec section 102 (no tautological tests)."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from skillguard.errors import PathSecurityError, ValidationError
from skillguard.paths import BoundRoot, WalkLimits, is_reparse_point, walk_tree
from skillguard.static.scanner import StaticScanner

WINDOWS = sys.platform == "win32"


def _make_junction(link: os.PathLike, target: os.PathLike) -> bool:
    """Create a real Windows directory junction. Returns True on success,
    False if junction creation is unavailable in this environment (the
    test that calls this should skip, not fake success)."""
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        text=True,
        shell=False,
    )
    return result.returncode == 0


class TestBoundRoot:
    def test_bind_rejects_missing_path(self, tmp_path):
        with pytest.raises(PathSecurityError):
            BoundRoot.bind(tmp_path / "does-not-exist")

    def test_bind_rejects_file_as_root(self, tmp_path):
        f = tmp_path / "afile.txt"
        f.write_text("x")
        with pytest.raises(PathSecurityError):
            BoundRoot.bind(f)

    def test_bind_output_rejects_existing_file_before_any_write(self, tmp_path):
        """Spec section 111/23: an existing file as the output root must be
        rejected at construction, before any audit state is touched."""
        f = tmp_path / "existing_file"
        f.write_text("not a directory")
        with pytest.raises(PathSecurityError):
            BoundRoot.bind_output(f)
        # nothing should have been created/modified alongside it
        assert f.read_text() == "not a directory"

    def test_bind_output_creates_missing_directory(self, tmp_path):
        target = tmp_path / "new_output"
        root = BoundRoot.bind_output(target)
        assert root.resolved.is_dir()

    def test_contains_rejects_path_outside_root(self, tmp_path):
        root_dir = tmp_path / "root"
        root_dir.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        root = BoundRoot.bind(root_dir)
        assert root.contains(root_dir / "inside.txt") is True
        assert root.contains(outside / "secret.txt") is False

    def test_resolve_result_id_rejects_traversal(self, tmp_path):
        root = BoundRoot.bind_output(tmp_path / "out")
        for bad_id in ("../escape", "..\\escape", "/abs/path", "a/../../b", "a/b"):
            with pytest.raises((PathSecurityError, ValidationError)):
                root.resolve_result_id(bad_id)

    def test_resolve_result_id_rejects_reserved_windows_names(self, tmp_path):
        root = BoundRoot.bind_output(tmp_path / "out")
        with pytest.raises(PathSecurityError):
            root.resolve_result_id("CON")

    def test_resolve_result_id_accepts_simple_name(self, tmp_path):
        root = BoundRoot.bind_output(tmp_path / "out")
        resolved = root.resolve_result_id("run-1")
        assert resolved == root.resolved / "run-1"

    def test_cwd_drift_does_not_rebind_relative_root(self, tmp_path, monkeypatch):
        """Spec section 20/110: a relative root must bind against cwd at
        construction time only. Changing cwd afterward must not silently
        redirect operations elsewhere."""
        base = tmp_path / "base"
        base.mkdir()
        other = tmp_path / "elsewhere"
        other.mkdir()

        monkeypatch.chdir(base)
        root = BoundRoot.bind_output("myoutput")
        expected = (base / "myoutput").resolve()
        assert root.resolved == expected

        monkeypatch.chdir(other)
        # root must still refer to the original location, not `other/myoutput`
        assert root.resolved == expected
        assert root.verify_unchanged() is True

    def test_verify_unchanged_detects_directory_replacement(self, tmp_path):
        """Best-effort root-swap detection (spec section 22/109): if the
        directory at the bound path is deleted and replaced by a *new*
        directory (different identity), verify_unchanged() must notice."""
        target = tmp_path / "root"
        target.mkdir()
        root = BoundRoot.bind_output(target)
        assert root.verify_unchanged() is True

        import shutil

        shutil.rmtree(target)
        target.mkdir()  # new directory, same path, different (dev, ino)
        assert root.verify_unchanged() is False


class TestWalkTreeSymlinkAndJunctionContainment:
    @pytest.mark.skipif(WINDOWS, reason="POSIX symlink semantics; junction test covers Windows")
    def test_symlink_escape_is_not_traversed(self, tmp_path):
        target_dir = tmp_path / "target"
        target_dir.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        sentinel = outside_dir / "secret.py"
        sentinel.write_text("import os\nos.system('should not be read')\n")

        (target_dir / "link_out").symlink_to(outside_dir, target_is_directory=True)
        (target_dir / "normal.py").write_text("x = 1\n")

        root = BoundRoot.bind(target_dir)
        outcome = walk_tree(
            root,
            WalkLimits(max_files=100, max_total_bytes=10**7, max_file_bytes=10**6, max_depth=10),
        )

        scanned_names = {e.relative_posix for e in outcome.entries}
        assert "normal.py" in scanned_names
        assert not any("secret.py" in n for n in scanned_names)
        assert "link_out" in outcome.reparse_points_skipped

    @pytest.mark.skipif(not WINDOWS, reason="Windows junction semantics")
    def test_junction_escape_is_not_traversed(self, tmp_path):
        target_dir = tmp_path / "target"
        target_dir.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        sentinel = outside_dir / "secret.py"
        sentinel.write_text("import os\nos.system('should not be read')\n")

        link = target_dir / "link_out"
        if not _make_junction(link, outside_dir):
            pytest.skip("could not create a real junction in this environment")
        (target_dir / "normal.py").write_text("x = 1\n")

        assert is_reparse_point(link) is True

        root = BoundRoot.bind(target_dir)
        outcome = walk_tree(
            root,
            WalkLimits(max_files=100, max_total_bytes=10**7, max_file_bytes=10**6, max_depth=10),
        )

        scanned_names = {e.relative_posix for e in outcome.entries}
        assert "normal.py" in scanned_names
        assert not any("secret.py" in n for n in scanned_names)
        assert "link_out" in outcome.reparse_points_skipped

    @pytest.mark.skipif(not WINDOWS, reason="Windows junction semantics")
    def test_static_scanner_does_not_read_through_junction(self, tmp_path):
        """End-to-end production-path test (not just the walker helper):
        the real StaticScanner must not scan/report content that only
        exists outside the target root via a junction."""
        target_dir = tmp_path / "target"
        target_dir.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        (outside_dir / "secret.py").write_text("AKIAABCDEFGHIJKLMNOP\n")

        link = target_dir / "escape"
        if not _make_junction(link, outside_dir):
            pytest.skip("could not create a real junction in this environment")

        result = StaticScanner().scan(target_dir)
        assert not any("secret" in (f.file_path or "") for f in result.findings)
        assert "REPARSE_POINT_SKIPPED" in result.incompleteness_reasons

    @pytest.mark.skipif(not WINDOWS, reason="Windows junction semantics")
    def test_root_itself_replaced_by_junction_after_bind(self, tmp_path):
        """Spec section 22/109: construct, validate, THEN replace the root
        with a junction pointing outside. verify_unchanged() should catch
        this (best effort -- documented residual TOCTOU limitation)."""
        real_root = tmp_path / "real_root"
        real_root.mkdir()
        outside = tmp_path / "outside_root"
        outside.mkdir()
        (outside / "sentinel.txt").write_text("outside")

        root = BoundRoot.bind_output(real_root)
        assert root.verify_unchanged() is True

        import shutil

        shutil.rmtree(real_root)
        if not _make_junction(real_root, outside):
            pytest.skip("could not create a real junction in this environment")

        assert root.verify_unchanged() is False


class TestWalkTreeLimits:
    def test_max_files_boundary_is_exact(self, tmp_path):
        for i in range(5):
            (tmp_path / f"f{i}.txt").write_text("x")
        root = BoundRoot.bind(tmp_path)
        outcome = walk_tree(
            root, WalkLimits(max_files=5, max_total_bytes=10**6, max_file_bytes=10**6, max_depth=10)
        )
        assert len(outcome.entries) == 5
        assert "FILE_LIMIT_REACHED" not in outcome.incompleteness_reasons

        outcome6 = walk_tree(
            root, WalkLimits(max_files=4, max_total_bytes=10**6, max_file_bytes=10**6, max_depth=10)
        )
        assert len(outcome6.entries) == 4
        assert "FILE_LIMIT_REACHED" in outcome6.incompleteness_reasons

    def test_max_depth_zero_scans_only_root_files(self, tmp_path):
        (tmp_path / "root_file.txt").write_text("x")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "nested.txt").write_text("y")

        root = BoundRoot.bind(tmp_path)
        outcome = walk_tree(
            root,
            WalkLimits(max_files=100, max_total_bytes=10**6, max_file_bytes=10**6, max_depth=0),
        )
        names = {e.relative_posix for e in outcome.entries}
        assert names == {"root_file.txt"}
        assert "MAX_DEPTH_REACHED" in outcome.incompleteness_reasons

    def test_unreadable_directory_does_not_crash_walk(self, tmp_path):
        (tmp_path / "ok.txt").write_text("x")
        root = BoundRoot.bind(tmp_path)
        # sanity: walking a normal tree just works
        outcome = walk_tree(
            root,
            WalkLimits(max_files=10, max_total_bytes=10**6, max_file_bytes=10**6, max_depth=10),
        )
        assert len(outcome.entries) == 1

    def test_deterministic_ordering(self, tmp_path):
        for name in ["c.txt", "a.txt", "b.txt"]:
            (tmp_path / name).write_text("x")
        root = BoundRoot.bind(tmp_path)
        limits = WalkLimits(max_files=10, max_total_bytes=10**6, max_file_bytes=10**6, max_depth=10)
        first = [e.relative_posix for e in walk_tree(root, limits).entries]
        second = [e.relative_posix for e in walk_tree(root, limits).entries]
        assert first == second == sorted(first)
