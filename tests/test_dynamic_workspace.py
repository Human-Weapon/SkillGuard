"""Real-filesystem tests for DynamicWorkspace: symlink/junction escape
containment during the copy step, and content-hash source-mutation
detection. These construct the real production DynamicWorkspace against
real symlinks/junctions/content edits -- no mocked shutil or path
resolution (spec section 14 of the pre-audit hardening pass)."""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys

import pytest

from skillguard.dynamic.workspace import DynamicWorkspace
from skillguard.errors import ObservationError, SourceMutationError
from skillguard.paths import BoundRoot

WINDOWS = sys.platform == "win32"


def _make_junction(link: os.PathLike, target: os.PathLike) -> bool:
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        text=True,
        shell=False,
    )
    return result.returncode == 0


def _read_all_copied_text(copy_dir) -> str:
    chunks = []
    for path in copy_dir.rglob("*"):
        if path.is_file():
            with contextlib.suppress(OSError):
                chunks.append(path.read_text(errors="ignore"))
    return "\n".join(chunks)


class TestOrdinaryCopy:
    def test_regular_files_are_copied(self, tmp_path):
        source = tmp_path / "source"
        source.mkdir()
        (source / "a.py").write_text("x = 1\n")
        sub = source / "sub"
        sub.mkdir()
        (sub / "b.py").write_text("y = 2\n")

        root = BoundRoot.bind(source)
        with DynamicWorkspace(root) as ws:
            assert (ws.path / "a.py").read_text() == "x = 1\n"
            assert (ws.path / "sub" / "b.py").read_text() == "y = 2\n"

    def test_original_source_untouched_by_copy(self, tmp_path):
        source = tmp_path / "source"
        source.mkdir()
        (source / "a.py").write_text("x = 1\n")
        root = BoundRoot.bind(source)
        with DynamicWorkspace(root) as ws:
            (ws.path / "a.py").write_text("mutated in copy\n")
        assert (source / "a.py").read_text() == "x = 1\n"


class TestSymlinkEscapeContainment:
    @pytest.mark.skipif(WINDOWS, reason="POSIX symlink semantics; junction test covers Windows")
    def test_posix_symlink_target_content_never_copied_into_workspace(self, tmp_path):
        source = tmp_path / "source"
        source.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        sentinel_text = "SECRET_SENTINEL_CONTENT_MUST_NOT_BE_COPIED"
        (outside / "SECRET_SENTINEL.txt").write_text(sentinel_text)

        (source / "normal.txt").write_text("ordinary content")
        (source / "outside_link").symlink_to(outside, target_is_directory=True)

        root = BoundRoot.bind(source)
        with DynamicWorkspace(root) as ws:
            assert (ws.path / "normal.txt").exists()
            assert sentinel_text not in _read_all_copied_text(ws.path)
            # the link itself must not become a live, followable link in
            # the copy either -- it must simply be absent.
            assert not (ws.path / "outside_link").exists()
            assert "outside_link" in ws.reparse_points_skipped


class TestJunctionEscapeContainment:
    @pytest.mark.skipif(not WINDOWS, reason="Windows junction semantics")
    def test_windows_junction_target_content_never_copied_into_workspace(self, tmp_path):
        source = tmp_path / "source"
        source.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        sentinel_text = "SECRET_SENTINEL_CONTENT_MUST_NOT_BE_COPIED"
        (outside / "SECRET_SENTINEL.txt").write_text(sentinel_text)

        (source / "normal.txt").write_text("ordinary content")
        link = source / "outside_junction"
        if not _make_junction(link, outside):
            pytest.skip("could not create a real junction in this environment")

        root = BoundRoot.bind(source)
        with DynamicWorkspace(root) as ws:
            assert (ws.path / "normal.txt").exists()
            assert sentinel_text not in _read_all_copied_text(ws.path)
            assert not (ws.path / "outside_junction").exists()
            assert "outside_junction" in ws.reparse_points_skipped


class TestContentIntegrityFingerprint:
    def test_unchanged_source_does_not_raise(self, tmp_path):
        source = tmp_path / "source"
        source.mkdir()
        (source / "a.py").write_text("x = 1\n")
        root = BoundRoot.bind(source)
        with DynamicWorkspace(root) as ws:
            ws.verify_source_unchanged()  # must not raise

    def test_same_size_content_edit_with_restored_mtime_is_detected(self, tmp_path):
        """The defect a metadata-only (path, size, mtime_ns) fingerprint
        cannot see: same length, same mtime, different bytes."""
        source = tmp_path / "source"
        source.mkdir()
        target_file = source / "file.bin"
        target_file.write_bytes(b"AAAAAAAA")
        original_stat = target_file.stat()

        root = BoundRoot.bind(source)
        with DynamicWorkspace(root) as ws:
            target_file.write_bytes(b"BBBBBBBB")  # same length
            os.utime(target_file, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            assert target_file.stat().st_size == original_stat.st_size
            assert target_file.stat().st_mtime_ns == original_stat.st_mtime_ns

            with pytest.raises(SourceMutationError):
                ws.verify_source_unchanged()

    def test_file_added_is_detected(self, tmp_path):
        source = tmp_path / "source"
        source.mkdir()
        (source / "a.py").write_text("x = 1\n")
        root = BoundRoot.bind(source)
        with DynamicWorkspace(root) as ws:
            (source / "new_file.py").write_text("new = True\n")
            with pytest.raises(SourceMutationError):
                ws.verify_source_unchanged()

    def test_file_deleted_is_detected(self, tmp_path):
        source = tmp_path / "source"
        source.mkdir()
        (source / "a.py").write_text("x = 1\n")
        root = BoundRoot.bind(source)
        with DynamicWorkspace(root) as ws:
            (source / "a.py").unlink()
            with pytest.raises(SourceMutationError):
                ws.verify_source_unchanged()

    def test_file_renamed_is_detected(self, tmp_path):
        source = tmp_path / "source"
        source.mkdir()
        (source / "a.py").write_text("x = 1\n")
        root = BoundRoot.bind(source)
        with DynamicWorkspace(root) as ws:
            (source / "a.py").rename(source / "renamed.py")
            with pytest.raises(SourceMutationError):
                ws.verify_source_unchanged()

    def test_resource_limit_raises_instead_of_silent_success(self, tmp_path, monkeypatch):
        """If the source tree exceeds the fingerprint's resource limits,
        construction must fail loudly -- never silently proceed with an
        incomplete fingerprint that could later report a false 'unchanged'."""
        import skillguard.dynamic.workspace as workspace_mod
        from skillguard.paths import WalkLimits

        tiny_limits = WalkLimits(
            max_files=100, max_total_bytes=10_000, max_file_bytes=5, max_depth=10
        )
        monkeypatch.setattr(workspace_mod, "_FINGERPRINT_LIMITS", tiny_limits)

        source = tmp_path / "source"
        source.mkdir()
        (source / "too_big.txt").write_text("this file is longer than five bytes")

        root = BoundRoot.bind(source)
        with pytest.raises(ObservationError):
            DynamicWorkspace(root)

    def test_copy_resource_limit_raises_instead_of_silent_truncation(self, tmp_path, monkeypatch):
        import skillguard.dynamic.workspace as workspace_mod
        from skillguard.paths import WalkLimits

        tiny_copy_limits = WalkLimits(
            max_files=1, max_total_bytes=10_000, max_file_bytes=10_000, max_depth=10
        )
        monkeypatch.setattr(workspace_mod, "_COPY_LIMITS", tiny_copy_limits)

        source = tmp_path / "source"
        source.mkdir()
        (source / "a.txt").write_text("a")
        (source / "b.txt").write_text("b")

        root = BoundRoot.bind(source)
        with pytest.raises(ObservationError):
            DynamicWorkspace(root)
