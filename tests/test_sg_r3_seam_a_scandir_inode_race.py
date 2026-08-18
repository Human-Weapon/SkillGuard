"""Regression test for SG-R3 seam A (third Daybreak adversarial audit):

Round 2's SG-R2-NEW-002 fix made ``_list_entries_secure()`` capture each
entry's identity "as part of listing" -- but the actual POSIX
implementation was ``raw_entries = list(os.scandir(dir_fd))`` followed by
a SEPARATE ``os.lstat(entry.name, dir_fd=dir_fd)`` call per entry, in a
second loop. That is two distinct syscalls with a real gap between them,
not one atomic operation, despite the function's own docstring claiming
otherwise. The third audit flagged this as "NOT VERIFIED": Windows
couldn't be used to probe it (the deny-write ``CreateFileW`` handle used
elsewhere blocks a real concurrent replacement outright, for unrelated
reasons), and no existing regression synchronized a replacement at this
specific internal seam -- the existing SG-R2-NEW-002 tests all swap
*after* ``_list_entries_secure()`` has already fully returned, which
proves a different (already-defended) gap, not this one.

The fix (this round) removes the separate lstat() call on POSIX
entirely: ``os.DirEntry.inode()`` returns the ``d_ino`` already present
in the same raw directory-entry record ``os.scandir()``'s underlying
``getdents64()`` call produced the name from -- CPython caches it on the
``DirEntry`` object as soon as the entry is yielded from the iterator,
before this module's code gets a chance to do anything else. There is no
longer a second syscall for an attacker to land a replacement between.

This test synchronizes a REAL hardlink-based replacement of the target
leaf file at exactly that point: it hooks the real ``os.scandir`` call
inside ``_list_entries_secure`` (not the function itself, and not a
later point after the function returns) so that the swap happens the
instant the real underlying enumeration syscall has produced its
results -- before this module's code (fixed or not) does anything
further with that data. Against the OLD code (verified via a baseline
worktree RED-proof), this ordering would have meant the deferred,
separate ``os.lstat()`` call reads the ALREADY-SWAPPED file, so the
captured "pre_open_identity" and the later atomic open's own fstat()
would agree with each other (both post-swap) and the swap would go
undetected -- the walk would silently read and report on the
outside-controlled replacement as if it were the original, legitimate
file. Against the fixed code, the identity is already captured (from
the pre-swap dirent) before the swap can happen at all, so the later
atomic open's fstat() necessarily disagrees with it, and the entry is
correctly rejected as unreadable rather than silently trusted.

POSIX-only: relies on os.link() (hardlink) and os.scandir(dir_fd);
Windows already has a structural deny-write handle defense for this
exact scenario, tested separately, and DirEntry.inode() does not carry
the same zero-syscall guarantee there (see paths.py's
_list_entries_secure docstring).
"""

from __future__ import annotations

import os
import sys

import pytest

from skillguard.models import AnalysisStatus
from skillguard.paths import BoundRoot, WalkLimits
from skillguard.paths import walk_tree as real_walk_tree
from skillguard.static.scanner import StaticScanner

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX scandir/hardlink semantics")


def _hook_swap_at_scandir_seam(monkeypatch, paths_mod, leaf_name: str, do_swap):
    """Wrap os.scandir so the swap happens the instant the REAL
    underlying enumeration syscall has produced its results for the
    directory containing ``leaf_name`` -- not before (there would be
    nothing to race against yet) and not after _list_entries_secure has
    already finished processing them (that's the already-defended,
    already-tested gap)."""
    real_scandir = os.scandir
    state = {"swapped": False}

    def wrapped_scandir(*args, **kwargs):
        entries = list(real_scandir(*args, **kwargs))
        if not state["swapped"] and any(e.name == leaf_name for e in entries):
            state["swapped"] = True
            do_swap()
        return entries

    monkeypatch.setattr(paths_mod.os, "scandir", wrapped_scandir)
    return state


class TestScandirInodeCaptureSurvivesImmediateSwap:
    def test_walk_tree_rejects_leaf_swapped_immediately_after_scandir_returns(
        self, tmp_path, monkeypatch
    ):
        import skillguard.paths as paths_mod

        source = tmp_path / "source"
        source.mkdir()
        leaf = source / "payload.txt"
        leaf.write_text("original-content")
        outside = tmp_path / "outside.txt"
        outside.write_text("OUTSIDE_SENTINEL_CONTENT")

        def do_swap():
            leaf.unlink()
            os.link(outside, leaf)

        state = _hook_swap_at_scandir_seam(monkeypatch, paths_mod, "payload.txt", do_swap)

        root = BoundRoot.bind(source)
        outcome = real_walk_tree(
            root,
            WalkLimits(max_files=10, max_total_bytes=10**6, max_file_bytes=10**6, max_depth=10),
        )

        assert state["swapped"] is True, "the hook never fired -- test setup is broken"
        assert not any(e.relative_posix == "payload.txt" for e in outcome.entries)
        assert "UNREADABLE_FILE" in outcome.incompleteness_reasons
        assert any(
            "payload.txt" in path or "identity changed" in msg
            for path, msg in outcome.unreadable_paths
        )

    def test_static_scan_never_reports_outside_content_for_swapped_leaf(
        self, tmp_path, monkeypatch
    ):
        """Same race, exercised through the real StaticScanner (the
        shared _SecureWalker engine), matching the audit's 'at minimum
        StaticScanner' requirement."""
        import skillguard.paths as paths_mod

        target = tmp_path / "target"
        target.mkdir()
        leaf = target / "payload.py"
        leaf.write_text("x = 1\n")
        outside = tmp_path / "outside.py"
        outside.write_text("eval('OUTSIDE_SENTINEL')\n")

        def do_swap():
            leaf.unlink()
            os.link(outside, leaf)

        state = _hook_swap_at_scandir_seam(monkeypatch, paths_mod, "payload.py", do_swap)

        result = StaticScanner().scan(target)

        assert state["swapped"] is True, "the hook never fired -- test setup is broken"
        assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE
        assert "UNREADABLE_FILE" in result.incompleteness_reasons
        assert all("OUTSIDE_SENTINEL" not in f.description for f in result.findings)

    def test_captured_identity_reflects_pre_swap_dirent_not_post_swap(self, tmp_path, monkeypatch):
        """Direct, low-level proof of the mechanism itself: call
        _list_entries_secure with the swap synchronized at the scandir
        seam, and confirm the returned identity is the ORIGINAL file's
        (dev, ino) -- not the replacement's -- because it was captured
        from data that already existed before the swap ran."""
        import skillguard.paths as paths_mod

        source = tmp_path / "source"
        source.mkdir()
        leaf = source / "payload.txt"
        leaf.write_text("original-content")
        outside = tmp_path / "outside.txt"
        outside.write_text("OUTSIDE_SENTINEL_CONTENT")

        original_stat = os.lstat(leaf)

        def do_swap():
            leaf.unlink()
            os.link(outside, leaf)

        state = _hook_swap_at_scandir_seam(monkeypatch, paths_mod, "payload.txt", do_swap)

        dir_fd = os.open(source, os.O_RDONLY)
        try:
            entries = paths_mod._list_entries_secure(dir_fd, source)
        finally:
            os.close(dir_fd)

        assert state["swapped"] is True
        by_name = dict(entries)
        identity = by_name["payload.txt"]
        assert identity is not None
        captured_dev, captured_ino, _ = identity
        assert (captured_dev, captured_ino) == (original_stat.st_dev, original_stat.st_ino)

        swapped_stat = os.lstat(leaf)
        assert (captured_dev, captured_ino) != (swapped_stat.st_dev, swapped_stat.st_ino)


class TestOutsideOfTargetLeafSwapKnownLimitationDocumented:
    def test_module_still_documents_toctou_as_best_effort_not_eliminated(self):
        """Guard against the docs drifting back to an overclaim: the
        module's own top-level docstring must keep stating this is a
        best-effort mitigation, not a race-free guarantee (spec
        requirement: never overclaim race-free/sandbox guarantees)."""
        import skillguard.paths as paths_mod

        assert paths_mod.__doc__ is not None
        assert "best-effort" in paths_mod.__doc__
        assert "cannot eliminate" in paths_mod.__doc__ or "does not close it" in paths_mod.__doc__
