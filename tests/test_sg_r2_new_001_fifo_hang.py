"""SG-R2-NEW-001 (implementer-found during Round 2 CI verification, not
part of the original audit's SG2-00X list): the SG2-001 atomic
walk+read engine (_SecureWalker/_open_entry_secure in paths.py) opens
every directory entry via os.open() to classify it from the resulting
handle's own fstat, instead of pre-classifying via os.scandir()'s
is_file()/is_dir() the way the pre-Round-2 walker did. On POSIX, opening
a FIFO (named pipe) for reading BLOCKS until some other process opens it
for writing -- standard open(2) semantics, not a target-tree defect.
Since nothing in a static/dynamic scan of an arbitrary directory ever
writes to a stray FIFO sitting in it, the walk hung indefinitely the
moment it reached one, discovered when real Ubuntu CI hung for 2+ hours
on tests/test_remediation_round1.py::test_dynamic_special_file_omission_is_incomplete
(a POSIX-only test, which is exactly why no Windows job hit it).

Fixed by opening every entry with O_NONBLOCK in addition to O_NOFOLLOW:
a no-op for regular files/directories, but for a FIFO it means open()
returns immediately instead of blocking, so classification (and the
existing SPECIAL_FILE_SKIPPED handling) can proceed normally.

These tests use a real os.mkfifo() FIFO with NO writer ever opening it
-- the exact condition that hung CI -- against the actual production
StaticScanner/DynamicWorkspace paths, with a wall-clock bound well under
what would indicate a hang."""

from __future__ import annotations

import os
import sys
import time

import pytest

from skillguard.paths import BoundRoot, WalkLimits, walk_tree
from skillguard.static.scanner import StaticScanner

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX FIFO semantics")

_MAX_ACCEPTABLE_SECONDS = 15.0


class TestFifoDoesNotHangTheWalk:
    def test_walk_tree_does_not_block_on_unopened_fifo(self, tmp_path):
        os.mkfifo(tmp_path / "fifo")
        (tmp_path / "normal.py").write_text("x = 1\n")

        started = time.monotonic()
        root = BoundRoot.bind(tmp_path)
        outcome = walk_tree(
            root,
            WalkLimits(max_files=10, max_total_bytes=10**6, max_file_bytes=10**6, max_depth=5),
        )
        elapsed = time.monotonic() - started

        assert elapsed < _MAX_ACCEPTABLE_SECONDS, f"walk_tree blocked for {elapsed:.1f}s on a FIFO"
        assert "fifo" in outcome.special_files_skipped
        assert "SPECIAL_FILE_SKIPPED" in outcome.incompleteness_reasons
        assert any(e.relative_posix == "normal.py" for e in outcome.entries)

    def test_static_scanner_does_not_block_on_unopened_fifo(self, tmp_path):
        os.mkfifo(tmp_path / "fifo")
        (tmp_path / "normal.py").write_text("x = 1\n")

        started = time.monotonic()
        result = StaticScanner().scan(tmp_path)
        elapsed = time.monotonic() - started

        assert elapsed < _MAX_ACCEPTABLE_SECONDS, f"StaticScanner blocked for {elapsed:.1f}s"
        assert "SPECIAL_FILE_SKIPPED" in result.incompleteness_reasons
        assert result.status.name == "ANALYSIS_INCOMPLETE"

    def test_dynamic_workspace_copy_does_not_block_on_unopened_fifo(self, tmp_path):
        from skillguard.dynamic.workspace import DynamicWorkspace

        os.mkfifo(tmp_path / "fifo")
        (tmp_path / "normal.py").write_text("x = 1\n")

        started = time.monotonic()
        root = BoundRoot.bind(tmp_path)
        with DynamicWorkspace(root) as ws:
            elapsed = time.monotonic() - started
            assert elapsed < _MAX_ACCEPTABLE_SECONDS, f"DynamicWorkspace blocked for {elapsed:.1f}s"
            assert (ws.path / "normal.py").exists()
            assert not (ws.path / "fifo").exists()
