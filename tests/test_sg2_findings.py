"""Regression tests for the second independent Codex audit round
(SkillGuard v0.1.0 Remediation Round 2). See docs/audits/second-adversarial-audit.md.

SG2-001 (P1): an ancestor directory inside a bound root could be replaced
by a real junction/symlink *during* a walk -- after the parent's
enumeration accepted it as an ordinary subdirectory but before that
subdirectory's own contents were listed -- causing StaticScanner /
DynamicWorkspace to silently read/copy/fingerprint out-of-tree content
while reporting COMPLETE. These tests exercise the real production
seam (real NTFS junctions on Windows, real symlinks on POSIX) at
multiple ancestor depths, not a mock of the containment logic.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys

import pytest

import skillguard.paths as paths_mod
from skillguard.dynamic.workspace import DynamicWorkspace
from skillguard.errors import ObservationError
from skillguard.paths import BoundRoot, WalkLimits, walk_tree
from skillguard.static.scanner import StaticScanner

WINDOWS = sys.platform == "win32"
SENTINEL_CONTENT = "SECRET_SENTINEL = 'sg2-001-outside-bytes'\n"


def _make_junction(link: os.PathLike, target: os.PathLike) -> bool:
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        text=True,
        shell=False,
    )
    return result.returncode == 0


def _replace_dir_with_link(link_path, target_path) -> bool:
    """Real ancestor replacement: an actual NTFS junction on Windows, an
    actual symlink on POSIX. Returns False (caller should skip) if the
    platform primitive is unavailable in this environment."""
    shutil.rmtree(link_path)
    if WINDOWS:
        return _make_junction(link_path, target_path)
    link_path.symlink_to(target_path, target_is_directory=True)
    return True


def _hook_swap_before_listing(monkeypatch, ancestor_path, target_path, outside_path):
    """Install the deterministic mid-walk attack hook used throughout this
    file: swap `ancestor_path` (named `target_path`, its own final path
    component) for a real link to `outside_path` at exactly the seam the
    auditor's required reproduction describes: "after the path has been
    initially accepted/enumerated [by its parent's directory listing]
    but before the later read/copy seam [the atomic open of that
    specific entry]". Hooking any later than this (e.g. after the
    walker has already opened its own handle to `ancestor_path`) is not
    a meaningful test on Windows -- that handle's deny-delete sharing
    would block the attacker's own replacement attempt, which is a
    *result* of the fix, not a gap in testing it. Returns a dict the
    caller can inspect for whether the swap actually fired/succeeded."""
    real_open_entry_secure = paths_mod._open_entry_secure
    ancestor_name = ancestor_path.name
    state = {"attempted": False, "swapped": False}

    def hook(name, dir_fd, dir_path):
        if (
            not state["attempted"]
            and name == ancestor_name
            and os.path.normcase(str(dir_path / name)) == os.path.normcase(str(target_path))
        ):
            state["attempted"] = True
            state["swapped"] = _replace_dir_with_link(ancestor_path, outside_path)
        return real_open_entry_secure(name, dir_fd, dir_path)

    monkeypatch.setattr(paths_mod, "_open_entry_secure", hook)
    return state


class TestAncestorSwapDuringStaticScan:
    @pytest.mark.parametrize("depth", [1, 2, 3])
    def test_ancestor_swap_mid_walk_not_scanned_and_not_complete(
        self, tmp_path, monkeypatch, depth
    ):
        root_dir = tmp_path / "ROOT"
        current = root_dir
        for i in range(depth - 1):
            current = current / f"a{i}"
        ancestor = current / "nested"
        target_file = ancestor / "target.py"
        target_file.parent.mkdir(parents=True)
        target_file.write_text("SAFE_CONTENT = 1\n")

        outside = tmp_path / "OUTSIDE"
        outside.mkdir()
        (outside / "target.py").write_text(SENTINEL_CONTENT)

        state = _hook_swap_before_listing(monkeypatch, ancestor, ancestor, outside)

        result = StaticScanner().scan(root_dir)

        if not state["swapped"]:
            pytest.skip("could not create a real junction/symlink in this environment")
        assert state["attempted"] is True
        outside_consumed = any(
            "sg2-001-outside-bytes" in (f.description or "") for f in result.findings
        ) or any("SECRET_SENTINEL" in (e.summary or "") for e in result.evidence)
        # The core invariant: outside bytes consumed AND status COMPLETE
        # must never both be true (SG2-001's exact failure mode).
        assert not outside_consumed
        assert not (outside_consumed and result.status.name == "COMPLETE")

    def test_static_scanner_never_reports_complete_with_outside_bytes_consumed(
        self, tmp_path, monkeypatch
    ):
        """Direct assertion of the auditor's exact failure mode: outside
        bytes read AND final status COMPLETE must never both be true."""
        root_dir = tmp_path / "ROOT" / "safe"
        nested = root_dir / "nested"
        nested.mkdir(parents=True)
        (nested / "target.py").write_text("SAFE = 1\n")
        outside = tmp_path / "OUTSIDE"
        outside.mkdir()
        (outside / "target.py").write_text(SENTINEL_CONTENT)

        state = _hook_swap_before_listing(monkeypatch, nested, nested, outside)
        result = StaticScanner().scan(root_dir)
        if not state["swapped"]:
            pytest.skip("could not create a real junction/symlink in this environment")

        outside_consumed = any(
            "sg2-001-outside-bytes" in (f.description or "") for f in result.findings
        ) or any("sg2-001-outside-bytes" in (e.summary or "") for e in result.evidence)
        assert not (outside_consumed and result.status.name == "COMPLETE")
        assert not outside_consumed


class TestAncestorSwapDuringWorkspaceCopyAndFingerprint:
    def test_ancestor_swap_mid_walk_not_copied_into_workspace(self, tmp_path, monkeypatch):
        source = tmp_path / "source"
        nested = source / "nested"
        nested.mkdir(parents=True)
        (nested / "target.py").write_text("SAFE = 1\n")
        outside = tmp_path / "OUTSIDE"
        outside.mkdir()
        (outside / "target.py").write_text(SENTINEL_CONTENT)

        state = _hook_swap_before_listing(monkeypatch, nested, nested, outside)
        root = BoundRoot.bind(source)

        try:
            with DynamicWorkspace(root) as ws:
                if not state["swapped"]:
                    pytest.skip("could not create a real junction/symlink in this environment")
                copied = list(ws.path.rglob("*"))
                assert not any(
                    p.is_file() and "sg2-001-outside-bytes" in p.read_text(errors="ignore")
                    for p in copied
                )
        except ObservationError:
            if not state["swapped"]:
                pytest.skip("could not create a real junction/symlink in this environment")
            # Failing closed (never starting/using a workspace built from
            # outside content) is an acceptable, safe outcome too.

    def test_ancestor_swap_mid_walk_not_fingerprinted_as_trusted(self, tmp_path, monkeypatch):
        source = tmp_path / "source"
        nested = source / "nested"
        nested.mkdir(parents=True)
        (nested / "target.py").write_text("SAFE = 1\n")
        outside = tmp_path / "OUTSIDE"
        outside.mkdir()
        (outside / "target.py").write_text(SENTINEL_CONTENT)
        outside_hash = hashlib.sha256(SENTINEL_CONTENT.encode()).hexdigest()

        state = _hook_swap_before_listing(monkeypatch, nested, nested, outside)
        root = BoundRoot.bind(source)

        try:
            with DynamicWorkspace(root) as ws:
                if not state["swapped"]:
                    pytest.skip("could not create a real junction/symlink in this environment")
                # _before is the internal (relative_path, sha256_hex)
                # fingerprint baseline -- the outside sentinel's hash must
                # never be present in it, i.e. it was never fingerprinted
                # as if it were trusted source content.
                fingerprint_hashes = {h for _, h in ws._before}
                assert outside_hash not in fingerprint_hashes
        except ObservationError:
            if not state["swapped"]:
                pytest.skip("could not create a real junction/symlink in this environment")


class TestSecureWalkerEdgeBranches:
    def test_root_replaced_by_plain_directory_with_different_inode_is_root_changed(
        self, tmp_path, monkeypatch
    ):
        """Covers the non-reparse identity-mismatch branch in
        _SecureWalker.run(): the opened root handle succeeds (it is not a
        symlink/junction) but its device+inode no longer match the
        BoundRoot construction-time snapshot, because the root was
        deleted and recreated as an ordinary directory in between."""
        target = tmp_path / "target"
        target.mkdir()
        (target / "a.txt").write_text("a")
        root = BoundRoot.bind(target)

        real_open_root_secure = paths_mod._open_root_secure

        def swap_to_fresh_dir(root_arg):
            shutil.rmtree(target)
            target.mkdir()
            return real_open_root_secure(root_arg)

        monkeypatch.setattr(paths_mod, "_open_root_secure", swap_to_fresh_dir)
        outcome = walk_tree(
            root,
            WalkLimits(max_files=10, max_total_bytes=100, max_file_bytes=100, max_depth=2),
        )
        assert "ROOT_CHANGED" in outcome.incompleteness_reasons
        assert outcome.entries == ()

    def test_entry_open_failure_is_recorded_as_unreadable_not_fatal(self, tmp_path, monkeypatch):
        """Covers _recurse's (OSError, ObservationError) handler around
        _open_entry_secure: one entry failing to open must not abort the
        whole walk."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "bad.py").write_text("x = 1\n")
        (source / "ok.py").write_text("y = 2\n")

        real_open_entry_secure = paths_mod._open_entry_secure

        def flaky_open(name, dir_fd, dir_path):
            if name == "bad.py":
                raise OSError("simulated open failure")
            return real_open_entry_secure(name, dir_fd, dir_path)

        monkeypatch.setattr(paths_mod, "_open_entry_secure", flaky_open)
        root = BoundRoot.bind(source)
        outcome = walk_tree(
            root,
            WalkLimits(max_files=10, max_total_bytes=10**6, max_file_bytes=10**6, max_depth=10),
        )
        assert "UNREADABLE_FILE" in outcome.incompleteness_reasons
        assert any(e.relative_posix == "ok.py" for e in outcome.entries)
        assert not any(e.relative_posix == "bad.py" for e in outcome.entries)

    def test_fstat_failure_after_open_is_recorded_as_unreadable(self, tmp_path, monkeypatch):
        """Covers _recurse's fstat-after-open error handler: the entry's
        atomic open (and the classification fstat inside it) succeeds,
        but the SECOND fstat call in _recurse -- used to get the file's
        size/identity for the WalkEntry -- fails. real_open_entry_secure's
        own internal fstat is left alone; only the _recurse-level call is
        made to fail, and only for the targeted fd."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "flaky.py").write_text("x = 1\n")
        (source / "ok.py").write_text("y = 2\n")

        real_open_entry_secure = paths_mod._open_entry_secure
        real_fstat = os.fstat
        flaky_fd = {"value": None}

        def open_then_mark(name, dir_fd, dir_path):
            kind, fd = real_open_entry_secure(name, dir_fd, dir_path)
            if name == "flaky.py":
                flaky_fd["value"] = fd
            return kind, fd

        def fstat_with_one_failure(fd):
            if fd == flaky_fd["value"]:
                flaky_fd["value"] = None  # only fail once, for this fd
                raise OSError("simulated fstat failure")
            return real_fstat(fd)

        monkeypatch.setattr(paths_mod, "_open_entry_secure", open_then_mark)
        monkeypatch.setattr(paths_mod.os, "fstat", fstat_with_one_failure)

        root = BoundRoot.bind(source)
        outcome = walk_tree(
            root,
            WalkLimits(max_files=10, max_total_bytes=10**6, max_file_bytes=10**6, max_depth=10),
        )
        assert "UNREADABLE_FILE" in outcome.incompleteness_reasons
        assert any(e.relative_posix == "ok.py" for e in outcome.entries)
        assert not any(e.relative_posix == "flaky.py" for e in outcome.entries)

    def test_file_swapped_between_pre_open_identity_and_atomic_open_is_unreadable(
        self, tmp_path, monkeypatch
    ):
        """Direct, single-walk exercise of the narrow AB-003 leaf-file
        residual defense: identity captured just before the atomic open
        must be compared against the freshly opened handle's own
        identity, and a mismatch must fail closed. This injects the
        mismatch directly (rather than via a real hardlink swap inside
        the currently-open directory) because on Windows the parent
        directory handle _pre_open_identity runs under is itself already
        deny-write-locked -- a real concurrent hardlink swap there is
        blocked by that same defense, which is a stronger property than
        this specific comparison, not a gap in it."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "payload.txt").write_text("original")

        real_pre_open_identity = paths_mod._pre_open_identity

        def lie_about_identity(name, dir_fd, dir_path):
            real_pre_open_identity(name, dir_fd, dir_path)
            if name == "payload.txt":
                return (999999, 999999, 0)
            return real_pre_open_identity(name, dir_fd, dir_path)

        monkeypatch.setattr(paths_mod, "_pre_open_identity", lie_about_identity)
        root = BoundRoot.bind(source)
        outcome = walk_tree(
            root,
            WalkLimits(max_files=10, max_total_bytes=10**6, max_file_bytes=10**6, max_depth=10),
        )
        assert "UNREADABLE_FILE" in outcome.incompleteness_reasons
        assert not any(e.relative_posix == "payload.txt" for e in outcome.entries)
        assert any(
            "identity changed between listing and open" in msg
            for _, msg in outcome.unreadable_paths
        )


class TestAncestorSwapNeverProducesCompleteWalk:
    def test_walk_tree_itself_fails_closed_on_mid_walk_ancestor_swap(self, tmp_path, monkeypatch):
        """Lowest-level assertion directly against walk_tree: a mid-walk
        ancestor swap must never yield a WalkOutcome with (a) an entry
        whose content is the outside sentinel's AND (b) zero
        incompleteness reasons (== COMPLETE) at the same time."""
        safe = tmp_path / "ROOT" / "safe"
        nested = safe / "nested"
        nested.mkdir(parents=True)
        (nested / "target.py").write_text("SAFE_CONTENT = 1\n")
        outside = tmp_path / "OUTSIDE"
        outside.mkdir()
        (outside / "target.py").write_text(SENTINEL_CONTENT)

        state = _hook_swap_before_listing(monkeypatch, nested, nested, outside)
        root = BoundRoot.bind(safe)
        limits = WalkLimits(
            max_files=1000, max_total_bytes=10_000_000, max_file_bytes=1_000_000, max_depth=64
        )
        outcome = walk_tree(root, limits)
        if not state["swapped"]:
            pytest.skip("could not create a real junction/symlink in this environment")

        # The walker must not have silently walked into OUTSIDE and
        # recorded self-consistent identities for it.
        assert len(outcome.entries) == 0 or outcome.incompleteness_reasons != ()
