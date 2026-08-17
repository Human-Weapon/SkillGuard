"""Source-protecting workspace copy for dynamic runs.

This is NOT a security sandbox -- it exists so that (a) dynamic analysis
never mutates the caller's original source tree, and (b) a run is
reproducible against a known, isolated snapshot. See spec sections 54-55
and SECURITY.md's "not a sandbox" note.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from skillguard.errors import SourceMutationError
from skillguard.paths import BoundRoot, WalkLimits, walk_tree

_FINGERPRINT_LIMITS = WalkLimits(
    max_files=200_000, max_total_bytes=2**40, max_file_bytes=2**40, max_depth=200
)


def _fingerprint(root: BoundRoot) -> tuple[tuple[str, int, int], ...]:
    """A cheap (path, size, mtime_ns) fingerprint of a tree. Does not hash
    file contents, so a same-size, same-mtime content edit within the same
    filesystem timer tick could theoretically be missed -- see
    docs/decisions/0007-source-mutation-detection.md for why this tradeoff
    was accepted for v0.1.0."""
    outcome = walk_tree(root, _FINGERPRINT_LIMITS)
    rows = []
    for entry in outcome.entries:
        st = entry.absolute_path.stat()
        rows.append((entry.relative_posix, entry.size_bytes, st.st_mtime_ns))
    return tuple(sorted(rows))


class DynamicWorkspace:
    """Copies ``source_root`` into a fresh temporary directory and exposes
    that copy for a dynamic run. Verifies the original was not mutated."""

    def __init__(self, source_root: BoundRoot, *, parent_dir: Path | None = None) -> None:
        self.source_root = source_root
        self._before = _fingerprint(source_root)
        base = Path(
            tempfile.mkdtemp(
                prefix="skillguard-ws-parent-", dir=str(parent_dir) if parent_dir else None
            )
        )
        self._copy_dir = base / "workspace"
        shutil.copytree(
            source_root.resolved, self._copy_dir, symlinks=False, ignore_dangling_symlinks=True
        )
        self._base_dir = base

    @property
    def path(self) -> Path:
        return self._copy_dir

    def verify_source_unchanged(self) -> None:
        after = _fingerprint(self.source_root)
        if after != self._before:
            raise SourceMutationError(
                f"source workspace {self.source_root.resolved} changed while dynamic analysis "
                "was running against an isolated copy of it"
            )

    def cleanup(self) -> None:
        shutil.rmtree(self._base_dir, ignore_errors=True)

    def __enter__(self) -> DynamicWorkspace:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.cleanup()
