"""Snapshot-based filesystem behavior observation.

Compares a pre-run and post-run snapshot of a configured scope (normally a
:class:`~skillguard.dynamic.workspace.DynamicWorkspace` copy) to report
created/modified/deleted files. This is snapshot/polling-based, not a real
filesystem event watcher: a file created and deleted between snapshots is
invisible to it. See spec section 53 -- this limitation is documented, not
hidden.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from skillguard.paths import BoundRoot, WalkLimits, walk_tree

DEFAULT_IGNORE_DIR_SEGMENTS = frozenset(
    {".git", "__pycache__", ".venv", "venv", "node_modules", ".pytest_cache", ".ruff_cache", ".mypy_cache"}
)


@dataclass(frozen=True)
class FileSnapshotEntry:
    relative_posix: str
    size_bytes: int
    mtime_ns: int


@dataclass(frozen=True)
class FilesystemSnapshot:
    entries: tuple[FileSnapshotEntry, ...]

    def by_path(self) -> dict[str, FileSnapshotEntry]:
        return {e.relative_posix: e for e in self.entries}


@dataclass(frozen=True)
class FilesystemDiff:
    created: tuple[str, ...]
    modified: tuple[str, ...]
    deleted: tuple[str, ...]


def _ignored(relative_posix: str, ignore_dir_segments: frozenset[str]) -> bool:
    return any(seg in relative_posix.split("/") for seg in ignore_dir_segments)


class FilesystemObserver:
    def __init__(
        self,
        *,
        scope: Path,
        max_files: int = 200_000,
        max_total_bytes: int = 2**34,
        max_file_bytes: int = 2**32,
        max_depth: int = 200,
        ignore_dir_segments: frozenset[str] = DEFAULT_IGNORE_DIR_SEGMENTS,
    ) -> None:
        self._root = BoundRoot.bind(scope, label="filesystem observation scope")
        self._limits = WalkLimits(
            max_files=max_files, max_total_bytes=max_total_bytes, max_file_bytes=max_file_bytes, max_depth=max_depth
        )
        self._ignore = ignore_dir_segments

    def snapshot(self) -> FilesystemSnapshot:
        outcome = walk_tree(self._root, self._limits)
        entries = []
        for entry in outcome.entries:
            if _ignored(entry.relative_posix, self._ignore):
                continue
            st = entry.absolute_path.stat()
            entries.append(
                FileSnapshotEntry(
                    relative_posix=entry.relative_posix, size_bytes=entry.size_bytes, mtime_ns=st.st_mtime_ns
                )
            )
        return FilesystemSnapshot(entries=tuple(sorted(entries, key=lambda e: e.relative_posix)))


def diff_snapshots(before: FilesystemSnapshot, after: FilesystemSnapshot) -> FilesystemDiff:
    before_map = before.by_path()
    after_map = after.by_path()
    created = sorted(set(after_map) - set(before_map))
    deleted = sorted(set(before_map) - set(after_map))
    modified = sorted(
        p
        for p in set(before_map) & set(after_map)
        if before_map[p].size_bytes != after_map[p].size_bytes or before_map[p].mtime_ns != after_map[p].mtime_ns
    )
    return FilesystemDiff(created=tuple(created), modified=tuple(modified), deleted=tuple(deleted))
