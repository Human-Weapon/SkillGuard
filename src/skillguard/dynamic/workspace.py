"""Source-protecting workspace copy for dynamic runs.

This is NOT a security sandbox -- it exists so that (a) dynamic analysis
never mutates the caller's original source tree through the workspace
copy itself, and (b) a run is reproducible against a known, integrity-
verified snapshot. See spec sections 54-55 and SECURITY.md's "not a
sandbox" note.

Both the copy step and the source-mutation fingerprint route through the
same containment-safe, reparse-point-refusing :func:`skillguard.paths.walk_tree`
used everywhere else in SkillGuard -- see docs/decisions/0008-workspace-copy-safety.md.
Naively using ``shutil.copytree(..., symlinks=False)`` does NOT achieve
containment: per the stdlib docs, ``symlinks=False`` means symlinks are
*dereferenced*, so a source tree containing a symlink to an outside
directory would have that outside directory's contents copied into the
workspace. This module never calls ``shutil.copytree``.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from skillguard.errors import ObservationError, SourceMutationError
from skillguard.paths import BoundRoot, WalkEntry, WalkLimits, walk_tree_and_read

_COPY_LIMITS = WalkLimits(
    max_files=50_000, max_total_bytes=2**31, max_file_bytes=2**28, max_depth=200
)
# Copying and fingerprinting must account for the same source tree. Keeping
# separate, smaller fingerprint limits allowed a tree to pass copying and
# then fail during constructor setup, or to be copied from a different set of
# entries than the one used for the integrity baseline.
_FINGERPRINT_LIMITS = _COPY_LIMITS
_HASH_CHUNK_BYTES = 1_048_576

# REPARSE_POINT_SKIPPED and SPECIAL_FILE_SKIPPED are intentional, safe
# omissions (see walk_tree) -- excluding a symlink/junction/device from the
# copy and fingerprint is the whole point of using walk_tree here, not a
# sign that either operation is incomplete. Only reasons indicating the
# walk genuinely could not see everything it was configured to count as a
# hard failure.
_HARD_LIMIT_REASONS = frozenset(
    {
        "FILE_LIMIT_REACHED",
        "BYTE_LIMIT_REACHED",
        "UNREADABLE_FILE",
        "MAX_DEPTH_REACHED",
        "UNEXPECTED_FILE_ERROR",
        "ROOT_CHANGED",
    }
)


def _check_limits(outcome, *, limits: WalkLimits, root: BoundRoot, operation: str) -> None:
    hard_hits = set(outcome.incompleteness_reasons) & _HARD_LIMIT_REASONS
    if hard_hits:
        raise ObservationError(
            f"could not {operation} {root.resolved}: {', '.join(sorted(hard_hits))}"
        )
    # walk_tree enforces the *aggregate* file-count/byte-total budget but,
    # like StaticScanner, leaves per-file size enforcement to the caller --
    # so a single oversized file would otherwise be hashed/copied in full,
    # unbounded. Silently skipping it would be worse: an attacker could hide
    # a real mutation inside a file made deliberately "too large" to
    # fingerprint. Treat it as a hard failure instead.
    oversized = [e.relative_posix for e in outcome.entries if e.size_bytes > limits.max_file_bytes]
    if oversized:
        raise ObservationError(
            f"could not {operation} {root.resolved}: FILE_TOO_LARGE ({oversized[0]} and "
            f"{len(oversized) - 1} more)"
            if len(oversized) > 1
            else f"could not {operation} {root.resolved}: FILE_TOO_LARGE ({oversized[0]})"
        )


@dataclass(frozen=True)
class _CopyResult:
    reparse_points_skipped: tuple[str, ...]
    incompleteness_reasons: tuple[str, ...]


def _safe_copy_tree(root: BoundRoot, destination: Path) -> _CopyResult:
    """Copy every regular file under ``root`` into ``destination``,
    preserving relative layout, without ever following a symlink or
    Windows junction/reparse point -- and without creating one in the
    destination either. Special files (devices/pipes/sockets) are skipped
    the same way the static scanner skips them, via the shared walker.

    Uses :func:`walk_tree_and_read` so every source file is opened and
    copied atomically, in the same traversal step that discovered it,
    rather than being reopened later by a remembered path string -- see
    SG2-001 in docs/audits: that gap is exactly what let an ancestor
    directory replaced *during* copying escape containment."""
    destination.mkdir(parents=True, exist_ok=True)

    def on_file(entry: WalkEntry, source) -> None:
        if entry.size_bytes > _COPY_LIMITS.max_file_bytes:
            # Recorded in outcome.entries; _check_limits below turns this
            # into the same hard FILE_TOO_LARGE failure as before, without
            # this callback reading/copying the oversized file's content.
            return
        dest_path = destination / entry.relative_posix
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        with dest_path.open("wb") as destination_file:
            shutil.copyfileobj(source, destination_file, length=_HASH_CHUNK_BYTES)
            source_stat = os.fstat(source.fileno())
        # Preserve executable/read-only bits without reopening the source
        # pathname for metadata. This keeps copied scripts runnable while
        # retaining the handle-checked content boundary.
        os.chmod(dest_path, stat.S_IMODE(source_stat.st_mode))
        os.utime(dest_path, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns))

    outcome = walk_tree_and_read(root, _COPY_LIMITS, on_file)
    _check_limits(
        outcome, limits=_COPY_LIMITS, root=root, operation="copy the source workspace for"
    )
    return _CopyResult(
        reparse_points_skipped=outcome.reparse_points_skipped,
        incompleteness_reasons=outcome.incompleteness_reasons,
    )


def _content_fingerprint(root: BoundRoot) -> tuple[tuple[str, str], ...]:
    """Deterministic ``(relative_path, sha256_hex)`` pairs for every
    regular file under ``root``, via the same containment-safe,
    atomic-open walk used for copying (see :func:`_safe_copy_tree` and
    SG2-001 in docs/audits). Detects added/deleted/renamed/content-modified
    files -- including a same-size edit with a restored mtime, which a
    metadata-only fingerprint cannot see.

    Raises :class:`ObservationError` rather than silently returning a
    fingerprint if a resource limit prevented a complete accounting of the
    source tree: an incomplete fingerprint must never be presented as
    proof the source is unchanged.
    """
    rows: list[tuple[str, str]] = []

    def on_file(entry: WalkEntry, fh) -> None:
        if entry.size_bytes > _FINGERPRINT_LIMITS.max_file_bytes:
            return
        digest = hashlib.sha256()
        for chunk in iter(lambda: fh.read(_HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
        rows.append((entry.relative_posix, digest.hexdigest()))

    outcome = walk_tree_and_read(root, _FINGERPRINT_LIMITS, on_file)
    _check_limits(
        outcome,
        limits=_FINGERPRINT_LIMITS,
        root=root,
        operation="build a complete source integrity fingerprint for",
    )
    return tuple(sorted(rows))


class DynamicWorkspace:
    """Copies ``source_root`` into a fresh temporary directory (never
    following symlinks/junctions, never touching content outside
    ``source_root``) and exposes that copy for a dynamic run. Verifies the
    original was not mutated using a content-hash fingerprint."""

    def __init__(self, source_root: BoundRoot, *, parent_dir: Path | None = None) -> None:
        self.source_root = source_root
        self._before = _content_fingerprint(source_root)
        self._base_dir: Path | None = None
        try:
            base = Path(
                tempfile.mkdtemp(
                    prefix="skillguard-ws-parent-", dir=str(parent_dir) if parent_dir else None
                )
            )
            self._base_dir = base
            self._copy_dir = base / "workspace"
            copy_result = _safe_copy_tree(source_root, self._copy_dir)
            self.reparse_points_skipped = copy_result.reparse_points_skipped
            self.incompleteness_reasons = copy_result.incompleteness_reasons
        except BaseException as exc:  # noqa: BLE001 - cleanup must cover every setup failure
            self.cleanup()
            if isinstance(exc, ObservationError):
                raise
            raise ObservationError(f"could not create dynamic workspace: {exc}") from exc

    @property
    def path(self) -> Path:
        return self._copy_dir

    def verify_source_unchanged(self) -> None:
        after = _content_fingerprint(self.source_root)
        if after != self._before:
            raise SourceMutationError(
                f"source workspace {self.source_root.resolved} changed while dynamic analysis "
                "was running against an isolated copy of it"
            )

    def cleanup(self) -> None:
        if self._base_dir is not None:
            shutil.rmtree(self._base_dir, ignore_errors=True)

    def __enter__(self) -> DynamicWorkspace:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.cleanup()
