"""Path containment primitives.

This module is the single place SkillGuard reasons about "is this path
inside the root I was told to scan/write to". Getting this wrong has been a
recurring source of security bugs in prior projects (see docs/decisions),
so every root-binding and directory-walk operation in the codebase must go
through :class:`BoundRoot` / :func:`walk_tree` rather than reimplementing
path math locally.

Design notes
------------
* A root is resolved to an absolute, symlink-free path **once**, at
  construction time. Later ``os.chdir()`` calls cannot silently rebind it
  (see docs/decisions/0002-cwd-drift.md).
* Symlinks and Windows junctions/reparse points are never traversed during a
  walk. ``os.path.islink()`` does **not** detect NTFS junctions (they use
  ``IO_REPARSE_TAG_MOUNT_POINT``, not ``IO_REPARSE_TAG_SYMLINK``), so this
  module checks ``FILE_ATTRIBUTE_REPARSE_POINT`` directly via
  ``st_file_attributes`` in addition to ``os.path.islink()``.
* Containment and "root replaced after construction" checks are
  best-effort. A sufficiently privileged local attacker can still win a
  TOCTOU race between a check and a subsequent filesystem operation. This
  module reduces that window; it does not close it. See SECURITY.md.
"""

from __future__ import annotations

import contextlib
import os
import stat as stat_module
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from skillguard.errors import ObservationError, PathSecurityError, ValidationError
from skillguard.validation import validate_non_negative_int

_REPARSE_POINT = getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def is_reparse_point(path: Path) -> bool:
    """Return True if ``path`` is a symlink, Windows junction, or other
    reparse point. Does not raise if the path is missing or inaccessible."""
    try:
        if os.path.islink(path):
            return True
        st = os.lstat(path)
    except OSError:
        return False
    attrs = getattr(st, "st_file_attributes", None)
    if attrs is not None:
        return bool(attrs & _REPARSE_POINT)
    return False


def _identity(path: Path) -> tuple[int, int, int] | None:
    """A best-effort identity fingerprint for TOCTOU/root-swap detection.
    The third element (``st_ctime_ns``) is captured for callers that need
    it (see ``handle_identity_matches``) but is deliberately NOT compared
    by :func:`identity_matches` -- see that function's docstring for why.
    """
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino, st.st_ctime_ns)


def identity_matches(a: tuple[int, int, int], b: tuple[int, int, int]) -> bool:
    """Identity match on device+inode only: "is this still the same
    underlying directory/file entity". Deliberately does NOT compare
    ctime.

    A directory's own ctime changes on POSIX whenever an entry is
    added or removed inside it -- and every root this check runs
    against is, by design, one that legitimately gets written to or
    observed repeatedly over its lifetime (``FilesystemObserver``
    before/after diffing, a ``DynamicWorkspace`` source root being
    fingerprinted more than once, a ``ResultStore`` output root
    receiving more than one ``save()``). A version of this comparison
    that included ctime was tried and, on real Ubuntu CI, rejected
    completely legitimate roots the moment anything was created inside
    them -- not a swap, just normal operation. Comparing only
    device+inode avoids that false-positive class entirely.

    This is a deliberate, documented tradeoff: comparing device+inode
    alone cannot detect a same-path directory replaced by a *different*
    plain directory that happens to reuse the just-freed inode number
    (observed achievable on Linux tmpfs). A junction/symlink-based
    replacement is still caught regardless, both by device+inode differing
    in the overwhelming majority of cases and by the separate
    ``is_reparse_point()`` check callers combine this with. See
    SECURITY.md's path-containment section for the residual-limitation
    statement this corresponds to.
    """
    return a[0] == b[0] and a[1] == b[1]


# On Windows, fstat() on a just-opened file handle can report st_ctime_ns
# up to ~60ms different from an lstat() taken moments earlier for the
# same, completely unmodified file -- observed consistently for files
# written via a lock-file-then-rename pattern (e.g. `git config` writing
# `.git/config`). Different underlying Win32 calls, not an actual change.
# An exact comparison here produced real, reproducible false-positive
# "file changed" rejections.
#
# This tolerance is scoped *only* to the lstat-vs-open-handle-fstat
# comparison in open_walk_entry() below. Two earlier, broader attempts at
# this fix both broke real Ubuntu CI: widening identity_matches() itself
# to a 2-second ctime tolerance let a fast delete-and-recreate root swap
# through, and even an *exact* ctime comparison in identity_matches()
# rejected completely unmodified roots the moment a legitimate write
# created a new entry inside them (see that function's docstring).
# identity_matches() now ignores ctime entirely; this is a second,
# separate comparator, used only around a single open() call on a
# regular *file* (not a directory, which is where the "own activity
# changes ctime" problem lives), where a bounded tolerance on ctime is
# both safe and necessary to absorb the Windows jitter described above.
_HANDLE_CTIME_TOLERANCE_NS = 150_000_000


def handle_identity_matches(opened: tuple[int, int, int], walked: tuple[int, int, int]) -> bool:
    o_dev, o_ino, o_ctime = opened
    w_dev, w_ino, w_ctime = walked
    return (
        o_dev == w_dev and o_ino == w_ino and abs(o_ctime - w_ctime) <= _HANDLE_CTIME_TOLERANCE_NS
    )


@dataclass(frozen=True)
class BoundRoot:
    """An absolute, resolved, identity-snapshotted directory root.

    Construct via :meth:`bind` (must already exist, e.g. a scan target) or
    :meth:`bind_output` (created if missing, e.g. a result store). Never
    construct directly.
    """

    label: str
    configured: Path
    resolved: Path
    _identity_snapshot: tuple[int, int, int] | None = field(repr=False)

    @classmethod
    def bind(cls, path: object, *, label: str = "root") -> BoundRoot:
        if not isinstance(path, (str, Path)):
            raise ValidationError(f"{label} must be a str or Path, got {type(path).__name__}")
        raw = Path(path)
        base = raw if raw.is_absolute() else Path.cwd() / raw
        if not base.exists():
            raise PathSecurityError(f"{label} does not exist: {base}")
        if not base.is_dir():
            raise PathSecurityError(f"{label} exists but is not a directory: {base}")
        resolved = Path(os.path.realpath(base))
        return cls(
            label=label,
            configured=base,
            resolved=resolved,
            _identity_snapshot=_identity(resolved),
        )

    @classmethod
    def bind_output(cls, path: object, *, label: str = "output root") -> BoundRoot:
        """Bind a root that SkillGuard will write into, creating it if
        needed. Rejects immediately (before any output is written) if the
        path already exists as a non-directory."""
        if not isinstance(path, (str, Path)):
            raise ValidationError(f"{label} must be a str or Path, got {type(path).__name__}")
        raw = Path(path)
        base = raw if raw.is_absolute() else Path.cwd() / raw
        if base.exists() and not base.is_dir():
            raise PathSecurityError(f"{label} exists and is not a directory: {base}")
        base.mkdir(parents=True, exist_ok=True)
        resolved = Path(os.path.realpath(base))
        return cls(
            label=label,
            configured=base,
            resolved=resolved,
            _identity_snapshot=_identity(resolved),
        )

    def verify_unchanged(self) -> bool:
        """Best-effort re-check that the root still refers to the same
        underlying directory it did at bind time. Returns False if the
        directory's (device, inode) identity has changed -- e.g. it was
        deleted and replaced with a junction/symlink to somewhere else.

        This narrows, but cannot eliminate, the TOCTOU window between this
        check and a subsequent filesystem operation.
        """
        current = _identity(self.resolved)
        if self._identity_snapshot is None or current is None:
            return False
        return identity_matches(current, self._identity_snapshot)

    def contains(self, candidate: Path) -> bool:
        """Return True if the *resolved, symlink-free* real path of
        ``candidate`` lies within this root."""
        try:
            candidate_resolved = Path(os.path.realpath(candidate))
            candidate_resolved.relative_to(self.resolved)
            return True
        except (ValueError, OSError):
            return False

    def require_contains(self, candidate: Path) -> Path:
        if not self.contains(candidate):
            raise PathSecurityError(f"{candidate} escapes bound {self.label} {self.resolved}")
        return candidate

    def resolve_result_id(self, result_id: str) -> Path:
        """Validate a caller-supplied result/run ID and resolve it to a path
        under this (output) root. Rejects traversal, absolute paths, and
        Windows-reserved names -- result IDs become filesystem directory
        names."""
        if not isinstance(result_id, str) or result_id == "":
            raise ValidationError("result_id must be a non-empty str")
        if result_id in {".", ".."}:
            raise PathSecurityError(f"result_id is not a valid directory name: {result_id!r}")
        if Path(result_id).is_absolute():
            raise PathSecurityError(f"result_id must not be absolute: {result_id!r}")
        if "/" in result_id or "\\" in result_id or ".." in result_id:
            raise PathSecurityError(f"result_id contains illegal path characters: {result_id!r}")
        if any(ord(ch) < 32 or ch in '<>:"|?*' for ch in result_id):
            raise PathSecurityError(
                f"result_id contains illegal filesystem characters: {result_id!r}"
            )
        if result_id[-1] in {".", " "}:
            raise PathSecurityError(
                f"result_id must not end with a dot or space on Windows: {result_id!r}"
            )
        reserved = {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10)),
        }
        if result_id.split(".", 1)[0].upper() in reserved:
            raise PathSecurityError(f"result_id is a reserved name: {result_id!r}")
        candidate = self.resolved / result_id
        if os.name == "nt" and self.resolved.exists():
            candidate_norm = os.path.normcase(os.path.abspath(candidate))
            for existing in self.resolved.iterdir():
                if (
                    existing.name != result_id
                    and os.path.normcase(os.path.abspath(existing)) == candidate_norm
                ):
                    raise PathSecurityError(
                        f"result_id aliases an existing Windows path: {result_id!r}"
                    )
        return self.require_contains(candidate)


@dataclass(frozen=True)
class WalkLimits:
    max_files: int
    max_total_bytes: int
    max_file_bytes: int
    max_depth: int

    def __post_init__(self) -> None:
        validate_non_negative_int(self.max_files, name="max_files")
        validate_non_negative_int(self.max_total_bytes, name="max_total_bytes")
        validate_non_negative_int(self.max_file_bytes, name="max_file_bytes")
        validate_non_negative_int(self.max_depth, name="max_depth")


@dataclass(frozen=True)
class WalkEntry:
    absolute_path: Path
    relative_posix: str
    size_bytes: int
    identity: tuple[int, int, int]


def _stat_identity(st: os.stat_result) -> tuple[int, int, int]:
    return (st.st_dev, st.st_ino, st.st_ctime_ns)


def open_walk_entry(entry: WalkEntry):
    """Open a regular file only if it is still the file captured by the walk.

    POSIX uses ``O_NOFOLLOW`` where available. Windows has no portable Python
    equivalent, so the pre-open reparse/identity check and post-open handle
    identity check provide fail-closed replacement detection there.
    """
    path = entry.absolute_path
    if is_reparse_point(path):
        raise ObservationError(f"file changed to a reparse point during read: {path}")
    try:
        current = os.lstat(path)
    except OSError as exc:
        raise ObservationError(f"file disappeared during read: {path}: {exc}") from exc
    if not identity_matches(_stat_identity(current), entry.identity):
        raise ObservationError(f"file identity changed during read: {path}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ObservationError(f"could not open stable file {path}: {exc}") from exc
    try:
        opened = os.fstat(fd)
        if not stat_module.S_ISREG(opened.st_mode) or not handle_identity_matches(
            _stat_identity(opened), entry.identity
        ):
            raise ObservationError(f"file identity changed during read: {path}")
        return os.fdopen(fd, "rb")
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise


@dataclass(frozen=True)
class WalkOutcome:
    entries: tuple[WalkEntry, ...]
    reparse_points_skipped: tuple[str, ...]
    unreadable_paths: tuple[tuple[str, str], ...]
    special_files_skipped: tuple[str, ...]
    incompleteness_reasons: tuple[str, ...]


def walk_tree(root: BoundRoot, limits: WalkLimits) -> WalkOutcome:
    """Deterministically walk ``root`` (a directory that must already have
    been validated to exist), never descending into symlinks or reparse
    points, and honoring hard resource limits.

    Traversal order is sorted by name at every level so results are
    reproducible across filesystems/platforms with identical content.
    """
    entries: list[WalkEntry] = []
    reparse_skipped: list[str] = []
    unreadable: list[tuple[str, str]] = []
    special_files: list[str] = []
    reasons: set[str] = set()
    total_bytes = 0
    truncated = False

    if not root.verify_unchanged() or is_reparse_point(root.resolved):
        return WalkOutcome(
            entries=(),
            reparse_points_skipped=(),
            unreadable_paths=(),
            special_files_skipped=(),
            incompleteness_reasons=("ROOT_CHANGED",),
        )

    def rel_posix(p: Path) -> str:
        rel = p.relative_to(root.resolved)
        return PurePosixPath(*rel.parts).as_posix()

    def recurse(dir_path: Path, depth: int) -> None:
        nonlocal total_bytes, truncated
        if truncated:
            return
        if dir_path == root.resolved and (
            not root.verify_unchanged() or is_reparse_point(root.resolved)
        ):
            reasons.add("ROOT_CHANGED")
            truncated = True
            return
        try:
            children = sorted(os.scandir(dir_path), key=lambda e: e.name)
        except OSError as exc:
            unreadable.append((str(dir_path), str(exc)))
            reasons.add("UNREADABLE_FILE")
            return
        for child in children:
            if truncated:
                return
            child_path = Path(child.path)
            if is_reparse_point(child_path):
                reparse_skipped.append(rel_posix(child_path))
                reasons.add("REPARSE_POINT_SKIPPED")
                continue
            try:
                is_dir = child.is_dir(follow_symlinks=False)
            except OSError as exc:
                unreadable.append((str(child_path), str(exc)))
                reasons.add("UNREADABLE_FILE")
                continue
            if is_dir:
                if depth + 1 > limits.max_depth:
                    reasons.add("MAX_DEPTH_REACHED")
                    continue
                recurse(child_path, depth + 1)
                continue
            try:
                is_file = child.is_file(follow_symlinks=False)
            except OSError as exc:
                unreadable.append((str(child_path), str(exc)))
                reasons.add("UNREADABLE_FILE")
                continue
            if not is_file:
                special_files.append(rel_posix(child_path))
                reasons.add("SPECIAL_FILE_SKIPPED")
                continue
            if len(entries) >= limits.max_files:
                reasons.add("FILE_LIMIT_REACHED")
                truncated = True
                return
            try:
                # DirEntry.stat() reports zero device/inode fields on some
                # Windows Python/filesystem combinations. os.lstat() gives a
                # stable identity that can be compared with the later file
                # handle's fstat().
                stat_result = os.lstat(child_path)
                size = stat_result.st_size
            except OSError as exc:
                unreadable.append((str(child_path), str(exc)))
                reasons.add("UNREADABLE_FILE")
                continue
            if total_bytes + size > limits.max_total_bytes:
                reasons.add("BYTE_LIMIT_REACHED")
                truncated = True
                return
            total_bytes += size
            entries.append(
                WalkEntry(
                    absolute_path=child_path,
                    relative_posix=rel_posix(child_path),
                    size_bytes=size,
                    identity=_stat_identity(stat_result),
                )
            )

    recurse(root.resolved, 0)
    entries.sort(key=lambda e: e.relative_posix)
    return WalkOutcome(
        entries=tuple(entries),
        reparse_points_skipped=tuple(sorted(reparse_skipped)),
        unreadable_paths=tuple(sorted(unreadable)),
        special_files_skipped=tuple(sorted(special_files)),
        incompleteness_reasons=tuple(sorted(reasons)),
    )
