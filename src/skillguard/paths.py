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
import errno
import os
import stat as stat_module
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from skillguard.errors import ObservationError, PathSecurityError, ValidationError
from skillguard.validation import validate_non_negative_int

_REPARSE_POINT = getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_IS_WINDOWS = os.name == "nt"

if _IS_WINDOWS:  # pragma: no cover - exercised only on Windows CI
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _GENERIC_READ = 0x80000000
    _FILE_SHARE_READ = 0x00000001
    _OPEN_EXISTING = 3
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def _win_open_secure_fd(path: str) -> int:
        """Open ``path`` via CreateFileW WITHOUT following a final-component
        reparse point (the Win32 equivalent of POSIX O_NOFOLLOW), sharing
        only READ with other processes -- i.e. denying WRITE and DELETE for
        as long as this handle stays open. That denial is a structural
        guarantee, not a timing one: while SkillGuard holds this handle,
        no other process can rename, delete, or junction-replace this exact
        filesystem entry (Windows returns ERROR_SHARING_VIOLATION for the
        attempt). FILE_FLAG_BACKUP_SEMANTICS is required to open a
        directory at all via CreateFileW and is harmless for files.
        FILE_FLAG_OPEN_REPARSE_POINT means a junction/symlink is opened as
        itself (never silently traversed) so classification happens on the
        real target of this open, atomically, with no separate check step
        that a swap could land between."""
        handle = _kernel32.CreateFileW(
            path,
            _GENERIC_READ,
            _FILE_SHARE_READ,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle in (0, _INVALID_HANDLE_VALUE):
            err = ctypes.get_last_error()
            raise OSError(err, ctypes.FormatError(err), path)
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY)
        return fd


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


class _ReparsePointError(Exception):
    """Raised internally when an entry turned out to be a symlink/reparse
    point at the moment it was atomically opened."""


def _open_entry_secure(name: str, dir_fd: int | None, dir_path: Path) -> tuple[str, int]:
    """Atomically open the direct child ``name`` of an already-verified,
    currently-held directory, WITHOUT following a final-component
    symlink/junction, and classify it (``"dir"`` or ``"file"``) from the
    resulting handle's own fstat -- never from a separate, racy pre-check
    against a path string. This is the seam SG2-001 exploited: any design
    that checks "is this a reparse point / what does this resolve to" and
    THEN separately opens/lists it by path leaves a gap for the entry to be
    swapped in between. Open-then-classify-the-handle has no such gap.

    Returns ``(kind, fd)`` with an OPEN fd the caller owns (must close it,
    or hand it to ``os.fdopen`` which takes ownership). Raises
    ``_ReparsePointError`` if the entry is currently a symlink/reparse
    point; propagates other ``OSError``s (e.g. the entry vanished).
    """
    if _IS_WINDOWS:  # pragma: no cover - exercised only on Windows CI
        try:
            fd = _win_open_secure_fd(str(dir_path / name))
        except OSError as exc:
            raise ObservationError(f"could not open {dir_path / name}: {exc}") from exc
        st = os.fstat(fd)
        if getattr(st, "st_file_attributes", 0) & _REPARSE_POINT:
            os.close(fd)
            raise _ReparsePointError(name)
        return ("dir" if stat_module.S_ISDIR(st.st_mode) else "file"), fd

    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise _ReparsePointError(name) from exc
        raise
    st = os.fstat(fd)
    if stat_module.S_ISLNK(st.st_mode):
        os.close(fd)
        raise _ReparsePointError(name)
    return ("dir" if stat_module.S_ISDIR(st.st_mode) else "file"), fd


def _open_root_secure(root: BoundRoot) -> int | None:
    """Open ``root.resolved`` itself the same atomic, non-follow way.
    Returns ``None`` (never raises) if the root is currently missing or a
    reparse point -- callers treat that as ``ROOT_CHANGED``."""
    try:
        if _IS_WINDOWS:  # pragma: no cover - exercised only on Windows CI
            fd = _win_open_secure_fd(str(root.resolved))
        else:
            fd = os.open(root.resolved, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    st = os.fstat(fd)
    if _IS_WINDOWS:  # pragma: no cover - exercised only on Windows CI
        is_reparse = bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)
    else:
        is_reparse = stat_module.S_ISLNK(st.st_mode)
    if is_reparse:
        os.close(fd)
        return None
    return fd


def _pre_open_identity(
    name: str, dir_fd: int | None, dir_path: Path
) -> tuple[int, int, int] | None:
    """Best-effort identity of ``name`` as currently listed, without
    opening it. Returns ``None`` (never raises) if it cannot be stat'd --
    the atomic open immediately afterward is the authoritative check in
    that case; this is purely an extra, narrow-window comparison."""
    try:
        if _IS_WINDOWS:  # noqa: SIM108 - if/else kept so the pragma below scopes to one platform
            st = os.lstat(dir_path / name)  # pragma: no cover - exercised only on Windows CI
        else:
            st = os.lstat(name, dir_fd=dir_fd)
    except OSError:
        return None
    return _stat_identity(st)


def _list_names_secure(dir_fd: int, dir_path: Path) -> list[str]:
    """List the direct children of the already-open, already-verified
    current directory. POSIX scans the held fd directly (no path
    re-resolution at all). Windows has no fd-relative directory listing in
    the Win32 API surface Python exposes, so it lists by path -- safe here
    specifically because the caller is holding a deny-write/deny-delete
    handle on this exact directory (and on every ancestor above it still
    being traversed), which structurally prevents this directory from
    being renamed/replaced out from under that path string while the
    handle is held."""
    if _IS_WINDOWS:  # pragma: no cover - exercised only on Windows CI
        names = [e.name for e in os.scandir(str(dir_path))]
    else:
        names = [e.name for e in os.scandir(dir_fd)]
    return names


class _SecureWalker:
    """Shared traversal engine behind :func:`walk_tree` and
    :func:`walk_tree_and_read`. Every directory entered and every file
    opened is verified and opened as ONE atomic operation via
    :func:`_open_entry_secure`/:func:`_open_root_secure` -- see those
    functions' docstrings for why that atomicity, not just doing the check
    "close in time" to the use, is what actually closes the ancestor-swap
    TOCTOU (SG2-001). Directory handles are held open for the entire time
    their subtree is being traversed and are only closed when recursion
    backtracks past them, so on Windows the whole currently-active ancestor
    chain is deny-delete-locked for as long as it is in use, not just the
    directory being immediately read.
    """

    def __init__(
        self,
        root: BoundRoot,
        limits: WalkLimits,
        on_file: Callable[[WalkEntry, BinaryIO], None] | None,
    ) -> None:
        self.root = root
        self.limits = limits
        self.on_file = on_file
        self.entries: list[WalkEntry] = []
        self.reparse_skipped: list[str] = []
        self.unreadable: list[tuple[str, str]] = []
        self.special_files: list[str] = []
        self.reasons: set[str] = set()
        self.total_bytes = 0
        self.truncated = False

    def run(self) -> WalkOutcome:
        if not self.root.verify_unchanged() or is_reparse_point(self.root.resolved):
            return WalkOutcome((), (), (), (), ("ROOT_CHANGED",))
        root_fd = _open_root_secure(self.root)
        if root_fd is None:
            return WalkOutcome((), (), (), (), ("ROOT_CHANGED",))
        try:
            st = os.fstat(root_fd)
            current_identity = _stat_identity(st)
            snapshot = self.root._identity_snapshot
            if snapshot is None or not identity_matches(current_identity, snapshot):
                return WalkOutcome((), (), (), (), ("ROOT_CHANGED",))
            self._recurse(root_fd, self.root.resolved, "", 0)
        finally:
            os.close(root_fd)
        self.entries.sort(key=lambda e: e.relative_posix)
        return WalkOutcome(
            entries=tuple(self.entries),
            reparse_points_skipped=tuple(sorted(self.reparse_skipped)),
            unreadable_paths=tuple(sorted(self.unreadable)),
            special_files_skipped=tuple(sorted(self.special_files)),
            incompleteness_reasons=tuple(sorted(self.reasons)),
        )

    def _recurse(self, dir_fd: int, dir_path: Path, rel_prefix: str, depth: int) -> None:
        if self.truncated:
            return
        try:
            names = sorted(_list_names_secure(dir_fd, dir_path))
        except OSError as exc:
            self.unreadable.append((str(dir_path), str(exc)))
            self.reasons.add("UNREADABLE_FILE")
            return

        for name in names:
            if self.truncated:
                return
            child_rel = rel_prefix + name
            child_display_path = dir_path / name
            # A lightweight "as listed" identity, captured immediately
            # before the atomic open below. Directories are already
            # structurally protected against ancestor replacement (held
            # dir_fd on POSIX; deny-write/deny-delete handle on Windows --
            # see _open_entry_secure), but an individual FILE can still be
            # unlinked and replaced (e.g. with a hardlink to different
            # content) without touching its parent directory's own
            # delete permission. This narrows that residual to the two
            # adjacent syscalls below instead of leaving it open for
            # however long a caller takes to get around to reading the
            # entry (which is exactly the SG2-001 class this walker
            # closes for ancestors). See AB-003 in docs/audits.
            pre_open_identity = _pre_open_identity(name, dir_fd, dir_path)
            try:
                kind, fd = _open_entry_secure(name, dir_fd, dir_path)
            except _ReparsePointError:
                self.reparse_skipped.append(child_rel)
                self.reasons.add("REPARSE_POINT_SKIPPED")
                continue
            except (OSError, ObservationError) as exc:
                self.unreadable.append((str(child_display_path), str(exc)))
                self.reasons.add("UNREADABLE_FILE")
                continue

            if kind == "dir":
                try:
                    if depth + 1 > self.limits.max_depth:
                        self.reasons.add("MAX_DEPTH_REACHED")
                    else:
                        self._recurse(fd, child_display_path, child_rel + "/", depth + 1)
                finally:
                    os.close(fd)
                continue

            try:
                st = os.fstat(fd)
            except OSError as exc:
                os.close(fd)
                self.unreadable.append((str(child_display_path), str(exc)))
                self.reasons.add("UNREADABLE_FILE")
                continue

            if not stat_module.S_ISREG(st.st_mode):
                os.close(fd)
                self.special_files.append(child_rel)
                self.reasons.add("SPECIAL_FILE_SKIPPED")
                continue

            current_identity = _stat_identity(st)
            if pre_open_identity is not None and not identity_matches(
                current_identity, pre_open_identity
            ):
                os.close(fd)
                self.unreadable.append(
                    (str(child_display_path), "file identity changed between listing and open")
                )
                self.reasons.add("UNREADABLE_FILE")
                continue

            size = st.st_size
            if len(self.entries) >= self.limits.max_files:
                os.close(fd)
                self.reasons.add("FILE_LIMIT_REACHED")
                self.truncated = True
                return
            if self.total_bytes + size > self.limits.max_total_bytes:
                os.close(fd)
                self.reasons.add("BYTE_LIMIT_REACHED")
                self.truncated = True
                return

            self.total_bytes += size
            entry = WalkEntry(
                absolute_path=child_display_path,
                relative_posix=PurePosixPath(child_rel).as_posix(),
                size_bytes=size,
                identity=_stat_identity(st),
            )
            self.entries.append(entry)

            if self.on_file is not None:
                fh = os.fdopen(fd, "rb")  # takes ownership of fd
                try:
                    self.on_file(entry, fh)
                finally:
                    fh.close()
            else:
                os.close(fd)


def walk_tree(root: BoundRoot, limits: WalkLimits) -> WalkOutcome:
    """Deterministically walk ``root`` (a directory that must already have
    been validated to exist), never descending into symlinks or reparse
    points, and honoring hard resource limits. Metadata only -- does not
    read file content (see :func:`walk_tree_and_read` for that).

    Traversal order is sorted by name at every level so results are
    reproducible across filesystems/platforms with identical content.

    Every directory entered and every file classified goes through one
    atomic open+classify step (see :class:`_SecureWalker`), so an ancestor
    replaced by a symlink/junction *during* the walk -- not just before or
    long after it -- cannot cause this function to silently walk into,
    and report identities for, content outside ``root`` (SG2-001).
    """
    return _SecureWalker(root, limits, on_file=None).run()


def walk_tree_and_read(
    root: BoundRoot,
    limits: WalkLimits,
    on_file: Callable[[WalkEntry, BinaryIO], None],
) -> WalkOutcome:
    """Like :func:`walk_tree`, but for every regular file found, opens it
    (via the same atomic, currently-held-ancestor-chain seam) and invokes
    ``on_file(entry, fh)`` with a fresh, already-verified handle -- before
    moving on to the next entry, while the containing directory (and every
    ancestor above it still being traversed) is still open and thus still
    deny-delete-locked on Windows / addressed by a still-valid dir_fd on
    POSIX.

    This is the shared boundary StaticScanner and DynamicWorkspace's copy
    and fingerprint operations must use for reading scan-target content:
    the previous design (walk fully to a list of paths, then reopen each
    path much later by its absolute path string) left exactly the gap
    SG2-001 exploited -- by the time of that later reopen, an ancestor
    could have been replaced, and the replacement's contents would be
    consumed with no discrepancy for a same-path identity check to catch,
    because nothing about that later reopen was tied to the moment the
    entry was actually discovered.

    ``on_file`` must not retain ``fh`` past the call -- it is closed
    immediately afterward.
    """
    return _SecureWalker(root, limits, on_file=on_file).run()
