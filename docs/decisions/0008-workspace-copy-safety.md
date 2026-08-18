# 0008: Workspace copy never follows symlinks/junctions, never uses `shutil.copytree`

**Status:** Accepted (supersedes the copytree-based approach from the
initial v0.1.0 candidate)

## Context

The first implementation of `DynamicWorkspace` copied the source tree with
`shutil.copytree(src, dst, symlinks=False, ...)`. Per the stdlib docs,
`symlinks=False` means symlinks in the source are **dereferenced** during
the copy -- the contents of whatever they point to are copied into the
destination as ordinary files. A source tree containing a symlink or
Windows junction pointing outside the scan target (e.g.
`source/external_link -> /etc` or a junction to another user's directory)
would therefore have that outside content copied straight into the
dynamic-analysis workspace, silently defeating the "target only sees its
own tree" boundary `DynamicWorkspace` exists to provide. This was caught
during pre-audit hardening, not by the original test suite -- the original
symlink tests exercised `StaticScanner`'s walker, not the separate copy
path `DynamicWorkspace` used.

## Decision

`DynamicWorkspace` no longer calls `shutil.copytree` at all. It uses
`skillguard.paths.walk_tree()` -- the same containment-safe walker the
static scanner and result persistence use -- to enumerate only regular
files, and copies each one individually from an identity-checked file
handle. The copy path does not reopen an unchecked pathname or follow a
symlink/junction replacement between enumeration and read.
`walk_tree()` never descends into a symlink/junction/reparse-point
directory and never returns a symlinked file as a regular entry, so
outside content can never enter the copy through a link that existed in
the source tree. Skipped reparse points are recorded (`reparse_points_skipped`)
and surfaced as `Evidence` + a `REPARSE_POINT_SKIPPED` incompleteness
reason on the resulting `DynamicResult`, mirroring how the static scanner
surfaces the same finding (`SG-PATH-001`) -- this is "omit and report" (option
B from the hardening spec), not "reject the whole audit", so a skill with
an unrelated internal symlink can still be analyzed, just without that
one entry.

The same walker also backs the source-mutation fingerprint (see
0007, superseded in part by this decision -- see below), so both
"what gets copied" and "what gets fingerprinted" share one containment
boundary instead of two independently-implemented ones that could drift
out of sync.

## Update (second remediation round, SG2-001)

The description above ("enumerate via `walk_tree()`, then copy each file
from an identity-checked handle") described a two-phase design: walk
fully to a list of paths, then reopen each one later by its remembered
path string. The second independent audit found that phase separation was
itself exploitable -- an ancestor directory (not the file, not the root)
replaced by a real junction *during* the walk, after its parent's listing
had already accepted it, let the walk silently descend into the redirected
target with self-consistent identities, leaving nothing for the later
reopen to catch (SG2-001).

`_safe_copy_tree` (and `_content_fingerprint`) now call
`skillguard.paths.walk_tree_and_read()` instead of `walk_tree()` followed
by a separate per-entry reopen: each file is opened and copied/hashed
atomically, in the same traversal step that discovered it, while the
directory holding it (and every ancestor above it still being traversed)
is still open and thus still deny-delete-locked on Windows / addressed by
a still-valid `dir_fd` on POSIX. See SECURITY.md's "Path containment"
section for the full mechanism. The core decision above -- no
`shutil.copytree`, no following symlinks/junctions, one shared walker
backing both copy and fingerprint -- is unchanged; only the walk-then-read
phase separation was replaced with an atomic walk+read.

## Consequences

- Empty directories with no files anywhere under them are not recreated in
  the copy (the walker only enumerates files). Accepted for v0.1.0: this
  affects layout fidelity, not the security boundary, and most executable
  skill code doesn't depend on pre-existing empty directories.
- A source tree exceeding the dedicated copy limits (`_COPY_LIMITS` in
  `workspace.py`) raises `ObservationError` rather than silently copying a
  truncated subset -- consistent with spec section 9/70 (never silently
  truncate and still claim completeness).
- Regression tests: `tests/test_dynamic_workspace.py` constructs a real
  `DynamicWorkspace` against a source tree containing a real POSIX symlink
  (Ubuntu CI) / Windows junction (Windows CI) pointing at a directory with
  a sentinel file, and asserts the sentinel's content never appears
  anywhere under the copy.
