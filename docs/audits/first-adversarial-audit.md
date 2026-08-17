# First independent adversarial audit

**Audited SHA:** `b96a65e2224bd97e3ca93018000d177090f3c13b`
**Verdict:** D -- NOT RELEASE READY
**Findings:** 1 P1, 10 P2, 2 P3 (AB-001 through AB-013)

This is a summary record of a real, independent adversarial audit this
project received before its first release candidate, and of the
remediation that followed. It is kept so the history is not lost: the
audit found and disclosed real defects, some of them security-relevant,
and this file exists so nobody later assumes the project was clean from
the start or reconstructs a rosier history than what actually happened.

## What the audit found

The audit exercised the real production code -- real Windows junctions,
real subprocesses, real loopback sockets, real hardlink/replacement races
coordinated with deterministic hooks, fresh wheel/sdist installs -- against
commit `b96a65e`. Its top-line findings:

- **AB-001 (P1):** a package-lifecycle-script static finding
  (`SG-MANIFEST-005`) interpolated the raw manifest value into
  `Finding.description`, so a synthetic secret placed in a `package.json`
  `postinstall` script was persisted to `findings.json` in cleartext, even
  though the dedicated secret scanner's own findings were correctly
  redacted.
- **AB-002 (P2):** `walk_tree()` did not enforce `BoundRoot.verify_unchanged()`
  before enumerating; a root replaced with a real junction after binding
  was still walked, enumerating outside content with no incompleteness
  signal.
- **AB-003 (P2):** file-level copy/hash/static-read operations reopened a
  pathname after the walk observed it, so a coordinated hardlink
  replacement between enumeration and read could put outside content into
  the workspace copy, into the content fingerprint, or into a static scan
  result.
- **AB-004 (P2):** a `DynamicWorkspace` constructor failure partway through
  copying could leave a partial temporary workspace -- including
  already-copied sensitive files -- on disk.
- **AB-005 (P2):** `FilesystemObserver` discarded `WalkOutcome.incompleteness_reasons`,
  so reparse-point/special-file/limit omissions during dynamic filesystem
  observation did not prevent a `COMPLETE` result.
- **AB-006 (P2):** `CommandRunner` captured stdout/stderr with unbounded
  `communicate()` before truncating, and truncation did not make the
  dynamic result incomplete.
- **AB-007 (P2):** a failure in observer/monitor setup (the
  `on_pid_available` callback) could leave the target process running and
  escape as a raw, undocumented exception.
- **AB-008 (P2):** invalid (non-UTF-8) Python source was treated the same
  as an intentionally-skipped binary file, producing a `COMPLETE` static
  result with no record that the file went unanalyzed.
- **AB-009 (P2):** malformed policy documents could raise a raw `TypeError`
  instead of `PolicyError`, and JSON string/int values could be silently
  coerced by Python truthiness (`"false"` truthy, `True == 1`).
- **AB-010 (P2):** `ResultStore.load()` validated only `audit.json`;
  corrupted or mismatched sibling artifacts (`findings.json`, etc.) were
  not detected, and JSON `NaN`/`Infinity` were accepted.
- **AB-011 (P2):** Windows filesystem name normalization (trailing
  dots/spaces, case-insensitive aliases, reserved-name-plus-extension)
  could make two distinct, individually-valid result IDs collide on disk.
- **AB-012 (P3):** the workspace copy and content-fingerprint resource
  limits diverged without documentation, so a file within the copy limit
  could still fail at the fingerprint gate.
- **AB-013 (P3):** decision record 0007 still described the original
  metadata-only fingerprint after the implementation had moved to
  SHA-256 content hashing.

Full detail, reproduction steps, and evidence for each finding are
preserved in the audit's own report (kept outside this repository,
alongside the remediation export, as working artifacts of the review
process rather than checked-in project history).

## Remediation

Every AB-* finding was independently reproduced against the audited
baseline before any fix was accepted (see the git history following
`b96a65e` and the commit messages under "Remediation Round 1"). A proposed
remediation was reviewed line-by-line rather than applied unread, and one
additional defect was found during that review that neither the original
audit nor the proposed remediation had caught:

- **SG-R1-NEW-001:** the first identity-checked file-read implementation
  compared `st_ctime_ns` for exact equality between a walk-time `lstat()`
  and a later `fstat()` on an open handle. On this project's Windows
  development host, an ordinary, completely untouched file's ctime as
  reported by a directory-entry query versus an open-handle `fstat()` can
  differ by up to roughly 60ms -- observed consistently for files written
  via a lock-file-then-rename pattern (exactly how `git config` writes
  `.git/config`). The exact-equality comparison therefore rejected
  legitimate, unmodified files at a real, reproducible rate (observed
  ~40% of runs in one isolated case). This was a reliability defect, not
  an exploitable security hole -- but severe enough that static scans and
  dynamic workspace setup would have been unacceptably flaky in normal
  use.

  Fixing it took three attempts, the first two of which were pushed and
  caught failing on real Ubuntu CI rather than assumed correct after
  passing locally on Windows:
  1. Widened the ctime comparison broadly (to 2 seconds) in the shared
     comparator. This let a genuine root-directory swap (delete and
     immediately recreate at the same path, real Linux tmpfs inode-reuse
     behavior) land inside the tolerance window and go undetected --
     defeating the exact defense an earlier round of hardening had added
     `st_ctime_ns` to provide in the first place.
  2. Reverted to an exact ctime comparison, applied everywhere identity
     is checked. This broke different, real Ubuntu CI jobs: a
     directory's own ctime changes on POSIX whenever a child entry is
     added or removed inside it, and `FilesystemObserver` before/after
     diffing plus repeated `ResultStore.save()` calls do exactly that as
     part of ordinary, correct operation -- so legitimate roots were
     rejected as "changed" the moment anything was written inside them.
  3. Final design: `skillguard.paths.identity_matches()` (used for
     root-swap detection, filesystem-snapshot diffing, and the pre-open
     file check) compares device+inode only and never ctime. A separate,
     narrowly-scoped `handle_identity_matches()` -- used only around the
     single open-handle verification in `open_walk_entry()`, where a file
     has no "children" whose creation could bump its own ctime -- carries
     a bounded 150ms ctime tolerance instead.

  Documented consequence of the final design (see SECURITY.md): a
  same-path directory replaced by a *different* plain directory that
  happens to reuse a just-freed inode number is no longer guaranteed
  detected. A junction/symlink-based replacement -- the realistic version
  of this attack, and the one the original AB-002 finding specifically
  demonstrated -- is still caught, both because device+inode differ in
  the overwhelming majority of cases and via the separate reparse-point
  check.

AB-003 remains classified **PARTIALLY FIXED**: the tested path-replacement
and hardlink vectors now fail closed, but no portable Python implementation
can provide an absolute snapshot guarantee against every privileged,
in-place, same-inode mutation or a race that wins after the final check.
This residual limitation is documented in SECURITY.md and is not claimed
away.

## Status after remediation

All 13 original findings have a recorded disposition (12 FIXED, 1
PARTIALLY FIXED with the residual limitation stated above) and one
implementer-found defect (SG-R1-NEW-001) was fixed. The candidate that
resulted from this remediation is intended for a **second** independent
adversarial audit before any release decision. See CHANGELOG.md and the
top-level build reports in the project's session history for exact
commit SHAs and CI run evidence.

**This project has not been released.** No tag, no GitHub Release, no PyPI
publication has occurred at any point covered by this record.
