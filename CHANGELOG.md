# Changelog

All notable changes to SkillGuard are documented here.

## v0.1.0 -- Unreleased release candidate

Initial build, followed by a remediation pass after the project's first
independent adversarial audit. Not tagged, not released.

### Changed (remediation round 1, post first independent audit)

The first independent adversarial audit (see
`docs/audits/first-adversarial-audit.md`) returned verdict **D -- NOT
RELEASE READY** against commit `b96a65e`, with 1 P1 and 10 P2 findings.
Every finding was independently reproduced against that baseline before
being fixed:

- Manifest-derived findings (lifecycle scripts, dependency strings, parse
  errors) now route through the same redaction boundary as detected
  secrets, instead of interpolating untrusted manifest text verbatim into
  `Finding.description` (AB-001, P1).
- `walk_tree()` now enforces bound-root identity before and during
  enumeration; a root replaced with a symlink/junction after binding is
  rejected with an explicit `ROOT_CHANGED` reason instead of being walked
  (AB-002).
- File reads (static scanning, workspace copying, content fingerprinting)
  now open through an identity-checked handle (`open_walk_entry`) that
  fails closed if the path was replaced between enumeration and read,
  using `O_NOFOLLOW` on POSIX and a pre/post-open device+inode+ctime check
  everywhere (AB-003, partially fixed -- see SECURITY.md for the residual
  TOCTOU limitation).
- `DynamicWorkspace` construction now cleans up its temporary directory on
  every setup failure, including a failure partway through copying
  (AB-004).
- Filesystem-observation omissions (reparse points, special files, limits,
  vanished/replaced entries) now propagate into `DynamicResult`
  incompleteness instead of being silently discarded (AB-005).
- `CommandRunner` now drains stdout/stderr through bounded reader threads
  instead of unbounded `communicate()`, and truncation now marks dynamic
  analysis incomplete with evidence (AB-006).
- Observer/monitor setup failures now terminate the target process tree
  and raise a typed `DynamicAnalysisError` instead of leaking a raw
  exception with the target still running (AB-007).
- Static scanning now distinguishes an intentionally-skipped binary file
  from a text-like file with an unsupported encoding, recording
  `UNSUPPORTED_ENCODING` for the latter instead of silently treating it as
  binary (AB-008).
- Policy and capability-manifest parsing now use strict type checks
  (rejecting `bool`-as-`int`, JSON string booleans, wrong container types)
  and always raise `PolicyError`/`ValidationError` rather than a raw
  `TypeError` (AB-009).
- `ResultStore.save()`/`load()` now write a per-artifact SHA-256 hash
  manifest into `audit.json` (written last, as a commit marker) and
  validate every sibling artifact's hash, schema, and nested record shapes
  on load; strict JSON parsing rejects `NaN`/`Infinity` (AB-010).
- Result IDs are validated against Windows filesystem normalization
  (trailing dots/spaces, reserved-name-plus-extension, case-insensitive
  collisions with existing entries), not just lexical traversal (AB-011).
- Workspace copy and content-fingerprint limits are now the same contract
  instead of silently divergent constants (AB-012).
- Decision record 0007 now describes the actual content-hash fingerprint
  implementation (AB-013).
- Found during remediation review (not part of the original audit,
  SG-R1-NEW-001), and requiring two follow-up fixes after each one broke
  real Ubuntu CI in a different way: the first identity-check
  implementation compared `st_ctime_ns` for exact equality between a
  walk-time `lstat()` and a later `fstat()` on an open handle, which is
  not reliably stable across different Win32 stat code paths on this
  project's Windows host (observed real, reproducible false-positive
  "file changed" rejections of unmodified files, especially files written
  via a lock-file-then-rename pattern such as `git config`). A first fix
  widened the ctime comparison broadly, which then let a genuine root
  swap through on Linux; a second attempt kept the comparison exact but
  applied it everywhere, which then made `identity_matches()` reject a
  root the moment anything legitimate was written inside it, since a
  directory's own ctime changes on POSIX whenever a child entry is
  added or removed -- exactly what `FilesystemObserver` before/after
  diffing and repeated `ResultStore.save()` calls do as part of normal
  operation. The final design: `identity_matches()` (root-swap detection,
  filesystem-snapshot diffing, the pre-open file check) compares
  device+inode only and never ctime; a separate, narrowly-scoped
  `handle_identity_matches()`, used only around a single file-open call,
  carries a bounded (150ms) ctime tolerance where that jitter actually
  occurs. Documented consequence: a same-path directory replaced by a
  different plain directory that happens to reuse a just-freed inode
  number is no longer guaranteed detected (a junction/symlink-based
  replacement still is). See SECURITY.md's path-containment section.

### Changed (remediation round 2, post second independent audit)

The second independent adversarial audit (see
`docs/audits/second-adversarial-audit.md`) returned verdict **D -- NOT
RELEASE READY** against commit `083629e`, with 1 P1 and 4 P2 and 1 P3 new
findings, plus AB-003 (round 1) reconfirmed still partially open. Every
finding was independently reproduced against that baseline before being
fixed:

- Directory traversal now routes every directory entered and every file
  opened through one shared, atomic walk+read engine, closing an ancestor
  directory (not root, not leaf file) that could previously be replaced by
  a real junction/symlink *during* a walk and have its redirected content
  silently read/copied/fingerprinted as if it were part of the bound root
  (SG2-001, P1). POSIX closes this structurally via `dir_fd`/`openat()`;
  Windows via `CreateFileW` handles that deny write/delete to other
  processes for as long as they're held. This also completes AB-003 (round
  1), moving it from partially fixed to fully fixed. Two implementer-found
  defects in this engine (SG-R2-NEW-001: a stray POSIX FIFO could hang the
  walk indefinitely; SG-R2-NEW-002: leaf-file identity was captured too
  late to close the intended window on POSIX) were both found via real
  Ubuntu CI runs, fixed, and re-verified green before this round shipped
  -- see `docs/audits/second-adversarial-audit.md`.
- `CommandRunner`'s configured `--timeout` now bounds the whole execution
  lifecycle -- a descendant process that inherits stdout/stderr and keeps
  it open after the direct target process exits no longer defeats the
  timeout. POSIX process groups / a Windows Job Object give deterministic,
  non-racy whole-tree cleanup, which now also runs on the normal-exit path,
  not only on an actual timeout (SG2-002).
- `DynamicWorkspace.verify_source_unchanged()` now always runs after a
  dynamic run, on every completion path -- success, a target-side failure,
  an observer/monitor setup or runtime failure, or any other unexpected
  exception -- so an observer failure can no longer make a mutated source
  look integrity-clean by preventing verification from running (SG2-003).
- Secret-*shaped* content embedded in a target-controlled filename/path
  component (not just file content) is now redacted before reaching any
  `Finding`/`Evidence` field, persisted artifact, or `--json` output
  (SG2-004).
- `--json` combined with `--output` no longer writes a human-readable
  banner line to stdout before the JSON document; stdout is the JSON
  document and nothing else (SG2-005).
- Invalid UTF-8 in captured dynamic stdout/stderr is still decoded safely
  for display, but now marks the result incomplete
  (`OUTPUT_ENCODING_LOSS`) instead of silently reporting `COMPLETE` for an
  observation that was not byte-for-byte faithful (SG2-006).

### Changed (remediation round 3, post third independent audit)

The third independent adversarial audit ("Daybreak Blue", see
`docs/audits/third-daybreak-adversarial-audit.md`) returned verdict **C --
FIX BEFORE PROMOTION** against commit `bce5aa11`, with 3 P2 and 1 P3 new
findings, plus a Round 2 regression (SG-R2-NEW-002) reclassified NOT
VERIFIED and a `setsid()` process-group escape question left unresolved
for lack of a POSIX test runtime. Every finding was independently
reproduced against that baseline before being fixed:

- The secret-shaped-path redaction boundary now also covers
  `AuditResult.target`, a dynamic run's filesystem-diff paths, policy
  outcome reasons, and CLI error messages for expected domain failures --
  not only `Finding`/`Evidence`, which Round 2's SG2-004 fix covered.
  Redaction happens at the serialization/CLI-output boundary itself, so
  target-controlled secret-shaped text cannot leak into a persisted or
  printed artifact merely because it never passed through a `Finding` or
  `Evidence` object (SG3-001).
- `--json` invocations of `scan`/`run`/`audit` now produce a defined,
  parseable JSON error document (`{"ok": false, "error": {...}}`) for
  expected domain failures (missing target, invalid output root, invalid
  policy/config, invalid dynamic invocation, a runtime-start failure),
  instead of empty stdout and a human-only stderr message. `json.loads(stdout)`
  now succeeds on every documented `--json` path, not only success/policy-
  block/incomplete (SG3-002).
- A source mutation discovered after a dynamic run has already completed
  no longer discards that run's own security-relevant facts (a timeout,
  output truncation, an encoding-loss flag, a monitor failure): the
  completed `DynamicResult` is now attached to the raised
  `SourceMutationError` and recovered by the auditor, so both the
  mutation and the other fact(s) stay observable together, while the
  overall result still reads as `FAILED`, never a clean `COMPLETE`
  (SG3-003).
- Dynamic output encoding-loss classification (`OUTPUT_ENCODING_LOSS`,
  added in Round 2's SG2-006) now uses strict UTF-8 decoding with
  `UnicodeDecodeError` inspection instead of searching decoded text for
  the U+FFFD replacement character: a target legitimately emitting a
  valid literal U+FFFD is no longer misflagged, and a valid multibyte
  character bisected solely by SkillGuard's own output-retention cap is
  now correctly `OUTPUT_TRUNCATED` rather than `OUTPUT_ENCODING_LOSS`
  (SG3-004).
- POSIX directory-entry identity (used to detect a leaf file replaced
  between listing and open) is now captured with zero syscall gap from
  the listing itself, via `os.DirEntry.inode()` instead of a separate
  `os.lstat()` call per entry -- closing the narrower gap a third-audit
  code review found still open in Round 2's SG-R2-NEW-002 fix, which had
  only closed a coarser version of the same problem. Windows keeps its
  existing per-entry `os.lstat()` design and deny-write handle defense.
- A POSIX descendant that escapes this run's process group via
  `setsid()` is still reached and killed directly by PID via the
  supplementary process tracker whenever that tracker observes the PID
  in time; when it cannot confirm a tracked descendant's termination
  (e.g. an escape fast enough to evade the tracker entirely), that is now
  reported as a new `PROCESS_CLEANUP_INCOMPLETE` incompleteness reason
  with matching evidence, instead of the run silently reading as fully
  cleaned up. SkillGuard's own run lifecycle was already bounded
  regardless of this escape and remains so; complete containment of a
  sufficiently fast double-fork is not achievable from user space and is
  not claimed.

### Added

- Static analysis: AST-aware Python rule engine, manifest inspection
  (`pyproject.toml`/`requirements*.txt`/`package.json`), conservative
  secret detection with redaction.
- Dynamic observation: argv/`shell=False` command execution contract,
  isolated workspace copy, process-tree/filesystem/network/git observers,
  process-tree-aware timeout termination, secret canary support.
- Capability manifest model and declared-vs-observed comparison
  (`DECLARED` / `OBSERVED` / `UNDECLARED_OBSERVED` / `DECLARED_NOT_OBSERVED`
  / `UNSUPPORTED_OBSERVATION`).
- Small, data-only policy engine (`PASS`/`WARN`/`BLOCK`/`REVIEW_REQUIRED`),
  kept separate from findings.
- Atomic, schema-validated JSON persistence (`ResultStore`) with corrupt-data
  rejection.
- CLI: `scan`, `run`, `audit`, `validate-manifest`, `report`, `rules`.
- Path containment primitives (`BoundRoot`, reparse-point-aware directory
  walk) shared by static scanning and result persistence.
- Centralized secret/canary redaction pipeline.

### Status

READY FOR A THIRD INDEPENDENT ADVERSARIAL AUDIT. No git tag, no GitHub
release, no PyPI publication yet.
