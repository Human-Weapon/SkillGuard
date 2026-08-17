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

READY FOR A SECOND INDEPENDENT ADVERSARIAL AUDIT. No git tag, no GitHub
release, no PyPI publication yet.
