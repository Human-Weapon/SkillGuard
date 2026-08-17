# 0007: Content fingerprint for source mutation detection

**Status:** Accepted

## Context

`DynamicWorkspace` copies the caller's source tree before running a target
command, so the original is never mutated by the run itself, and verifies
that assumption afterward. The check must detect same-size edits whose
mtime is restored, while still using bounded streaming reads rather than
loading whole files into memory.

## Decision

`skillguard.dynamic.workspace._content_fingerprint()` walks the source tree
(via the same containment-safe `walk_tree()` used everywhere else) and
builds a deterministic `(relative_path, sha256_hex)` tuple for every
regular file. Each file is opened through the walk entry's identity check,
so replacement or hard-link races fail closed instead of hashing a
different path target. Fingerprinting and copying use the same
`WalkLimits` contract.

## Consequences

- This is stronger than a metadata-only check and deliberately reads every
  accounted-for file on each dynamic run. Reads are streamed in fixed-size
  chunks and bounded by the shared workspace limits.
- The fingerprint is an integrity check, not a sandbox or an absolute
  concurrency guarantee. Handle/identity checks close the replacement and
  hard-link cases covered by the workspace boundary; a sufficiently
  privileged local attacker can still race filesystem operations outside
  those guarantees.
