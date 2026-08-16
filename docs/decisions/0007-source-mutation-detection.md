# 0007: Metadata fingerprint, not content hash, for source mutation detection

**Status:** Accepted

## Context

`DynamicWorkspace` copies the caller's source tree before running a
target command, so the original is never mutated by the run itself, and
verifies that assumption afterward. The verification needs to be cheap
enough to run on every dynamic audit without meaningfully slowing it
down, even for moderately large targets.

## Decision

`skillguard.dynamic.workspace._fingerprint()` walks the source tree (via
the same containment-safe `walk_tree()` used everywhere else) and builds a
fingerprint from `(relative_path, size_bytes, mtime_ns)` tuples, not from
file content hashes.

## Consequences

- This is a deliberate accuracy/cost tradeoff: a same-size content edit
  that also happens to preserve the filesystem's mtime resolution could
  theoretically go undetected. On the filesystems and mtime resolutions
  SkillGuard targets (NTFS, ext4, etc., all sub-second resolution), this
  requires an adversary to both edit the file and reset its mtime to the
  exact original value, which is a deliberate, hostile act rather than an
  accidental one.
- If a future version needs a stronger guarantee, `_fingerprint()` is the
  single place to swap in content hashing, at the cost of reading every
  file in the source tree on every dynamic run.
- This module is documented as an integrity *check*, not a security
  boundary: SkillGuard does not claim it prevents concurrent mutation,
  only that it detects the mutations its fingerprint function can see.
