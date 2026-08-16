# 0003: Rule ID scheme

**Status:** Accepted

## Decision

Static rule IDs use `SG-<CATEGORY>-<NNN>`: `SG-PY-*` (Python AST rules),
`SG-SECRET-*` (secret detection), `SG-MANIFEST-*` (manifest inspection),
`SG-PATH-*` (containment-related observations, e.g. a symlink found in the
scan target). `NNN` is a zero-padded, monotonically assigned sequence
number within its category, assigned once and never reused or renumbered.

All rule IDs are registered in `skillguard/static/rules.py` and documented
in `docs/rules/README.md`. A rule ID's *meaning* never changes after
release; if a detector's behavior needs to change incompatibly, it gets a
new ID and the old one is marked deprecated in the docs rather than
repurposed.

## Consequences

- Rule ID assignment does not depend on scan order, file order, or
  directory traversal order -- it is a static table, not derived at scan
  time. See spec section 14 / 73 (scan determinism).
- Suppressions (`skillguard.policy.Suppression`) reference rule IDs
  directly, so they remain stable across SkillGuard versions as long as
  the rule itself isn't deprecated.
