# 0005: Per-capability observability matrix

**Status:** Accepted

## Context

Not every declared capability can actually be checked. `environment.read`
is the clearest example: there is no supported mechanism in v0.1.0 that
tells SkillGuard which environment variables a target process actually
read (as opposed to merely could read). Reporting `DECLARED_NOT_OBSERVED`
for that capability in the same way as, say, `network.outbound` (which
*is* observable, just imperfectly) would misleadingly imply symmetrical
confidence.

## Decision

`skillguard.capabilities.OBSERVABILITY_MATRIX` maps every `Capability` to
the observation mechanisms that can support it: `STATIC_SUPPORTED`,
`DYNAMIC_SUPPORTED`, `BEST_EFFORT`, or `UNSUPPORTED`. This is exposed in
reports as `unsupported_observation`, distinct from `declared_not_observed`.

## Consequences

- A capability that is `UNSUPPORTED` for observation should never be
  reported as "not observed, therefore likely absent" -- the report
  language makes clear this is a tooling gap, not a finding.
- Extending observability (e.g., adding a supported mechanism for
  `environment.read`) means updating this matrix and is itself a
  documented, reviewable change.
