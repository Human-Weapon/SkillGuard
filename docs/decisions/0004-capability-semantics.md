# 0004: Capabilities are not verdicts

**Status:** Accepted

## Context

It is tempting to treat "this skill can make network connections" as
itself a security finding. In practice, most useful skills need at least
one of filesystem access, network access, or process spawning to do
anything at all. Conflating "has a powerful capability" with "is
malicious" produces a tool nobody can use without constant false alarms,
which in turn trains users to ignore its output.

## Decision

A `Finding` (evidence: "this pattern/behavior was observed") is a
different object from a `Capability` observation (normalized: "this
skill can do X"), which is again different from a `PolicyResult`
(verdict: "given *your* rules, is this acceptable"). `skillguard.policy`
never derives a verdict from capability presence alone -- only from
explicit, caller-configured `PolicyRule` conditions such as "block if
`network.outbound` was observed but not declared".

The default policy (`skillguard.policy.default_policy()`) blocks nothing.
A stricter example is provided separately
(`skillguard.policy.example_strict_policy()`) so adopting stricter
behavior is an explicit caller choice, not a surprise default.

## Consequences

- `skillguard audit` with no `--policy` never returns `BLOCK` on its own;
  it surfaces findings/capabilities for human review.
- Docs and CLI help must not describe any single capability as inherently
  unsafe. See the Critical Honesty Rule in the README.
