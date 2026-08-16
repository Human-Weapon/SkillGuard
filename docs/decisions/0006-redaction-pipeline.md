# 0006: One centralized redaction module, not per-observer redaction

**Status:** Accepted

## Context

If every observer (static secret scanner, process monitor, network
monitor, command runner) implements its own "don't leak the secret" logic,
it is only a matter of time before one of them forgets, especially as new
observers get added later.

## Decision

`skillguard.redaction` is the single place that knows how to fingerprint
(`fingerprint()`), safely truncate (`safe_prefix()`), and scrub known
values out of arbitrary text (`scrub_text()`). Every code path that might
write a caller-observed secret or canary value into a `Finding`,
`Evidence`, captured stdout/stderr, or a command-line record calls into
this module rather than reimplementing redaction locally. This is a
top-level module (`skillguard/redaction.py`), not nested under
`skillguard/dynamic/`, specifically so both the static secret scanner and
every dynamic observer import the same implementation.

## Consequences

- A single regression test suite
  (`tests/test_redaction.py::test_secret_never_appears_in_persisted_output`)
  can cover the invariant end-to-end: inject a synthetic secret into
  target stdout, run a full audit, and grep every persisted artifact for
  the raw value.
- Adding a new observer that touches potentially-sensitive text is a
  one-line `scrub_text()` call, not a new redaction implementation.
