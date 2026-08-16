# 0002: Roots bind to an absolute path at construction time

**Status:** Accepted

## Context

A prior project in this ecosystem shipped a bug class where a relative
output/scan root was resolved lazily against `os.getcwd()` at write time
rather than at construction time. Any code path that called
`os.chdir()` between constructing the store/scanner and using it silently
changed where results were read from or written to -- a correctness bug
that is also a security-relevant containment bug, since it can redirect
writes outside the directory the caller believed they'd bound.

## Decision

`skillguard.paths.BoundRoot.bind()` / `.bind_output()` resolve a
caller-supplied path to an absolute, symlink-free (`os.path.realpath`)
path exactly once, at construction time, and store only that resolved
`Path`. No later method call re-derives the root from the *current*
working directory. Every scanner, observer, and the `ResultStore`
construct their root through `BoundRoot` and only ever operate on
`root.resolved`.

## Consequences

- `os.chdir()` after constructing a `BoundRoot` cannot rebind it.
- Regression test: `tests/test_paths.py::test_cwd_drift_does_not_rebind_root`
  constructs a `BoundRoot` with a relative path, changes `cwd`, and asserts
  writes still land under the originally-resolved location.
- Residual limitation: this defends against *drift*, not against a
  privileged racer replacing the directory at `root.resolved` after
  binding. `BoundRoot.verify_unchanged()` (device/inode identity check)
  narrows that separate TOCTOU window; it does not close it. See
  SECURITY.md.
