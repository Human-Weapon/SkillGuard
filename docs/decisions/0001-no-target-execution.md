# 0001: Static analysis never executes the target

**Status:** Accepted

## Context

The most direct way to find out what a Python package does is to import
it. That is also the most direct way for a malicious package to run its
payload against the machine doing the scanning -- including during
`pip install`/build-backend hooks, which is a well-documented supply-chain
attack vector independent of SkillGuard.

## Decision

`skillguard.static` never imports, `exec`s, or otherwise runs code from the
scan target. It only:

- reads file bytes,
- calls `ast.parse()` on Python source,
- calls `tomllib.loads()` / `json.loads()` on manifest text.

It never calls `pip install`, never invokes a PEP 517 build backend, never
uses `importlib` against target modules, and never triggers `setup.py`.

## Consequences

- Static findings are pattern matches on syntax, not proof of runtime
  behavior. A dynamic-code-execution finding (`SG-PY-004`/`005`/`006`) does
  not mean the code definitely ran maliciously -- only that the primitive
  is present in source.
- Some malicious behavior hidden behind heavy obfuscation or requiring
  actual execution to manifest will only be visible to dynamic analysis
  (`skillguard.dynamic`), which is opt-in and explicitly not a sandbox
  (see SECURITY.md).
- Regression test: `tests/test_no_target_import.py` uses a fixture package
  whose import would create a marker file, and asserts `skillguard scan`
  never causes that marker to appear.
