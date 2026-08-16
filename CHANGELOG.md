# Changelog

All notable changes to SkillGuard are documented here.

## v0.1.0 -- Unreleased release candidate

Initial build. Not tagged, not released, not yet independently audited.

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

READY FOR INDEPENDENT ADVERSARIAL AUDIT. No git tag, no GitHub release, no
PyPI publication yet.
