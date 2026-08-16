# Contributing to SkillGuard

Thanks for considering a contribution. SkillGuard is a young (v0.1.0,
pre-audit) project; expect the internals to still be settling.

## Setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   POSIX: source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a PR

```bash
ruff check .
ruff format --check .
pytest --cov=skillguard
python -m build
```

## Ground rules

- **Static analysis must never execute, import, or otherwise run target
  code.** If you're adding a static detector, it must work purely from
  `ast.parse()` output, file bytes, or a stdlib text-format parser
  (`tomllib`/`json`). See `docs/decisions/0001-no-target-execution.md`.
- **Dynamic execution is always `argv` + `shell=False`.** No shell-string
  execution mode. No silently forwarding the full parent environment.
- **New static rules need a stable rule ID** (`SG-<CATEGORY>-<NNN>`,
  registered in `skillguard/static/rules.py`) and a doc entry under
  `docs/rules/`. Rule IDs, once released, never change meaning.
- **Findings vs. capabilities vs. policy stay separate.** A finding is
  evidence. A capability is a normalized observation. A policy decides
  whether evidence/capabilities are acceptable. Don't collapse these.
- **No absolute safety claims.** "shell=True detected" is evidence, not
  "malware detected". See the Critical Honesty Rule in the README.
- **Security-relevant changes need a real regression test**, not a mock
  that exercises a helper instead of the actual production code path
  (path containment, process-tree cleanup, secret redaction, and
  persistence corruption handling are the areas this matters most).
- Adversarial test fixtures must be harmless: temp files, a sleeping
  child process, a localhost socket, a synthetic canary -- never real
  secrets, real external hosts, or anything that mutates the developer's
  actual git repos or system config.

## Architecture decisions

Nontrivial design calls live in `docs/decisions/` as short ADRs. If you're
proposing a change to path containment, the redaction pipeline, capability
semantics, or the persistence schema, add or update one.

## Reporting bugs / security issues

Open a GitHub issue: <https://github.com/Human-Weapon/SkillGuard/issues>.
See [SECURITY.md](SECURITY.md) for the threat model this project operates
under.
