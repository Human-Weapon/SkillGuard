# SkillGuard

Security and behavior auditor for AI skills, plugins, and agents: static
analysis, optional runtime observation, capability verification, and
secret-leak detection.

SkillGuard answers four questions about a directory containing a
skill/plugin/agent extension:

1. What capabilities does it appear to have? (static analysis)
2. What did it actually do when observed? (optional dynamic analysis)
3. Does observed behavior match what it declares? (capability comparison)
4. Did we detect anything that deserves security review? (findings + policy)

**Read [SECURITY.md](SECURITY.md) before using dynamic analysis on
anything you don't already trust to run on your machine. SkillGuard's
dynamic mode executes target code; it is not a sandbox.**

## What SkillGuard is not

- Not a sandbox, container, or VM. See [SECURITY.md](SECURITY.md).
- Not a malware scanner or antivirus engine.
- Not a guarantee of safety. A clean report means "the analyses that
  completed found no matching issue" -- never "this is safe". See
  [Critical honesty rule](#critical-honesty-rule).
- Not a package-reputation or live-CVE-database service. No network access
  is used by SkillGuard itself; no API keys are required.

## Critical honesty rule

SkillGuard never asserts that a target is safe/secure or that it found
zero grounds for concern. Absence of evidence is not evidence of absence.
Findings use language like
*"no matching issue was detected by the analyses that completed"*,
*"review required"*, *"behavior not observed"*, or *"analysis incomplete"*.
See `skillguard.report` for the exact wording used in generated reports,
and `docs/decisions/` for why this matters.

## Install

```bash
pip install skillguard
```

Requires Python 3.10-3.12. Depends on `psutil` (process/network
observation) and, on Python 3.10, `tomli` (stdlib `tomllib` backport).
YAML policy/config support is optional (`pip install skillguard[yaml]`);
core functionality never requires PyYAML.

## Quick start (static-only, never executes anything)

```bash
skillguard scan ./some-skill-directory
```

```bash
skillguard scan ./some-skill-directory --json --output ./skillguard-output
```

## Dynamic observation (executes a command you specify -- NOT a sandbox)

```bash
skillguard run ./some-skill-directory --timeout 30 -- python -m some_skill --demo
```

The command after `--` runs against an isolated **copy** of the target
directory (your original source is never modified), as an explicit argv
list with `shell=False` -- never through a shell, so quotes/semicolons/
pipes in arguments stay literal. See [SECURITY.md](SECURITY.md).

## Full audit (static + optional dynamic + capability/policy evaluation)

```bash
skillguard audit ./some-skill-directory \
  --capabilities ./some-skill-directory/skillguard.capabilities.json \
  --policy ./my-policy.json \
  --dynamic -- python -m some_skill --demo
```

## A deterministic local example (no internet required)

`examples/demo_skill/` is a small, harmless fixture that demonstrates a
filesystem write, a subprocess spawn, and a declared-vs-observed capability
mismatch, entirely on loopback/local disk:

```bash
skillguard audit examples/demo_skill \
  --capabilities examples/demo_skill/skillguard.capabilities.json \
  --dynamic -- python run.py
```

The fixture declares `filesystem.read` only, but its `run.py` also writes a
file and spawns a subprocess -- so the report's "undeclared observed
capabilities" section will show `filesystem.write` and `process.spawn`.
This is normal for the example; it exists to demonstrate the comparison,
not to imply anything is wrong with writing files.

## Static analysis

Never imports or executes the target. Walks the target directory (never
following symlinks/junctions), and for each file:

- **Python source** (`*.py`): AST-based pattern detection --
  `subprocess`/`os.system`/`os.popen` (and whether `shell=True`),
  `eval`/`exec`/`compile`, dynamic imports, `pickle` deserialization,
  network-capable imports, `os.environ`/`os.getenv`, filesystem writes,
  `ctypes`, `winreg`, `chmod`, and base64-decode-into-eval/exec patterns.
  See `docs/rules/` for the full, stable rule ID list (`SG-PY-*`).
- **Manifests** (`pyproject.toml`, `requirements*.txt`, `package.json`):
  direct-URL/git/local-path dependencies, custom build backends, npm
  install-lifecycle scripts (`SG-MANIFEST-*`). Parses these formats;
  never builds/installs what they describe.
- **Secrets**: PEM private key blocks, well-known cloud/SaaS token
  formats, credential-like assignments, and (optional, conservative)
  high-entropy string literals (`SG-SECRET-*`). Raw values are never
  included in output -- see [Secret handling](#secret-handling).

Hard limits (`max_files`, `max_total_bytes`, `max_file_bytes`, `max_depth`)
protect against runaway scans; hitting one marks the result
`ANALYSIS_INCOMPLETE` with the specific reason, never a silent "clean" scan.

## Dynamic observation

`skillguard.dynamic.observer.DynamicObserver` launches your command via
`skillguard.dynamic.runner.CommandRunner` (argv list, `shell=False`,
explicit timeout, explicit environment policy) against an isolated copy of
the target, and watches:

- **Process tree**: spawned descendants, best-effort (`psutil`-based).
  On timeout, the *entire* process tree is terminated, not just the direct
  child.
- **Filesystem**: before/after snapshot diff of the workspace copy
  (created/modified/deleted). Snapshot-based, not a live event watcher --
  a file created and deleted between snapshots is invisible to it.
- **Network**: best-effort polling of each observed process's connection
  table. Very short-lived connections between polls may be missed. No
  packet payload is captured.
- **Git**: read-only `git rev-parse HEAD` / `git status --porcelain`
  before and after. SkillGuard itself never checks out, resets, cleans,
  commits, or pushes a target repository.
- **Secret canaries** (optional, `--canary VALUE`): caller-supplied,
  non-sensitive values checked for appearance in captured stdout/stderr,
  as a best-effort exposure signal. Never a proof of "no exfiltration".

Every dynamic capability claim traces back to specific `Evidence` records
(process/filesystem/network/git observations) -- nothing is asserted from
nowhere.

## Capability manifest & declared vs. observed

A skill can declare its capabilities in `skillguard.capabilities.json`:

```json
{
  "schema_version": 1,
  "capabilities": ["filesystem.read", "network.outbound"],
  "constraints": {}
}
```

Capabilities: `filesystem.read`, `filesystem.write`, `network.outbound`,
`process.spawn`, `environment.read`, `secrets.access`, `packages.install`,
`git.read`, `git.write`, `dynamic_code.execute`.

SkillGuard compares declared vs. observed and reports five explicit sets:
`DECLARED`, `OBSERVED`, `UNDECLARED_OBSERVED`, `DECLARED_NOT_OBSERVED`, and
`UNSUPPORTED_OBSERVATION`. **`DECLARED_NOT_OBSERVED` does not mean the
capability is absent** -- only that this run's observation mechanisms
didn't see evidence of it. A capability is not inherently malicious;
`network.outbound` may be entirely legitimate. What matters is whether it
was declared, observed, and whether that agrees with your policy.

## Policy

A policy is a small, declarative (never executable) set of rules
evaluated against findings and the capability comparison, producing a
`PASS` / `WARN` / `BLOCK` / `REVIEW_REQUIRED` disposition -- kept
separate from findings themselves (a finding is evidence; a policy decides
whether it's acceptable). The default policy blocks nothing; see
`skillguard.policy.example_strict_policy()` for an opt-in stricter example.
Suppressions require an explicit rule ID, scope, and reason, and remain
visible in machine-readable output as `suppressed: true` -- never silently
dropped.

## Secret handling

Detected secret material and canaries are never printed or persisted in
full. Findings and evidence store only a type tag, a length, a short
non-reversible SHA-256 fingerprint, and a truncated safe prefix. See
`skillguard.redaction` and [SECURITY.md](SECURITY.md).

## CLI

```
skillguard scan TARGET [--output DIR] [--json] [--policy FILE]
skillguard run TARGET -- COMMAND ARGS... [--timeout N] [--canary V ...] ...
skillguard audit TARGET [--dynamic -- COMMAND ARGS...] [--capabilities FILE] [--policy FILE] ...
skillguard validate-manifest FILE
skillguard report OUTPUT_DIR RESULT_ID
skillguard rules
```

Run `skillguard --help` or `skillguard <command> --help` for full options.
Configuration/caller errors print a short message to stderr and exit
non-zero; pass `--debug` for a full traceback.

## Python API

```python
from skillguard.auditor import AuditConfig, SkillGuardAuditor
from skillguard.static.scanner import StaticScanConfig

result = SkillGuardAuditor(AuditConfig(static=StaticScanConfig())).audit("./some-skill-directory")
print(result.status, result.policy_result.disposition)
```

## Platform support

Windows and Linux (Ubuntu) are first-class and covered by CI across
Python 3.10/3.11/3.12. macOS is **not verified** -- there is no macOS CI
job configured or executed for this project yet.

## Limitations (v0.1.0)

- Directory targets only; archive extraction (zip/tar) is not supported
  (would introduce zip-slip/tar-traversal/symlink-extraction risks not yet
  addressed -- documented future work).
- Sequential audit execution only; no concurrent multi-target scanning.
- No packet payload capture, no kernel/eBPF/ETW tracing, no live
  CVE/package-reputation database, no automatic remediation.
- Environment-variable reads are not observable at runtime.

## Ecosystem

SkillGuard is part of the HERMES OSS ecosystem (**useful alone, better
together**): PromptGraph (context compilation), AgentGear (execution
routing), **SkillGuard** (security/behavior auditing -- this project),
AgentBench (benchmarking), ProjectKaizen (continuous improvement).
SkillGuard has no hard dependency on any of them; its JSON output is
designed to be easy for a tool like AgentBench or AgentGear to consume
later, but nothing here requires it.

## License

MIT. See [LICENSE](LICENSE).
