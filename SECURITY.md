# Security model

SkillGuard is a security *auditing* tool, not a security *boundary*. Read
this document before using dynamic analysis on anything you don't already
trust to run on your machine.

## Static analysis (`skillguard scan`, and the static half of `audit`)

- Static analysis **does not intentionally execute, import, or otherwise
  run the target's code**. It only reads file bytes and, for recognized
  text formats, parses them: `ast.parse()` for Python, `tomllib.loads()`
  for `pyproject.toml`, `json.loads()` for `package.json`/manifests.
- It never installs packages, never invokes a PEP 517/518 build backend,
  and never triggers `setup.py`. Parsing `pyproject.toml` is safe; building
  the project it describes is not, and SkillGuard's static scan never does
  the latter.
- It does not follow symlinks or Windows junctions/reparse points during
  its directory walk (see `skillguard.paths`).

Despite this, static analysis of a directory you do not control is not
risk-free: SkillGuard reads and, for very large files, may truncate file
content into memory. It does not protect against a maliciously crafted
filesystem structure designed to exhaust resources beyond the configured
limits (`max_files`, `max_total_bytes`, `max_file_bytes`, `max_depth`).

## Dynamic analysis (`skillguard run`, and `audit --dynamic`)

**Dynamic analysis executes a command you specify, using code from the
target directory, on your machine, with your user's OS-level
permissions.** This is the entire point of dynamic analysis -- observing
real behavior requires letting the behavior happen -- but it means:

- **SkillGuard is not a sandbox.** It does not use containers, virtual
  machines, seccomp, AppContainer/Job Objects, or any other OS-level
  isolation. A malicious target can do anything your user account can do,
  including things SkillGuard's observers cannot see (see "Observability
  limits" below).
- The target command always runs as an explicit `argv` list with
  `shell=False`. There is no "shell string" execution mode, so shell
  metacharacters in target arguments are never interpreted.
- The target's environment is never the full parent environment by
  default (`EnvMode.MINIMAL`); you must explicitly allowlist or supply
  variables it can see (`EnvMode.ALLOWLIST` / `EnvMode.EXPLICIT`).
- The isolated workspace copy (`skillguard.dynamic.workspace`) means the
  target normally only sees and modifies a disposable copy, not your
  original source tree, and a content-hash fingerprint (taken before and
  after the run) detects whether the original changed anyway. Precisely:
  - It protects the original from *incidental* mutation through the copy
    itself -- the target writing/deleting files in its own working
    directory, which is the copy, never touches the original.
  - It protects the original from symlinks/junctions *inside the source
    tree* being used to reach outside content during the copy step: the
    copy never follows a link, so a link to your home directory sitting
    in the scanned tree cannot pull that content into the workspace.
  - It does **not** prevent a command that already knows your original
    source path from opening and modifying that path directly and
    deliberately -- the target runs with your OS-level permissions and
    can address any path those permissions allow, exactly like any other
    program you'd run yourself. The fingerprint check will detect that
    this happened (raising `SourceMutationError`); it does not prevent it.
  - It does not protect the rest of your machine outside the source tree.
  This is source-tree hygiene and tamper-evidence, not an OS-level access
  control -- SkillGuard is still not a sandbox.

**If you are analyzing software you do not trust, run SkillGuard's dynamic
mode inside your own disposable container, VM, or throwaway account/host.
SkillGuard does not provide that isolation itself, and does not pretend
to.**

## Observability limits

Even when nothing malicious is happening, SkillGuard's observers are
best-effort:

- **Process observation** polls `psutil` at a configured interval. A
  process that starts and exits between polls may be missed. Permission
  errors on individual processes are recorded, not fatal to the whole run.
- **Network observation** polls each observed process's connection table.
  Very short-lived connections between polls may be missed. No packet
  payload is ever captured.
- **Filesystem observation** is snapshot-based (before/after, not a live
  event watcher). A file created and deleted between snapshots is
  invisible to it.
- **Environment-variable reads are not observable** by any mechanism in
  v0.1.0. Static analysis can note that `os.environ`/`os.getenv` appear in
  source; it cannot tell you which values were actually read.
- A target's exit code, timeout, or crash is evidence about the target,
  not about SkillGuard. See `skillguard.dynamic.runner.TargetOutcome` for
  how these are distinguished from an observer failure.

Absence of an observation is never reported as proof of absence of the
underlying behavior. SkillGuard uses `ANALYSIS_INCOMPLETE` and specific
`incompleteness_reasons` whenever a limit, permission error, or observer
failure means a run could not see everything it was configured to look
for.

## Path containment

`skillguard.paths.BoundRoot` binds scan/output roots to an absolute,
symlink-resolved path at construction time and never re-derives them from
a possibly-changed working directory. The directory walker does not
descend into symlinks or Windows junctions/reparse points.

This is a **best-effort defense**, not a guarantee: a sufficiently
privileged local process racing SkillGuard can still win a
time-of-check-to-time-of-use (TOCTOU) window between a containment check
and the filesystem operation that follows it (e.g., replacing a directory
with a junction between validation and traversal). `walk_tree()` re-checks
`BoundRoot.verify_unchanged()` before and during enumeration (not only in
callers), and individual file reads (static scanning, workspace copying,
content fingerprinting) open through an identity-checked handle
(`skillguard.paths.open_walk_entry`) that fails closed if the path was
replaced between enumeration and read -- using `O_NOFOLLOW` on POSIX, a
device+inode check before opening, and a device+inode check (plus a
narrow, Windows-jitter-tolerant creation-time check) against the actual
opened handle afterward. `verify_unchanged()` and the pre-open check
compare device+inode only, deliberately: a directory's own metadata-change
time on POSIX changes whenever an entry is added or removed inside it,
which is normal, expected activity for a root SkillGuard observes or
writes to repeatedly (before/after filesystem diffing, more than one
saved audit result) -- so it cannot be used as a swap signal there without
also rejecting legitimate use. The known consequence: a same-path
directory replaced by a *different* plain directory that happens to reuse
a just-freed inode number (achievable on Linux tmpfs) is not detected by
this check alone; a junction/symlink-based replacement is still caught,
both because device+inode differ in the overwhelming majority of cases
and via the separate reparse-point check. This narrows the window
considerably; it does not close it. A privileged actor that wins the
remaining race between the
final check and the filesystem call immediately after it is not detected.

## Secrets

- Values matched by the static secret scanner (`skillguard.static.secrets`)
  and dynamic canaries are never persisted or printed in full. Findings and
  evidence store only a type tag, length, a short non-reversible SHA-256
  fingerprint, and a truncated safe prefix (see `skillguard.redaction`).
- SkillGuard never loads real credentials automatically and never phones
  home. It does not query any network service, package registry, or CVE
  database in v0.1.0.
- Canaries used to test for secret exposure (`--canary`) must be
  caller-supplied, non-sensitive values. SkillGuard does not generate or
  inject real-looking credentials.

## What SkillGuard does not claim

SkillGuard never states that a target "is safe", "is secure", or that "no
malicious behavior exists". A clean result means: *the analyses that
completed did not match anything in scope*. It does not mean nothing is
wrong. See `skillguard.report` for the exact language used in generated
reports.

## Reporting a vulnerability in SkillGuard itself

This is a pre-release (v0.1.0, not yet tagged or published) open-source
project maintained on a best-effort basis. It has completed one independent
adversarial audit and a remediation pass (see `docs/audits/first-adversarial-audit.md`)
and is awaiting a second independent audit before any release decision.
Please open a GitHub issue at
<https://github.com/Human-Weapon/SkillGuard/issues> describing the problem.
Do not include real secrets or exploit payloads targeting third-party
systems in a public issue.
