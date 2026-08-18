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

**Ancestor-chain containment (since the second remediation round).** An
earlier design validated the walk root once and then reopened each file by
its remembered path string later (for static scanning, workspace copying,
content fingerprinting). That left a gap: an *intermediate ancestor
directory* -- not the root, not the leaf file -- replaced by a real
junction/symlink *during* the walk, after its parent's listing had already
accepted it as an ordinary subdirectory, let the walker silently descend
into and record self-consistent identities for the redirected target, with
no discrepancy left for the later reopen to catch. `skillguard.paths` now
routes every directory entered and every file opened through one shared,
atomic walk+read engine (`_SecureWalker`, used by `walk_tree` and
`walk_tree_and_read`) instead:

- **POSIX:** each directory is opened once via `os.open(..., dir_fd=parent,
  O_NOFOLLOW)` and held open (as a `dir_fd`) for as long as its subtree is
  being traversed; every child -- file or directory -- is then opened
  *relative to that fd*, never by re-resolving a path string from the
  drive root. Once a directory's fd is held, no ancestor above it can be
  redirected in a way that affects it: `openat()`-family calls resolve
  purely through the fd, bypassing name resolution of everything above it.
  This closes the ancestor-swap class structurally, not just narrows it.
- **Windows:** each directory/file is opened via `CreateFileW` with
  `FILE_FLAG_OPEN_REPARSE_POINT` (atomic check-and-open: a junction/symlink
  is opened as itself, never silently traversed, with no separate check
  step a swap could land between) and `FILE_SHARE_READ` only -- denying
  write and delete to every other process for as long as the handle is
  held. This is a structural guarantee, not a timing one: while SkillGuard
  holds a directory's handle, another process's attempt to delete or
  junction-replace that exact directory fails outright
  (`ERROR_SHARING_VIOLATION`), verified empirically against real
  `CreateFileW`/`AssignProcessToJobObject`-style Windows behavior. The
  residual on Windows is genuinely narrow: a swap that lands in the small
  window before SkillGuard's own handle is opened, or a sufficiently
  privileged actor able to force past the share-mode denial.
- A narrower, already-documented residual remains for an individual **leaf
  file** replaced without touching its parent directory (e.g. unlink +
  hardlink to different content) -- holding a directory's own handle does
  not prevent files *within* it from being individually replaced. This is
  narrowed (not eliminated) via an "as listed" identity captured at
  listing time and compared against the freshly opened handle's own
  identity; a mismatch fails closed (`ObservationError`). **On POSIX, that
  identity is now captured with zero syscall gap from the listing itself:**
  `os.scandir()` is backed by `getdents64()`, which returns each entry's
  name and inode number together, from the same raw directory-entry
  record; `os.DirEntry.inode()` returns that already-cached value with no
  separate system call. An earlier version of this check (SG-R2-NEW-002 in
  docs/audits, closed before the second remediation round shipped) fixed a
  *coarser* version of this gap -- identity captured much later, deep
  inside the per-entry processing loop, with a window proportional to how
  much other work the loop had already done -- but still called a
  *separate* `os.lstat()` per entry right after `os.scandir()` returned,
  which is two syscalls with a real, if much narrower, gap between them.
  The third independent audit flagged that narrower gap as unverified
  (real concurrent replacement couldn't be tested on Windows, where a
  different defense -- the deny-write handle described above -- blocks the
  attempt outright for unrelated reasons); it is closed on POSIX as of the
  third remediation round by reading the inode from the same syscall as
  the name, leaving no second syscall for a replacement to land between.
  Windows keeps a per-entry `os.lstat()` call (`DirEntry.inode()` does not
  carry the same free-data guarantee there) and relies on the deny-write
  handle instead. A same-path file replaced by a *different* file that
  happens to reuse a just-freed inode number (achievable on Linux
  tmpfs), or a hardlink to a file whose bytes SkillGuard was already going
  to read as part of the same tree, remains a documented, accepted
  residual -- consistent with the same device+inode-only design rationale
  below. The remaining window -- between this identity capture and the
  entry's own atomic open, moments later -- is not eliminated, only
  detected: a replacement landing there is caught by the post-open
  identity comparison and rejected, not silently trusted.
- `BoundRoot.verify_unchanged()`/the walker's root-level check compare
  device+inode only, deliberately: a directory's own metadata-change time
  on POSIX changes whenever an entry is added or removed inside it, which
  is normal, expected activity for a root SkillGuard observes or writes to
  repeatedly (before/after filesystem diffing, more than one saved audit
  result) -- so it cannot be used as a swap signal there without also
  rejecting legitimate use.

**This is still a best-effort defense, not a guarantee.** SkillGuard is
not a sandbox and does not claim to be race-free. A sufficiently
privileged local actor with the ability to force past OS-level
sharing/permission denial, or one that wins a race narrower than the
handle-holding window described above, is not claimed to be detected. The
threat model this defends is a malicious *scan target* (the skill/plugin
being analyzed) attempting to redirect SkillGuard's own read/copy/fingerprint
operations outside the bound root -- not a separate, co-resident local
attacker with write access to the same filesystem racing SkillGuard's
process at the OS privilege level.

## Secrets

- Values matched by the static secret scanner (`skillguard.static.secrets`)
  and dynamic canaries are never persisted or printed in full. Findings and
  evidence store only a type tag, length, a short non-reversible SHA-256
  fingerprint, and a truncated safe prefix (see `skillguard.redaction`).
- The same redaction boundary also covers secret-*shaped* content embedded
  in a target-controlled **path or filename** component, not only file
  *content* -- a filename like `payload_AKIA....py` is redacted (each
  distinct match gets its own stable fingerprint, so two records differing
  only in which secret-shaped path they reference stay distinguishable)
  before it reaches `Finding.file_path`, `Evidence.summary/origin/details`,
  or any persisted artifact. This applies uniformly at the two points every
  `Finding`/`Evidence` object is constructed (`skillguard.models`), not as
  a special case for any one call site, and never mutates the actual
  filesystem path SkillGuard uses internally to open the file.
- **The boundary is not limited to `Finding`/`Evidence`.** Every other
  place target-controlled or target-influenced text reaches a persisted or
  printed artifact is redacted at the serialization/output boundary itself
  (`skillguard.report.audit_to_dict`/`render_markdown`, `skillguard.cli`'s
  error path): `AuditResult.target`, the created/modified/deleted paths in
  a dynamic run's filesystem diff, policy outcome reason strings, static
  and dynamic incompleteness/failure reason strings (which can embed an
  exception message that itself names a path), and CLI error messages for
  expected domain failures -- in Markdown, in the JSON audit/findings/
  evidence documents, in `--json` stdout, and in human stderr alike. The
  third independent audit found several of these bypassing the
  `Finding`/`Evidence`-only boundary entirely; the invariant since the
  third remediation round is that target-controlled secret-shaped text
  must not leak through *any* user-facing or persisted SkillGuard output
  merely because it did not happen to pass through a `Finding` or
  `Evidence` object.
- SkillGuard never loads real credentials automatically and never phones
  home. It does not query any network service, package registry, or CVE
  database in v0.1.0.
- Canaries used to test for secret exposure (`--canary`) must be
  caller-supplied, non-sensitive values. SkillGuard does not generate or
  inject real-looking credentials.

## Dynamic execution lifecycle

- **The configured `--timeout` bounds SkillGuard's own execution lifecycle,
  not only `Popen.wait()` on the direct child, and not by waiting on every
  descendant to actually exit.** A target that spawns a descendant and
  exits quickly, leaving the descendant holding the inherited
  stdout/stderr pipe open, does not defeat the timeout: process-tree
  cleanup runs unconditionally in `CommandRunner.run()`'s cleanup path --
  on the normal-exit path too, not only on an actual timeout -- and the
  reader-thread drain afterward is bounded by a single, small cleanup
  allowance applied on top of (never carved out of) the configured
  timeout, regardless of whether every descendant has actually died by
  then. **Whole-tree containment itself is best-effort, not guaranteed,**
  and differs by platform:
  - Windows assigns the target to a Job Object that every descendant
    automatically joins at creation time; `TerminateJobObject` kills the
    whole tree in one call regardless of process ancestry at the time of
    the call. This is not subject to the POSIX residual below.
  - POSIX runs the target in its own session (`start_new_session=True`) so
    `os.killpg()` reaches every process still in that group -- but a
    descendant that itself calls `setsid()` (the standard, ordinary POSIX
    daemonization primitive, not an exotic technique) leaves that group
    entirely, and `os.killpg()` can no longer reach it. A supplementary,
    polling-based tracker still discovers such a descendant, and a
    discovered PID is killed directly (SIGKILL by PID has no dependency on
    process group membership), *as long as the tracker's poll interval
    wins its race against however fast the descendant is reparented away*
    from the tracked root's process-ancestry chain -- the same class of
    race already documented below for process/network observation
    generally. A sufficiently fast double-fork can escape this entirely,
    undetected. SkillGuard's own run does not hang either way (the bound
    above holds regardless), and a tracked-but-unconfirmed-dead descendant
    is reported honestly via an `IncompletenessReason.PROCESS_CLEANUP_INCOMPLETE`
    fact rather than the run silently reading as fully cleaned up -- but an
    escape fast enough to never be tracked at all is not detectable or
    reportable by this mechanism, and SkillGuard does not claim otherwise.
    Closing this completely would require a privileged, OS-level mechanism
    (cgroups, PID namespaces) outside a userspace Python tool's reach; if
    you need that guarantee, provide it yourself (container, VM, cgroup)
    around SkillGuard's dynamic mode, per the sandboxing guidance above.
- **Source-integrity verification runs on every completion path**, not
  only success: `DynamicObserver.run()` always calls
  `DynamicWorkspace.verify_source_unchanged()` afterward regardless of
  whether the run body returned normally or raised (an observer/monitor
  setup or runtime failure, a target-side error, or any other unexpected
  exception). If both a source mutation and an unrelated failure occurred
  in the same run, neither is silently discarded -- a `SourceMutationError`
  is always raised when a mutation is detected, with any other exception
  named in its message and chained as its cause. **When the run itself had
  already completed and produced a result** -- e.g. it timed out, or its
  output was truncated or contained invalid UTF-8, or a monitor failed --
  before the mutation was discovered afterward, that completed result is
  attached to the raised `SourceMutationError` as `partial_result` rather
  than discarded, so a caller can recover and surface both facts together;
  it is never true that learning about one of these facts silently hides
  the other.
- **Invalid UTF-8 in captured stdout/stderr is decoded safely for display
  (never a raised exception) but is never silently treated as a complete,
  byte-for-byte-faithful observation.** The classification is based on
  strict UTF-8 decoding and inspecting exactly where and why decoding
  failed, not on searching the decoded text for the U+FFFD replacement
  character: a target legitimately emitting the valid 3-byte UTF-8
  encoding of U+FFFD itself is not flagged, and a valid multibyte
  character simply cut in half by SkillGuard's own output-retention cap
  is not flagged as an encoding failure -- that case is exactly what the
  separate, always-tracked `OUTPUT_TRUNCATED` reason already covers. A
  target that itself ends its stream with an incomplete UTF-8 sequence,
  without hitting SkillGuard's cap, is malformed and does set
  `OUTPUT_ENCODING_LOSS`. Only bytes that are genuinely
  not valid UTF-8 anywhere in the retained buffer set `OUTPUT_ENCODING_LOSS`
  and matching evidence naming the affected stream(s); `AnalysisStatus.COMPLETE`
  is never reported for a run whose captured output lost information this
  way, and truncation and encoding loss are tracked and reported
  independently of each other -- a run can have either, both, or neither.

## Machine-readable output contract

When `--json` is passed to `scan`/`run`/`audit`, stdout is the JSON
document and nothing else -- no banner, warning, or progress line, even
when `--output` is also given (that diagnostic goes to stderr instead).
This holds on the success path, a policy-`BLOCK` disposition, a clean
validation error, **and an expected domain failure** alike (a missing
target, an invalid output root, an invalid policy/config/capabilities
document, an invalid dynamic invocation, or a runtime-start failure), so a
caller doing `json.loads(stdout)` never has to work around extraneous
text or an empty stream on the error path. An error document has the
shape `{"ok": false, "error": {"type": "...", "message": "...", "exit_code": N}}`;
`message` is passed through the same redaction boundary described below,
so a domain error naming a target-controlled path never leaks a
secret-shaped substring through the error channel either. This does not
extend to argparse-level usage errors (a malformed flag, a missing
required positional argument) that never reach a parsed command at all --
those remain plain-text usage messages on stderr with a non-JSON exit, the
same as any other Python CLI built on `argparse`.

## What SkillGuard does not claim

SkillGuard never states that a target "is safe", "is secure", or that "no
malicious behavior exists". A clean result means: *the analyses that
completed did not match anything in scope*. It does not mean nothing is
wrong. See `skillguard.report` for the exact language used in generated
reports.

## Reporting a vulnerability in SkillGuard itself

This is a pre-release (v0.1.0, not yet tagged or published) open-source
project maintained on a best-effort basis. It has completed three
independent adversarial audits and remediation passes (see
`docs/audits/first-adversarial-audit.md`,
`docs/audits/second-adversarial-audit.md`, and
`docs/audits/third-daybreak-adversarial-audit.md`) and is awaiting a
fourth independent audit before any release decision. Please open a
GitHub issue at
<https://github.com/Human-Weapon/SkillGuard/issues> describing the problem.
Do not include real secrets or exploit payloads targeting third-party
systems in a public issue.
