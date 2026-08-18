# Third independent adversarial audit ("Daybreak Blue")

**Audited SHA:** `bce5aa11a26a980bc9b3d9912284c98f0353887f`
**Verdict:** C -- FIX BEFORE PROMOTION
**Findings:** 3 P2 new (SG3-001 through SG3-003), 1 P3 new (SG3-004);
SG-R2-NEW-002 reclassified NOT VERIFIED (its regression proved a different,
narrower gap than the one it claimed to close); `setsid()` process-group
escape flagged NOT VERIFIED (no POSIX runtime available to the auditor)

This is a summary record of a third, independent adversarial audit,
performed after Remediation Round 2 (see `second-adversarial-audit.md`)
closed all six SG2-* findings and both implementer-found defects
(SG-R2-NEW-001, SG-R2-NEW-002) against the exact pinned SHA above. It
exists for the same reason the first two records do: so the project's
real history -- including what a round that shipped fully green CI still
got wrong -- is not lost or reconstructed more favorably later.

## What the audit found

The audit re-exercised the full SG2-* finding set against `bce5aa11` and
confirmed the seven-job CI run for that exact SHA was green. It found four
new defects and one verification gap in a Round 2 regression that had been
marked fixed:

- **SG3-001 (P2):** Round 2's SG2-004 fix redacted secret-shaped path
  content inside `Finding`/`Evidence`, but several other serialization and
  CLI paths never routed through those two models. `AuditResult.target`,
  a dynamic run's filesystem-diff paths (`created`/`modified`/`deleted`),
  and CLI exception messages for expected domain errors all wrote
  target-controlled text directly, leaking a secret-shaped substring
  verbatim into `audit.json`, `report.md`, `--json` stdout, and
  validation-error stderr.
- **SG3-002 (P2):** `main()`'s `SkillGuardError` handler always printed a
  human `error: ...` line to stderr, regardless of `--json`. A JSON-capable
  command (`scan`/`run`/`audit`) invoked with `--json` produced *empty*
  stdout on an expected domain failure (missing target, invalid output
  root, invalid policy/config, invalid dynamic invocation, a runtime-start
  failure), breaking the `json.loads(stdout)`-always-succeeds contract
  SG2-005 established for the success/policy-block/incomplete paths.
- **SG3-003 (P2):** `DynamicObserver.run()` called
  `verify_source_unchanged()` after `_run_inner()` returned and, on a
  mutation, raised `SourceMutationError` while discarding whatever
  fully-formed `DynamicResult` `_run_inner()` had just produced. A run
  that timed out, had its output truncated, contained invalid UTF-8, or
  hit a monitor failure -- while a source mutation was *also* discovered
  -- lost every one of those facts the moment the mutation exception was
  raised; only the mutation itself remained observable.
- **SG3-004 (P3):** `_BoundedStreamCapture.result()` computed
  `encoding_lossy` by checking whether the literal U+FFFD replacement
  character appeared in text decoded with `errors="replace"`. That
  conflates three distinct situations: a target emitting genuinely
  invalid UTF-8 (correctly lossy), a target *legitimately* emitting the
  valid 3-byte UTF-8 encoding of U+FFFD itself (incorrectly flagged
  lossy), and SkillGuard's own output-retention cap bisecting a valid
  multibyte character (incorrectly flagged lossy instead of merely
  truncated).
- **SG-R2-NEW-002 verification gap (NOT VERIFIED, not a new SG3 finding):**
  the auditor could not execute POSIX code (Windows-only host) and so
  could not independently confirm the Round 2 regression synchronized
  against the seam it claimed to close. Inspecting the code directly, the
  auditor found `_list_entries_secure()`'s POSIX path still called
  `list(os.scandir(dir_fd))` and *then*, in a separate loop, a per-name
  `os.lstat(entry.name, dir_fd=dir_fd)` -- i.e. the "captured as a direct
  byproduct of listing" claim in that function's own docstring was
  accurate for the coarser problem SG-R2-NEW-002 fixed (identity captured
  much later, deep in the walker's per-entry loop) but not literally true
  at the syscall level: two syscalls, with a real gap between them, not
  one. The existing regression test swapped the leaf file only *after*
  `_list_entries_secure()` had already fully returned, which does not
  synchronize against that internal `scandir`-then-`lstat` interval at
  all -- it proves a different, already-defended gap.
- **`setsid()` process-group escape (NOT VERIFIED):** the auditor asked
  whether a POSIX descendant that calls `setsid()` -- leaving the process
  group `os.killpg()` targets -- could escape `CommandRunner`'s whole-tree
  cleanup and cause an unbounded run. No POSIX runtime was available to
  the auditor to test this, and CI at the time had no such regression.

Two mandatory follow-up investigations were specified regardless of
whether SG-R2-NEW-002 and the `setsid()` question turned out to be real
defects: synchronize a real replacement exactly at the `scandir`→identity-
capture seam on real Ubuntu CI, and exercise a real `setsid()`-escaping
descendant (both parent-exits-quickly and parent-exceeds-timeout) on real
Ubuntu CI.

## Remediation

Every SG3-* finding was independently reproduced against the audited
baseline (`bce5aa11`) via a detached `git worktree` before a fix was
accepted, matching the same RED-proof methodology used in Round 2.

**SG3-001** was fixed with a small, shared redaction boundary at the
serialization/output layer itself, complementing (not replacing) the
existing `Finding`/`Evidence`-level boundary: `skillguard.report.audit_to_dict`/
`render_markdown` now redact `result.target`, every path in the dynamic
filesystem diff, policy outcome reason strings, and incompleteness/failure
reason strings; `skillguard.cli`'s error-printing path redacts the
exception message before it reaches stderr or a `--json` error document.
See `tests/test_sg3_001_redaction_boundary.py` -- distinct synthetic
tokens in the target root name, a created/modified/deleted/nested dynamic
path, and an expected-domain-error path, checked against zero raw
occurrences across every artifact and stream, plus a collision test
confirming two different secrets stay distinguishable after redaction
(each keeps its own fingerprint) rather than colliding into identical
markers.

**SG3-002** was fixed by defining a small, deterministic JSON error
schema -- `{"ok": false, "error": {"type": "...", "message": "...", "exit_code": N}}`
-- emitted by a new shared `_emit_error()` helper whenever the parsed
command supports `--json`; the message is redacted through the same
SG3-001 boundary. Argparse-level usage errors (which happen before a
command is successfully parsed, so `ns.json` is not yet known) are
explicitly out of scope, matching the audit's own "do not undertake a
dangerous argparse rewrite" framing. See
`tests/test_sg3_002_json_error_contract.py` -- real installed-CLI
subprocess invocations across scan/run/audit error paths, asserting
`json.loads(stdout)` succeeds and stdout is never empty, plus a
regression confirming `--debug` still re-raises with a real traceback
instead of the JSON envelope.

**SG3-003** was fixed at the data-model/orchestration boundary:
`SourceMutationError` now carries the completed `DynamicResult` as a new
`partial_result` attribute when `_run_inner()` did produce one before the
mutation was discovered (`None` when it didn't -- e.g. observer setup
itself failed). `SkillGuardAuditor.audit()` recovers `partial_result` on
`SourceMutationError` so `AuditResult.dynamic` still exposes those facts,
while `failure_reasons`/`status` stay forced to `FAILED` so the mutation
remains unmistakably security-relevant rather than reading as a clean
`COMPLETE`. `skillguard run`'s own exit code was updated the same way --
a `FAILED` overall status now always yields a non-zero exit, so a
mutation cannot read as success merely because the target's own process
happened to exit cleanly. See `tests/test_sg3_003_mutation_multi_fact.py`
-- real mutations combined with a real timeout, real stdout truncation,
real stderr truncation, real invalid UTF-8, and a real process-monitor
failure, each confirming both facts survive on `partial_result`; plus
`tests/test_sg3_self_adversarial_round3.py` for a mutation combined with
*two* simultaneous facts (timeout **and** truncation) at once.

**SG3-004** was fixed by replacing the "does U+FFFD appear in the decoded
text" heuristic with strict UTF-8 decoding plus `UnicodeDecodeError`
inspection: a decode failure whose `reason` is exactly `"unexpected end
of data"` and which ends at the buffer's own end is the stream (or
SkillGuard's own retention cap) simply stopping mid-character -- already
covered by the independently-tracked `OUTPUT_TRUNCATED` reason -- and is
not counted as lossy. Any other decode error (invalid start byte, invalid
continuation byte, or an incomplete sequence not at the buffer's end) is
genuinely malformed input and is. See
`tests/test_sg3_004_encoding_classification.py` -- real subprocesses
emitting a legitimate literal U+FFFD alone, embedded in text, repeated,
and near a byte cap (all correctly non-lossy); a valid multibyte
character deliberately bisected by `max_output_bytes` (truncated, not
lossy); and genuinely invalid bytes (still correctly lossy, confirming no
overcorrection).

### SG-R2-NEW-002 / enumeration→lstat seam: resolved

A dedicated real-hardlink-replacement test
(`tests/test_sg_r3_seam_a_scandir_inode_race.py`, POSIX-only) synchronizes
the swap exactly where the audit asked: by wrapping `os.scandir` itself
(not `_list_entries_secure`, and not a point after it returns), the leaf
is replaced with a real hardlink to outside content the instant the real
underlying enumeration syscall has produced its results, before any
further processing of them.

Rather than trying to further narrow the gap between that enumeration and
a later `lstat()` call, the separate `lstat()` call was removed entirely
on POSIX: `os.scandir()` is backed by `getdents64()`, which returns each
entry's name and inode number (`d_ino`) together, from the same raw
directory-entry record; CPython's `DirEntry` object caches `d_ino` at the
moment the entry is produced during iteration, so `entry.inode()` returns
already-captured data with no separate system call. There is no longer a
second syscall for a replacement to land between -- the docstring's
"captured as a direct byproduct of listing" claim the audit flagged as
inaccurate is now literally true, not just true for the coarser problem
SG-R2-NEW-002 originally fixed. Windows keeps the previous per-entry
`os.lstat()` design (`DirEntry.inode()` does not carry the same
free-data guarantee there) and continues to rely on the deny-write
`CreateFileW` handle instead, which the audit itself confirmed blocks a
real concurrent replacement attempt outright.

Local Windows execution cannot exercise `os.scandir(dir_fd)` (Windows
`os.scandir` takes a path, not an fd) or `os.link()`, so this fix is
necessarily unverified by local RED/GREEN proof; it runs for real for the
first time on Ubuntu CI for this round's remediation SHA (see the
Verification section below for that result).

### `setsid()` process-group escape: resolved (with an honestly-documented residual)

Investigation confirmed SkillGuard's own bounded-lifecycle guarantee
already held regardless of a `setsid()` escape (`CommandRunner.run()`
bounds its cleanup wait via a fixed allowance, never by waiting on the
escapee -- see SG2-002), and that the supplementary, ppid-chain-based
`ProcessMonitor` tracker still discovers a `setsid()`'d descendant as
long as the chain stays intact when it polls (`setsid()` changes process
group/session, not parent PID) -- once a PID is known, `kill_pids()`
SIGKILLs it directly, which `setsid()` provides no immunity from. The one
real gap: a sufficiently fast double-fork can reparent the descendant
away before any poll observes it, making the escape genuinely invisible
to this mechanism -- the same class of race already documented for
process/network observation generally (SkillGuard is not a sandbox and
does not claim otherwise).

Fixed the honesty of the reporting, per the audit brief's own fallback
guidance ("record incomplete cleanup honestly ... never falsely claim
escaped processes were terminated if they were not"): `kill_pids()` now
returns the subset of tracked PIDs it could not confirm terminated after
both a `terminate()` and a `kill()` attempt, instead of discarding that
information. `CommandRunner.run()` threads it into a new
`CommandResult.unterminated_descendant_pids` field, and
`DynamicObserver` surfaces a non-empty value as a new
`IncompletenessReason.PROCESS_CLEANUP_INCOMPLETE` fact with matching
evidence, so a run with a confirmed-unterminated tracked descendant can
never read as `COMPLETE`. See
`tests/test_sg_r3_seam_b_reporting.py` (deterministic, all platforms,
RED-proofed against baseline) for the reporting mechanism itself, and
`tests/test_sg_r3_seam_b_setsid_escape.py` (POSIX-only, real
`fork()`/`setsid()`) for real escapes under both an `EXITED` and a
`TIMED_OUT` outcome, plus a best-effort double-fork race test asserting
only the one property that must always hold regardless of which side
wins that race: `CommandRunner.run()` still returns within its
documented bound. As with seam A, this file cannot be exercised on local
Windows and runs for real for the first time on Ubuntu CI.

## Implementer scope note

Both the enumeration→lstat seam and the `setsid()` escape were treated,
per the audit brief's own instruction, as **investigations to resolve
honestly**, not as findings to reflexively "fix" by construction. Neither
turned out to require accepting an unbounded run or a false completeness
claim; both were closed by (a) a genuine, verifiable architectural
improvement where one was available (removing the second syscall on the
enumeration seam) and (b) honest, mechanical reporting of the residual
where complete containment is not achievable from user space without a
privileged mechanism (cgroups/PID namespaces) outside this project's
reach (the `setsid()` double-fork race). Neither is claimed to be
eliminated where it structurally cannot be; SECURITY.md's "Dynamic
execution lifecycle" and "Path containment" sections were updated to
state the actual, narrower guarantee rather than the previous, broader
claim.

## Verification

Local gates (pytest with branch coverage, ruff check, ruff format,
build, wheel/sdist black-box, standalone) were run after every fix in
this round; see the final remediation report delivered alongside this
document for the exact numbers and the GitHub Actions run this round's
remediation SHA produced, including explicit confirmation that the new
Ubuntu-only tests (seam A, seam B, and the pre-existing FIFO regressions)
actually executed rather than being silently skipped.
