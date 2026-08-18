# Second independent adversarial audit

**Audited SHA:** `083629e2743c244b96bd77cd924e1deaa65e708f`
**Verdict:** D -- NOT RELEASE READY
**Findings:** 1 P1, 4 P2, 1 P3 new (SG2-001 through SG2-006); AB-003
reconfirmed still broken; SG-R1-NEW-001 reconfirmed partially fixed

This is a summary record of a second, independent adversarial audit,
performed after Remediation Round 1 (see `first-adversarial-audit.md`)
closed all 13 findings from the first audit. It exists for the same
reason the first record does: so the project's real history -- including
what was still broken after a round that looked complete -- is not lost
or reconstructed more favorably later.

## What the audit found

The audit re-exercised the full first-round finding set against `083629e`
and independently verified AB-001, AB-002, AB-004 through AB-013, and
ADD-001/ADD-002 as still fixed. It also found that Round 1's fix for
AB-003 (file-level hardlink/reopen replacement) was incomplete, and
discovered six new findings:

- **SG2-001 (P1):** an ancestor directory *inside* an already-bound root
  could be replaced by a real junction/symlink *during* a walk -- after
  its parent's directory listing had already accepted it as an ordinary
  subdirectory, but before that subdirectory's own contents were listed --
  causing the walker to silently descend into and record self-consistent
  identities for the redirected target. Because static scanning, workspace
  copying, and content fingerprinting all deferred the actual file read to
  a separate pass over the walk's recorded entries, the later read saw no
  discrepancy to catch: out-of-tree bytes were read/copied/fingerprinted
  while the final status still reported `COMPLETE`. This is the class
  AB-003's Round 1 fix addressed for hardlink replacement of a *leaf* file
  but did not close for an *ancestor* directory.
- **SG2-002 (P2):** a target process could exit quickly while a descendant
  it spawned kept the inherited stdout/stderr pipe open. `Popen.wait()` on
  the direct child returned normally in that case, the reader threads
  draining stdout/stderr then blocked waiting for EOF that never came, and
  -- because `kill_tree()` was only ever called on the timeout branch --
  nothing killed the process tree on the normal-exit path at all. The
  configured `--timeout` did not bound the run's actual wall-clock time.
- **SG2-003 (P2):** `DynamicWorkspace.verify_source_unchanged()` was
  called inline, partway through `DynamicObserver.run()`'s body, after the
  filesystem/git "after" snapshots. Anything upstream of that point raising
  -- an observer/monitor setup failure, a filesystem/git observer
  exception, or any other unexpected error -- propagated straight out of
  `run()` and skipped source-integrity verification entirely, so a source
  mutation happening during a run that also hit one of these failures went
  completely undetected.
- **SG2-004 (P2):** Round 1's AB-001 fix redacted secret *values* embedded
  in scanned file *content*. It did not cover secret-*shaped* content
  embedded in a target-controlled **path or filename** component itself --
  `Finding.file_path` and `Evidence.summary/origin/details` were populated
  directly from the walker's relative-path strings with no redaction step,
  so a filename like `payload_AKIA....py` persisted the credential-shaped
  substring verbatim into `findings.json`, `evidence.json`, `report.md`,
  and `--json` stdout.
- **SG2-005 (P2):** using `--json` together with `--output` wrote a normal
  human "wrote results to ..." banner line to stdout before the JSON
  document, corrupting the machine-readable stream for any caller doing
  `json.loads(stdout)`.
- **SG2-006 (P3):** invalid UTF-8 in captured dynamic stdout/stderr was
  decoded lossily (`errors="replace"`) for safe display, but nothing
  recorded that this had happened -- a run whose output contained
  genuinely corrupted or binary bytes could still report
  `AnalysisStatus.COMPLETE`, silently claiming a byte-for-byte-faithful
  observation that did not occur.

## Remediation

Every SG2-* finding was independently reproduced against the audited
baseline before a fix was accepted -- for SG2-001, with a real NTFS
junction injected at the exact seam the finding describes (see
`tests/test_sg2_findings.py`); for SG2-002, with a real subprocess
descendant holding a real OS pipe past the configured timeout (see
`tests/test_sg2_002_pipe_timeout.py`); for SG2-004, with a real file on
disk named with a synthetic, pattern-matching secret (see
`tests/test_sg2_004_redaction.py`); for SG2-005, against the real CLI as
a subprocess with `json.loads(stdout)` (see `tests/test_sg2_005_json_cli.py`);
for SG2-006, with real subprocesses writing genuinely invalid UTF-8 bytes
(see `tests/test_sg2_006_invalid_utf8.py`).

**SG2-001** required a genuine architectural change, not a patch to the
existing check: `skillguard.paths` now routes every directory entered and
every file opened through one shared, atomic walk+read engine
(`_SecureWalker`). POSIX closes the ancestor-swap class structurally via
`dir_fd`/`openat()` (a directory's fd, once held, is immune to anything
happening to its ancestors). Windows narrows it to a genuine structural
guarantee -- not just a smaller timing window -- via `CreateFileW` with
`FILE_FLAG_OPEN_REPARSE_POINT` (atomic check-and-open) and
`FILE_SHARE_READ`-only handles, which make a concurrent replacement of any
directory SkillGuard currently holds open fail outright
(`ERROR_SHARING_VIOLATION`), verified empirically. See SECURITY.md's "Path
containment" section for the full design and its honestly-stated residual
(a leaf file replaced without touching its parent directory, narrowed via
an adjacent identity comparison but not eliminated -- the same class of
residual Round 1's AB-003 fix already documented).

**SG2-002** was fixed with deterministic whole-tree cleanup instead of a
racy polling tracker (a polling-based descendant tracker was tried first
and found to miss a parent that spawns and exits within tens of
milliseconds): POSIX process groups (`start_new_session=True` +
`os.killpg()`) and a Windows Job Object (`ProcessTreeJob`, every descendant
auto-joins at creation, `TerminateJobObject` kills the whole tree in one
call) that neither depend on observing the tree at the right moment.
Cleanup now runs unconditionally in `run()`'s `finally` block.

**SG2-003** was fixed by wrapping `DynamicObserver.run()`'s body so
`verify_source_unchanged()` always runs afterward, regardless of whether
the body returned or raised; a detected mutation is never allowed to be
silently discarded in favor of an unrelated primary failure (or the
reverse) -- both facts are preserved in a composed `SourceMutationError`
when they co-occur.

**SG2-004** was fixed with a single shared redaction boundary at the two
places every `Finding`/`Evidence` object is constructed
(`__post_init__` in `skillguard.models`), reusing the same secret-shape
patterns `skillguard.static.secrets` already looks for in file content
(non-`\b`-anchored variants, since a path idiomatically delimits an
embedded token with `_`/`.`/`-`, none of which produce a `\b` transition
the content-scanning patterns rely on).

**SG2-005** was fixed by moving the "wrote results to ..." banner to
stderr specifically when `--json` is set.

**SG2-006** was fixed by having output capture report whether decoding
was lossy (via presence of the U+FFFD replacement character after decoding
the full accumulated buffer in one call, not per read() chunk -- so a
valid multibyte character split across two reads is never misclassified),
surfaced as a new `OUTPUT_ENCODING_LOSS` incompleteness reason.

### AB-003 final disposition

**FIXED**, closing the residual this audit found still open. Concrete
replacement vectors now fail closed for: ancestor junction/symlink
replacement at multiple depths (the class this round added), hardlink
replacement of a leaf file, file symlink replacement, same-size
content-edit-with-restored-mtime (content-hash fingerprinting, not
metadata-only), and the copy/static-read/fingerprint operations
uniformly, via the same shared boundary. The remaining documented
residual is narrower than Round 1 left it: a same-path *file* replaced by
a different file that happens to reuse a just-freed inode number, or a
race that wins inside the small window a Windows handle takes to open,
is not claimed to be detected. This is a genuine, honestly-documented
architectural limitation (see SECURITY.md), not an unresolved P1/P2 --
SkillGuard does not claim to be race-free or a sandbox.

### SG-R1-NEW-001 (stable identity checks under repeated legitimate use)

Reconfirmed stable after the SG2-001 rewrite: 100 repeated iterations of
the real production `StaticScanner`, `DynamicWorkspace`, and
`ResultStore.save()` paths against the same root produce zero false
`ROOT_CHANGED`/identity-mismatch results (see
`tests/test_sg_r1_new_001_stability.py`).

## Implementer-found defects (self-adversarial pass, not in the audit's original list)

Two defects were found during this round's own real-CI verification --
neither is in the auditor's SG2-00X list, both were caught by real
Ubuntu execution before being declared fixed, not assumed away because
they only affect POSIX:

- **SG-R2-NEW-001:** the SG2-001 atomic walk+read engine classifies each
  directory entry by opening it and inspecting the resulting handle's
  fstat, rather than pre-classifying via `os.scandir()`'s
  `is_file()`/`is_dir()` the way the pre-Round-2 walker did. On POSIX,
  `open()` on a FIFO (named pipe) for reading blocks until some other
  process opens it for writing -- correct `open(2)` behavior, not a bug
  in the target tree. Since nothing in a scan of an arbitrary directory
  ever writes to a stray FIFO sitting in it, the walk hung the instant it
  reached one. Found via real Ubuntu CI hanging for 2+ hours (all 3
  Ubuntu test jobs plus coverage-gate; all 3 Windows jobs passed in under
  2 minutes, since the specific test that exposed it,
  `test_dynamic_special_file_omission_is_incomplete`, is POSIX-only).
  Fixed with `O_NONBLOCK` on every atomic open in `paths.py` -- a no-op
  for regular files/directories, but lets a FIFO's `open()` return
  immediately for classification instead of blocking.
- **SG-R2-NEW-002:** the per-name "capture identity immediately before
  open" leaf-file defense (documented as part of the SG2-001 fix, above)
  captured identity from *inside* the walker's per-entry processing loop,
  so its actual window was bounded by how much OTHER work the loop did
  before reaching that specific entry -- not by anything close to
  "immediately". A real Ubuntu CI failure of
  `test_static_read_replacement_is_incomplete_and_does_not_scan_outside`
  (a hardlink swap timed to happen right after directory listing) showed
  this precisely: the test had been silently passing on Windows only
  because SG2-001's deny-write-locked directory handle happened to block
  the swap's own `unlink()` call as a side effect, not because the
  intended identity check ran in time -- POSIX has no such locking
  side-effect, so the swap succeeded and went undetected there. Fixed by
  capturing every entry's identity as a direct byproduct of directory
  listing itself (before the per-entry loop -- and therefore before an
  attacker's swap timed to that loop -- ever runs), bounding the window
  to "between this one listing and this one entry's atomic open"
  regardless of loop position or directory size.

Both were reproduced on real Ubuntu CI (not simulated), fixed at the root
cause, covered by new regressions using real FIFOs/real hardlink swaps
against the actual production paths, and re-verified green on the exact
next CI run before being folded into this round's disposition above.

## Status after remediation

All six SG2-* findings have a recorded, independently-reproduced-then-fixed
disposition. AB-003 moved from PARTIALLY FIXED to FIXED. SG-R1-NEW-001's
stability property was reconfirmed against the substantially rewritten
path-containment engine. See the Round 2 remediation report for full
verification detail (coverage, lint, build, black-box wheel install, CI).

Preserved history: the first audit (`b96a65e`, verdict D) and this second
audit (`083629e`, verdict D) are both kept as checked-in project history,
not summarized away. A prior D verdict does not disappear from this
project's record because a later round fixed the findings behind it.
