"""Orchestrates one dynamic (behavior-observation) run: launches the
target command against an isolated workspace copy, and watches process,
filesystem, network, and git behavior around it.

This module is NOT a sandbox. It executes exactly the command the caller
specified. See SECURITY.md.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone

from skillguard.capabilities import Capability
from skillguard.dynamic.filesystem import FilesystemDiff, FilesystemObserver
from skillguard.dynamic.filesystem import diff_snapshots as diff_fs
from skillguard.dynamic.git import GitDiff, GitObserver
from skillguard.dynamic.git import diff_snapshots as diff_git
from skillguard.dynamic.network import ConnectionRecord, NetworkMonitor
from skillguard.dynamic.process import ProcessMonitor, ProcessRecord
from skillguard.dynamic.runner import CommandResult, CommandRunner, EnvironmentPolicy, TargetOutcome
from skillguard.dynamic.workspace import DynamicWorkspace
from skillguard.errors import SourceMutationError, ValidationError
from skillguard.models import AnalysisStatus, Evidence, EvidenceKind, IncompletenessReason
from skillguard.paths import BoundRoot
from skillguard.redaction import fingerprint, scrub_text
from skillguard.validation import (
    materialize_iterable,
    validate_finite_number,
    validate_non_negative_int,
)

_PACKAGE_MANAGER_MARKERS = ("pip", "pip3", "uv", "poetry", "npm", "pnpm", "yarn")
_PACKAGE_ACTION_MARKERS = ("install", "add")


@dataclass(frozen=True)
class DynamicRunConfig:
    argv: tuple[str, ...]
    timeout: float
    env_policy: EnvironmentPolicy = field(default_factory=EnvironmentPolicy)
    poll_interval: float = 0.2
    canaries: tuple[str, ...] = ()
    max_output_bytes: int = 2_000_000
    observe_network: bool = True
    observe_git: bool = True

    def __post_init__(self) -> None:
        argv = materialize_iterable(self.argv, name="argv")
        if not argv:
            raise ValidationError("argv must not be empty")
        object.__setattr__(self, "argv", argv)
        validate_finite_number(self.timeout, name="timeout", allow_zero=False)
        validate_finite_number(self.poll_interval, name="poll_interval", allow_zero=False)
        validate_non_negative_int(self.max_output_bytes, name="max_output_bytes")
        object.__setattr__(
            self, "canaries", tuple(materialize_iterable(self.canaries, name="canaries"))
        )
        for c in self.canaries:
            if not isinstance(c, str):
                raise ValidationError("canaries must be strings")
        if not isinstance(self.observe_network, bool):
            raise ValidationError("observe_network must be a bool")
        if not isinstance(self.observe_git, bool):
            raise ValidationError("observe_git must be a bool")


@dataclass(frozen=True)
class DynamicResult:
    status: AnalysisStatus
    command_result: CommandResult
    process_records: tuple[ProcessRecord, ...]
    filesystem_diff: FilesystemDiff
    network_records: tuple[ConnectionRecord, ...]
    git_diff: GitDiff | None
    capabilities_observed: frozenset[Capability]
    evidence: tuple[Evidence, ...]
    incompleteness_reasons: tuple[str, ...]
    workspace_path: str
    probable_canary_exposure: bool


class DynamicObserver:
    def __init__(self, config: DynamicRunConfig) -> None:
        self.config = config

    def run(self, source_root: BoundRoot) -> DynamicResult:
        """Run the target and observe it, against an isolated workspace
        copy of ``source_root``.

        Source-integrity verification (``ws.verify_source_unchanged()``)
        runs on EVERY completion path below -- success, a target-side
        failure, a timeout, an observer/monitor setup or runtime failure,
        or any other unexpected exception from the body of this method --
        not only the success path. A source mutation and an unrelated
        run failure can both be true at once; neither is allowed to
        silently hide the other (SG2-003 in docs/audits: an observer
        failure must never be able to make a mutated source look
        integrity-clean simply by preventing this check from running).

        When ``_run_inner`` DID complete and produced a ``DynamicResult``
        (which may itself already carry TIMED_OUT, OUTPUT_TRUNCATED,
        OUTPUT_ENCODING_LOSS, MONITOR_FAILURE, or other completed-run
        facts) and the mutation is only discovered afterward, that result
        is attached to the raised ``SourceMutationError`` as
        ``partial_result`` instead of being discarded -- both the
        mutation and the other facts remain observable (SG3-003 in
        docs/audits). When ``_run_inner`` itself failed before producing
        a result, there is nothing to attach and ``partial_result`` stays
        ``None``.
        """
        with DynamicWorkspace(source_root) as ws:
            primary_exc: BaseException | None = None
            result: DynamicResult | None = None
            try:
                result = self._run_inner(ws)
            except BaseException as exc:  # noqa: BLE001 - must still verify source below
                primary_exc = exc

            try:
                ws.verify_source_unchanged()
            except SourceMutationError as mutation_exc:
                if primary_exc is not None:
                    raise SourceMutationError(
                        f"{mutation_exc} -- additionally, the run itself failed with "
                        f"{type(primary_exc).__name__}: {primary_exc}"
                    ) from primary_exc
                raise SourceMutationError(
                    str(mutation_exc), partial_result=result
                ) from mutation_exc

            if primary_exc is not None:
                raise primary_exc
            assert result is not None  # noqa: S101 - reachable only if _run_inner succeeded
            return result

    def _run_inner(self, ws: DynamicWorkspace) -> DynamicResult:
        reasons: set[str] = set()
        evidence: list[Evidence] = []
        capabilities: set[Capability] = set()

        reasons.update(ws.incompleteness_reasons)
        if ws.reparse_points_skipped:
            reasons.add(IncompletenessReason.REPARSE_POINT_SKIPPED.value)
            evidence.append(
                Evidence(
                    kind=EvidenceKind.FILESYSTEM,
                    source="DynamicWorkspace",
                    summary=(
                        f"{len(ws.reparse_points_skipped)} symlink/junction/reparse point(s) "
                        "in the source tree were not copied into the workspace"
                    ),
                    origin="dynamic.workspace",
                    timestamp=_now(),
                    details={"paths": ",".join(ws.reparse_points_skipped)},
                )
            )

        fs_observer = FilesystemObserver(scope=ws.path)
        before_fs = fs_observer.snapshot()
        reasons.update(before_fs.incompleteness_reasons)

        git_observer = GitObserver()
        before_git = git_observer.snapshot(ws.path) if self.config.observe_git else None

        runner = CommandRunner(max_output_bytes=self.config.max_output_bytes)
        monitors: dict[str, object] = {}

        def on_pid(pid: int) -> None:
            started: list[object] = []
            try:
                pm = ProcessMonitor(
                    pid,
                    poll_interval=self.config.poll_interval,
                    redact_values=list(self.config.canaries),
                )
                pm.start()
                started.append(pm)
                monitors["process"] = pm
                if self.config.observe_network:
                    nm = NetworkMonitor(pid, poll_interval=self.config.poll_interval)
                    nm.start()
                    started.append(nm)
                    monitors["network"] = nm
            except BaseException:
                for monitor in reversed(started):
                    with contextlib.suppress(BaseException):
                        monitor.stop_and_join()
                monitors.clear()
                raise

        cmd_result = runner.run(
            self.config.argv,
            cwd=ws.path,
            timeout=self.config.timeout,
            env_policy=self.config.env_policy,
            on_pid_available=on_pid,
        )

        process_records: tuple[ProcessRecord, ...] = ()
        network_records: tuple[ConnectionRecord, ...] = ()

        pm = monitors.get("process")
        if pm is not None:
            try:
                process_records = tuple(pm.stop_and_join())
            except BaseException as exc:  # noqa: BLE001
                reasons.add(IncompletenessReason.MONITOR_FAILURE.value)
                evidence.append(
                    Evidence(
                        kind=EvidenceKind.PROCESS,
                        source="ProcessMonitor",
                        summary=f"process monitor failed: {exc}",
                        origin="dynamic.process",
                        timestamp=_now(),
                    )
                )

        nm = monitors.get("network")
        if nm is not None:
            try:
                network_records, partial = nm.stop_and_join()
                network_records = tuple(network_records)
                if partial:
                    reasons.add(IncompletenessReason.NETWORK_OBSERVER_PARTIAL.value)
            except BaseException as exc:  # noqa: BLE001
                reasons.add(IncompletenessReason.MONITOR_FAILURE.value)
                evidence.append(
                    Evidence(
                        kind=EvidenceKind.NETWORK,
                        source="NetworkMonitor",
                        summary=f"network monitor failed: {exc}",
                        origin="dynamic.network",
                        timestamp=_now(),
                    )
                )

        after_fs = fs_observer.snapshot()
        reasons.update(after_fs.incompleteness_reasons)
        fs_diff = diff_fs(before_fs, after_fs)

        after_git = git_observer.snapshot(ws.path) if self.config.observe_git else None
        git_diff = (
            diff_git(before_git, after_git)
            if before_git is not None and after_git is not None
            else None
        )

        # Source-integrity verification happens once, in run() above,
        # after this method returns or raises -- not here -- so it runs
        # on every completion path uniformly (see run()'s docstring and
        # SG2-003 in docs/audits).

        probable_exposure = any(
            canary and (canary in cmd_result.stdout or canary in cmd_result.stderr)
            for canary in self.config.canaries
        )
        if probable_exposure:
            exposed = [
                c for c in self.config.canaries if c in cmd_result.stdout or c in cmd_result.stderr
            ]
            evidence.append(
                Evidence(
                    kind=EvidenceKind.SECRET_CANARY,
                    source="DynamicObserver",
                    summary="canary value(s) observed in captured target output",
                    origin="dynamic.canary",
                    timestamp=_now(),
                    details={
                        "count": str(len(exposed)),
                        "fingerprints": ",".join(fingerprint(c) for c in exposed),
                    },
                )
            )

        stdout_redacted, _ = scrub_text(cmd_result.stdout, list(self.config.canaries))
        stderr_redacted, _ = scrub_text(cmd_result.stderr, list(self.config.canaries))
        cmd_result = replace(cmd_result, stdout=stdout_redacted, stderr=stderr_redacted)

        if cmd_result.stdout_truncated or cmd_result.stderr_truncated:
            reasons.add(IncompletenessReason.OUTPUT_TRUNCATED.value)
            streams = ", ".join(
                stream
                for stream, truncated in (
                    ("stdout", cmd_result.stdout_truncated),
                    ("stderr", cmd_result.stderr_truncated),
                )
                if truncated
            )
            evidence.append(
                Evidence(
                    kind=EvidenceKind.PROCESS,
                    source="CommandRunner",
                    summary=f"target output exceeded the capture limit ({streams})",
                    origin="dynamic.output",
                    timestamp=_now(),
                )
            )

        if cmd_result.stdout_encoding_lossy or cmd_result.stderr_encoding_lossy:
            # Invalid UTF-8 in captured output is decoded safely (U+FFFD
            # replacement, never a raised UnicodeDecodeError) for display,
            # but that means this was NOT a byte-for-byte-faithful
            # observation -- COMPLETE must not be reported for a run
            # whose captured output silently lost information (SG2-006
            # in docs/audits).
            reasons.add(IncompletenessReason.OUTPUT_ENCODING_LOSS.value)
            streams = ", ".join(
                stream
                for stream, lossy in (
                    ("stdout", cmd_result.stdout_encoding_lossy),
                    ("stderr", cmd_result.stderr_encoding_lossy),
                )
                if lossy
            )
            evidence.append(
                Evidence(
                    kind=EvidenceKind.PROCESS,
                    source="CommandRunner",
                    summary=(
                        f"target output contained invalid UTF-8 and was decoded lossily ({streams})"
                    ),
                    origin="dynamic.output",
                    timestamp=_now(),
                )
            )

        if cmd_result.unterminated_descendant_pids:
            # A tracked descendant PID could not be confirmed terminated
            # after cleanup -- most plausibly because it escaped this
            # run's process-group/job containment (e.g. called setsid()
            # on POSIX) and was reparented before it could be re-killed
            # by PID. SkillGuard is not a sandbox and cannot guarantee
            # containment against this; what matters here is never
            # implying COMPLETE cleanup when it demonstrably did not
            # happen (SG-R3 seam B in docs/audits).
            reasons.add(IncompletenessReason.PROCESS_CLEANUP_INCOMPLETE.value)
            evidence.append(
                Evidence(
                    kind=EvidenceKind.PROCESS,
                    source="CommandRunner",
                    summary=(
                        f"{len(cmd_result.unterminated_descendant_pids)} tracked descendant "
                        "process(es) could not be confirmed terminated after cleanup"
                    ),
                    origin="dynamic.process_cleanup",
                    timestamp=_now(),
                )
            )

        if cmd_result.outcome == TargetOutcome.TIMED_OUT:
            evidence.append(
                Evidence(
                    kind=EvidenceKind.PROCESS,
                    source="CommandRunner",
                    summary="target exceeded timeout; process tree terminated",
                    origin="dynamic.timeout",
                    timestamp=_now(),
                )
            )

        spawned_children = [r for r in process_records if r.pid != cmd_result.pid]
        if spawned_children:
            capabilities.add(Capability.PROCESS_SPAWN)
            evidence.append(
                Evidence(
                    kind=EvidenceKind.PROCESS,
                    source="ProcessMonitor",
                    summary=f"target spawned {len(spawned_children)} descendant process(es)",
                    origin="dynamic.process",
                    timestamp=_now(),
                )
            )

        if fs_diff.created or fs_diff.modified or fs_diff.deleted:
            capabilities.add(Capability.FILESYSTEM_WRITE)
            evidence.append(
                Evidence(
                    kind=EvidenceKind.FILESYSTEM,
                    source="FilesystemObserver",
                    summary=(
                        f"created={len(fs_diff.created)} modified={len(fs_diff.modified)} "
                        f"deleted={len(fs_diff.deleted)}"
                    ),
                    origin="dynamic.filesystem",
                    timestamp=_now(),
                )
            )

        if network_records:
            capabilities.add(Capability.NETWORK_OUTBOUND)
            evidence.append(
                Evidence(
                    kind=EvidenceKind.NETWORK,
                    source="NetworkMonitor",
                    summary=f"{len(network_records)} connection record(s) observed",
                    origin="dynamic.network",
                    timestamp=_now(),
                )
            )

        if git_diff is not None and (git_diff.head_changed or git_diff.working_tree_changed):
            capabilities.add(Capability.GIT_WRITE)
            evidence.append(
                Evidence(
                    kind=EvidenceKind.GIT,
                    source="GitObserver",
                    summary="git HEAD or working tree changed during run",
                    origin="dynamic.git",
                    timestamp=_now(),
                )
            )
        elif before_git is not None and before_git.is_repo:
            capabilities.add(Capability.GIT_READ)

        for rec in process_records:
            if not rec.cmdline_redacted:
                continue
            joined = " ".join(rec.cmdline_redacted).lower()
            if any(m in joined for m in _PACKAGE_MANAGER_MARKERS) and any(
                a in joined for a in _PACKAGE_ACTION_MARKERS
            ):
                capabilities.add(Capability.PACKAGES_INSTALL)
                evidence.append(
                    Evidence(
                        kind=EvidenceKind.PROCESS,
                        source="ProcessMonitor",
                        summary="process command line matches a package-manager install pattern",
                        origin="dynamic.packages",
                        timestamp=_now(),
                    )
                )
                break

        status = AnalysisStatus.COMPLETE if not reasons else AnalysisStatus.ANALYSIS_INCOMPLETE
        return DynamicResult(
            status=status,
            command_result=cmd_result,
            process_records=process_records,
            filesystem_diff=fs_diff,
            network_records=network_records,
            git_diff=git_diff,
            capabilities_observed=frozenset(capabilities),
            evidence=tuple(evidence),
            incompleteness_reasons=tuple(sorted(reasons)),
            workspace_path=str(ws.path),
            probable_canary_exposure=probable_exposure,
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
