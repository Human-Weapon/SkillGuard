"""Read-only git provenance observation.

Only invokes read-only git subcommands (``rev-parse``, ``status
--porcelain``). SkillGuard never checks out, resets, cleans, commits, or
pushes a target repository itself -- see spec sections 60-61.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

_GIT_EXE = shutil.which("git")


def _run_git(args: list[str], cwd: Path) -> str | None:
    if _GIT_EXE is None:
        return None
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, shell=False, read-only subcommands only
            [_GIT_EXE, *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout


@dataclass(frozen=True)
class GitSnapshot:
    is_repo: bool
    head: str | None
    status_porcelain: tuple[str, ...]


@dataclass(frozen=True)
class GitDiff:
    head_changed: bool
    before_head: str | None
    after_head: str | None
    working_tree_changed: bool


class GitObserver:
    def snapshot(self, repo_path: Path) -> GitSnapshot:
        head = _run_git(["rev-parse", "HEAD"], repo_path)
        if head is None:
            return GitSnapshot(is_repo=False, head=None, status_porcelain=())
        status = _run_git(["status", "--porcelain"], repo_path) or ""
        lines = tuple(sorted(line for line in status.splitlines() if line))
        return GitSnapshot(is_repo=True, head=head.strip(), status_porcelain=lines)


def diff_snapshots(before: GitSnapshot, after: GitSnapshot) -> GitDiff:
    return GitDiff(
        head_changed=before.head != after.head,
        before_head=before.head,
        after_head=after.head,
        working_tree_changed=before.status_porcelain != after.status_porcelain,
    )
