"""Real-subprocess tests for the dynamic command contract: argv/shell=False,
process-tree timeout cleanup, environment policy, output capping. No
mocked subprocess calls -- these launch real Python child processes."""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path

import psutil
import pytest

from skillguard.dynamic.runner import CommandRunner, EnvironmentPolicy, EnvMode, TargetOutcome
from skillguard.errors import ValidationError

FIXTURES = Path(__file__).parent / "fixtures"


class TestArgvShellFalseContract:
    @pytest.mark.parametrize(
        "arg",
        [
            "has spaces",
            "quote's here",
            'double"quote',
            "semi;colon",
            "amp&ersand",
            "pipe|char",
            "dollar$sign",
            "backtick`char",
        ],
    )
    def test_shell_metacharacters_remain_literal_argv(self, tmp_path, arg):
        """If these were ever passed through a shell, semicolons/pipes/etc.
        would be interpreted. They must not be."""
        result = CommandRunner().run(
            [sys.executable, str(FIXTURES / "print_canary.py"), arg],
            cwd=tmp_path,
            timeout=15,
            env_policy=EnvironmentPolicy(),
        )
        assert result.outcome == TargetOutcome.EXITED
        assert result.exit_code == 0
        assert result.stdout.strip() == arg

    def test_rejects_empty_argv(self, tmp_path):
        with pytest.raises(ValidationError):
            CommandRunner().run([], cwd=tmp_path, timeout=5, env_policy=EnvironmentPolicy())

    def test_rejects_non_str_argv_items(self, tmp_path):
        with pytest.raises(ValidationError):
            CommandRunner().run(
                [sys.executable, 123], cwd=tmp_path, timeout=5, env_policy=EnvironmentPolicy()
            )

    def test_rejects_bare_string_argv(self, tmp_path):
        with pytest.raises(ValidationError):
            CommandRunner().run(
                "python script.py", cwd=tmp_path, timeout=5, env_policy=EnvironmentPolicy()
            )


class TestTimeoutValidation:
    def test_rejects_zero_timeout(self, tmp_path):
        with pytest.raises(ValidationError):
            CommandRunner().run(
                [sys.executable, "-c", "pass"],
                cwd=tmp_path,
                timeout=0,
                env_policy=EnvironmentPolicy(),
            )

    def test_rejects_negative_timeout(self, tmp_path):
        with pytest.raises(ValidationError):
            CommandRunner().run(
                [sys.executable, "-c", "pass"],
                cwd=tmp_path,
                timeout=-1,
                env_policy=EnvironmentPolicy(),
            )

    def test_rejects_nan_timeout(self, tmp_path):
        with pytest.raises(ValidationError):
            CommandRunner().run(
                [sys.executable, "-c", "pass"],
                cwd=tmp_path,
                timeout=float("nan"),
                env_policy=EnvironmentPolicy(),
            )

    def test_rejects_infinite_timeout(self, tmp_path):
        with pytest.raises(ValidationError):
            CommandRunner().run(
                [sys.executable, "-c", "pass"],
                cwd=tmp_path,
                timeout=float("inf"),
                env_policy=EnvironmentPolicy(),
            )


class TestProcessTreeTimeoutCleanup:
    def test_timeout_kills_parent_and_child_no_orphan(self, tmp_path):
        pids: dict[str, int] = {}

        def on_pid(pid: int) -> None:
            pids["parent"] = pid

        result = CommandRunner().run(
            [sys.executable, str(FIXTURES / "sleeper_with_child.py")],
            cwd=tmp_path,
            timeout=2.0,
            env_policy=EnvironmentPolicy(),
            on_pid_available=on_pid,
        )

        assert result.outcome == TargetOutcome.TIMED_OUT
        assert result.exit_code is None

        match = re.search(r"CHILD_PID=(\d+)", result.stdout)
        assert match is not None, f"child never reported its PID; stdout={result.stdout!r}"
        child_pid = int(match.group(1))
        parent_pid = pids["parent"]

        # Give the OS a brief moment to finish tearing down.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if not psutil.pid_exists(parent_pid) and not psutil.pid_exists(child_pid):
                break
            time.sleep(0.2)

        assert not psutil.pid_exists(parent_pid), "parent process survived the timeout"
        assert not psutil.pid_exists(child_pid), "child process was orphaned after timeout"


class TestEnvironmentPolicy:
    def test_minimal_mode_does_not_forward_arbitrary_variable(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKILLGUARD_TEST_SECRET", "should-not-be-forwarded")
        result = CommandRunner().run(
            [
                sys.executable,
                "-c",
                "import os; print(repr(os.environ.get('SKILLGUARD_TEST_SECRET')))",
            ],
            cwd=tmp_path,
            timeout=15,
            env_policy=EnvironmentPolicy(mode=EnvMode.MINIMAL),
        )
        assert "should-not-be-forwarded" not in result.stdout
        assert "None" in result.stdout

    def test_explicit_mode_uses_only_supplied_vars(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKILLGUARD_TEST_SECRET", "should-not-leak")
        result = CommandRunner().run(
            [sys.executable, "-c", "import os; print(sorted(os.environ.keys()))"],
            cwd=tmp_path,
            timeout=15,
            env_policy=EnvironmentPolicy(mode=EnvMode.EXPLICIT, explicit_vars={"ONLY_THIS": "1"}),
        )
        assert "SKILLGUARD_TEST_SECRET" not in result.stdout
        assert "ONLY_THIS" in result.stdout

    def test_allowlist_mode_forwards_named_variable_only(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKILLGUARD_ALLOWED_VAR", "visible")
        monkeypatch.setenv("SKILLGUARD_OTHER_VAR", "not-visible")
        result = CommandRunner().run(
            [
                sys.executable,
                "-c",
                "import os; print(os.environ.get('SKILLGUARD_ALLOWED_VAR'), os.environ.get('SKILLGUARD_OTHER_VAR'))",
            ],
            cwd=tmp_path,
            timeout=15,
            env_policy=EnvironmentPolicy(
                mode=EnvMode.ALLOWLIST, allowlist_names=frozenset({"SKILLGUARD_ALLOWED_VAR"})
            ),
        )
        assert "visible None" in result.stdout


class TestOutputCapping:
    def test_large_output_is_truncated_and_marked(self, tmp_path):
        runner = CommandRunner(max_output_bytes=1000)
        result = runner.run(
            [sys.executable, "-c", "print('x' * 100000)"],
            cwd=tmp_path,
            timeout=15,
            env_policy=EnvironmentPolicy(),
        )
        assert result.stdout_truncated is True
        assert len(result.stdout.encode("utf-8")) <= 1000

    def test_small_output_is_not_marked_truncated(self, tmp_path):
        result = CommandRunner().run(
            [sys.executable, "-c", "print('hi')"],
            cwd=tmp_path,
            timeout=15,
            env_policy=EnvironmentPolicy(),
        )
        assert result.stdout_truncated is False
