"""RED/GREEN regression for SG4-003: true malformed EOF is not cap truncation."""

from __future__ import annotations

import sys

import pytest

from skillguard.auditor import AuditConfig, SkillGuardAuditor
from skillguard.dynamic.observer import DynamicObserver, DynamicRunConfig
from skillguard.dynamic.runner import EnvironmentPolicy
from skillguard.models import AnalysisStatus, PolicyDisposition
from skillguard.paths import BoundRoot
from skillguard.policy import Policy


def _config(payload: bytes, *, cap: int = 1024, fd: int = 1):
    command = f"import os; os.write({fd}, bytes.fromhex('{payload.hex()}'))"
    return DynamicRunConfig(
        argv=(sys.executable, "-c", command),
        timeout=15,
        max_output_bytes=cap,
        env_policy=EnvironmentPolicy(),
        observe_network=False,
        observe_git=False,
    )


def _observe(target, payload: bytes, *, cap: int = 1024, fd: int = 1):
    return DynamicObserver(_config(payload, cap=cap, fd=fd)).run(BoundRoot.bind(target))


@pytest.mark.parametrize("payload", [b"\xe2", b"\xe2\x82", b"abc\xe2\x82"])
def test_target_emitted_incomplete_utf8_at_true_eof_is_lossy(tmp_path, payload):
    target = tmp_path / "target"
    target.mkdir()

    result = _observe(target, payload)

    assert result.command_result.stdout_truncated is False
    assert result.command_result.stdout_encoding_lossy is True
    assert "OUTPUT_ENCODING_LOSS" in result.incompleteness_reasons
    assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE


def test_target_emitted_incomplete_utf8_on_stderr_is_lossy(tmp_path):
    target = tmp_path / "target"
    target.mkdir()

    result = _observe(target, b"abc\xe2\x82", fd=2)

    assert result.command_result.stderr_truncated is False
    assert result.command_result.stderr_encoding_lossy is True
    assert "OUTPUT_ENCODING_LOSS" in result.incompleteness_reasons
    assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE


def test_require_complete_analysis_fails_closed_for_true_eof_loss(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    policy = Policy(schema_version=1, rules=(), require_complete_analysis=True)

    result = SkillGuardAuditor(AuditConfig(dynamic=_config(b"\xe2"), policy=policy)).audit(target)

    assert result.status == AnalysisStatus.ANALYSIS_INCOMPLETE
    assert result.policy_result.disposition == PolicyDisposition.REVIEW_REQUIRED


def test_cap_bisected_valid_utf8_is_truncated_but_not_lossy(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    payload = b"x" * 15 + "€".encode()

    result = _observe(target, payload, cap=16)

    assert result.command_result.stdout_truncated is True
    assert result.command_result.stdout_encoding_lossy is False
    assert "OUTPUT_TRUNCATED" in result.incompleteness_reasons
    assert "OUTPUT_ENCODING_LOSS" not in result.incompleteness_reasons
