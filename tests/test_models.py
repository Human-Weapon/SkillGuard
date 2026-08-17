"""Immutability tests: frozen dataclasses must not merely be frozen at the
top level -- nested mutable containers must be deep-frozen too (spec
sections 26/115)."""

from __future__ import annotations

from types import MappingProxyType

import pytest

from skillguard.models import (
    Confidence,
    Evidence,
    EvidenceKind,
    Finding,
    FindingSource,
    Severity,
    sort_findings,
)


class TestFindingImmutability:
    def test_finding_is_frozen(self):
        f = _finding()
        with pytest.raises(AttributeError):
            f.severity = Severity.LOW  # type: ignore[misc]

    def test_evidence_ids_list_mutation_after_construction_does_not_leak(self):
        original = ["ev-1", "ev-2"]
        f = Finding(
            rule_id="SG-TEST-001",
            title="t",
            description="d",
            severity=Severity.LOW,
            category="c",
            source=FindingSource.STATIC,
            confidence=Confidence.LOW,
            recommendation="r",
            evidence_ids=tuple(original),
        )
        original.append("ev-3")
        assert f.evidence_ids == ("ev-1", "ev-2")

    def test_sort_findings_is_deterministic_regardless_of_input_order(self):
        f1 = _finding(rule_id="SG-A-001", severity=Severity.LOW, file_path="b.py", line=2)
        f2 = _finding(rule_id="SG-A-002", severity=Severity.CRITICAL, file_path="a.py", line=1)
        f3 = _finding(rule_id="SG-A-003", severity=Severity.CRITICAL, file_path="a.py", line=5)

        order1 = sort_findings([f1, f2, f3])
        order2 = sort_findings([f3, f1, f2])
        assert order1 == order2
        assert order1[0].severity == Severity.CRITICAL


class TestEvidenceImmutability:
    def test_details_dict_mutation_after_construction_does_not_leak(self):
        original = {"key": "value"}
        e = Evidence(
            kind=EvidenceKind.PROCESS, source="test", summary="s", origin="o", details=original
        )
        original["key"] = "mutated"
        original["new"] = "also mutated"
        assert dict(e.details) == {"key": "value"}

    def test_details_is_read_only(self):
        e = Evidence(
            kind=EvidenceKind.PROCESS, source="test", summary="s", origin="o", details={"a": "b"}
        )
        assert isinstance(e.details, MappingProxyType)
        with pytest.raises(TypeError):
            e.details["a"] = "c"  # type: ignore[index]

    def test_nested_dict_in_details_is_also_frozen(self):
        original = {"outer": {"inner": "value"}}
        e = Evidence(
            kind=EvidenceKind.PROCESS, source="test", summary="s", origin="o", details=original
        )
        original["outer"]["inner"] = "mutated"
        assert isinstance(e.details["outer"], MappingProxyType)
        assert e.details["outer"]["inner"] == "value"


def _finding(
    *, rule_id="SG-TEST-000", severity=Severity.INFO, file_path=None, line=None
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="title",
        description="description",
        severity=severity,
        category="category",
        source=FindingSource.STATIC,
        confidence=Confidence.LOW,
        recommendation="recommendation",
        file_path=file_path,
        line=line,
    )
