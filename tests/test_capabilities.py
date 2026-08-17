"""CapabilityManifest parsing/validation tests."""

from __future__ import annotations

import pytest

from skillguard.capabilities import Capability, CapabilityManifest
from skillguard.errors import ValidationError


class TestCapabilityManifestFromDict:
    def test_valid_manifest_parses(self):
        manifest = CapabilityManifest.from_dict(
            {"schema_version": 1, "capabilities": ["filesystem.read", "network.outbound"]}
        )
        assert manifest.declared == frozenset(
            {Capability.FILESYSTEM_READ, Capability.NETWORK_OUTBOUND}
        )

    def test_missing_schema_version_rejected(self):
        with pytest.raises(ValidationError):
            CapabilityManifest.from_dict({"capabilities": []})

    def test_wrong_schema_version_rejected(self):
        with pytest.raises(ValidationError):
            CapabilityManifest.from_dict({"schema_version": 99, "capabilities": []})

    def test_unknown_capability_rejected(self):
        with pytest.raises(ValidationError):
            CapabilityManifest.from_dict(
                {"schema_version": 1, "capabilities": ["not.a.real.capability"]}
            )

    def test_non_dict_input_rejected(self):
        with pytest.raises(ValidationError):
            CapabilityManifest.from_dict(["not", "a", "dict"])  # type: ignore[arg-type]

    def test_constraints_default_empty(self):
        manifest = CapabilityManifest.from_dict({"schema_version": 1, "capabilities": []})
        assert dict(manifest.constraints) == {}

    def test_constraints_dict_is_frozen_against_caller_mutation(self):
        original_constraints = {"allowed_paths": ["a"]}
        manifest = CapabilityManifest.from_dict(
            {"schema_version": 1, "capabilities": [], "constraints": original_constraints}
        )
        original_constraints["allowed_paths"].append("b")
        assert list(manifest.constraints["allowed_paths"]) == ["a"]
