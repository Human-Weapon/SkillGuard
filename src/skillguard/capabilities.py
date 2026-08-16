"""Capability manifest model and declared-vs-observed comparison.

Capabilities are not inherently malicious -- ``network.outbound`` may be
completely legitimate for a given skill. What matters is whether a
capability was *declared*, *observed*, and whether the two agree. See
docs/decisions/0004-capability-semantics.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType

from skillguard.errors import ValidationError
from skillguard.models import deep_freeze

SCHEMA_VERSION = 1


class Capability(str, Enum):
    FILESYSTEM_READ = "filesystem.read"
    FILESYSTEM_WRITE = "filesystem.write"
    NETWORK_OUTBOUND = "network.outbound"
    PROCESS_SPAWN = "process.spawn"
    ENVIRONMENT_READ = "environment.read"
    SECRETS_ACCESS = "secrets.access"
    PACKAGES_INSTALL = "packages.install"
    GIT_READ = "git.read"
    GIT_WRITE = "git.write"
    DYNAMIC_CODE_EXECUTE = "dynamic_code.execute"


class Observability(str, Enum):
    """Per-capability declaration of what SkillGuard v0.1.0 can actually
    tell you about a given capability. See docs/decisions/0005-observability-matrix.md."""

    STATIC_SUPPORTED = "STATIC_SUPPORTED"
    DYNAMIC_SUPPORTED = "DYNAMIC_SUPPORTED"
    BEST_EFFORT = "BEST_EFFORT"
    UNSUPPORTED = "UNSUPPORTED"


OBSERVABILITY_MATRIX: MappingProxyType[Capability, tuple[Observability, ...]] = MappingProxyType(
    {
        Capability.FILESYSTEM_READ: (Observability.STATIC_SUPPORTED,),
        Capability.FILESYSTEM_WRITE: (Observability.STATIC_SUPPORTED, Observability.DYNAMIC_SUPPORTED),
        Capability.NETWORK_OUTBOUND: (Observability.STATIC_SUPPORTED, Observability.BEST_EFFORT),
        Capability.PROCESS_SPAWN: (Observability.STATIC_SUPPORTED, Observability.BEST_EFFORT),
        Capability.ENVIRONMENT_READ: (Observability.STATIC_SUPPORTED, Observability.UNSUPPORTED),
        Capability.SECRETS_ACCESS: (Observability.BEST_EFFORT,),
        Capability.PACKAGES_INSTALL: (Observability.STATIC_SUPPORTED, Observability.BEST_EFFORT),
        Capability.GIT_READ: (Observability.BEST_EFFORT,),
        Capability.GIT_WRITE: (Observability.BEST_EFFORT,),
        Capability.DYNAMIC_CODE_EXECUTE: (Observability.STATIC_SUPPORTED,),
    }
)


@dataclass(frozen=True)
class CapabilityManifest:
    """A skill/plugin's declared capabilities. Constructed from a parsed
    ``skillguard.capabilities.json`` document (schema_version=1) or built
    programmatically."""

    schema_version: int
    declared: frozenset[Capability]
    constraints: MappingProxyType = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValidationError(
                f"unsupported capability manifest schema_version: {self.schema_version}"
            )
        object.__setattr__(self, "constraints", deep_freeze(self.constraints))

    @classmethod
    def from_dict(cls, data: dict) -> CapabilityManifest:
        if not isinstance(data, dict):
            raise ValidationError("capability manifest must be a JSON object")
        try:
            schema_version = data["schema_version"]
        except KeyError as exc:
            raise ValidationError("capability manifest missing 'schema_version'") from exc
        raw_declared = data.get("capabilities", [])
        if not isinstance(raw_declared, list):
            raise ValidationError("capability manifest 'capabilities' must be a list")
        try:
            declared = frozenset(Capability(c) for c in raw_declared)
        except ValueError as exc:
            raise ValidationError(f"unknown capability in manifest: {exc}") from exc
        constraints = data.get("constraints", {})
        if not isinstance(constraints, dict):
            raise ValidationError("capability manifest 'constraints' must be an object")
        return cls(schema_version=schema_version, declared=declared, constraints=constraints)


@dataclass(frozen=True)
class CapabilityComparison:
    declared: frozenset[Capability]
    observed: frozenset[Capability]
    undeclared_observed: frozenset[Capability]
    declared_not_observed: frozenset[Capability]
    unknown: frozenset[Capability]
    unsupported_observation: frozenset[Capability]


def compare_capabilities(
    *, declared: frozenset[Capability], observed: frozenset[Capability]
) -> CapabilityComparison:
    """Produce the declared/observed capability sets described in the spec.

    ``declared_not_observed`` does NOT mean the capability is absent --
    only that no supported observation mechanism saw evidence of it in this
    run. Absence of evidence is not evidence of absence.
    """
    all_known = frozenset(Capability)
    unsupported = frozenset(
        c for c in all_known if Observability.UNSUPPORTED in OBSERVABILITY_MATRIX[c]
        and Observability.BEST_EFFORT not in OBSERVABILITY_MATRIX[c]
        and Observability.DYNAMIC_SUPPORTED not in OBSERVABILITY_MATRIX[c]
    )
    return CapabilityComparison(
        declared=declared,
        observed=observed,
        undeclared_observed=observed - declared,
        declared_not_observed=declared - observed,
        unknown=frozenset(),
        unsupported_observation=unsupported,
    )
