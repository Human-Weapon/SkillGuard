"""Atomic, schema-validated persistence of audit results.

All writes go to a temporary sibling file and are then atomically replaced
into position (``os.replace``), so a crash mid-write never leaves a
half-written file where a caller expects valid JSON. All reads validate the
top-level schema shape and raise :class:`CorruptResultError` -- never a raw
``JSONDecodeError``/``KeyError`` -- if it doesn't match, and never silently
return an empty/"clean" result for corrupt input.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from skillguard.errors import CorruptResultError, PersistenceError
from skillguard.paths import BoundRoot

SCHEMA_VERSION = 1

_REQUIRED_TOP_LEVEL_KEYS = {"schema_version", "audit_id", "status"}


def atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True, allow_nan=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    except (TypeError, ValueError) as exc:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise PersistenceError(f"could not serialize JSON for {path}: {exc}") from exc
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def load_json_strict(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
    except UnicodeError as exc:
        raise CorruptResultError(f"{path} is not valid UTF-8: {exc}") from exc
    except OSError as exc:
        raise PersistenceError(f"could not read {path}: {exc}") from exc
    try:
        data = json.loads(raw, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, ValueError) as exc:
        raise CorruptResultError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise CorruptResultError(f"{path} does not contain a JSON object at the top level")
    return data


def validate_audit_schema(data: dict, *, path: Path) -> dict:
    missing = _REQUIRED_TOP_LEVEL_KEYS - data.keys()
    if missing:
        raise CorruptResultError(f"{path} is missing required keys: {sorted(missing)}")
    version = data.get("schema_version")
    if isinstance(version, bool) or not isinstance(version, int) or version != SCHEMA_VERSION:
        raise CorruptResultError(
            f"{path} has unsupported schema_version {version!r} (expected {SCHEMA_VERSION})"
        )
    if not isinstance(data.get("audit_id"), str) or not data["audit_id"]:
        raise CorruptResultError(f"{path}: 'audit_id' must be a non-empty string")
    if not isinstance(data.get("status"), str) or not data["status"]:
        raise CorruptResultError(f"{path}: 'status' must be a non-empty string")
    return data


@dataclass(frozen=True)
class ResultLocation:
    audit_json: Path
    findings_json: Path
    capabilities_json: Path
    evidence_json: Path
    report_md: Path


class ResultStore:
    """Persists and loads audit results under a bound output root.

    The output root is validated (and created) once at construction via
    :meth:`BoundRoot.bind_output`, which rejects immediately if the
    configured path already exists as a non-directory file -- before any
    audit state is touched.
    """

    def __init__(self, output_root: object) -> None:
        self._root = BoundRoot.bind_output(output_root, label="output root")

    @property
    def root(self) -> BoundRoot:
        return self._root

    def location_for(self, result_id: str) -> ResultLocation:
        base = self._root.resolve_result_id(result_id)
        return ResultLocation(
            audit_json=base / "audit.json",
            findings_json=base / "findings.json",
            capabilities_json=base / "capabilities.json",
            evidence_json=base / "evidence.json",
            report_md=base / "report.md",
        )

    def save(
        self,
        result_id: str,
        *,
        audit: dict,
        findings: list,
        capabilities: dict,
        evidence: list,
        report_markdown: str,
    ) -> ResultLocation:
        if not self._root.verify_unchanged():
            raise PersistenceError(
                f"output root {self._root.resolved} changed identity since construction; refusing to write"
            )
        loc = self.location_for(result_id)
        if not isinstance(audit, dict):
            raise PersistenceError("audit must be a JSON object")
        if not isinstance(report_markdown, str):
            raise PersistenceError("report_markdown must be a string")
        audit_id = audit.get("audit_id")
        if audit_id != result_id:
            raise PersistenceError(f"audit_id {audit_id!r} does not match result_id {result_id!r}")
        loc.audit_json.parent.mkdir(parents=True, exist_ok=True)
        audit_doc = {**audit, "schema_version": SCHEMA_VERSION}
        findings_doc = {"schema_version": SCHEMA_VERSION, "findings": findings}
        capabilities_doc = {
            "schema_version": SCHEMA_VERSION,
            "capabilities": capabilities,
        }
        evidence_doc = {"schema_version": SCHEMA_VERSION, "evidence": evidence}
        atomic_write_json(
            loc.findings_json,
            findings_doc,
        )
        atomic_write_json(
            loc.capabilities_json,
            capabilities_doc,
        )
        atomic_write_json(
            loc.evidence_json,
            evidence_doc,
        )
        _atomic_write_text(loc.report_md, report_markdown)

        audit_doc["artifact_hashes"] = {
            loc.findings_json.name: _sha256_file(loc.findings_json),
            loc.capabilities_json.name: _sha256_file(loc.capabilities_json),
            loc.evidence_json.name: _sha256_file(loc.evidence_json),
            loc.report_md.name: _sha256_file(loc.report_md),
        }
        # The audit document is the commit marker: it is written last and
        # contains hashes for every sibling artifact. A crash or partial
        # overwrite therefore fails closed during load instead of producing a
        # report assembled from mixed generations.
        atomic_write_json(loc.audit_json, audit_doc)
        return loc

    def load(self, result_id: str) -> dict:
        loc = self.location_for(result_id)
        data = load_json_strict(loc.audit_json)
        data = validate_audit_schema(data, path=loc.audit_json)
        if data["audit_id"] != result_id:
            raise CorruptResultError(
                f"{loc.audit_json}: audit_id {data['audit_id']!r} does not match result_id {result_id!r}"
            )
        hashes = data.get("artifact_hashes")
        if not isinstance(hashes, dict):
            raise CorruptResultError(
                f"{loc.audit_json}: missing artifact_hashes integrity manifest"
            )
        expected_names = {
            loc.findings_json.name,
            loc.capabilities_json.name,
            loc.evidence_json.name,
            loc.report_md.name,
        }
        if set(hashes) != expected_names or any(
            not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None
            for value in hashes.values()
        ):
            raise CorruptResultError(
                f"{loc.audit_json}: invalid artifact_hashes integrity manifest"
            )

        findings = load_json_strict(loc.findings_json)
        _validate_sibling(findings, key="findings", expected_type=list, path=loc.findings_json)
        _validate_findings(findings["findings"], path=loc.findings_json)
        capabilities = load_json_strict(loc.capabilities_json)
        _validate_sibling(
            capabilities, key="capabilities", expected_type=dict, path=loc.capabilities_json
        )
        _validate_capabilities(capabilities["capabilities"], path=loc.capabilities_json)
        evidence = load_json_strict(loc.evidence_json)
        _validate_sibling(evidence, key="evidence", expected_type=list, path=loc.evidence_json)
        _validate_evidence(evidence["evidence"], path=loc.evidence_json)
        try:
            loc.report_md.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise CorruptResultError(f"could not read {loc.report_md}: {exc}") from exc

        for artifact in (
            loc.findings_json,
            loc.capabilities_json,
            loc.evidence_json,
            loc.report_md,
        ):
            try:
                actual = _sha256_file(artifact)
            except OSError as exc:
                raise CorruptResultError(f"could not hash {artifact}: {exc}") from exc
            if actual != hashes[artifact.name]:
                raise CorruptResultError(f"{artifact} failed the audit artifact integrity check")
        return data


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _reject_json_constant(value: str):
    raise ValueError(f"non-finite JSON number {value} is not allowed")


def _validate_sibling(data: dict, *, key: str, expected_type: type, path: Path) -> None:
    version = data.get("schema_version")
    if isinstance(version, bool) or not isinstance(version, int) or version != SCHEMA_VERSION:
        raise CorruptResultError(f"{path}: unsupported or invalid schema_version {version!r}")
    if not isinstance(data.get(key), expected_type):
        raise CorruptResultError(f"{path}: {key!r} must be a {expected_type.__name__}")


def _validate_findings(findings: list, *, path: Path) -> None:
    required = {
        "rule_id",
        "title",
        "description",
        "severity",
        "category",
        "source",
        "confidence",
        "recommendation",
    }
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or not required.issubset(finding):
            raise CorruptResultError(f"{path}: finding {index} has an invalid schema")
        if any(not isinstance(finding[key], str) or not finding[key] for key in required):
            raise CorruptResultError(f"{path}: finding {index} has invalid string fields")
        if not isinstance(finding.get("evidence_ids", []), list) or any(
            not isinstance(value, str) for value in finding.get("evidence_ids", [])
        ):
            raise CorruptResultError(f"{path}: finding {index} has invalid evidence_ids")
        for key in ("line", "column"):
            if finding.get(key) is not None and (
                isinstance(finding[key], bool) or not isinstance(finding[key], int)
            ):
                raise CorruptResultError(f"{path}: finding {index} has invalid {key}")
        for key in (
            "file_path",
            "observed_capability",
            "declared_capability",
            "suppression_reason",
        ):
            if finding.get(key) is not None and not isinstance(finding[key], str):
                raise CorruptResultError(f"{path}: finding {index} has invalid {key}")
        if not isinstance(finding.get("suppressed", False), bool):
            raise CorruptResultError(f"{path}: finding {index} has invalid suppressed flag")


def _validate_capabilities(capabilities: dict, *, path: Path) -> None:
    known = {
        "declared",
        "observed",
        "undeclared_observed",
        "declared_not_observed",
        "unsupported_observation",
    }
    for key, value in capabilities.items():
        if (
            key not in known
            or not isinstance(value, list)
            or any(not isinstance(item, str) for item in value)
        ):
            raise CorruptResultError(f"{path}: invalid capabilities field {key!r}")


def _validate_evidence(evidence: list, *, path: Path) -> None:
    required = {"kind", "source", "summary", "origin", "details"}
    for index, item in enumerate(evidence):
        if not isinstance(item, dict) or not required.issubset(item):
            raise CorruptResultError(f"{path}: evidence {index} has an invalid schema")
        if any(
            not isinstance(item[key], str) or not item[key]
            for key in ("kind", "source", "summary", "origin")
        ):
            raise CorruptResultError(f"{path}: evidence {index} has invalid string fields")
        if item.get("timestamp") is not None and not isinstance(item["timestamp"], str):
            raise CorruptResultError(f"{path}: evidence {index} has invalid timestamp")
        if not isinstance(item["details"], dict):
            raise CorruptResultError(f"{path}: evidence {index} has invalid details")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_text(path: Path, text: str) -> None:
    report_tmp_fd, report_tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(report_tmp_fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(report_tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(report_tmp_name)
        raise
