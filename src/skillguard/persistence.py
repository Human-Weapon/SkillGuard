"""Atomic, schema-validated persistence of audit results.

All writes go to a temporary sibling file and are then atomically replaced
into position (``os.replace``), so a crash mid-write never leaves a
half-written file where a caller expects valid JSON. All reads validate the
top-level schema shape and raise :class:`CorruptResultError` -- never a raw
``JSONDecodeError``/``KeyError`` -- if it doesn't match, and never silently
return an empty/"clean" result for corrupt input.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from skillguard.errors import CorruptResultError, PersistenceError
from skillguard.paths import BoundRoot

SCHEMA_VERSION = 1

_REQUIRED_TOP_LEVEL_KEYS = {"schema_version", "audit_id", "status", "findings", "capabilities"}


def atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def load_json_strict(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PersistenceError(f"could not read {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CorruptResultError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise CorruptResultError(f"{path} does not contain a JSON object at the top level")
    return data


def validate_audit_schema(data: dict, *, path: Path) -> dict:
    missing = _REQUIRED_TOP_LEVEL_KEYS - data.keys()
    if missing:
        raise CorruptResultError(f"{path} is missing required keys: {sorted(missing)}")
    version = data.get("schema_version")
    if version != SCHEMA_VERSION:
        raise CorruptResultError(
            f"{path} has unsupported schema_version {version!r} (expected {SCHEMA_VERSION})"
        )
    if not isinstance(data.get("findings"), list):
        raise CorruptResultError(f"{path}: 'findings' must be a list")
    if not isinstance(data.get("capabilities"), dict):
        raise CorruptResultError(f"{path}: 'capabilities' must be an object")
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

    def save(self, result_id: str, *, audit: dict, findings: list, capabilities: dict, evidence: list, report_markdown: str) -> ResultLocation:
        if not self._root.verify_unchanged():
            raise PersistenceError(
                f"output root {self._root.resolved} changed identity since construction; refusing to write"
            )
        loc = self.location_for(result_id)
        loc.audit_json.parent.mkdir(parents=True, exist_ok=True)
        audit_doc = {"schema_version": SCHEMA_VERSION, **audit}
        atomic_write_json(loc.audit_json, audit_doc)
        atomic_write_json(loc.findings_json, {"schema_version": SCHEMA_VERSION, "findings": findings})
        atomic_write_json(loc.capabilities_json, {"schema_version": SCHEMA_VERSION, "capabilities": capabilities})
        atomic_write_json(loc.evidence_json, {"schema_version": SCHEMA_VERSION, "evidence": evidence})

        report_tmp_fd, report_tmp_name = tempfile.mkstemp(
            prefix=".report.md.", suffix=".tmp", dir=str(loc.report_md.parent)
        )
        try:
            with os.fdopen(report_tmp_fd, "w", encoding="utf-8") as fh:
                fh.write(report_markdown)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(report_tmp_name, loc.report_md)
        except BaseException:
            try:
                os.unlink(report_tmp_name)
            except OSError:
                pass
            raise
        return loc

    def load(self, result_id: str) -> dict:
        loc = self.location_for(result_id)
        data = load_json_strict(loc.audit_json)
        return validate_audit_schema(data, path=loc.audit_json)
