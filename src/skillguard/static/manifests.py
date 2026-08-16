"""Static manifest inspection: pyproject.toml, requirements*.txt,
package.json.

Parses text formats only (stdlib tomllib/json). Never installs packages,
never invokes a build backend, never queries a package registry.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass

from skillguard.models import Finding, FindingSource
from skillguard.static import rules

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10 CI
    import tomli as tomllib  # type: ignore[no-redef]

_DEFAULT_BUILD_BACKENDS = {
    "setuptools.build_meta",
    "hatchling.build",
    "flit_core.buildapi",
    "poetry.core.masonry.api",
    "pdm.backend",
}

_URL_DEP_RE = re.compile(r"^[\w.\-]+\s*@\s*(https?|file)://", re.IGNORECASE)
_GIT_DEP_RE = re.compile(r"(git\+|@\s*git\+|^git\+)", re.IGNORECASE)
_LOCAL_PATH_DEP_RE = re.compile(r"^[\w.\-]+\s*@\s*file://")

_LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall"}


@dataclass
class ManifestScanResult:
    findings: list[Finding]
    parse_ok: bool


def scan_pyproject(*, relative_path: str, text: str) -> ManifestScanResult:
    findings: list[Finding] = []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return ManifestScanResult(
            findings=[_manifest_error(relative_path, str(exc))], parse_ok=False
        )

    backend = data.get("build-system", {}).get("build-backend")
    if backend and backend not in _DEFAULT_BUILD_BACKENDS:
        findings.append(_finding(rules.SG_MANIFEST_004, relative_path, extra=f"build-backend={backend!r}"))

    deps: list[str] = []
    project = data.get("project", {})
    deps.extend(project.get("dependencies", []) or [])
    for group_deps in (project.get("optional-dependencies", {}) or {}).values():
        deps.extend(group_deps or [])

    for dep in deps:
        findings.extend(_classify_dependency(relative_path, dep))

    return ManifestScanResult(findings=findings, parse_ok=True)


def scan_requirements(*, relative_path: str, text: str) -> ManifestScanResult:
    findings: list[Finding] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        findings.extend(_classify_dependency(relative_path, stripped))
    return ManifestScanResult(findings=findings, parse_ok=True)


def scan_package_json(*, relative_path: str, text: str) -> ManifestScanResult:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return ManifestScanResult(
            findings=[_manifest_error(relative_path, str(exc))], parse_ok=False
        )
    findings: list[Finding] = []
    scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
    if isinstance(scripts, dict):
        for name in _LIFECYCLE_SCRIPTS & scripts.keys():
            findings.append(
                _finding(rules.SG_MANIFEST_005, relative_path, extra=f'scripts.{name}="{scripts[name]}"')
            )
    return ManifestScanResult(findings=findings, parse_ok=True)


def _classify_dependency(relative_path: str, dep: str) -> list[Finding]:
    findings: list[Finding] = []
    if _GIT_DEP_RE.search(dep):
        findings.append(_finding(rules.SG_MANIFEST_002, relative_path, extra=dep))
    elif _LOCAL_PATH_DEP_RE.match(dep) or dep.strip().startswith("."):
        findings.append(_finding(rules.SG_MANIFEST_003, relative_path, extra=dep))
    elif _URL_DEP_RE.match(dep):
        findings.append(_finding(rules.SG_MANIFEST_001, relative_path, extra=dep))
    return findings


def _finding(rule_def, relative_path: str, *, extra: str) -> Finding:
    return Finding(
        rule_id=rule_def.rule_id,
        title=rule_def.title,
        description=f"{rule_def.title}: {extra}",
        severity=rule_def.default_severity,
        category=rule_def.category,
        source=FindingSource.STATIC,
        confidence=rule_def.default_confidence,
        recommendation=rule_def.recommendation,
        file_path=relative_path,
    )


def _manifest_error(relative_path: str, message: str) -> Finding:
    rule = rules.SG_MANIFEST_006
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        description=f"{rule.title}: {message}",
        severity=rule.default_severity,
        category=rule.category,
        source=FindingSource.STATIC,
        confidence=rule.default_confidence,
        recommendation=rule.recommendation,
        file_path=relative_path,
    )
