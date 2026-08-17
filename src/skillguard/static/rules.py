"""Registry of stable, documented static-analysis rule IDs.

Rule IDs never depend on scan order and never change meaning once released.
Every rule listed here must also be documented in ``docs/rules/``. See
docs/decisions/0003-rule-id-scheme.md for the naming rationale.
"""

from __future__ import annotations

from dataclasses import dataclass

from skillguard.models import Confidence, Severity


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    title: str
    category: str
    default_severity: Severity
    default_confidence: Confidence
    recommendation: str


_RULES: dict[str, RuleDefinition] = {}


def _register(
    rule_id: str,
    title: str,
    category: str,
    severity: Severity,
    confidence: Confidence,
    recommendation: str,
) -> RuleDefinition:
    rule = RuleDefinition(rule_id, title, category, severity, confidence, recommendation)
    _RULES[rule_id] = rule
    return rule


# --- Python AST rules -------------------------------------------------

SG_PY_001 = _register(
    "SG-PY-001",
    "subprocess call with shell=True",
    "process",
    Severity.MEDIUM,
    Confidence.HIGH,
    "shell=True passes a string through a shell; prefer an argv list with shell=False "
    "unless shell features (globbing, pipes) are specifically required.",
)
SG_PY_002 = _register(
    "SG-PY-002",
    "os.system usage",
    "process",
    Severity.MEDIUM,
    Confidence.HIGH,
    "os.system runs a command through the platform shell. Prefer subprocess with an argv list.",
)
SG_PY_003 = _register(
    "SG-PY-003",
    "os.popen usage",
    "process",
    Severity.MEDIUM,
    Confidence.HIGH,
    "os.popen runs a command through the platform shell. Prefer subprocess with an argv list.",
)
SG_PY_004 = _register(
    "SG-PY-004",
    "eval() dynamic execution primitive",
    "dynamic_code",
    Severity.MEDIUM,
    Confidence.HIGH,
    "eval() executes arbitrary Python expressions constructed at runtime. Review the source "
    "of its argument.",
)
SG_PY_005 = _register(
    "SG-PY-005",
    "exec() dynamic execution primitive",
    "dynamic_code",
    Severity.MEDIUM,
    Confidence.HIGH,
    "exec() executes arbitrary Python code constructed at runtime. Review the source of its "
    "argument.",
)
SG_PY_006 = _register(
    "SG-PY-006",
    "compile() dynamic execution primitive",
    "dynamic_code",
    Severity.LOW,
    Confidence.HIGH,
    "compile() prepares code for eval/exec. Review how the compiled code is later executed.",
)
SG_PY_007 = _register(
    "SG-PY-007",
    "dynamic import (__import__/importlib)",
    "dynamic_code",
    Severity.LOW,
    Confidence.MEDIUM,
    "Dynamic imports can load modules whose name is not visible via static analysis. Review "
    "how the module name is constructed.",
)
SG_PY_008 = _register(
    "SG-PY-008",
    "pickle deserialization",
    "dynamic_code",
    Severity.HIGH,
    Confidence.HIGH,
    "pickle.load/loads can execute arbitrary code when deserializing untrusted data. Prefer a "
    "safe serialization format (JSON) for untrusted input.",
)
SG_PY_009 = _register(
    "SG-PY-009",
    "subprocess process creation",
    "process",
    Severity.INFO,
    Confidence.HIGH,
    "Evidence of process-spawning capability. Not inherently unsafe; review the command and "
    "arguments.",
)
SG_PY_010 = _register(
    "SG-PY-010",
    "network-capable import",
    "network",
    Severity.INFO,
    Confidence.MEDIUM,
    "Evidence of network capability (socket/urllib/http.client import). Not inherently unsafe; "
    "review how it is used.",
)
SG_PY_011 = _register(
    "SG-PY-011",
    "environment variable access",
    "environment",
    Severity.INFO,
    Confidence.MEDIUM,
    "Evidence of environment-read capability (os.environ/os.getenv). SkillGuard cannot "
    "observe which values are read at runtime.",
)
SG_PY_012 = _register(
    "SG-PY-012",
    "filesystem write capability",
    "filesystem",
    Severity.INFO,
    Confidence.MEDIUM,
    "Evidence of filesystem-write capability (open in a write mode, Path.write_text/bytes, "
    "unlink, rename, replace, mkdir, rmdir).",
)
SG_PY_013 = _register(
    "SG-PY-013",
    "ctypes usage",
    "native_interop",
    Severity.MEDIUM,
    Confidence.HIGH,
    "ctypes allows calling arbitrary native code and bypasses most Python-level analysis. "
    "Review what is being called.",
)
SG_PY_014 = _register(
    "SG-PY-014",
    "winreg usage",
    "system",
    Severity.MEDIUM,
    Confidence.HIGH,
    "winreg reads/writes the Windows registry, which can affect persistent system state.",
)
SG_PY_015 = _register(
    "SG-PY-015",
    "permission modification (chmod)",
    "filesystem",
    Severity.LOW,
    Confidence.HIGH,
    "os.chmod/os.fchmod changes filesystem permissions. Review the target path and mode.",
)
SG_PY_016 = _register(
    "SG-PY-016",
    "base64-decoded content passed to dynamic execution",
    "dynamic_code",
    Severity.HIGH,
    Confidence.MEDIUM,
    "A base64 decode call appears nested inside an eval/exec/compile call. This is a common "
    "pattern for obfuscated payloads, but also appears in legitimate code. Review the decoded "
    "content's origin.",
)
SG_PY_017 = _register(
    "SG-PY-017",
    "Python source could not be parsed",
    "analysis",
    Severity.INFO,
    Confidence.HIGH,
    "The file's AST could not be built (syntax error). Static analysis for this file is "
    "incomplete.",
)

# --- Secret rules -------------------------------------------------------

SG_SECRET_001 = _register(
    "SG-SECRET-001",
    "private key block",
    "secrets",
    Severity.CRITICAL,
    Confidence.HIGH,
    "A PEM-style private key block was found in a file. Rotate the key immediately if it is "
    "real and remove it from source.",
)
SG_SECRET_002 = _register(
    "SG-SECRET-002",
    "well-known credential token prefix",
    "secrets",
    Severity.HIGH,
    Confidence.HIGH,
    "A string matching a known cloud/SaaS credential token format was found. Rotate the "
    "credential if real and remove it from source.",
)
SG_SECRET_003 = _register(
    "SG-SECRET-003",
    "credential-like assignment",
    "secrets",
    Severity.MEDIUM,
    Confidence.LOW,
    "A variable named like a credential (password/api_key/secret/token) is assigned a literal "
    "string. Review whether this is a real credential.",
)
SG_SECRET_004 = _register(
    "SG-SECRET-004",
    "high-entropy string literal",
    "secrets",
    Severity.LOW,
    Confidence.LOW,
    "A string literal has unusually high character entropy, which can (weakly) indicate "
    "embedded secret material. High entropy alone is a common false positive source.",
)

# --- Manifest rules -------------------------------------------------------

SG_MANIFEST_001 = _register(
    "SG-MANIFEST-001",
    "direct URL dependency",
    "supply_chain",
    Severity.MEDIUM,
    Confidence.HIGH,
    "A dependency is pinned to a direct URL rather than a registry + version. This bypasses "
    "registry provenance checks.",
)
SG_MANIFEST_002 = _register(
    "SG-MANIFEST-002",
    "VCS (git) dependency",
    "supply_chain",
    Severity.LOW,
    Confidence.HIGH,
    "A dependency is sourced directly from a VCS repository rather than a registry release.",
)
SG_MANIFEST_003 = _register(
    "SG-MANIFEST-003",
    "local path dependency",
    "supply_chain",
    Severity.INFO,
    Confidence.HIGH,
    "A dependency is sourced from a local path rather than a registry.",
)
SG_MANIFEST_004 = _register(
    "SG-MANIFEST-004",
    "custom PEP 517 build backend",
    "supply_chain",
    Severity.LOW,
    Confidence.HIGH,
    "A non-default build backend is declared. Build backends can execute code during "
    "packaging operations; SkillGuard's static scan does not invoke it.",
)
SG_MANIFEST_005 = _register(
    "SG-MANIFEST-005",
    "npm install lifecycle script",
    "supply_chain",
    Severity.MEDIUM,
    Confidence.HIGH,
    "package.json declares a preinstall/install/postinstall script, which npm/yarn/pnpm "
    "execute automatically during `install`.",
)
SG_MANIFEST_006 = _register(
    "SG-MANIFEST-006",
    "manifest could not be parsed",
    "analysis",
    Severity.INFO,
    Confidence.HIGH,
    "The manifest file could not be parsed. Manifest-derived analysis for this file is incomplete.",
)

# --- Path/containment rules ----------------------------------------------

SG_PATH_001 = _register(
    "SG-PATH-001",
    "symlink or reparse point in scan target",
    "filesystem",
    Severity.INFO,
    Confidence.HIGH,
    "A symlink, Windows junction, or other reparse point was found inside the scan target. "
    "SkillGuard does not follow it. Review its target manually if relevant.",
)


def get_rule(rule_id: str) -> RuleDefinition:
    return _RULES[rule_id]


def all_rules() -> tuple[RuleDefinition, ...]:
    return tuple(_RULES[k] for k in sorted(_RULES))
