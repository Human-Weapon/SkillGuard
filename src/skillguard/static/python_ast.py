"""AST-aware static analysis for Python source.

This module NEVER imports, executes, or otherwise runs the code it
inspects. It only calls :func:`ast.parse` on file text and walks the
resulting syntax tree. See docs/decisions/0001-no-target-execution.md.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from skillguard.capabilities import Capability
from skillguard.models import Evidence, Finding, FindingSource
from skillguard.static import rules

_FS_WRITE_ATTRS = {
    "write_text",
    "write_bytes",
    "unlink",
    "rename",
    "replace",
    "mkdir",
    "rmdir",
    "touch",
    "rmtree",
    "makedirs",
    "remove",
}
_NETWORK_MODULES = {
    "socket",
    "urllib",
    "urllib.request",
    "http.client",
    "http",
    "ftplib",
    "smtplib",
}
_PROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}


@dataclass
class AstScanResult:
    findings: list[Finding]
    evidence: list[Evidence]
    capabilities: set[Capability]
    parse_ok: bool


def _dotted(node: ast.expr) -> str | None:
    """Render a Name/Attribute chain like `os.path.join` back to a dotted
    string, or None if the expression isn't a simple dotted chain."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    else:
        return None
    return ".".join(reversed(parts))


class _ImportAliasCollector(ast.NodeVisitor):
    """First pass: build a map of local name -> fully-qualified module/attr
    path, so later matching survives `import subprocess as sp`."""

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.aliases[local] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            return
        for alias in node.names:
            local = alias.asname or alias.name
            self.aliases[local] = f"{node.module}.{alias.name}"


class PythonAstScanner:
    def scan_source(self, *, relative_path: str, source: str) -> AstScanResult:
        findings: list[Finding] = []
        evidence: list[Evidence] = []
        capabilities: set[Capability] = set()

        try:
            tree = ast.parse(source, filename=relative_path)
        except SyntaxError as exc:
            rule = rules.SG_PY_017
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    description=f"Failed to parse {relative_path}: {exc.msg} (line {exc.lineno})",
                    severity=rule.default_severity,
                    category=rule.category,
                    source=FindingSource.STATIC,
                    confidence=rule.default_confidence,
                    recommendation=rule.recommendation,
                    file_path=relative_path,
                    line=exc.lineno,
                )
            )
            return AstScanResult(
                findings=findings, evidence=evidence, capabilities=capabilities, parse_ok=False
            )

        alias_collector = _ImportAliasCollector()
        alias_collector.visit(tree)
        aliases = alias_collector.aliases

        visitor = _RuleVisitor(relative_path=relative_path, aliases=aliases)
        visitor.visit(tree)

        for f in visitor.findings:
            capabilities.update(_CAPABILITY_BY_RULE.get(f.rule_id, ()))
        return AstScanResult(
            findings=visitor.findings,
            evidence=visitor.evidence,
            capabilities=capabilities,
            parse_ok=True,
        )


_CAPABILITY_BY_RULE: dict[str, tuple[Capability, ...]] = {
    "SG-PY-001": (Capability.PROCESS_SPAWN,),
    "SG-PY-002": (Capability.PROCESS_SPAWN,),
    "SG-PY-003": (Capability.PROCESS_SPAWN,),
    "SG-PY-004": (Capability.DYNAMIC_CODE_EXECUTE,),
    "SG-PY-005": (Capability.DYNAMIC_CODE_EXECUTE,),
    "SG-PY-006": (Capability.DYNAMIC_CODE_EXECUTE,),
    "SG-PY-008": (Capability.DYNAMIC_CODE_EXECUTE,),
    "SG-PY-009": (Capability.PROCESS_SPAWN,),
    "SG-PY-010": (Capability.NETWORK_OUTBOUND,),
    "SG-PY-011": (Capability.ENVIRONMENT_READ,),
    "SG-PY-012": (Capability.FILESYSTEM_WRITE,),
    "SG-PY-016": (Capability.DYNAMIC_CODE_EXECUTE,),
}


def _contains_base64_decode(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            dotted = _dotted(child.func)
            if dotted and dotted.split(".")[-1] in {
                "b64decode",
                "b32decode",
                "b16decode",
                "decodebytes",
            }:
                return True
    return False


class _RuleVisitor(ast.NodeVisitor):
    def __init__(self, *, relative_path: str, aliases: dict[str, str]) -> None:
        self.relative_path = relative_path
        self.aliases = aliases
        self.findings: list[Finding] = []
        self.evidence: list[Evidence] = []
        self._reported_network = False
        self._reported_env: set[int] = set()

    def _resolve(self, node: ast.expr) -> str | None:
        dotted = _dotted(node)
        if dotted is None:
            return None
        head, _, rest = dotted.partition(".")
        resolved_head = self.aliases.get(head, head)
        return f"{resolved_head}.{rest}" if rest else resolved_head

    def _emit(self, rule_def, *, line: int, col: int, extra: str = "") -> None:
        desc = rule_def.title
        if extra:
            desc = f"{rule_def.title}: {extra}"
        self.findings.append(
            Finding(
                rule_id=rule_def.rule_id,
                title=rule_def.title,
                description=desc,
                severity=rule_def.default_severity,
                category=rule_def.category,
                source=FindingSource.STATIC,
                confidence=rule_def.default_confidence,
                recommendation=rule_def.recommendation,
                file_path=self.relative_path,
                line=line,
                column=col,
            )
        )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            mod = alias.name
            if mod in {"ctypes"} or mod.startswith("ctypes."):
                self._emit(rules.SG_PY_013, line=node.lineno, col=node.col_offset)
            if mod == "winreg":
                self._emit(rules.SG_PY_014, line=node.lineno, col=node.col_offset)
            if mod in _NETWORK_MODULES and not self._reported_network:
                self._emit(
                    rules.SG_PY_010, line=node.lineno, col=node.col_offset, extra=f"import {mod}"
                )
                self._reported_network = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        if mod in _NETWORK_MODULES and not self._reported_network:
            self._emit(
                rules.SG_PY_010,
                line=node.lineno,
                col=node.col_offset,
                extra=f"from {mod} import ...",
            )
            self._reported_network = True
        if mod == "ctypes":
            self._emit(rules.SG_PY_013, line=node.lineno, col=node.col_offset)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        resolved = self._resolve(node)
        if resolved == "os.environ" and node.lineno not in self._reported_env:
            self._emit(rules.SG_PY_011, line=node.lineno, col=node.col_offset, extra="os.environ")
            self._reported_env.add(node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        resolved = self._resolve(node.func)
        if resolved:
            self._visit_resolved_call(node, resolved)
        self.generic_visit(node)

    def _visit_resolved_call(self, node: ast.Call, resolved: str) -> None:  # noqa: C901
        leaf = resolved.split(".")[-1]
        root = resolved.split(".")[0]

        if root == "subprocess" and leaf in _PROCESS_FUNCS:
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if shell_true:
                self._emit(rules.SG_PY_001, line=node.lineno, col=node.col_offset)
            else:
                self._emit(
                    rules.SG_PY_009,
                    line=node.lineno,
                    col=node.col_offset,
                    extra=f"subprocess.{leaf}",
                )

        elif resolved == "os.system":
            self._emit(rules.SG_PY_002, line=node.lineno, col=node.col_offset)
        elif resolved == "os.popen":
            self._emit(rules.SG_PY_003, line=node.lineno, col=node.col_offset)
        elif resolved in {"os.chmod", "os.fchmod", "os.lchmod"}:
            self._emit(rules.SG_PY_015, line=node.lineno, col=node.col_offset)
        elif resolved in {"os.getenv"}:
            self._emit(rules.SG_PY_011, line=node.lineno, col=node.col_offset, extra="os.getenv")
        elif resolved in {"pickle.load", "pickle.loads"}:
            self._emit(rules.SG_PY_008, line=node.lineno, col=node.col_offset, extra=resolved)
        elif resolved in {
            "os.unlink",
            "os.remove",
            "os.rename",
            "os.replace",
            "os.rmdir",
            "os.mkdir",
            "os.makedirs",
            "shutil.rmtree",
        }:
            self._emit(rules.SG_PY_012, line=node.lineno, col=node.col_offset, extra=resolved)
        elif leaf in _FS_WRITE_ATTRS and root not in {"subprocess", "os"}:
            # e.g. Path(...).write_text(...) -- can't statically confirm the
            # receiver is a pathlib.Path, so this is a best-effort pattern match.
            self._emit(
                rules.SG_PY_012, line=node.lineno, col=node.col_offset, extra=f"{resolved}(...)"
            )

        if leaf in {"eval", "exec", "compile"} and root == leaf:
            rule = {"eval": rules.SG_PY_004, "exec": rules.SG_PY_005, "compile": rules.SG_PY_006}[
                leaf
            ]
            if _contains_base64_decode(node):
                self._emit(
                    rules.SG_PY_016, line=node.lineno, col=node.col_offset, extra=f"inside {leaf}()"
                )
            else:
                self._emit(rule, line=node.lineno, col=node.col_offset)

        if resolved in {"__import__"} or resolved == "importlib.import_module":
            self._emit(rules.SG_PY_007, line=node.lineno, col=node.col_offset, extra=resolved)

        if resolved.startswith("open") and root == "open" and node.args:
            self._check_open_mode(node)

    def _check_open_mode(self, node: ast.Call) -> None:
        mode_arg = None
        if len(node.args) >= 2:
            mode_arg = node.args[1]
        else:
            for kw in node.keywords:
                if kw.arg == "mode":
                    mode_arg = kw.value
        if (
            isinstance(mode_arg, ast.Constant)
            and isinstance(mode_arg.value, str)
            and any(c in mode_arg.value for c in "wax+")
        ):
            self._emit(
                rules.SG_PY_012,
                line=node.lineno,
                col=node.col_offset,
                extra=f"open(mode={mode_arg.value!r})",
            )
