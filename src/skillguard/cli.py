"""SkillGuard command-line interface.

`scan` never executes the target. `run` and `audit --dynamic` DO execute a
caller-specified command against a copy of the target -- see SECURITY.md.
Everything after a literal ``--`` token is passed to the target verbatim as
an argv list (``shell=False``); it is never re-parsed or passed through a
shell, so spaces/quotes/semicolons/ampersands/pipes in target arguments
remain plain, inert argv items.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from skillguard._version import __version__
from skillguard.auditor import AuditConfig, SkillGuardAuditor
from skillguard.capabilities import CapabilityManifest
from skillguard.dynamic.observer import DynamicRunConfig
from skillguard.dynamic.runner import EnvironmentPolicy, EnvMode
from skillguard.errors import SkillGuardError, ValidationError
from skillguard.persistence import ResultStore
from skillguard.policy import Policy, default_policy
from skillguard.report import audit_to_dict, finding_to_dict, render_markdown
from skillguard.static.rules import all_rules
from skillguard.static.scanner import StaticScanConfig


def _split_dynamic_command(args: list[str]) -> tuple[list[str], list[str] | None]:
    if "--" in args:
        idx = args.index("--")
        return args[:idx], args[idx + 1 :]
    return args, None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillguard",
        description=(
            "Security and behavior auditor for AI skills, plugins, and agents. "
            "`scan` is static-only and never executes the target; `run`/`audit --dynamic` "
            "execute a caller-specified command and are NOT a sandbox."
        ),
    )
    parser.add_argument("--version", action="version", version=f"skillguard {__version__}")
    parser.add_argument(
        "--debug", action="store_true", help="show full tracebacks instead of a short error line"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser(
        "scan", help="static-only analysis of a directory (never executes target code)"
    )
    scan_p.add_argument("target")
    scan_p.add_argument(
        "--output",
        help="write audit.json/findings.json/capabilities.json/evidence.json/report.md here",
    )
    scan_p.add_argument(
        "--json", action="store_true", help="print the JSON audit document instead of a summary"
    )
    scan_p.add_argument("--max-files", type=int, default=5000)
    scan_p.add_argument("--max-total-bytes", type=int, default=200_000_000)
    scan_p.add_argument("--max-file-bytes", type=int, default=5_000_000)
    scan_p.add_argument("--max-depth", type=int, default=64)
    scan_p.add_argument("--policy", help="path to a policy JSON document")

    run_p = sub.add_parser(
        "run",
        help="execute `-- COMMAND ARGS...` against a copy of TARGET and observe it (NOT a sandbox)",
    )
    run_p.add_argument("target")
    run_p.add_argument("--timeout", type=float, default=30.0)
    run_p.add_argument("--output")
    run_p.add_argument("--json", action="store_true")
    run_p.add_argument(
        "--env-mode", choices=["minimal", "allowlist", "explicit"], default="minimal"
    )
    run_p.add_argument("--env", action="append", default=[], metavar="KEY=VALUE")
    run_p.add_argument("--allow-env", action="append", default=[], metavar="NAME")
    run_p.add_argument("--canary", action="append", default=[])
    run_p.add_argument("--no-network", action="store_true")
    run_p.add_argument("--no-git", action="store_true")

    audit_p = sub.add_parser(
        "audit",
        help="static analysis, optional `--dynamic -- COMMAND ARGS...`, and policy evaluation",
    )
    audit_p.add_argument("target")
    audit_p.add_argument(
        "--dynamic", action="store_true", help="also execute `-- COMMAND ARGS...` and observe it"
    )
    audit_p.add_argument("--timeout", type=float, default=30.0)
    audit_p.add_argument("--policy")
    audit_p.add_argument("--capabilities")
    audit_p.add_argument("--output")
    audit_p.add_argument("--json", action="store_true")
    audit_p.add_argument(
        "--env-mode", choices=["minimal", "allowlist", "explicit"], default="minimal"
    )
    audit_p.add_argument("--env", action="append", default=[])
    audit_p.add_argument("--allow-env", action="append", default=[])
    audit_p.add_argument("--canary", action="append", default=[])
    audit_p.add_argument("--no-network", action="store_true")
    audit_p.add_argument("--no-git", action="store_true")

    vm_p = sub.add_parser("validate-manifest", help="validate a capability manifest JSON file")
    vm_p.add_argument("file")

    report_p = sub.add_parser("report", help="print the saved Markdown report for a result")
    report_p.add_argument("output")
    report_p.add_argument("result_id")

    sub.add_parser("rules", help="list built-in static-analysis rule IDs")

    return parser


def _build_env_policy(ns: argparse.Namespace) -> EnvironmentPolicy:
    mode = EnvMode(ns.env_mode.upper())
    explicit: dict[str, str] = {}
    for item in ns.env:
        if "=" not in item:
            raise ValidationError(f"--env must be KEY=VALUE, got {item!r}")
        key, _, value = item.partition("=")
        explicit[key] = value
    return EnvironmentPolicy(
        mode=mode, allowlist_names=frozenset(ns.allow_env), explicit_vars=explicit
    )


def _load_policy(path: str | None) -> Policy:
    if path is None:
        return default_policy()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Policy.from_dict(data)


def _load_capabilities(path: str | None) -> CapabilityManifest | None:
    if path is None:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return CapabilityManifest.from_dict(data)


def _prevalidate_output(output: str | None) -> ResultStore | None:
    """Validate (and, if needed, create) the output root before running a
    potentially expensive -- and for `--dynamic`, code-executing -- audit.
    An existing-file-as-output-root error should surface immediately, not
    only after the audit has already run to completion."""
    if output is None:
        return None
    return ResultStore(output)


def _save_and_print(result, *, store: ResultStore | None, as_json: bool) -> None:
    audit_id = result.audit_id
    if store is not None:
        store.save(
            audit_id,
            audit=audit_to_dict(result),
            findings=[finding_to_dict(f) for f in result.findings],
            capabilities=audit_to_dict(result)["capabilities"],
            evidence=[
                {
                    "kind": e.kind.value,
                    "source": e.source,
                    "summary": e.summary,
                    "origin": e.origin,
                    "timestamp": e.timestamp,
                    "details": dict(e.details),
                }
                for e in result.evidence
            ],
            report_markdown=render_markdown(result),
        )
        print(f"wrote results to {store.location_for(audit_id).audit_json.parent}")
    if as_json:
        print(json.dumps(audit_to_dict(result), indent=2, sort_keys=True))
    else:
        print(render_markdown(result))


def _cmd_scan(ns: argparse.Namespace) -> int:
    static_config = StaticScanConfig(
        max_files=ns.max_files,
        max_total_bytes=ns.max_total_bytes,
        max_file_bytes=ns.max_file_bytes,
        max_depth=ns.max_depth,
    )
    policy = _load_policy(ns.policy)
    store = _prevalidate_output(ns.output)
    config = AuditConfig(
        static=static_config, dynamic=None, capability_manifest=None, policy=policy
    )
    result = SkillGuardAuditor(config).audit(ns.target)
    _save_and_print(result, store=store, as_json=ns.json)
    return 3 if result.policy_result.disposition.value == "BLOCK" else 0


def _cmd_run(ns: argparse.Namespace, command_argv: list[str] | None) -> int:
    if not command_argv:
        raise ValidationError(
            "`skillguard run TARGET -- COMMAND ARGS...` requires a command after `--`"
        )
    dynamic_config = DynamicRunConfig(
        argv=tuple(command_argv),
        timeout=ns.timeout,
        env_policy=_build_env_policy(ns),
        canaries=tuple(ns.canary),
        observe_network=not ns.no_network,
        observe_git=not ns.no_git,
    )
    store = _prevalidate_output(ns.output)
    config = AuditConfig(
        static=StaticScanConfig(),
        dynamic=dynamic_config,
        capability_manifest=None,
        policy=default_policy(),
    )
    result = SkillGuardAuditor(config).audit(ns.target)
    _save_and_print(result, store=store, as_json=ns.json)
    outcome = result.dynamic.command_result.outcome.value if result.dynamic else "OBSERVER_FAILED"
    return 0 if outcome == "EXITED" else 1


def _cmd_audit(ns: argparse.Namespace, command_argv: list[str] | None) -> int:
    dynamic_config = None
    if ns.dynamic:
        if not command_argv:
            raise ValidationError(
                "`skillguard audit TARGET --dynamic -- COMMAND ARGS...` requires a command after `--`"
            )
        dynamic_config = DynamicRunConfig(
            argv=tuple(command_argv),
            timeout=ns.timeout,
            env_policy=_build_env_policy(ns),
            canaries=tuple(ns.canary),
            observe_network=not ns.no_network,
            observe_git=not ns.no_git,
        )
    store = _prevalidate_output(ns.output)
    config = AuditConfig(
        static=StaticScanConfig(),
        dynamic=dynamic_config,
        capability_manifest=_load_capabilities(ns.capabilities),
        policy=_load_policy(ns.policy),
    )
    result = SkillGuardAuditor(config).audit(ns.target)
    _save_and_print(result, store=store, as_json=ns.json)
    return 3 if result.policy_result.disposition.value == "BLOCK" else 0


def _cmd_validate_manifest(ns: argparse.Namespace) -> int:
    data = json.loads(Path(ns.file).read_text(encoding="utf-8"))
    CapabilityManifest.from_dict(data)
    print(f"{ns.file}: valid capability manifest")
    return 0


def _cmd_report(ns: argparse.Namespace) -> int:
    """Print a saved report -- but only after confirming its backing
    audit.json is present and passes schema validation. `save()` writes
    audit.json/findings.json/capabilities.json/evidence.json/report.md as
    separate atomic file replacements. The audit document is written last
    with hashes for every sibling, and `ResultStore.load()` verifies those
    hashes before returning; a corrupt or mixed-generation artifact must not
    be presented to the caller as verified evidence."""
    store = ResultStore(ns.output)
    loc = store.location_for(ns.result_id)
    store.load(ns.result_id)  # raises CorruptResultError/PersistenceError if audit.json is bad
    if not loc.report_md.exists():
        raise SkillGuardError(f"no saved report for result_id {ns.result_id!r} under {ns.output}")
    print(loc.report_md.read_text(encoding="utf-8"))
    return 0


def _cmd_rules(ns: argparse.Namespace) -> int:
    for rule in all_rules():
        print(f"{rule.rule_id}\t{rule.default_severity.value}\t{rule.category}\t{rule.title}")
    return 0


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    known_args, command_argv = _split_dynamic_command(raw)
    parser = build_parser()
    ns = parser.parse_args(known_args)

    try:
        if ns.command == "scan":
            return _cmd_scan(ns)
        if ns.command == "run":
            return _cmd_run(ns, command_argv)
        if ns.command == "audit":
            return _cmd_audit(ns, command_argv)
        if ns.command == "validate-manifest":
            return _cmd_validate_manifest(ns)
        if ns.command == "report":
            return _cmd_report(ns)
        if ns.command == "rules":
            return _cmd_rules(ns)
        parser.error(f"unknown command {ns.command!r}")
        return 2
    except SkillGuardError as exc:
        if ns.debug:
            raise
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
