# Built-in static analysis rules

Rule IDs are stable once released (see
[0003-rule-id-scheme](../decisions/0003-rule-id-scheme.md)) and never
depend on scan order. Run `skillguard rules` to print this table from the
live registry (`skillguard/static/rules.py`) at any time.

Findings are **evidence**, not verdicts -- see
[0004-capability-semantics](../decisions/0004-capability-semantics.md).
"subprocess call with shell=True" is a fact about the source; it is not by
itself "malware detected".

## Python AST rules (`SG-PY-*`)

| ID | Default severity | Title |
|---|---|---|
| SG-PY-001 | MEDIUM | subprocess call with `shell=True` |
| SG-PY-002 | MEDIUM | `os.system` usage |
| SG-PY-003 | MEDIUM | `os.popen` usage |
| SG-PY-004 | MEDIUM | `eval()` dynamic execution primitive |
| SG-PY-005 | MEDIUM | `exec()` dynamic execution primitive |
| SG-PY-006 | LOW | `compile()` dynamic execution primitive |
| SG-PY-007 | LOW | dynamic import (`__import__`/`importlib`) |
| SG-PY-008 | HIGH | `pickle` deserialization |
| SG-PY-009 | INFO | subprocess process creation (evidence of `process.spawn`, `shell=False`) |
| SG-PY-010 | INFO | network-capable import (`socket`/`urllib`/`http.client`/...) |
| SG-PY-011 | INFO | environment variable access (`os.environ`/`os.getenv`) |
| SG-PY-012 | INFO | filesystem write capability (`open(mode="w"/"a"/"x"/"+")`, `Path.write_text`/`write_bytes`, `unlink`, `rename`, `replace`, `mkdir`, `rmdir`, ...) |
| SG-PY-013 | MEDIUM | `ctypes` usage |
| SG-PY-014 | MEDIUM | `winreg` usage |
| SG-PY-015 | LOW | permission modification (`os.chmod`/`fchmod`/`lchmod`) |
| SG-PY-016 | HIGH | base64-decoded content passed to `eval`/`exec`/`compile` |
| SG-PY-017 | INFO | Python source could not be parsed (analysis incompleteness for this file) |

## Secret rules (`SG-SECRET-*`)

| ID | Default severity | Title |
|---|---|---|
| SG-SECRET-001 | CRITICAL | PEM-style private key block |
| SG-SECRET-002 | HIGH | well-known credential token prefix (AWS, GitHub, Slack, Google, OpenAI-style, JWT) |
| SG-SECRET-003 | MEDIUM | credential-like assignment (`password`/`api_key`/`secret`/`token` = literal string) |
| SG-SECRET-004 | LOW | high-entropy string literal (opt-in, off by default; common false-positive source) |

Detected values are never included in output -- see
[0006-redaction-pipeline](../decisions/0006-redaction-pipeline.md).

## Manifest rules (`SG-MANIFEST-*`)

| ID | Default severity | Title |
|---|---|---|
| SG-MANIFEST-001 | MEDIUM | direct URL dependency |
| SG-MANIFEST-002 | LOW | VCS (git) dependency |
| SG-MANIFEST-003 | INFO | local path dependency |
| SG-MANIFEST-004 | LOW | custom PEP 517 build backend (never invoked by SkillGuard) |
| SG-MANIFEST-005 | MEDIUM | npm `preinstall`/`install`/`postinstall` lifecycle script |
| SG-MANIFEST-006 | INFO | manifest could not be parsed (analysis incompleteness for this file) |

## Path/containment rules (`SG-PATH-*`)

| ID | Default severity | Title |
|---|---|---|
| SG-PATH-001 | INFO | symlink or reparse point found in scan target (not followed) |
