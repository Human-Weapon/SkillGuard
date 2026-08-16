"""Centralized secret/canary redaction.

Every code path that might write a caller-observed value (secret material
found by the static scanner, a dynamic canary, captured stdout/stderr, a
command line) into a Finding, Evidence record, or persisted artifact must
route through this module rather than reimplementing redaction locally.
See docs/decisions/0006-redaction-pipeline.md.
"""

from __future__ import annotations

import hashlib
from types import MappingProxyType


def fingerprint(value: str) -> str:
    """A short, non-reversible fingerprint safe to persist alongside a
    finding so two reports can be compared without ever storing the
    original secret."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12]


def safe_prefix(value: str, n: int = 4) -> str:
    if len(value) <= n:
        return "***"
    return value[:n] + "***"


def redact_details(value: str, *, kind: str) -> MappingProxyType:
    return MappingProxyType(
        {
            "type": kind,
            "length": str(len(value)),
            "prefix": safe_prefix(value),
            "sha256_prefix": fingerprint(value),
        }
    )


def scrub_text(text: str, secrets: list[str], *, max_len: int | None = None) -> tuple[str, bool]:
    """Replace every occurrence of each value in ``secrets`` with a
    fingerprinted redaction marker. Returns (scrubbed_text, was_truncated).

    Longer secrets are replaced first so a short secret that happens to be a
    substring of a longer one doesn't leave a partial fragment behind.
    """
    truncated = False
    if max_len is not None and len(text) > max_len:
        text = text[:max_len]
        truncated = True
    redacted = text
    for s in sorted({s for s in secrets if s}, key=len, reverse=True):
        redacted = redacted.replace(s, f"[REDACTED:{fingerprint(s)}]")
    return redacted, truncated
