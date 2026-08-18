"""Centralized secret/canary redaction.

Every code path that might write a caller-observed value (secret material
found by the static scanner, a dynamic canary, captured stdout/stderr, a
command line) into a Finding, Evidence record, or persisted artifact must
route through this module rather than reimplementing redaction locally.
See docs/decisions/0006-redaction-pipeline.md.
"""

from __future__ import annotations

import hashlib
import re
from types import MappingProxyType

#: Recognizable secret *shapes* -- not caller-supplied values. Used to
#: redact secret-like content that a TARGET can embed somewhere SkillGuard
#: never intended to carry a secret and so never scans as content, e.g. a
#: filename or directory name (see SG2-004 in docs/audits: AB-001 already
#: redacted known manifest-text patterns, but only in the specific spots
#: that were being scanned as *content* -- a secret-shaped substring in a
#: PATH component was still persisted raw). The token shapes here are
#: intentionally the same ones :mod:`skillguard.static.secrets` looks for
#: in file content, so a target can't dodge redaction just by moving the
#: same-shaped string from a file's content into its name.
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)
SECRET_TOKEN_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)

# Same shapes as SECRET_TOKEN_PATTERNS, without \b word-boundary anchors.
# A path/filename idiomatically delimits an embedded token with '_', '.',
# or '-' -- all of which are word characters (or, for '.'/'-', simply
# don't produce a \b transition against the token's own leading/trailing
# alnum runs the way whitespace/punctuation in source text usually does)
# -- so the \b-anchored patterns above, tuned for scanning file *content*,
# would silently miss the exact same token shape sitting in a path
# component. The character-class-and-length structure of each shape is
# specific enough on its own that dropping \b does not introduce
# meaningful over-matching. See SG2-004 in docs/audits.
_PATH_SECRET_TOKEN_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
)


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


def redact_secret_like_patterns(text: str) -> str:
    """Replace any substring matching a known secret SHAPE (not a
    caller-supplied value list -- see :func:`scrub_text` for that) with a
    fingerprinted redaction marker. Each distinct match gets its own
    fingerprint, so two records that differed only in which secret-shaped
    path they referenced stay distinguishable after redaction -- the
    fingerprint is a stable stand-in identifier, never the secret itself.
    Safe to call on arbitrary text: the patterns are specific token
    shapes, not general heuristics, so this does not mangle ordinary
    prose, paths, or code.
    """
    if not text:
        return text
    redacted = PRIVATE_KEY_PATTERN.sub(lambda m: f"[REDACTED:{fingerprint(m.group(0))}]", text)
    for pattern in _PATH_SECRET_TOKEN_PATTERNS:
        redacted = pattern.sub(lambda m: f"[REDACTED:{fingerprint(m.group(0))}]", redacted)
    return redacted


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
