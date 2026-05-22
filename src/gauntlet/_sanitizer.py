"""
_sanitizer.py — canonical credential/path sanitizer (internal module).

A single source of truth for the redaction patterns used throughout Gauntlet.
All three sanitization layers (finding evidence, error messages, report output)
import from here so they share the same patterns and thresholds.

Security contract:
  - Path threshold is {3,} (3 or more path components) — the strictest bound
    used in this codebase.  Applying it uniformly means no layer is weaker
    than any other.
  - The function is pure (no side-effects) and idempotent.
  - Do not add credentials or secrets as arguments to this function.

Threat model note: see README.md → Threat model.
"""

from __future__ import annotations

import re

# Maximum length of any single string passed through the sanitizer.
# Evidence from an untrusted agent could be arbitrarily large; truncating
# before applying regexes prevents unbounded memory allocation.
_MAX_INPUT_LENGTH = 16_384  # 16 KiB — enough for any legitimate finding

_BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)
_SK_KEY_RE = re.compile(r"sk-[A-Za-z0-9]{20,}")
_TOKEN_PREFIX_RE = re.compile(r"(?:ghp|ghs|ghr|npm)_[A-Za-z0-9]{10,}")
_ABS_PATH_RE = re.compile(r"(?:/[\w.\-]+){3,}")  # 3+ components — stricter than 4+
_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=]{40,}")


def sanitize(raw: str) -> str:
    """Strip credential-like strings and host paths from arbitrary text.

    Applied to:
      - AssuranceFinding.evidence (at construction time)
      - SandboxError and SeamError messages (before raising)
      - render_report() output (defence-in-depth)

    Patterns removed:
      - Bearer tokens
      - OpenAI sk- keys
      - GitHub (ghp_/ghs_/ghr_) and npm (npm_) tokens
      - Absolute filesystem paths with 3 or more components
      - Long unbroken alphanumeric runs >= 40 chars (base64/hex tokens)

    Args:
        raw: Arbitrary string that may contain credentials or host paths.

    Returns:
        The sanitized string with sensitive substrings replaced by
        ``[REDACTED_*]`` placeholders.
    """
    # Truncate before applying regexes to bound memory use on untrusted input.
    text = raw[:_MAX_INPUT_LENGTH]

    text = _BEARER_RE.sub("[REDACTED_BEARER]", text)
    text = _SK_KEY_RE.sub("[REDACTED_SK_KEY]", text)
    text = _TOKEN_PREFIX_RE.sub("[REDACTED_TOKEN]", text)
    text = _ABS_PATH_RE.sub("[REDACTED_PATH]", text)
    text = _LONG_TOKEN_RE.sub("[REDACTED_TOKEN]", text)
    return text
