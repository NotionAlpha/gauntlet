"""
policy_loader.py — Read a YAML policy file into a SandboxPolicy.

The loader is the single seam between user-authored YAML and the typed
SandboxPolicy that adapters (OpenShellSandbox, FakeSandbox) consume. Keeping
this responsibility separate from the CLI and the adapters means a future
"policy as Python dict" or "policy from a remote source" can drop in without
touching either.

Security:
  Error messages MUST NOT leak the on-disk filesystem path of the policy file
  or any user-content snippets — the policy file may live next to other
  user-controlled files, and error strings flow into the report which may be
  shared. Use the same `sanitize` discipline as sandbox.py.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from gauntlet._sanitizer import sanitize as _sanitize
from gauntlet.sandbox import SandboxPolicy


class PolicyLoadError(Exception):
    """Raised when a policy YAML cannot be loaded or doesn't match the schema.

    Messages are sanitized — they must not expose host filesystem paths or
    arbitrary YAML user content.
    """


def _coerce_list(raw: object, key: str) -> tuple[str, ...]:
    """Coerce a YAML value into a tuple of strings; raise for any other shape."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise PolicyLoadError(_sanitize(f"policy: '{key}' must be a list of strings"))
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise PolicyLoadError(_sanitize(f"policy: '{key}' entries must be strings"))
        out.append(item)
    return tuple(out)


def load_policy(path: Path | str) -> SandboxPolicy:
    """Read `path` as a YAML policy file and return a SandboxPolicy.

    Missing top-level sections are treated as empty (deny-by-default posture).
    Unknown top-level keys are ignored — forward-compatible with future schema
    additions like `landlock_mode`.

    Raises:
        PolicyLoadError: file unreadable, YAML invalid, or schema violation.
                         Message is sanitized.
    """
    p = Path(path)
    try:
        text = p.read_text()
    except OSError as exc:
        raise PolicyLoadError(
            _sanitize(f"policy: cannot read file: {exc.strerror or 'unknown error'}")
        ) from exc

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        # yaml errors include line/column but not file paths — still sanitize
        # in case a user policy embeds a host path that the sanitizer recognizes.
        raise PolicyLoadError(
            _sanitize(f"policy: invalid YAML: {type(exc).__name__}")
        ) from exc

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise PolicyLoadError(_sanitize("policy: top-level must be a mapping"))

    return SandboxPolicy(
        network_allow=list(_coerce_list(data.get("network_allow"), "network_allow")),
        fs_read_only=list(_coerce_list(data.get("fs_read_only"), "fs_read_only")),
        fs_read_write=list(_coerce_list(data.get("fs_read_write"), "fs_read_write")),
    )


__all__ = ["PolicyLoadError", "load_policy"]
