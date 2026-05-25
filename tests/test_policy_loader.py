"""Tests for gauntlet.policy_loader — translates YAML policy files into
SandboxPolicy instances. The loader is the single seam between user-authored
YAML and the typed policy the adapters consume.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gauntlet.policy_loader import PolicyLoadError, load_policy
from gauntlet.sandbox import SandboxPolicy


def _write_policy(tmp_path: Path, contents: str) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(contents)
    return p


def test_load_returns_sandbox_policy(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        """
network_allow:
  - "https://router.huggingface.co:443"
fs_read_only:
  - "/usr"
fs_read_write:
  - "/tmp/agent"
""",
    )
    policy = load_policy(path)
    assert isinstance(policy, SandboxPolicy)


def test_load_preserves_network_allow_in_order(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        """
network_allow:
  - "https://a.example.com:443"
  - "https://b.example.com:443"
""",
    )
    policy = load_policy(path)
    assert policy.network_allow == (
        "https://a.example.com:443",
        "https://b.example.com:443",
    )


def test_load_preserves_fs_paths(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        """
fs_read_only: ["/usr", "/lib"]
fs_read_write: ["/tmp/agent"]
""",
    )
    policy = load_policy(path)
    assert policy.fs_read_only == ("/usr", "/lib")
    assert policy.fs_read_write == ("/tmp/agent",)


def test_load_treats_missing_sections_as_empty(tmp_path: Path) -> None:
    """A policy with no network_allow/fs_* keys is deny-by-default — empty
    tuples, NOT a load error."""
    path = _write_policy(tmp_path, "landlock_mode: best_effort\n")
    policy = load_policy(path)
    assert policy.network_allow == ()
    assert policy.fs_read_only == ()
    assert policy.fs_read_write == ()


def test_load_raises_on_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyLoadError) as excinfo:
        load_policy(tmp_path / "does-not-exist.yaml")
    # Error message must NOT include the host filesystem path verbatim
    # (sanitizer discipline — same rule as SandboxError).
    assert "does-not-exist.yaml" not in str(excinfo.value)


def test_load_raises_on_invalid_yaml(tmp_path: Path) -> None:
    path = _write_policy(tmp_path, "network_allow: [unterminated\n")
    with pytest.raises(PolicyLoadError):
        load_policy(path)


def test_load_raises_when_network_allow_is_not_a_list(tmp_path: Path) -> None:
    path = _write_policy(tmp_path, "network_allow: not-a-list\n")
    with pytest.raises(PolicyLoadError) as excinfo:
        load_policy(path)
    assert "network_allow" in str(excinfo.value)


def test_load_returns_immutable_tuples(tmp_path: Path) -> None:
    """SandboxPolicy stores allowlists as tuples for immutability — verify the
    loader doesn't accidentally pass through mutable lists."""
    path = _write_policy(
        tmp_path,
        """
network_allow: ["https://x.example:443"]
""",
    )
    policy = load_policy(path)
    assert isinstance(policy.network_allow, tuple)
    assert isinstance(policy.fs_read_only, tuple)
    assert isinstance(policy.fs_read_write, tuple)


def test_load_treats_empty_list_as_empty_tuple(tmp_path: Path) -> None:
    """A policy with an explicit empty list is valid — produces an empty
    tuple, NOT a load error. This is a real-world shape: a policy that
    opens filesystem paths but blocks all network egress."""
    path = _write_policy(tmp_path, "network_allow: []\n")
    policy = load_policy(path)
    assert policy.network_allow == ()


def test_load_treats_explicit_null_as_empty_tuple(tmp_path: Path) -> None:
    """A policy with an explicit `key: null` is treated the same as an absent
    key — deny-by-default empty tuple. Documents that `null` is not an error
    so users who YAML-comment out a section don't get a surprise."""
    path = _write_policy(tmp_path, "network_allow: null\n")
    policy = load_policy(path)
    assert policy.network_allow == ()
