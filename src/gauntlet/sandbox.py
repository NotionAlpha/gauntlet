"""
sandbox.py — OpenShell isolation adapter.

Thin adapter interface over NVIDIA OpenShell (Apache-2.0).
The SandboxAdapter abstract class defines the seam; the seam logic (seam.py)
depends on this interface, not on OpenShell directly.

Two concrete implementations:
  FakeSandbox       — scripted fake for unit tests; no OpenShell install required.
  OpenShellSandbox  — wraps the real OpenShell client; requires openshell>=0.0.46.
                      Constructed only when the [integration] extra is installed.

Security contract:
  - The isolation boundary is DENY-BY-DEFAULT.  SandboxPolicy with no allowlists
    means the agent has no permitted network egress and no permitted filesystem access
    beyond what OpenShell grants by default (none).
  - SandboxPolicy lists are immutable after construction — widening the boundary
    requires constructing a new policy, making accidental mutation visible.
  - The agent image is treated as UNTRUSTED.  No credentials, API keys, or host
    filesystem paths are passed INTO the sandbox.
  - SandboxError messages are sanitized before being raised — they must not expose
    host filesystem paths or credential-like strings.

Threat model note: see README.md → Threat model.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Generator, Optional

from gauntlet._sanitizer import sanitize as _sanitize


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class SandboxError(Exception):
    """Raised when the OpenShell sandbox fails to start or encounters a runtime error.

    Messages are sanitized — they must not expose host paths or credentials.
    """


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

class SandboxPolicy:
    """Declarative deny-by-default sandbox policy.

    Maps directly to OpenShell's YAML policy structure.  Empty sequences mean
    DENY for that domain — no allowlisted network destinations, no readable
    filesystem paths, no writable filesystem paths.

    This is the default posture and should not be relaxed without explicit reason.

    Policy allowlists are stored as tuples and are immutable after construction.
    To widen the boundary, construct a new SandboxPolicy — mutation at the call
    site is not possible, which makes boundary widening intentional and visible.

    Args:
        network_allow: Allowlisted outbound network destinations (e.g. "https://api.example.com").
        fs_read_only:  Filesystem paths the agent may read (e.g. "/proc/version").
        fs_read_write: Filesystem paths the agent may write (e.g. "/tmp/agent-workdir").

    Security: never put credentials, API keys, or host secrets in this policy.
    """

    def __init__(
        self,
        network_allow: Optional[list[str]] = None,
        fs_read_only: Optional[list[str]] = None,
        fs_read_write: Optional[list[str]] = None,
    ) -> None:
        self.network_allow: tuple[str, ...] = tuple(network_allow or [])
        self.fs_read_only: tuple[str, ...] = tuple(fs_read_only or [])
        self.fs_read_write: tuple[str, ...] = tuple(fs_read_write or [])

    def to_dict(self) -> dict:
        return {
            "network_allow": list(self.network_allow),
            "fs_read_only": list(self.fs_read_only),
            "fs_read_write": list(self.fs_read_write),
        }

    def __repr__(self) -> str:
        return (
            f"SandboxPolicy("
            f"network_allow={list(self.network_allow)!r}, "
            f"fs_read_only={list(self.fs_read_only)!r}, "
            f"fs_read_write={list(self.fs_read_write)!r})"
        )


# ---------------------------------------------------------------------------
# Context yielded by the sandbox
# ---------------------------------------------------------------------------

class SandboxContext:
    """Live context of a running sandbox.

    Yielded by SandboxAdapter.start() as a context manager.  Contains the
    sandboxed agent's HTTP endpoint (the address inside the isolation boundary)
    and metadata about the active isolation.

    Security: agent_endpoint is the sandboxed address — NOT a host address.
    Do not substitute a raw host address; route all assurance traffic through
    this endpoint so it passes through the isolation boundary.
    """

    def __init__(
        self,
        sandbox_id: str,
        agent_endpoint: str,
        policy: SandboxPolicy,
        isolated: bool,
    ) -> None:
        self.sandbox_id = sandbox_id
        self.agent_endpoint = agent_endpoint
        self.policy = policy
        self.isolated = isolated

    def to_dict(self) -> dict:
        return {
            "sandbox_id": self.sandbox_id,
            "agent_endpoint": self.agent_endpoint,
            "isolated": self.isolated,
            "policy": self.policy.to_dict(),
        }

    def __repr__(self) -> str:
        return (
            f"SandboxContext(sandbox_id={self.sandbox_id!r}, "
            f"agent_endpoint={self.agent_endpoint!r}, "
            f"isolated={self.isolated!r})"
        )


# ---------------------------------------------------------------------------
# Abstract adapter
# ---------------------------------------------------------------------------

class SandboxAdapter(ABC):
    """Abstract interface for OpenShell isolation.

    seam.py depends on this interface, not on OpenShell directly.  Swap
    FakeSandbox for OpenShellSandbox to run against real infrastructure.
    """

    @abstractmethod
    @contextmanager
    def start(
        self,
        agent_image: str,
        policy: SandboxPolicy,
    ) -> Generator[SandboxContext, None, None]:
        """Start an isolated sandbox for the agent image.

        Yields a SandboxContext for the duration of the with-block.  The sandbox
        is torn down when the context manager exits (whether normally or via exception).

        Args:
            agent_image: OCI image reference for the agent to place under test.
            policy:      Declarative deny-by-default policy governing the sandbox.

        Yields:
            SandboxContext with the agent's sandboxed endpoint.

        Raises:
            SandboxError: If the sandbox fails to start or encounters a runtime error.
                          Messages are sanitized — no host paths or credentials.

        Security:
            - Do NOT inject credentials into the sandbox environment.
            - Do NOT grant the agent write access to host paths.
            - The policy is the ONLY way to widen the isolation boundary;
              widen it intentionally and document the reason.
        """
        ...


# ---------------------------------------------------------------------------
# Fake sandbox — for unit tests
# ---------------------------------------------------------------------------

class FakeSandbox(SandboxAdapter):
    """Scripted fake sandbox for unit testing.

    Returns a synthetic SandboxContext without starting any real container.
    No OpenShell install required.

    Args:
        fail:        If True, raise SandboxError when start() is called.
        fail_reason: The reason string included in SandboxError (will be sanitized).
        endpoint:    The fake sandboxed agent endpoint to report.
    """

    def __init__(
        self,
        fail: bool = False,
        fail_reason: str = "simulated sandbox failure",
        endpoint: str = "http://localhost:19090",
    ) -> None:
        self._fail = fail
        self._fail_reason = fail_reason
        self._endpoint = endpoint
        self.last_agent_image: Optional[str] = None

    @contextmanager
    def start(
        self,
        agent_image: str,
        policy: SandboxPolicy,
    ) -> Generator[SandboxContext, None, None]:
        if self._fail:
            msg = _sanitize(f"SandboxError (fake): {self._fail_reason}")
            raise SandboxError(msg)
        self.last_agent_image = agent_image
        ctx = SandboxContext(
            sandbox_id=f"fake-{uuid.uuid4().hex[:8]}",
            agent_endpoint=self._endpoint,
            policy=policy,
            isolated=True,
        )
        yield ctx


# ---------------------------------------------------------------------------
# Real OpenShell adapter — requires openshell>=0.0.46 (integration extra)
# ---------------------------------------------------------------------------

class OpenShellSandbox(SandboxAdapter):
    """OpenShell sandbox adapter.

    Wraps the real openshell client.  Requires `pip install -e ".[integration]"`.

    Args:
        policy_path: Path to the OpenShell declarative YAML policy file.
                     The policy governs filesystem access, network egress,
                     process behavior, and inference routing.

    Security:
        The OpenShell sandbox enforces deny-by-default isolation at the kernel
        level (Landlock LSM + seccomp-bpf).  The agent cannot reach host resources
        beyond what the policy explicitly permits.
    """

    def __init__(self, policy_path: str = "policy.yaml") -> None:
        self._policy_path = policy_path

    @contextmanager
    def start(
        self,
        agent_image: str,
        policy: SandboxPolicy,
    ) -> Generator[SandboxContext, None, None]:
        try:
            import openshell  # type: ignore[import]
        except ImportError as exc:
            raise SandboxError(
                "OpenShell is not installed.  "
                "Install with: pip install -e '.[integration]'"
            ) from exc

        # Translate our SandboxPolicy to the openshell policy format.
        # OpenShell's alpha API (v0.0.46) accepts a policy dict or YAML path;
        # we pass the structured policy dict so the deny-by-default posture is
        # enforced regardless of what the on-disk YAML contains.
        openshell_policy = {
            "network": {
                "allow": [{"destination": d} for d in policy.network_allow],
            },
            "filesystem": {
                "read_only": policy.fs_read_only,
                "read_write": policy.fs_read_write,
            },
        }

        sandbox_id = str(uuid.uuid4())
        try:
            # OpenShell alpha API: openshell.Sandbox(image, policy)
            # The sandbox client manages the full lifecycle (start/stop).
            with openshell.Sandbox(
                image=agent_image,
                policy=openshell_policy,
                sandbox_id=sandbox_id,
            ) as sb:
                agent_endpoint = sb.agent_endpoint
                ctx = SandboxContext(
                    sandbox_id=sandbox_id,
                    agent_endpoint=agent_endpoint,
                    policy=policy,
                    isolated=True,
                )
                yield ctx
        except SandboxError:
            raise
        except Exception as exc:
            msg = _sanitize(f"OpenShell sandbox error: {type(exc).__name__}: {exc}")
            raise SandboxError(msg) from exc
