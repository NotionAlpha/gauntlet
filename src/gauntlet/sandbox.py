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

# A stable key for the canonical agent's network egress rule. OpenShell's
# SandboxPolicy.network_policies is a map<string, NetworkPolicyRule>; the key
# is the rule's name in reports and logs.
_DEFAULT_EGRESS_RULE_NAME = "agent_egress"

# The agent's HTTP port. Must match the canonical agent's EXPOSE 8080 / PORT=8080.
_AGENT_HTTP_PORT = 8080

# The OpenShell-side service name we register for the agent's HTTP server.
# Reported back in ExposeServiceRequest and shown in `openshell sandbox list`.
_AGENT_SERVICE_NAME = "http"


class OpenShellSandbox(SandboxAdapter):
    """Real OpenShell sandbox adapter.

    Wraps `openshell.Sandbox` (NVIDIA OpenShell Python SDK, Apache-2.0). The
    SDK is a gRPC client for a running OpenShell gateway cluster; this adapter
    assumes a gateway is reachable per the user's `~/.config/openshell/active_gateway`
    or `$OPENSHELL_GATEWAY` env var (the latter overrides the former). In the
    canonical NotionAlpha/gauntlet dev setup the gateway runs inside a Lima VM
    at `https://127.0.0.1:17670`, registered by `scripts/lima/gateway-up.sh`;
    contributors with a non-default endpoint can `export OPENSHELL_GATEWAY=...`
    inside the VM session without touching adapter code.

    Requires `pip install -e ".[integration]"`.

    Per the M1.3.5 spike (docs/m1.3.5-openshell-binding-spike.md), this adapter
    implements the three fixups discovered against the speculative shape:
      1. `openshell.Sandbox(spec=SandboxSpec(template=SandboxTemplate(image=...)))`
         — image goes inside the template, not as a top-level kwarg.
      2. `SandboxPolicy.network_allow` → `NetworkPolicyRule` proto map
         (deny-by-default; only listed destinations egress).
      3. Post-`wait_ready` `ExposeService` gRPC call to recover the
         host-reachable `agent_endpoint` (no `sb.agent_endpoint` attribute exists).

    Args:
        policy_path: Reserved for future use (currently ignored — `start()`
                     receives a typed `SandboxPolicy` from the caller, loaded
                     elsewhere by `gauntlet.policy_loader.load_policy`).

    Security:
        Deny-by-default at the network and filesystem layers. SMTP egress
        (`send_email`-class side effects) is blocked because ports 25/587 are
        never in the allow-list. Defense-in-depth at the process/syscall layer
        is not available in OpenShell 0.0.47 (no seccomp, no exec-deny list)
        — accepted per the spike, which classifies this as a defense-in-depth
        observation rather than a binding gap.
    """

    def __init__(self, policy_path: str | None = None) -> None:
        # Kept for CLI backward-compatibility — `gauntlet run --policy <path>`
        # passes this even though the typed SandboxPolicy is what we use at
        # start() time. A future revision may drop this parameter.
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

        # The openshell SDK splits its proto bindings across two sub-modules:
        #   openshell._proto.sandbox_pb2   — SandboxPolicy, FilesystemPolicy,
        #                                    LandlockPolicy, NetworkEndpoint,
        #                                    NetworkPolicyRule
        #   openshell._proto.openshell_pb2 — SandboxSpec, SandboxTemplate,
        #                                    ExposeServiceRequest
        # (openshell.sandbox_pb2 does not exist in the installed wheel.)
        # We import lazily here (not at module top-level) so that the unit-test
        # fixture can inject these sub-modules into sys.modules before the first
        # real import, and so that this file stays importable when openshell is
        # not installed.
        import importlib
        sandbox_pb2 = importlib.import_module("openshell._proto.sandbox_pb2")
        openshell_pb2 = importlib.import_module("openshell._proto.openshell_pb2")

        # ---- Translate Gauntlet's SandboxPolicy → openshell proto policy ----
        # Filesystem and Landlock are direct mappings; network requires building
        # one NetworkPolicyRule per allowed destination.
        endpoints = [
            sandbox_pb2.NetworkEndpoint(host=host, port=port)
            for host, port in (_split_host_port(d) for d in policy.network_allow)
        ]
        network_policies = (
            {_DEFAULT_EGRESS_RULE_NAME: sandbox_pb2.NetworkPolicyRule(endpoints=endpoints)}
            if endpoints
            else {}
        )
        proto_policy = sandbox_pb2.SandboxPolicy(
            filesystem=sandbox_pb2.FilesystemPolicy(
                read_only=list(policy.fs_read_only),
                read_write=list(policy.fs_read_write),
            ),
            landlock=sandbox_pb2.LandlockPolicy(compatibility="best_effort"),
            network_policies=network_policies,
        )

        spec = openshell_pb2.SandboxSpec(
            template=openshell_pb2.SandboxTemplate(image=agent_image),
            policy=proto_policy,
        )

        # ---- Lifecycle: open the real Sandbox, expose the HTTP port, yield ----
        # We wrap only exceptions that originate from OpenShell's own layer
        # (during sandbox creation / ExposeService). Exceptions raised by the
        # caller inside the `with s.start(...):` body propagate unchanged so
        # test assertions and application error-handling are not silently swallowed.
        caller_exc: BaseException | None = None
        try:
            with openshell.Sandbox(spec=spec) as session:
                # ExposeService is the spike-confirmed path to recover the
                # host-reachable URL — there is no `sb.agent_endpoint`.
                # TODO(openshell-binding): replace with session.expose_http(port)
                # if/when openshell ships a public convenience wrapper
                # (tracked as a future-upstream-contribution candidate in
                # docs/m1.3.5-openshell-binding-spike.md).
                # ExposeService routes by the short sandbox NAME (the
                # animal-adjective string, ≤28 chars), not the UUID `session.id`.
                # The gateway rejects requests where `sandbox` exceeds 28 chars
                # with StatusCode.INVALID_ARGUMENT.
                sandbox_name = session.sandbox.name
                exposed = session._client._stub.ExposeService(  # noqa: SLF001
                    openshell_pb2.ExposeServiceRequest(
                        sandbox=sandbox_name,
                        service=_AGENT_SERVICE_NAME,
                        target_port=_AGENT_HTTP_PORT,
                    )
                )
                ctx = SandboxContext(
                    sandbox_id=sandbox_name,
                    agent_endpoint=exposed.url,
                    policy=policy,
                    isolated=True,
                )
                try:
                    yield ctx
                except BaseException as exc:  # noqa: BLE001
                    # Stash caller exception; re-raise after context exit so the
                    # inner `with openshell.Sandbox` tears down first.
                    caller_exc = exc
                    raise
        except BaseException as exc:  # noqa: BLE001
            if caller_exc is exc:
                # Caller-body exception — let it propagate as-is.
                raise
            # OpenShell-layer exception — map to typed SandboxError (sanitized).
            if isinstance(exc, SandboxError):
                raise
            if isinstance(exc, openshell.SandboxError):
                msg = _sanitize(f"OpenShell sandbox error: {exc}")
                raise SandboxError(msg) from exc
            msg = _sanitize(f"OpenShell sandbox error: {type(exc).__name__}: {exc}")
            raise SandboxError(msg) from exc


def _split_host_port(destination: str) -> tuple[str, int]:
    """Parse a destination like `https://router.huggingface.co:443` into
    `("router.huggingface.co", 443)`. Tolerates bare `host:port` too.

    OpenShell's NetworkEndpoint takes host + port separately; the destination
    strings in SandboxPolicy.network_allow are user-friendly URLs.
    """
    s = destination
    for prefix in ("https://", "http://"):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    s = s.split("/", 1)[0]  # strip path
    if ":" in s:
        host, port_str = s.rsplit(":", 1)
        return host, int(port_str)
    # Default to 443 for HTTPS-shaped destinations; 80 otherwise.
    if destination.startswith("http://"):
        return s, 80
    return s, 443
