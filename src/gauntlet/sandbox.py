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

import time
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

    `isolation_kind` distinguishes the three states the report renderer needs
    to communicate accurately:
      - "isolated" — sandbox is active and enforcing policy (OpenShellSandbox).
      - "bypassed" — `--no-sandbox` mode; isolation is intentionally absent
                     (DirectDockerRunner). This is NOT a failure.
      - "fake"     — FakeSandbox in unit tests; no real boundary.
    """

    def __init__(
        self,
        sandbox_id: str,
        agent_endpoint: str,
        policy: SandboxPolicy,
        isolated: bool,
        isolation_kind: str | None = None,
    ) -> None:
        self.sandbox_id = sandbox_id
        self.agent_endpoint = agent_endpoint
        self.policy = policy
        self.isolated = isolated
        # Default for callers that haven't been updated to pass an explicit
        # kind: "isolated" when isolated=True, otherwise "fake" (the only
        # non-isolated yield path that existed before isolation_kind was
        # added was FakeSandbox; the new "bypassed" kind is opt-in).
        self.isolation_kind = isolation_kind or ("isolated" if isolated else "fake")

    def to_dict(self) -> dict:
        return {
            "sandbox_id": self.sandbox_id,
            "agent_endpoint": self.agent_endpoint,
            "isolated": self.isolated,
            "isolation_kind": self.isolation_kind,
            "policy": self.policy.to_dict(),
        }

    def __repr__(self) -> str:
        return (
            f"SandboxContext(sandbox_id={self.sandbox_id!r}, "
            f"agent_endpoint={self.agent_endpoint!r}, "
            f"isolated={self.isolated!r}, "
            f"isolation_kind={self.isolation_kind!r})"
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
            # FakeSandbox claims isolated=True (preserved for the unit-test
            # invariant that a successful FakeSandbox.start yields ctx.isolated
            # as True), while isolation_kind tells the report renderer this
            # was actually the fake adapter so the verdict shouldn't be
            # presented as a real isolation guarantee.
            isolated=True,
            isolation_kind="fake",
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

# The command to run inside the sandbox to start the canonical agent.
# OpenShell's BYOC supervisor replaces the image's CMD/ENTRYPOINT, so we have
# to exec this explicitly after wait_ready. Matches the canonical Dockerfile's
# `CMD ["python", "agent.py"]` line — the supervisor's working directory is /app.
_AGENT_START_COMMAND = ("python", "/app/agent.py")

# How long to wait for the agent's /health to return 200 after we exec the
# start command. Inference imports + Flask boot typically take 5–10s; we
# allow 60s to be safe on cold container caches.
_AGENT_READY_TIMEOUT_SECONDS = 60


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

    Uses the SDK helpers that landed on NotionAlpha/OpenShell gauntlet-bindings
    (SHA 31f9122):
      - `openshell.policy_from_network_allow` (Fix 5) for policy construction.
      - `session.expose_http(port)` (Fix 3) to recover the host-reachable URL.
      - `session.exec_detached(command)` (Fix 4) for non-blocking agent launch.
      - `openshell.http_client_for_sandbox(session)` (Fix 6) for mTLS-aware probes.

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

        # Proto modules are now re-exported at the top level of the openshell
        # package (gauntlet-bindings Fix 1). We import them after the lazy
        # `import openshell` so this file stays importable when openshell is
        # not installed, and so unit-test fixtures injecting sys.modules['openshell']
        # before the first import will have the aliases available.
        from openshell import sandbox_pb2, openshell_pb2  # type: ignore[import]  # noqa: PLC0415

        # ---- Translate Gauntlet's SandboxPolicy → openshell proto policy ----
        # policy_from_network_allow (gauntlet-bindings Fix 5) handles host:port
        # parsing and the NetworkPolicyRule proto construction for us.
        proto_policy = openshell.policy_from_network_allow(
            policy.network_allow,
            rule_name=_DEFAULT_EGRESS_RULE_NAME,
            filesystem=sandbox_pb2.FilesystemPolicy(
                read_only=list(policy.fs_read_only),
                read_write=list(policy.fs_read_write),
            ),
            landlock=sandbox_pb2.LandlockPolicy(compatibility="best_effort"),
        )

        spec = openshell_pb2.SandboxSpec(
            template=openshell_pb2.SandboxTemplate(image=agent_image),
            policy=proto_policy,
        )

        # ---- Lifecycle: open the real Sandbox, expose the HTTP port, yield ----
        # We wrap only exceptions that originate from OpenShell's own layer
        # (during sandbox creation / expose_http / exec_detached). Exceptions
        # raised by the caller inside the `with s.start(...):` body propagate
        # unchanged so test assertions and application error-handling are not
        # silently swallowed.
        caller_exc: BaseException | None = None
        try:
            with openshell.Sandbox(spec=spec) as session:
                # expose_http (gauntlet-bindings Fix 3) returns the
                # host-reachable URL directly — no private-attribute gRPC call.
                agent_url = session.expose_http(
                    _AGENT_HTTP_PORT, service_name=_AGENT_SERVICE_NAME
                )

                # exec_detached (gauntlet-bindings Fix 4) launches the agent
                # start command in a daemon thread without blocking. The
                # returned ExecHandle exposes `.error` for the readiness probe.
                # We forward only the inference-provider credentials from the
                # gauntlet process's env — everything else is denied by the
                # SandboxPolicy isolation contract.
                agent_env = _agent_runtime_env()
                agent_handle = session.exec_detached(
                    _AGENT_START_COMMAND, env=agent_env
                )

                sandbox_name = session.sandbox.name

                # Probe /health to confirm the agent's HTTP server is up before
                # yielding ctx to the caller. Without this, RAMPART (or any
                # caller) would race the agent's startup and see 502s.
                _wait_for_agent_ready(agent_url, agent_handle, session)

                ctx = SandboxContext(
                    sandbox_id=sandbox_name,
                    agent_endpoint=agent_url,
                    policy=policy,
                    isolated=True,
                    isolation_kind="isolated",
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


_AGENT_FORWARDED_ENV_VARS = ("HF_TOKEN", "OPENAI_BASE_URL", "OPENAI_API_KEY")


def _agent_runtime_env() -> dict[str, str]:
    """Build the env dict forwarded into the sandboxed agent process.

    Only inference-provider credentials are crossed in — everything else
    is denied by the SandboxPolicy isolation contract. Keys absent from
    the host env are omitted (passing them as empty strings would shadow
    any defaults the agent code might apply).
    """
    import os
    return {
        var: os.environ[var]
        for var in _AGENT_FORWARDED_ENV_VARS
        if os.environ.get(var)
    }


def _wait_for_agent_ready(endpoint: str, agent_handle, session_or_client) -> None:
    """Probe the agent's /health URL until it returns 200, with a timeout.

    Uses `openshell.http_client_for_sandbox` (gauntlet-bindings Fix 6) to
    obtain a requests.Session pre-configured with the gateway's mTLS cert.
    If `agent_handle.error` is non-None when the probe times out, the
    exception is included in the SandboxError message so the user sees the
    actual root cause instead of just "no service."

    Args:
        endpoint:        The host-reachable URL returned by expose_http.
        agent_handle:    The ExecHandle returned by exec_detached.
        session_or_client: The SandboxSession (or SandboxClient) passed to
                         openshell.http_client_for_sandbox for mTLS setup.

    Raises:
        SandboxError: if /health doesn't return 200 within
                      _AGENT_READY_TIMEOUT_SECONDS.
    """
    # Imports are local — `requests` is in the canonical-agent extras, not
    # gauntlet's core dependencies, and gauntlet.sandbox should be importable
    # without it (the FakeSandbox path doesn't need it).
    try:
        import requests  # type: ignore[import]
    except ImportError as exc:
        raise SandboxError(
            "The `requests` package is required for the OpenShell readiness "
            "probe. Install with: pip install -e '.[integration]'"
        ) from exc

    import openshell  # type: ignore[import]  # noqa: PLC0415
    http = openshell.http_client_for_sandbox(session_or_client)

    health_url = endpoint.rstrip("/") + "/health"
    deadline = time.time() + _AGENT_READY_TIMEOUT_SECONDS
    last_status: int | str | None = None
    while time.time() < deadline:
        try:
            r = http.get(health_url, timeout=3)
            last_status = r.status_code
            if r.status_code == 200:
                return
        except requests.RequestException as exc:
            last_status = type(exc).__name__
        time.sleep(1)

    # Timed out. Surface the exec handle's error if the agent failed to launch.
    agent_err = agent_handle.error if agent_handle is not None else None
    if agent_err is not None:
        agent_cause = f" Agent-launch error: {type(agent_err).__name__}: {agent_err}"
    else:
        agent_cause = ""

    raise SandboxError(
        _sanitize(
            f"agent /health did not return 200 within "
            f"{_AGENT_READY_TIMEOUT_SECONDS}s (last status: {last_status!r}).{agent_cause} "
            "The canonical-agent container is running under OpenShell, but "
            "its HTTP server never came up. Common causes: the image "
            "doesn't include `requirements.txt`'s deps; HF_TOKEN is "
            "missing inside the sandbox; the agent crashed on startup."
        )
    )
