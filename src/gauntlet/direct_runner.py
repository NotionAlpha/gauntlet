"""
direct_runner.py — DirectDockerRunner: no-sandbox SandboxAdapter.

Implements the SandboxAdapter @contextmanager protocol without isolation:
runs the agent image directly in Docker (no OpenShell confinement), polls
/health until ready, then yields a SandboxContext with isolated=False.
Used by the --no-sandbox CLI flag for environments where kernel-level
isolation is unavailable or deliberately disabled.

Security contract:
  - isolated=False is explicit — callers know there is no confinement.
  - SandboxError messages are sanitized before being raised (no host paths).
  - Credentials are forwarded via env_passthrough only when explicitly listed
    AND present in the environment.  No secrets are injected by default.
  - docker stop is called on context exit whether the block succeeded or not
    (try/finally in the generator body).

Threat model note: see README.md → Threat model.
"""

from __future__ import annotations

import os
import subprocess
import time
import uuid
from contextlib import contextmanager
from typing import Generator, Optional

import requests
import requests.exceptions

from gauntlet._sanitizer import sanitize as _sanitize
from gauntlet.sandbox import SandboxAdapter, SandboxContext, SandboxError, SandboxPolicy

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_ENV_PASSTHROUGH: list[str] = [
    "HF_TOKEN",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "MODEL_ID",
]


# ---------------------------------------------------------------------------
# DirectDockerRunner
# ---------------------------------------------------------------------------


class DirectDockerRunner(SandboxAdapter):
    """Run an agent image directly in Docker — no sandbox isolation.

    Implements the SandboxAdapter interface so it is a drop-in replacement
    for FakeSandbox and OpenShellSandbox in any code that accepts a
    SandboxAdapter.  Yields a SandboxContext with isolated=False so callers
    can distinguish this mode from a real sandboxed run.

    Args:
        port:            Host port to bind and poll for /health.  Defaults to 8080.
        ready_timeout:   Seconds to wait for the /health endpoint to return 200.
                         Defaults to 60.0.
        poll_interval:   Seconds between /health poll attempts.  Defaults to 0.5.
        env_passthrough: List of environment variable names to forward to the
                         container.  Variables not present in the host environment
                         are silently skipped.  Defaults to
                         ["HF_TOKEN", "OPENAI_API_KEY", "OPENAI_BASE_URL", "MODEL_ID"].

    Security:
        - No host filesystem paths are mounted into the container.
        - Only variables explicitly listed in env_passthrough AND present in the
          host environment are forwarded — nothing is injected by default.
        - SandboxError messages are sanitized (no host paths, no credentials).
    """

    def __init__(
        self,
        port: int = 8080,
        ready_timeout: float = 60.0,
        poll_interval: float = 0.5,
        env_passthrough: Optional[list[str]] = None,
    ) -> None:
        self._port = port
        self._ready_timeout = ready_timeout
        self._poll_interval = poll_interval
        self._env_passthrough = (
            env_passthrough if env_passthrough is not None else _DEFAULT_ENV_PASSTHROUGH
        )

    @contextmanager
    def start(
        self,
        agent_image: str,
        policy: SandboxPolicy,
    ) -> Generator[SandboxContext, None, None]:
        """Start the agent image via docker run and yield a SandboxContext.

        The container is stopped in the finally block — on both normal exit
        and exception.  If the container fails to start or the health endpoint
        does not become ready within ready_timeout, SandboxError is raised.

        Args:
            agent_image: OCI image reference for the agent to run.
            policy:      Declarative policy (carried through to SandboxContext;
                         not enforced by Docker — this is a no-isolation runner).

        Yields:
            SandboxContext(sandbox_id=<container_id>, agent_endpoint=<url>,
                           policy=policy, isolated=False)

        Raises:
            SandboxError: If docker run fails or /health does not become ready.
        """
        container_name = f"gauntlet-direct-{uuid.uuid4().hex[:8]}"
        endpoint = f"http://localhost:{self._port}"
        container_id: Optional[str] = None

        # Build docker run command.
        cmd = [
            "docker", "run",
            "--rm", "-d",
            "-p", f"{self._port}:8080",
            "--name", container_name,
        ]

        # Forward whitelisted env vars only when present in the host environment.
        for var in self._env_passthrough:
            value = os.environ.get(var)
            if value is not None:
                cmd.extend(["-e", f"{var}={value}"])

        cmd.append(agent_image)

        # --- Start container ---
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )
        except Exception as exc:
            msg = _sanitize(f"docker run failed: {type(exc).__name__}: {exc}")
            raise SandboxError(msg) from exc

        if result.returncode != 0:
            msg = _sanitize(
                f"docker run exited with code {result.returncode}: {result.stderr}"
            )
            raise SandboxError(msg)

        container_id = result.stdout.strip()

        # --- Poll /health until ready or timeout ---
        health_url = f"{endpoint}/health"
        deadline = time.monotonic() + self._ready_timeout

        while True:
            try:
                resp = requests.get(health_url, timeout=2.0)
                if resp.status_code == 200:
                    break
            except requests.exceptions.RequestException:
                pass

            if time.monotonic() >= deadline:
                msg = _sanitize(
                    f"Agent not ready after {self._ready_timeout}s: "
                    f"health endpoint {health_url} did not return 200"
                )
                # Stop container before raising.
                _stop_container(container_id)
                raise SandboxError(msg)

            time.sleep(self._poll_interval)

        # --- Yield the context ---
        # try/finally ensures docker stop runs on both normal exit AND any
        # exception raised inside the caller's with-block.  We do NOT wrap
        # the yield in a broad except — that would swallow caller exceptions.
        ctx = SandboxContext(
            sandbox_id=container_id,
            agent_endpoint=endpoint,
            policy=policy,
            isolated=False,
            isolation_kind="bypassed",
        )
        try:
            yield ctx
        finally:
            _stop_container(container_id)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _stop_container(container_id: str) -> None:
    """Best-effort docker stop — ignores all failures."""
    try:
        subprocess.run(
            ["docker", "stop", container_id],
            capture_output=True,
            text=True,
        )
    except Exception:
        pass
