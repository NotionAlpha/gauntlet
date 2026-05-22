"""
seam.py — RAMPART-in-OpenShell orchestration.

This is the Gauntlet seam: start an OpenShell isolation boundary, execute
RAMPART assurance against the target agent INSIDE that boundary, emit a result.
One function, one responsibility.

The seam depends only on the adapter interfaces (SandboxAdapter, AssuranceAdapter),
not on RAMPART or OpenShell directly.  Swap the fake adapters for real ones to
run against real infrastructure.

Usage (with fakes, for development/testing):
    from gauntlet.sandbox import FakeSandbox, SandboxPolicy
    from gauntlet.assurance import FakeAssurance
    from gauntlet.seam import run_seam

    result = run_seam(
        agent_image="my-agent:latest",
        sandbox=FakeSandbox(),
        assurance=FakeAssurance(),
        policy=SandboxPolicy(),
        suite="default",
    )

Usage (with real adapters, requires [integration] extra):
    from gauntlet.sandbox import OpenShellSandbox, SandboxPolicy
    from gauntlet.assurance import RampartAssurance
    from gauntlet.seam import run_seam

    result = run_seam(
        agent_image="my-agent:latest",
        sandbox=OpenShellSandbox(policy_path="policy.yaml"),
        assurance=RampartAssurance(),
        policy=SandboxPolicy(),
        suite="default",
    )

Security contract:
    - The agent image is treated as UNTRUSTED throughout.
    - The assurance runner is called with the sandboxed endpoint (from
      SandboxContext.agent_endpoint), never with a raw host address.
    - SandboxError and AssuranceError are wrapped in SeamError before surfacing
      to the caller; the SeamError message does not expose host paths or credentials.
    - Dry-run mode is purely a planning path — no sandbox is started and no
      assurance is executed.

Threat model note: see README.md → Threat model.
"""

from __future__ import annotations

import re
from typing import Optional

from gauntlet.assurance import AssuranceAdapter, AssuranceError, AssuranceResult
from gauntlet.sandbox import SandboxAdapter, SandboxContext, SandboxError, SandboxPolicy


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class SeamError(Exception):
    """Raised when the seam orchestration fails.

    Always indicates either a sandbox failure or an assurance failure.
    The message identifies which component failed and is sanitized —
    no host paths or credentials are exposed.
    """


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

class SeamResult:
    """Result of a Gauntlet seam run.

    Contains the sandbox context (what isolation was active), the assurance
    result (what RAMPART found), and the aggregate verdict.

    In dry-run mode, sandbox_context and assurance_result are None; dry_run is True.

    Args:
        agent_image:      The OCI image that was placed under test.
        suite:            The RAMPART test suite that was run.
        dry_run:          True if this is a plan-only result (nothing was executed).
        overall_passed:   True iff sandbox started and all assurance tests passed.
        sandbox_context:  The live SandboxContext (None in dry-run).
        assurance_result: The AssuranceResult (None in dry-run).
    """

    def __init__(
        self,
        agent_image: str,
        suite: str,
        dry_run: bool,
        overall_passed: bool,
        sandbox_context: Optional[SandboxContext],
        assurance_result: Optional[AssuranceResult],
    ) -> None:
        self.agent_image = agent_image
        self.suite = suite
        self.dry_run = dry_run
        self.overall_passed = overall_passed
        self.sandbox_context = sandbox_context
        self.assurance_result = assurance_result

    def __repr__(self) -> str:
        return (
            f"SeamResult(agent_image={self.agent_image!r}, "
            f"suite={self.suite!r}, "
            f"overall_passed={self.overall_passed!r}, "
            f"dry_run={self.dry_run!r})"
        )


# ---------------------------------------------------------------------------
# Seam orchestration
# ---------------------------------------------------------------------------

def _sanitize_seam_error(raw: str) -> str:
    """Strip host paths and credentials from SeamError messages."""
    text = re.sub(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "[REDACTED_BEARER]", raw, flags=re.IGNORECASE)
    text = re.sub(r"sk-[A-Za-z0-9]{20,}", "[REDACTED_SK_KEY]", text)
    text = re.sub(r"(?:ghp|ghs|ghr|npm)_[A-Za-z0-9]{10,}", "[REDACTED_TOKEN]", text)
    text = re.sub(r"(?:/[\w.\-]+){4,}", "[REDACTED_PATH]", text)
    text = re.sub(r"[A-Za-z0-9+/=]{40,}", "[REDACTED_TOKEN]", text)
    return text


def run_seam(
    agent_image: str,
    sandbox: SandboxAdapter,
    assurance: AssuranceAdapter,
    policy: SandboxPolicy,
    suite: str = "default",
    dry_run: bool = False,
) -> SeamResult:
    """Run the Gauntlet seam: OpenShell isolation + RAMPART assurance.

    Orchestration steps:
      1. Start an OpenShell sandbox around the agent image (deny-by-default policy).
      2. Execute RAMPART assurance against the agent endpoint INSIDE the sandbox.
      3. Return a SeamResult with the combined verdict.

    In dry-run mode, steps 1 and 2 are skipped; the result describes the plan.

    Args:
        agent_image: OCI image reference for the agent to place under test.
        sandbox:     SandboxAdapter implementation (FakeSandbox or OpenShellSandbox).
        assurance:   AssuranceAdapter implementation (FakeAssurance or RampartAssurance).
        policy:      Declarative deny-by-default sandbox policy.
        suite:       RAMPART test suite to run (default: "default").
        dry_run:     If True, validate inputs and return a plan without executing.

    Returns:
        SeamResult with sandbox context, assurance result, and overall verdict.

    Raises:
        SeamError: If the sandbox fails to start or assurance fails to run.
                   Message identifies the failing component; no credentials or
                   host paths are exposed.

    Security:
        - The agent image is UNTRUSTED.  Never pass credentials to it.
        - Assurance is run against ctx.agent_endpoint (the sandboxed address),
          never against a raw host address.
        - SeamError messages are sanitized before surfacing to the caller.
    """
    if dry_run:
        return SeamResult(
            agent_image=agent_image,
            suite=suite,
            dry_run=True,
            overall_passed=False,  # Not meaningful in dry-run
            sandbox_context=None,
            assurance_result=None,
        )

    # Step 1: Start the sandbox (deny-by-default boundary).
    try:
        with sandbox.start(agent_image=agent_image, policy=policy) as ctx:
            # Step 2: Run RAMPART assurance against the sandboxed agent endpoint.
            # Critical: use ctx.agent_endpoint (inside the boundary), not a host address.
            try:
                assurance_result = assurance.run(
                    suite=suite,
                    agent_endpoint=ctx.agent_endpoint,
                )
            except AssuranceError as exc:
                msg = _sanitize_seam_error(
                    f"Assurance failed: {exc}"
                )
                raise SeamError(msg) from exc

            return SeamResult(
                agent_image=agent_image,
                suite=suite,
                dry_run=False,
                overall_passed=assurance_result.overall_passed,
                sandbox_context=ctx,
                assurance_result=assurance_result,
            )
    except SeamError:
        raise
    except SandboxError as exc:
        msg = _sanitize_seam_error(
            f"Sandbox failed: {exc}"
        )
        raise SeamError(msg) from exc
    except Exception as exc:
        msg = _sanitize_seam_error(
            f"Seam error: {type(exc).__name__}: {exc}"
        )
        raise SeamError(msg) from exc
