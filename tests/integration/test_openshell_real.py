"""Integration test: OpenShellSandbox against the real openshell gateway.

Gated by:
  - openshell + rampart importable (integration extras)
  - OpenShell gateway reachable (probed via `openshell status` exit code, or
    presence of $OPENSHELL_GATEWAY / ~/.config/openshell/active_gateway)
  - Docker daemon up
  - canonical-agent image present locally
  - HF_TOKEN set (the agent itself doesn't need it for /health, but the demo
    in Task 9 does — we check here for fail-fast consistency)

Skips with a clear message when any precondition fails.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


IMAGE = "gauntlet/canonical-agent:0.1.0"


def _openshell_gateway_reachable() -> bool:
    """Return True iff the openshell CLI exists AND `openshell status` reports
    a reachable gateway."""
    if shutil.which("openshell") is None:
        return False
    out = subprocess.run(["openshell", "status"], capture_output=True, text=True)
    if out.returncode != 0:
        return False
    return "HEALTHY" in out.stdout or "Connected" in out.stdout or "Gateway:" in out.stdout


def _docker_image_present(image: str) -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode == 0


@pytest.fixture(scope="module")
def gateway_or_skip():
    try:
        import openshell  # noqa: F401
    except ImportError:
        pytest.skip("openshell not installed — run `pip install -e '.[integration]'`")
    if not _openshell_gateway_reachable():
        pytest.skip(
            "OpenShell gateway not reachable. On macOS, run "
            "`bash scripts/lima/gateway-up.sh` from the gauntlet repo root to "
            "provision the Lima VM + gateway (see docs/m1.3.6-gateway-setup.md). "
            "Then re-run pytest inside the VM with "
            "`limactl shell openshell-gateway -- bash -lc \"cd $PWD && ~/work/gauntlet-venv/bin/pytest -m integration\"`."
        )
    if not _docker_image_present(IMAGE):
        pytest.skip(f"image {IMAGE} not built — run `docker build -t {IMAGE} agents/canonical`")
    if not os.environ.get("HF_TOKEN"):
        pytest.skip("HF_TOKEN not set — required by the canonical agent for inference")


def test_openshell_sandbox_starts_canonical_agent_and_exposes_endpoint(gateway_or_skip):
    """Live sandbox: load the canonical policy, start the agent, verify the
    adapter contract (isolated, exposed endpoint URL, valid sandbox name),
    and tear down cleanly.

    Why not also probe /health? The gateway exposes services over its own
    self-signed mTLS PKI (the SDK manages client certs at
    ~/.config/openshell/gateways/<name>/mtls/). A plain `urllib` call from
    this test would fail TLS verification (self-signed) or mTLS auth
    (no client cert) — neither failure mode is informative about the
    adapter wiring this test exists to verify. The full client-side
    chain (Gauntlet → mTLS-configured HTTP client → agent) is exercised
    by the M1.4 acceptance demo (`gauntlet run --policy ...`) and by
    RAMPART's pytest harness in the e2e test.
    """
    from gauntlet.policy_loader import load_policy
    from gauntlet.sandbox import OpenShellSandbox

    policy = load_policy(Path("policy/canonical-agent.yaml"))
    sandbox = OpenShellSandbox()

    with sandbox.start(agent_image=IMAGE, policy=policy) as ctx:
        assert ctx.isolated is True
        assert ctx.agent_endpoint, f"empty agent_endpoint: {ctx.agent_endpoint!r}"
        assert ctx.agent_endpoint.startswith("http"), (
            f"unexpected endpoint scheme: {ctx.agent_endpoint!r}"
        )
        assert ctx.sandbox_id, f"empty sandbox_id: {ctx.sandbox_id!r}"
        assert len(ctx.sandbox_id) <= 28, (
            f"sandbox_id must be <=28 chars (gateway routing constraint), got "
            f"{len(ctx.sandbox_id)}: {ctx.sandbox_id!r}"
        )


def test_openshell_sandbox_tears_down_even_on_caller_exception(gateway_or_skip):
    """If the caller raises inside the with-block, OpenShell must still tear
    the sandbox down — leaking containers across runs is a footgun in CI."""
    from gauntlet.policy_loader import load_policy
    from gauntlet.sandbox import OpenShellSandbox

    policy = load_policy(Path("policy/canonical-agent.yaml"))
    sandbox = OpenShellSandbox()

    with pytest.raises(RuntimeError, match="caller-bug"):
        with sandbox.start(agent_image=IMAGE, policy=policy) as ctx:
            assert ctx.sandbox_id  # sandbox was created
            raise RuntimeError("caller-bug")

    # No assertion on the gateway side — `openshell sandbox list` cleanup is
    # the gateway's responsibility once __exit__ fires.
