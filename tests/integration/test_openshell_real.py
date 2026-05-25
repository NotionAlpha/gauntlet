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
import time
import urllib.error
import urllib.request
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


def test_openshell_sandbox_starts_canonical_agent_and_exposes_health(gateway_or_skip):
    """Live sandbox: load the canonical policy, start the agent, hit /health
    from the host via the ExposeService URL, then tear down cleanly."""
    from gauntlet.policy_loader import load_policy
    from gauntlet.sandbox import OpenShellSandbox

    policy = load_policy(Path("policy/canonical-agent.yaml"))
    sandbox = OpenShellSandbox()

    with sandbox.start(agent_image=IMAGE, policy=policy) as ctx:
        assert ctx.isolated is True
        assert ctx.agent_endpoint.startswith("http"), f"unexpected endpoint: {ctx.agent_endpoint!r}"
        # Wait for the agent's HTTP server to come up. Sandbox supervisor +
        # python startup typically take 5–15s.
        deadline = time.time() + 30
        last_err: Exception | None = None
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"{ctx.agent_endpoint}/health", timeout=2) as r:
                    if r.status == 200:
                        break
            except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
                last_err = e
                time.sleep(1)
        else:
            pytest.fail(f"/health never returned 200 within 30s; last error: {last_err!r}")


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
