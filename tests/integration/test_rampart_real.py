"""
M1.3 integration test: real RampartAssurance against the canonical agent
(no sandbox). Skipped when prerequisites are missing.

To run:
    pip install -e ".[integration]"
    export HF_TOKEN=hf_...
    pytest -m integration -v
"""

import os
import shutil
import subprocess

import pytest

from gauntlet.direct_runner import DirectDockerRunner
from gauntlet.assurance import RampartAssurance
from gauntlet.sandbox import SandboxPolicy


pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def docker_available():
    if not shutil.which("docker"):
        pytest.skip("docker CLI not available")
    result = subprocess.run(["docker", "info"], capture_output=True)
    if result.returncode != 0:
        pytest.skip("docker daemon not running")


@pytest.fixture(scope="module")
def hf_token_available():
    if not os.environ.get("HF_TOKEN"):
        pytest.skip("HF_TOKEN not set")


@pytest.fixture(scope="module")
def canonical_agent_image_built(docker_available):
    result = subprocess.run(
        ["docker", "image", "ls", "gauntlet/canonical-agent:0.1.0", "-q"],
        capture_output=True, text=True,
    )
    if not result.stdout.strip():
        pytest.skip("gauntlet/canonical-agent:0.1.0 image not built")


def test_rampart_against_canonical_agent_no_sandbox(
    docker_available, hf_token_available, canonical_agent_image_built
):
    """End-to-end: DirectDockerRunner (context manager) + RampartAssurance produce a real report."""
    runner = DirectDockerRunner()
    with runner.start("gauntlet/canonical-agent:0.1.0", SandboxPolicy()) as ctx:
        result = RampartAssurance().run(suite="default", agent_endpoint=ctx.agent_endpoint)

    # The seam ran end to end — at least one test executed
    assert result.passed + result.failed + result.errors >= 1, (
        f"expected at least one test executed; got result={result!r}"
    )
    # The single bundled scenario should be present
    assert any(
        "send_email" in f.test_id or "xpia" in f.test_id.lower()
        for f in result.findings
    ), f"send_email XPIA case not in report: {[f.test_id for f in result.findings]}"
