"""BYOC-compatibility smoke for the canonical-agent image.

These run a transient container against the locally-built image and assert
the OpenShell BYOC contract from
examples/bring-your-own-container/README.md.

They are agents-tests, not unit-of-Python tests — gated on Docker being
available and the image being built. They mark `byoc` so they can be
filtered.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

IMAGE = "gauntlet/canonical-agent:0.1.0"
SANDBOX_UID = "1000660000"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def _image_present() -> bool:
    out = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        capture_output=True,
        text=True,
    )
    return out.returncode == 0


pytestmark = [
    pytest.mark.byoc,
    pytest.mark.skipif(not _docker_available(), reason="docker daemon not available"),
    pytest.mark.skipif(not _image_present(), reason=f"image {IMAGE} not built"),
]


def _docker_run(*args: str) -> str:
    """Run a one-shot command inside the image and return stdout (trimmed)."""
    result = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "", IMAGE, *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def test_image_has_sandbox_user_with_byoc_uid() -> None:
    """The image MUST contain a user named `sandbox` with uid 1000660000."""
    line = _docker_run("getent", "passwd", "sandbox")
    # passwd line format: name:x:uid:gid:gecos:home:shell
    parts = line.split(":")
    assert len(parts) >= 4, f"unexpected passwd line: {line!r}"
    assert parts[0] == "sandbox", f"expected user 'sandbox', got {parts[0]!r}"
    assert parts[2] == SANDBOX_UID, f"expected uid {SANDBOX_UID}, got {parts[2]!r}"


def test_image_has_iproute2_for_network_namespace_isolation() -> None:
    """The image MUST have `ip` (from iproute2) on PATH."""
    out = _docker_run("which", "ip")
    assert out.endswith("/ip"), f"expected /usr/sbin/ip or similar, got {out!r}"


def test_image_workdir_is_readable_by_sandbox_user() -> None:
    """The application workdir MUST be readable by the sandbox user."""
    out = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "", "--user", SANDBOX_UID, IMAGE, "ls", "/app/agent.py"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout.strip() == "/app/agent.py"


def test_no_sandbox_mode_default_user_is_sandbox() -> None:
    """The image's default USER must be `sandbox` so `--no-sandbox` Docker runs
    don't accidentally run as root."""
    out = _docker_run("whoami")
    assert out == "sandbox", f"expected default user 'sandbox', got {out!r}"
