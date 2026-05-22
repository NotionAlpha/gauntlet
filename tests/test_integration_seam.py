"""
Integration test: real RAMPART + OpenShell seam run.

This test exercises the full seam — OpenShell sandbox + RAMPART assurance —
against a real agent image.  It is marked @pytest.mark.integration and skips
cleanly when RAMPART or OpenShell are not installed.

To run this test:
    1. Install integration dependencies:
           pip install -e ".[integration]"
    2. Set environment variables:
           GAUNTLET_AGENT_IMAGE  — OCI image reference for the agent (e.g. my-agent:latest)
           GAUNTLET_POLICY_PATH  — path to the OpenShell policy YAML (default: policy.yaml)
    3. Run:
           pytest -v -m integration

When RAMPART or OpenShell are absent, pytest reports this test as SKIPPED with a
clear reason.  This satisfies acceptance criterion 4.

Security note:
    The agent image is treated as UNTRUSTED.  The OpenShell sandbox enforces a
    deny-by-default isolation boundary; the agent cannot reach host resources.
    Do NOT pass real credentials or production endpoints via environment variables.
    See README.md → Threat model for details.
"""

from __future__ import annotations

import os

import pytest


# ---------------------------------------------------------------------------
# Dependency availability checks
# ---------------------------------------------------------------------------

def _rampart_available() -> bool:
    try:
        import rampart  # type: ignore[import]  # noqa: F401
        return True
    except ImportError:
        return False


def _openshell_available() -> bool:
    try:
        import openshell  # type: ignore[import]  # noqa: F401
        return True
    except ImportError:
        return False


_DEPS_MISSING_REASON = (
    "Integration dependencies not installed.  "
    "Install with: pip install -e '.[integration]'  "
    "Requires: rampart>=0.1.0, openshell>=0.0.46.  "
    "See README.md for integration test setup."
)

_DEPS_AVAILABLE = _rampart_available() and _openshell_available()


# ---------------------------------------------------------------------------
# Integration test class
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.skipif(not _DEPS_AVAILABLE, reason=_DEPS_MISSING_REASON)
class TestRealSeam:
    """Full seam run using real RAMPART and real OpenShell.

    These tests are intentionally thin — seam orchestration logic is validated
    by the unit tests.  The integration tests confirm:
      (a) The real OpenShell adapter can start a sandbox and yield a SandboxContext.
      (b) The real RAMPART adapter can run against the sandboxed agent endpoint.
      (c) The seam produces a valid SeamResult with all required fields.
      (d) The report renders cleanly on the real result.
    """

    def _get_agent_image(self) -> str:
        image = os.environ.get("GAUNTLET_AGENT_IMAGE")
        if not image:
            pytest.skip(
                "GAUNTLET_AGENT_IMAGE environment variable not set.  "
                "Set it to the OCI image reference before running integration tests."
            )
        return image

    def _get_policy_path(self) -> str:
        return os.environ.get("GAUNTLET_POLICY_PATH", "policy.yaml")

    def test_real_seam_imports(self):
        """Confirm that real adapter modules can be imported when deps are available."""
        from gauntlet.sandbox import OpenShellSandbox  # type: ignore[attr-defined]
        from gauntlet.assurance import RampartAssurance  # type: ignore[attr-defined]
        assert OpenShellSandbox is not None
        assert RampartAssurance is not None

    def test_full_seam_run_produces_valid_result(self):
        """Run the full seam against the real agent and validate the SeamResult schema."""
        from gauntlet.sandbox import OpenShellSandbox, SandboxPolicy
        from gauntlet.assurance import RampartAssurance
        from gauntlet.seam import run_seam
        from gauntlet.report import render_report

        agent_image = self._get_agent_image()
        policy_path = self._get_policy_path()

        sandbox = OpenShellSandbox(policy_path=policy_path)
        assurance = RampartAssurance()
        policy = SandboxPolicy()  # deny-by-default

        result = run_seam(
            agent_image=agent_image,
            sandbox=sandbox,
            assurance=assurance,
            policy=policy,
            suite="default",
        )

        # Schema validation
        assert result.agent_image == agent_image
        assert result.suite == "default"
        assert isinstance(result.overall_passed, bool)
        assert result.sandbox_context is not None
        assert result.assurance_result is not None
        assert result.dry_run is False

        # Report renders without error
        report = render_report(result)
        assert len(report.strip()) > 0

        # Print for human inspection (visible with pytest -s)
        print(f"\nSeam result: overall_passed={result.overall_passed}")
        print(report)
