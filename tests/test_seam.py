"""
Unit tests for seam.py — the orchestration layer.

Verifies:
- run_seam() executes sandbox startup, then assurance, then returns a SeamResult.
- SeamResult contains sandbox context, assurance result, and overall status.
- Sandbox failure (SandboxError) propagates cleanly as a SeamError.
- Assurance failure (AssuranceError) propagates cleanly as a SeamError.
- When assurance finds failures, SeamResult.overall_passed is False.
- When assurance passes, SeamResult.overall_passed is True.
- The seam depends only on adapter interfaces (SandboxAdapter, AssuranceAdapter),
  not on real RAMPART or OpenShell.
- Dry-run mode skips execution and returns a plan-only SeamResult.
- The seam does not pass credentials or host paths across the isolation boundary.

No RAMPART or OpenShell required — uses FakeSandbox and FakeAssurance.
"""

from __future__ import annotations

import pytest

from gauntlet.assurance import FakeAssurance
from gauntlet.sandbox import FakeSandbox, SandboxPolicy
from gauntlet.seam import SeamError, SeamResult, run_seam


class TestSeamHappyPath:
    def test_run_seam_returns_seam_result(self):
        result = run_seam(
            agent_image="my-agent:latest",
            sandbox=FakeSandbox(),
            assurance=FakeAssurance(),
            policy=SandboxPolicy(),
            suite="default",
        )
        assert isinstance(result, SeamResult)

    def test_seam_result_overall_passed_when_assurance_passes(self):
        result = run_seam(
            agent_image="my-agent:latest",
            sandbox=FakeSandbox(),
            assurance=FakeAssurance(pass_result=True),
            policy=SandboxPolicy(),
            suite="default",
        )
        assert result.overall_passed is True

    def test_seam_result_has_sandbox_context(self):
        result = run_seam(
            agent_image="my-agent:latest",
            sandbox=FakeSandbox(),
            assurance=FakeAssurance(),
            policy=SandboxPolicy(),
            suite="default",
        )
        assert result.sandbox_context is not None

    def test_seam_result_has_assurance_result(self):
        result = run_seam(
            agent_image="my-agent:latest",
            sandbox=FakeSandbox(),
            assurance=FakeAssurance(),
            policy=SandboxPolicy(),
            suite="default",
        )
        assert result.assurance_result is not None

    def test_seam_result_has_agent_image(self):
        result = run_seam(
            agent_image="my-agent:v2",
            sandbox=FakeSandbox(),
            assurance=FakeAssurance(),
            policy=SandboxPolicy(),
            suite="default",
        )
        assert result.agent_image == "my-agent:v2"

    def test_seam_result_has_suite(self):
        result = run_seam(
            agent_image="my-agent:latest",
            sandbox=FakeSandbox(),
            assurance=FakeAssurance(),
            policy=SandboxPolicy(),
            suite="xpia",
        )
        assert result.suite == "xpia"


class TestSeamFailurePropagation:
    def test_sandbox_error_raises_seam_error(self):
        with pytest.raises(SeamError) as exc_info:
            run_seam(
                agent_image="my-agent:latest",
                sandbox=FakeSandbox(fail=True, fail_reason="kernel LSM unavailable"),
                assurance=FakeAssurance(),
                policy=SandboxPolicy(),
                suite="default",
            )
        assert "sandbox" in str(exc_info.value).lower()

    def test_assurance_error_raises_seam_error(self):
        with pytest.raises(SeamError) as exc_info:
            run_seam(
                agent_image="my-agent:latest",
                sandbox=FakeSandbox(),
                assurance=FakeAssurance(raise_error=True, error_reason="RAMPART runner timeout"),
                policy=SandboxPolicy(),
                suite="default",
            )
        assert "assurance" in str(exc_info.value).lower()

    def test_assurance_fail_result_makes_seam_not_passed(self):
        result = run_seam(
            agent_image="my-agent:latest",
            sandbox=FakeSandbox(),
            assurance=FakeAssurance(pass_result=False),
            policy=SandboxPolicy(),
            suite="default",
        )
        assert result.overall_passed is False

    def test_seam_error_message_does_not_contain_host_paths(self):
        """SeamError propagation must not leak host filesystem paths."""
        import re
        sandbox = FakeSandbox(fail=True, fail_reason="timeout")
        with pytest.raises(SeamError) as exc_info:
            run_seam(
                agent_image="my-agent:latest",
                sandbox=sandbox,
                assurance=FakeAssurance(),
                policy=SandboxPolicy(),
                suite="default",
            )
        msg = str(exc_info.value)
        assert not re.search(r"(?:/[\w.\-]+){4,}", msg), (
            "SeamError leaked a host filesystem path"
        )


class TestSeamDryRun:
    def test_dry_run_returns_seam_result(self):
        result = run_seam(
            agent_image="my-agent:latest",
            sandbox=FakeSandbox(),
            assurance=FakeAssurance(),
            policy=SandboxPolicy(),
            suite="default",
            dry_run=True,
        )
        assert isinstance(result, SeamResult)

    def test_dry_run_does_not_execute_sandbox(self):
        """In dry-run mode the sandbox must not be started."""
        sandbox = FakeSandbox()
        run_seam(
            agent_image="my-agent:latest",
            sandbox=sandbox,
            assurance=FakeAssurance(),
            policy=SandboxPolicy(),
            suite="default",
            dry_run=True,
        )
        assert sandbox.last_agent_image is None, (
            "Dry-run must not start the sandbox"
        )

    def test_dry_run_does_not_execute_assurance(self):
        """In dry-run mode the assurance runner must not be called."""
        assurance = FakeAssurance()
        run_seam(
            agent_image="my-agent:latest",
            sandbox=FakeSandbox(),
            assurance=assurance,
            policy=SandboxPolicy(),
            suite="default",
            dry_run=True,
        )
        assert assurance.last_endpoint is None, (
            "Dry-run must not run assurance"
        )

    def test_dry_run_result_is_plan_only(self):
        result = run_seam(
            agent_image="my-agent:latest",
            sandbox=FakeSandbox(),
            assurance=FakeAssurance(),
            policy=SandboxPolicy(),
            suite="default",
            dry_run=True,
        )
        assert result.dry_run is True
        assert result.sandbox_context is None
        assert result.assurance_result is None


class TestSeamIsolationDiscipline:
    def test_assurance_called_with_sandbox_endpoint_not_host(self):
        """
        The assurance runner must be called with the sandboxed agent endpoint
        from the SandboxContext, not a direct host address.
        The sandbox endpoint must come from ctx.agent_endpoint.
        """
        sandbox = FakeSandbox()
        assurance = FakeAssurance()
        run_seam(
            agent_image="my-agent:latest",
            sandbox=sandbox,
            assurance=assurance,
            policy=SandboxPolicy(),
            suite="default",
        )
        # The endpoint the assurance adapter received must match what the sandbox provided.
        # FakeSandbox returns a deterministic endpoint we can introspect.
        assert assurance.last_endpoint is not None
        # Must not be a raw host path (e.g. /path/to/socket)
        assert assurance.last_endpoint.startswith("http"), (
            "Assurance must be called with an HTTP(S) endpoint, not a host path"
        )
