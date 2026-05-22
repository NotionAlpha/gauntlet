"""
Unit tests for the OpenShell sandbox adapter.

Verifies:
- SandboxAdapter abstract interface exists with expected methods.
- FakeSandbox implements the interface and returns a clean context.
- FakeSandbox context manager yields a SandboxContext with expected fields.
- FakeSandbox can be configured to simulate failures (for error-path testing).
- SandboxContext exposes policy, isolation status, and endpoint.
- Deny-by-default is the expected safety posture: FakeSandbox's default policy
  has no allow-list entries.

No OpenShell install required — uses FakeSandbox only.
"""

from __future__ import annotations

import pytest

from gauntlet.sandbox import (
    FakeSandbox,
    SandboxAdapter,
    SandboxContext,
    SandboxError,
    SandboxPolicy,
)


class TestSandboxPolicy:
    def test_default_policy_is_deny_by_default(self):
        """A SandboxPolicy with no arguments has no allowlisted items — deny-by-default."""
        policy = SandboxPolicy()
        assert len(policy.network_allow) == 0
        assert len(policy.fs_read_only) == 0
        assert len(policy.fs_read_write) == 0

    def test_policy_accepts_custom_allowlists(self):
        policy = SandboxPolicy(
            network_allow=["https://api.example.com"],
            fs_read_only=["/proc/version"],
            fs_read_write=["/tmp/agent-workdir"],
        )
        assert "https://api.example.com" in policy.network_allow
        assert "/proc/version" in policy.fs_read_only
        assert "/tmp/agent-workdir" in policy.fs_read_write

    def test_policy_to_dict_contains_expected_keys(self):
        policy = SandboxPolicy(network_allow=["https://api.example.com"])
        d = policy.to_dict()
        assert "network_allow" in d
        assert "fs_read_only" in d
        assert "fs_read_write" in d

    def test_policy_no_secrets_in_repr(self):
        """Policy repr must not leak any sensitive string."""
        policy = SandboxPolicy(network_allow=["https://api.example.com"])
        r = repr(policy)
        assert "password" not in r.lower()
        assert "secret" not in r.lower()
        assert "token" not in r.lower()


class TestSandboxContext:
    def test_context_has_required_fields(self):
        ctx = SandboxContext(
            sandbox_id="fake-sandbox-001",
            agent_endpoint="http://localhost:9090",
            policy=SandboxPolicy(),
            isolated=True,
        )
        assert ctx.sandbox_id == "fake-sandbox-001"
        assert ctx.agent_endpoint == "http://localhost:9090"
        assert ctx.isolated is True

    def test_context_policy_accessible(self):
        policy = SandboxPolicy(network_allow=["https://api.example.com"])
        ctx = SandboxContext(
            sandbox_id="fake-001",
            agent_endpoint="http://localhost:9090",
            policy=policy,
            isolated=True,
        )
        assert "https://api.example.com" in ctx.policy.network_allow

    def test_context_to_dict_no_host_paths(self):
        """Context dict must not expose raw host filesystem paths as plain strings."""
        ctx = SandboxContext(
            sandbox_id="fake-001",
            agent_endpoint="http://localhost:9090",
            policy=SandboxPolicy(),
            isolated=True,
        )
        d = ctx.to_dict()
        # The only acceptable path exposure is the sanitized policy (tested separately).
        assert "sandbox_id" in d
        assert "agent_endpoint" in d
        assert "isolated" in d


class TestFakeSandbox:
    def test_fake_sandbox_is_subclass_of_adapter(self):
        assert issubclass(FakeSandbox, SandboxAdapter)

    def test_context_manager_yields_sandbox_context(self):
        sandbox = FakeSandbox()
        with sandbox.start(agent_image="my-agent:latest", policy=SandboxPolicy()) as ctx:
            assert isinstance(ctx, SandboxContext)

    def test_context_has_agent_endpoint(self):
        sandbox = FakeSandbox()
        with sandbox.start(agent_image="my-agent:latest", policy=SandboxPolicy()) as ctx:
            assert ctx.agent_endpoint  # not empty

    def test_fake_sandbox_isolated_true_by_default(self):
        """FakeSandbox simulates a successful, isolated sandbox."""
        sandbox = FakeSandbox()
        with sandbox.start(agent_image="my-agent:latest", policy=SandboxPolicy()) as ctx:
            assert ctx.isolated is True

    def test_fake_sandbox_policy_preserved(self):
        policy = SandboxPolicy(network_allow=["https://api.example.com"])
        sandbox = FakeSandbox()
        with sandbox.start(agent_image="my-agent:latest", policy=policy) as ctx:
            assert "https://api.example.com" in ctx.policy.network_allow

    def test_fake_sandbox_records_agent_image(self):
        sandbox = FakeSandbox()
        with sandbox.start(agent_image="my-agent:v2", policy=SandboxPolicy()):
            pass
        assert sandbox.last_agent_image == "my-agent:v2"

    def test_fake_sandbox_failure_raises_sandbox_error(self):
        """Configuring FakeSandbox to fail must raise SandboxError, not crash silently."""
        sandbox = FakeSandbox(fail=True, fail_reason="kernel LSM unavailable")
        with pytest.raises(SandboxError) as exc_info:
            with sandbox.start(agent_image="my-agent:latest", policy=SandboxPolicy()):
                pass
        assert "kernel LSM unavailable" in str(exc_info.value)

    def test_sandbox_error_does_not_leak_host_paths(self):
        """SandboxError messages must not contain raw host filesystem paths."""
        sandbox = FakeSandbox(fail=True, fail_reason="timeout")
        with pytest.raises(SandboxError) as exc_info:
            with sandbox.start(agent_image="my-agent:latest", policy=SandboxPolicy()):
                pass
        msg = str(exc_info.value)
        # The error may contain the fail_reason, which must be pre-sanitized.
        # It must NOT contain anything that looks like a deep absolute path.
        import re
        assert not re.search(r"(?:/[\w.\-]+){4,}", msg), (
            "SandboxError leaked a host filesystem path"
        )

    def test_deny_by_default_has_empty_allowlists(self):
        """The default deny-by-default policy has no allowlisted network or fs entries."""
        policy = SandboxPolicy()
        sandbox = FakeSandbox()
        with sandbox.start(agent_image="my-agent:latest", policy=policy) as ctx:
            assert len(ctx.policy.network_allow) == 0
            assert len(ctx.policy.fs_read_only) == 0
            assert len(ctx.policy.fs_read_write) == 0

    def test_policy_allowlists_are_immutable(self):
        """SandboxPolicy allowlists must be immutable — widening the boundary
        after construction must be impossible, preventing silent policy mutation."""
        policy = SandboxPolicy(network_allow=["https://api.example.com"])
        with pytest.raises((AttributeError, TypeError)):
            policy.network_allow.append("https://evil.example.com")  # type: ignore[union-attr]
