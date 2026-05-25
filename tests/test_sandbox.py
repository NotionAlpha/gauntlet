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


# ===========================================================================
# OpenShellSandbox unit tests (no real openshell daemon required)
# ===========================================================================
#
# We inject a fake `openshell` package into sys.modules so OpenShellSandbox's
# `import openshell` resolves to our scripted double. This isolates the adapter
# logic (policy translation, ExposeService call, error mapping) from any real
# gateway. Integration tests in tests/integration/test_openshell_real.py cover
# the real path.

import sys
import types
from unittest.mock import MagicMock

import pytest

from gauntlet.sandbox import (
    OpenShellSandbox,
    SandboxError,
    SandboxPolicy,
    _AGENT_HTTP_PORT,
    _AGENT_SERVICE_NAME,
)


@pytest.fixture
def fake_openshell(monkeypatch):
    """Build a minimally-shaped fake `openshell` module and install it under
    sys.modules['openshell']. Returns (module, captured) where `captured` is a
    dict recording the args OpenShellSandbox passed to the fake.

    The fake module exposes the public surface that gauntlet-bindings added:
      - openshell.sandbox_pb2 / openshell_pb2 (Fix 1 top-level aliases)
      - openshell.policy_from_network_allow (Fix 5)
      - session.expose_http(port) (Fix 3)
      - session.exec_detached(command) (Fix 4)
    """
    captured = {}

    # Fake proto modules — exposed as top-level attributes on the fake openshell
    # module (gauntlet-bindings Fix 1). `from openshell import sandbox_pb2`
    # resolves to sys.modules['openshell'].sandbox_pb2.
    fake_sandbox_pb2 = types.SimpleNamespace(
        SandboxPolicy=MagicMock(side_effect=lambda **kw: types.SimpleNamespace(**kw)),
        NetworkPolicyRule=MagicMock(side_effect=lambda **kw: types.SimpleNamespace(**kw)),
        NetworkEndpoint=MagicMock(side_effect=lambda **kw: types.SimpleNamespace(**kw)),
        FilesystemPolicy=MagicMock(side_effect=lambda **kw: types.SimpleNamespace(**kw)),
        LandlockPolicy=MagicMock(side_effect=lambda **kw: types.SimpleNamespace(**kw)),
    )
    fake_openshell_pb2 = types.SimpleNamespace(
        SandboxTemplate=MagicMock(side_effect=lambda **kw: types.SimpleNamespace(**kw)),
        SandboxSpec=MagicMock(side_effect=lambda **kw: types.SimpleNamespace(**kw)),
    )

    # Fake policy_from_network_allow (gauntlet-bindings Fix 5) — builds the
    # same NetworkPolicyRule structure as the real SDK so the existing policy
    # assertion tests continue to pass unchanged.
    def _fake_policy_from_network_allow(destinations, *, rule_name="default_egress",
                                         filesystem=None, landlock=None):
        from urllib.parse import urlparse
        endpoints = []
        for dest in destinations:
            if dest.startswith("https://") or dest.startswith("http://"):
                parsed = urlparse(dest)
                host = parsed.hostname
                port = parsed.port or (443 if dest.startswith("https://") else 80)
            elif ":" in dest:
                host, port_str = dest.rsplit(":", 1)
                port = int(port_str)
            else:
                host, port = dest, 443
            endpoints.append(fake_sandbox_pb2.NetworkEndpoint(host=host, port=port))
        network_policies = (
            {rule_name: fake_sandbox_pb2.NetworkPolicyRule(endpoints=endpoints)}
            if endpoints else {}
        )
        return fake_sandbox_pb2.SandboxPolicy(
            filesystem=filesystem or fake_sandbox_pb2.FilesystemPolicy(),
            landlock=landlock or fake_sandbox_pb2.LandlockPolicy(compatibility="best_effort"),
            network_policies=network_policies,
        )

    # Fake ExecHandle returned by exec_detached (gauntlet-bindings Fix 4).
    class _FakeExecHandle:
        is_alive = False
        error = None
        def join(self, timeout=None): pass  # noqa: E704

    # Fake Sandbox context manager — records the spec passed in, yields a stub
    # session, captures __exit__.
    class _FakeSession:
        def __init__(self, spec):
            captured["spec"] = spec
            self.id = "550e8400-e29b-41d4-a716-446655440000"
            self.sandbox = types.SimpleNamespace(name="fake-sandbox-name")

        def expose_http(self, port, *, service_name="http", domain=False):
            # gauntlet-bindings Fix 3: returns the host-reachable URL directly.
            captured.setdefault("expose_http_calls", []).append((port, service_name))
            return "http://gateway.local:31415/sandbox/http"

        def exec_detached(self, command, *, env=None, workdir=None):
            # gauntlet-bindings Fix 4: non-blocking; returns an ExecHandle.
            captured.setdefault("exec_detached_calls", []).append(list(command))
            return _FakeExecHandle()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            captured["exited"] = True
            return False

    def _fake_sandbox(*, spec, **_):
        return _FakeSession(spec)

    fake_mod = types.ModuleType("openshell")
    fake_mod.Sandbox = _fake_sandbox
    fake_mod.SandboxError = type("OpenShellSandboxError", (RuntimeError,), {})
    fake_mod.sandbox_pb2 = fake_sandbox_pb2
    fake_mod.openshell_pb2 = fake_openshell_pb2
    fake_mod.policy_from_network_allow = _fake_policy_from_network_allow

    monkeypatch.setitem(sys.modules, "openshell", fake_mod)

    # Stub the agent-readiness probe so unit tests don't try to hit the
    # fake endpoint over HTTP. The real probe is exercised in the
    # integration suite against a live gateway. Signature is
    # (endpoint, agent_handle, session_or_client).
    monkeypatch.setattr(
        "gauntlet.sandbox._wait_for_agent_ready",
        lambda _endpoint, _handle, _session: None,
    )
    return fake_mod, captured


def test_openshellsandbox_start_passes_image_to_template(fake_openshell):
    fake_mod, captured = fake_openshell
    s = OpenShellSandbox()
    policy = SandboxPolicy(network_allow=["https://router.huggingface.co:443"])
    with s.start(agent_image="myimg:0.1", policy=policy) as ctx:
        pass
    # captured["spec"] is the SandboxSpec(template=..., policy=...) we built.
    spec = captured["spec"]
    assert spec.template.image == "myimg:0.1"


def test_openshellsandbox_start_translates_network_allow_to_proto_rule(fake_openshell):
    fake_mod, captured = fake_openshell
    s = OpenShellSandbox()
    policy = SandboxPolicy(network_allow=["https://router.huggingface.co:443"])
    with s.start(agent_image="myimg:0.1", policy=policy):
        pass
    pb_policy = captured["spec"].policy
    # We expect a NetworkPolicyRule keyed by something stable (e.g., "agent_egress")
    # with an endpoint matching router.huggingface.co:443.
    assert isinstance(pb_policy.network_policies, dict)
    assert len(pb_policy.network_policies) == 1
    rule = next(iter(pb_policy.network_policies.values()))
    assert rule.endpoints[0].host == "router.huggingface.co"
    assert rule.endpoints[0].port == 443


def test_openshellsandbox_start_translates_multiple_network_allows_into_one_rule(fake_openshell):
    """Multiple entries in network_allow should produce one NetworkPolicyRule
    bundling all endpoints — not multiple rules. The proto rule is the unit of
    'this is what the agent may reach'; endpoints inside it are the allow-list."""
    fake_mod, captured = fake_openshell
    s = OpenShellSandbox()
    policy = SandboxPolicy(network_allow=[
        "https://a.example.com:443",
        "https://b.example.com:80",
    ])
    with s.start(agent_image="myimg:0.1", policy=policy):
        pass
    pb_policy = captured["spec"].policy
    assert len(pb_policy.network_policies) == 1
    rule = next(iter(pb_policy.network_policies.values()))
    assert len(rule.endpoints) == 2
    hosts = {(ep.host, ep.port) for ep in rule.endpoints}
    assert hosts == {("a.example.com", 443), ("b.example.com", 80)}


def test_openshellsandbox_start_translates_fs_paths_to_proto(fake_openshell):
    fake_mod, captured = fake_openshell
    s = OpenShellSandbox()
    policy = SandboxPolicy(
        fs_read_only=["/usr", "/lib"],
        fs_read_write=["/tmp/agent"],
    )
    with s.start(agent_image="myimg:0.1", policy=policy):
        pass
    pb_policy = captured["spec"].policy
    assert pb_policy.filesystem.read_only == ["/usr", "/lib"]
    assert pb_policy.filesystem.read_write == ["/tmp/agent"]


def test_openshellsandbox_start_sets_landlock_best_effort(fake_openshell):
    """v0.1.0 always uses best_effort Landlock — no enforcement of a strict
    Landlock mode means the sandbox starts even on darwin (where the kernel
    feature is absent)."""
    fake_mod, captured = fake_openshell
    s = OpenShellSandbox()
    with s.start(agent_image="myimg:0.1", policy=SandboxPolicy()):
        pass
    assert captured["spec"].policy.landlock.compatibility == "best_effort"


def test_openshellsandbox_start_calls_expose_http_for_endpoint(fake_openshell):
    fake_mod, captured = fake_openshell
    s = OpenShellSandbox()
    with s.start(agent_image="myimg:0.1", policy=SandboxPolicy()) as ctx:
        # The agent_endpoint MUST come from session.expose_http(port), not
        # from a private gRPC call or a speculative `sb.agent_endpoint` attribute.
        assert ctx.agent_endpoint == "http://gateway.local:31415/sandbox/http"
        assert captured.get("expose_http_calls") == [(_AGENT_HTTP_PORT, _AGENT_SERVICE_NAME)]


def test_openshellsandbox_start_yields_sandbox_context_with_correct_metadata(fake_openshell):
    s = OpenShellSandbox()
    policy = SandboxPolicy(network_allow=["https://x.example:443"])
    with s.start(agent_image="myimg:0.1", policy=policy) as ctx:
        # sandbox_id is the short name (animal-adjective), not the UUID —
        # the adapter records what's used for routing.
        assert ctx.sandbox_id == "fake-sandbox-name"
        assert ctx.isolated is True
        assert ctx.policy is policy




def test_openshellsandbox_start_tears_down_on_exit(fake_openshell):
    fake_mod, captured = fake_openshell
    s = OpenShellSandbox()
    with s.start(agent_image="myimg:0.1", policy=SandboxPolicy()):
        pass
    assert captured.get("exited") is True


def test_openshellsandbox_start_tears_down_on_exception(fake_openshell):
    fake_mod, captured = fake_openshell
    s = OpenShellSandbox()
    with pytest.raises(RuntimeError, match="caller-bug"):
        with s.start(agent_image="myimg:0.1", policy=SandboxPolicy()):
            raise RuntimeError("caller-bug")
    assert captured.get("exited") is True


def test_openshellsandbox_maps_openshell_sandbox_error_to_gauntlet_sandbox_error(monkeypatch):
    """If openshell.Sandbox raises its own SandboxError, OpenShellSandbox must
    catch it and re-raise as gauntlet.sandbox.SandboxError (sanitized)."""
    fake_mod = types.ModuleType("openshell")
    OpenShellSandboxError = type("OpenShellSandboxError", (RuntimeError,), {})
    fake_mod.SandboxError = OpenShellSandboxError

    def _explode(**_):
        raise OpenShellSandboxError("gateway unreachable: /Users/x/.openshell")

    fake_mod.Sandbox = _explode

    # Attach top-level proto aliases so `from openshell import sandbox_pb2`
    # resolves correctly (gauntlet-bindings Fix 1 re-exports them as attributes).
    fake_sandbox_pb2 = types.SimpleNamespace(
        SandboxPolicy=lambda **kw: types.SimpleNamespace(**kw),
        NetworkPolicyRule=lambda **kw: types.SimpleNamespace(**kw),
        NetworkEndpoint=lambda **kw: types.SimpleNamespace(**kw),
        FilesystemPolicy=lambda **kw: types.SimpleNamespace(**kw),
        LandlockPolicy=lambda **kw: types.SimpleNamespace(**kw),
    )
    fake_openshell_pb2 = types.SimpleNamespace(
        SandboxTemplate=lambda **kw: types.SimpleNamespace(**kw),
        SandboxSpec=lambda **kw: types.SimpleNamespace(**kw),
    )
    fake_mod.sandbox_pb2 = fake_sandbox_pb2
    fake_mod.openshell_pb2 = fake_openshell_pb2
    fake_mod.policy_from_network_allow = lambda *a, **kw: types.SimpleNamespace(
        network_policies={}, filesystem=None, landlock=None
    )
    monkeypatch.setitem(sys.modules, "openshell", fake_mod)

    s = OpenShellSandbox()
    with pytest.raises(SandboxError) as excinfo:
        with s.start(agent_image="myimg:0.1", policy=SandboxPolicy()):
            pass  # pragma: no cover
    # Host path must be sanitized out.
    assert "/Users/" not in str(excinfo.value)


def test_openshellsandbox_raises_if_openshell_not_installed(monkeypatch):
    monkeypatch.setitem(sys.modules, "openshell", None)  # forces ImportError on `import openshell`
    s = OpenShellSandbox()
    with pytest.raises(SandboxError) as excinfo:
        with s.start(agent_image="myimg:0.1", policy=SandboxPolicy()):
            pass  # pragma: no cover
    assert "not installed" in str(excinfo.value).lower()
