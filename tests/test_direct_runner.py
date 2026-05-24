"""
Unit tests for DirectDockerRunner — the no-sandbox SandboxAdapter.

Verifies:
- start() is a @contextmanager that yields a SandboxContext.
- Yielded context has isolated=False, the configured agent_endpoint, and the supplied policy.
- Health polling retries on connection errors until the endpoint is ready.
- SandboxError is raised when the health endpoint never returns 200 within the timeout.
- docker stop <container_id> is called on context exit (normal and exception paths).
- HF_TOKEN (and other env_passthrough vars) are forwarded to docker run when set.

No Docker install required — all subprocess calls are patched.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from unittest.mock import MagicMock, call, patch

import pytest
import requests

from gauntlet.direct_runner import DirectDockerRunner
from gauntlet.sandbox import SandboxContext, SandboxError, SandboxPolicy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_CID = "abc123def456"
_FAKE_IMAGE = "my-agent:latest"
_DEFAULT_POLICY = SandboxPolicy()


def _make_docker_run_result(container_id: str = _FAKE_CID) -> MagicMock:
    """A successful `docker run -d` result: returncode=0, stdout=<container_id>."""
    result = MagicMock()
    result.returncode = 0
    result.stdout = container_id + "\n"
    return result


def _make_ok_response() -> MagicMock:
    """A requests.Response-like object with status_code=200."""
    resp = MagicMock()
    resp.status_code = 200
    return resp


# ---------------------------------------------------------------------------
# Test: yielded SandboxContext shape
# ---------------------------------------------------------------------------


class TestDirectDockerRunnerContextShape:
    def test_start_yields_sandbox_context_with_unisolated_endpoint(self):
        """start() must yield a SandboxContext with isolated=False and the right endpoint."""
        runner = DirectDockerRunner(port=8080, ready_timeout=5.0, poll_interval=0.01)

        docker_result = _make_docker_run_result()
        ok_resp = _make_ok_response()

        with patch("subprocess.run", return_value=docker_result) as mock_run, \
             patch("requests.get", return_value=ok_resp):
            with runner.start(_FAKE_IMAGE, _DEFAULT_POLICY) as ctx:
                assert isinstance(ctx, SandboxContext)
                assert ctx.isolated is False
                assert ctx.agent_endpoint == "http://localhost:8080"
                assert ctx.policy is _DEFAULT_POLICY
                assert ctx.sandbox_id == _FAKE_CID

    def test_start_yields_context_with_custom_port(self):
        """agent_endpoint reflects the configured port."""
        runner = DirectDockerRunner(port=9090, ready_timeout=5.0, poll_interval=0.01)

        docker_result = _make_docker_run_result()
        ok_resp = _make_ok_response()

        with patch("subprocess.run", return_value=docker_result), \
             patch("requests.get", return_value=ok_resp):
            with runner.start(_FAKE_IMAGE, _DEFAULT_POLICY) as ctx:
                assert ctx.agent_endpoint == "http://localhost:9090"


# ---------------------------------------------------------------------------
# Test: health polling retries
# ---------------------------------------------------------------------------


class TestDirectDockerRunnerHealthPolling:
    def test_start_polls_health_until_ready(self):
        """First 2 poll attempts raise ConnectionError; third returns 200 — verify 3 calls."""
        runner = DirectDockerRunner(port=8080, ready_timeout=10.0, poll_interval=0.01)

        docker_result = _make_docker_run_result()

        get_calls = []

        def fake_get(url, timeout=None):
            get_calls.append(url)
            if len(get_calls) < 3:
                raise requests.exceptions.ConnectionError("not up yet")
            return _make_ok_response()

        with patch("subprocess.run", return_value=docker_result), \
             patch("requests.get", side_effect=fake_get):
            with runner.start(_FAKE_IMAGE, _DEFAULT_POLICY) as ctx:
                assert ctx.isolated is False

        assert len(get_calls) == 3

    def test_start_raises_sandbox_error_on_ready_timeout(self):
        """If the health endpoint never returns 200 within timeout, raise SandboxError."""
        runner = DirectDockerRunner(port=8080, ready_timeout=0.05, poll_interval=0.01)

        docker_result = _make_docker_run_result()

        with patch("subprocess.run", return_value=docker_result), \
             patch("requests.get", side_effect=requests.exceptions.ConnectionError("never up")):
            with pytest.raises(SandboxError) as exc_info:
                with runner.start(_FAKE_IMAGE, _DEFAULT_POLICY):
                    pass  # should not reach here

        # Message must not be empty and must not look like a RuntimeError.
        assert "timeout" in str(exc_info.value).lower() or "ready" in str(exc_info.value).lower()

    def test_sandbox_error_on_docker_run_failure(self):
        """If `docker run` returns non-zero, raise SandboxError (not RuntimeError)."""
        runner = DirectDockerRunner(port=8080, ready_timeout=5.0, poll_interval=0.01)

        failed_result = MagicMock()
        failed_result.returncode = 1
        failed_result.stderr = "image not found"

        with patch("subprocess.run", return_value=failed_result):
            with pytest.raises(SandboxError):
                with runner.start(_FAKE_IMAGE, _DEFAULT_POLICY):
                    pass


# ---------------------------------------------------------------------------
# Test: docker stop on context exit
# ---------------------------------------------------------------------------


class TestDirectDockerRunnerTeardown:
    def test_stop_runs_docker_stop_on_context_exit(self):
        """After the with-block exits normally, docker stop <cid> must be called."""
        runner = DirectDockerRunner(port=8080, ready_timeout=5.0, poll_interval=0.01)

        docker_result = _make_docker_run_result()
        ok_resp = _make_ok_response()

        with patch("subprocess.run", return_value=docker_result) as mock_run, \
             patch("requests.get", return_value=ok_resp):
            with runner.start(_FAKE_IMAGE, _DEFAULT_POLICY):
                pass

        # Collect all subprocess.run calls and find the docker stop call.
        all_calls = mock_run.call_args_list
        stop_calls = [c for c in all_calls if "stop" in c.args[0]]
        assert len(stop_calls) == 1
        assert _FAKE_CID in stop_calls[0].args[0]

    def test_stop_runs_docker_stop_on_exception_exit(self):
        """docker stop must also be called when the with-block raises an exception."""
        runner = DirectDockerRunner(port=8080, ready_timeout=5.0, poll_interval=0.01)

        docker_result = _make_docker_run_result()
        ok_resp = _make_ok_response()

        with patch("subprocess.run", return_value=docker_result) as mock_run, \
             patch("requests.get", return_value=ok_resp):
            with pytest.raises(RuntimeError):
                with runner.start(_FAKE_IMAGE, _DEFAULT_POLICY):
                    raise RuntimeError("deliberate error inside the block")

        all_calls = mock_run.call_args_list
        stop_calls = [c for c in all_calls if "stop" in c.args[0]]
        assert len(stop_calls) == 1
        assert _FAKE_CID in stop_calls[0].args[0]


# ---------------------------------------------------------------------------
# Test: env passthrough
# ---------------------------------------------------------------------------


class TestDirectDockerRunnerEnvPassthrough:
    def test_env_passthrough_includes_hf_token_when_set(self):
        """When HF_TOKEN is in the environment, docker run must include -e HF_TOKEN=<value>."""
        runner = DirectDockerRunner(port=8080, ready_timeout=5.0, poll_interval=0.01)

        docker_result = _make_docker_run_result()
        ok_resp = _make_ok_response()

        env_with_token = {**os.environ, "HF_TOKEN": "hf_test_token_abc123"}

        with patch("subprocess.run", return_value=docker_result) as mock_run, \
             patch("requests.get", return_value=ok_resp), \
             patch.dict(os.environ, {"HF_TOKEN": "hf_test_token_abc123"}, clear=False):
            with runner.start(_FAKE_IMAGE, _DEFAULT_POLICY):
                pass

        # Find the docker run call (first subprocess.run call).
        run_call = mock_run.call_args_list[0]
        docker_cmd = run_call.args[0]
        cmd_str = " ".join(docker_cmd)
        assert "HF_TOKEN" in cmd_str

    def test_env_passthrough_skips_unset_vars(self):
        """Env vars not present in the environment must NOT appear in docker run args."""
        runner = DirectDockerRunner(port=8080, ready_timeout=5.0, poll_interval=0.01)

        docker_result = _make_docker_run_result()
        ok_resp = _make_ok_response()

        # Ensure OPENAI_API_KEY is absent from the test environment.
        clean_env = {k: v for k, v in os.environ.items() if k != "OPENAI_API_KEY"}

        with patch("subprocess.run", return_value=docker_result) as mock_run, \
             patch("requests.get", return_value=ok_resp), \
             patch.dict(os.environ, clean_env, clear=True):
            with runner.start(_FAKE_IMAGE, _DEFAULT_POLICY):
                pass

        run_call = mock_run.call_args_list[0]
        docker_cmd = run_call.args[0]
        cmd_str = " ".join(docker_cmd)
        assert "OPENAI_API_KEY" not in cmd_str

    def test_custom_env_passthrough_list(self):
        """Custom env_passthrough list is forwarded when the vars are set."""
        runner = DirectDockerRunner(
            port=8080,
            ready_timeout=5.0,
            poll_interval=0.01,
            env_passthrough=["MY_CUSTOM_VAR"],
        )

        docker_result = _make_docker_run_result()
        ok_resp = _make_ok_response()

        with patch("subprocess.run", return_value=docker_result) as mock_run, \
             patch("requests.get", return_value=ok_resp), \
             patch.dict(os.environ, {"MY_CUSTOM_VAR": "my_value"}, clear=False):
            with runner.start(_FAKE_IMAGE, _DEFAULT_POLICY):
                pass

        run_call = mock_run.call_args_list[0]
        docker_cmd = run_call.args[0]
        cmd_str = " ".join(docker_cmd)
        assert "MY_CUSTOM_VAR" in cmd_str
