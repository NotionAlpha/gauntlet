"""
Conftest for the RAMPART XPIA test suite.

Supplies the ``agent_adapter`` fixture, which is backed by
``GAUNTLET_AGENT_ENDPOINT`` from the environment.  When the variable is
unset the whole suite is skipped — no RAMPART calls will be made.

Adapter protocol confirmed from docs/m1.3-rampart-spike.md:
  - agent_adapter.create_session_async() -> Session
  - session.send_async(request: rampart.Request) -> rampart.Response
  - agent_adapter.manifest -> AppManifest
  - agent_adapter.observability_profile -> ObservabilityLevel
"""

from __future__ import annotations

import os
import json
from pathlib import Path

import pytest
import requests as _requests
import urllib3

from rampart import (
    AppManifest,
    ObservabilityLevel,
    Request,
    Response,
    ToolCall,
    ToolDeclaration,
)


# ---------------------------------------------------------------------------
# OpenShell mTLS — gateway-exposed sandbox services require client certs
# ---------------------------------------------------------------------------
#
# When `gauntlet run --policy ...` (real OpenShell path) sets GAUNTLET_AGENT_ENDPOINT,
# the URL points at the gateway's TLS proxy. We supply the active gateway's
# client cert/key automatically via the shared helper; for plain http://
# endpoints (--no-sandbox path) `requests` ignores `cert=` and the call goes
# through as plain HTTP.
from gauntlet._openshell_mtls import discover_openshell_mtls

# Silence the InsecureRequestWarning that urllib3 emits when verify=False —
# expected and intentional in this code path; the gateway uses self-signed
# PKI and the URL host doesn't match the cert SAN. See
# docs/m1.3.6-gateway-setup.md and src/gauntlet/_openshell_mtls.py.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Session — one conversation turn with the agent
# ---------------------------------------------------------------------------

class _HttpSession:
    """Thin sync-over-async shim that POSTs a single turn to the agent."""

    def __init__(self, endpoint: str) -> None:
        # endpoint is the base URL (e.g. http://localhost:8080); /chat is the
        # canonical agent route for inference requests.
        self._chat_url = endpoint.rstrip("/") + "/chat"
        # mTLS material is fetched once per session; None when the endpoint
        # is a plain HTTP URL or no active openshell gateway is configured.
        self._cert, self._verify = discover_openshell_mtls()

    async def send_async(self, request: Request) -> Response:  # type: ignore[override]
        """POST the prompt to the agent and convert the response shape.

        The canonical agent accepts::

            POST /chat
            {"messages": [{"role": "user", "content": "<prompt>"}]}

        and replies with::

            {"response": "<text>", "tool_calls": [{"name": "...", "arguments": {...}}]}
        """
        payload: dict = {
            "messages": [{"role": "user", "content": request.prompt}],
        }
        resp = _requests.post(
            self._chat_url,
            json=payload,
            timeout=60,
            cert=self._cert,
            verify=self._verify,
        )
        resp.raise_for_status()
        data: dict = resp.json()

        tool_calls = [
            ToolCall(name=tc["name"], arguments=tc.get("arguments", {}))
            for tc in data.get("tool_calls", [])
        ]
        # The canonical agent returns "response"; fall back to "text" for
        # any RAMPART-compatible agent that uses the alternative field name.
        text = data.get("response") or data.get("text", "")
        return Response(text=text, tool_calls=tool_calls)

    async def __aenter__(self) -> "_HttpSession":
        return self

    async def __aexit__(self, *_: object) -> None:
        pass


# ---------------------------------------------------------------------------
# Adapter — RAMPART AgentAdapter Protocol implementation
# ---------------------------------------------------------------------------

class _HttpAgentAdapter:
    """
    Implements the RAMPART AgentAdapter Protocol over a plain HTTP endpoint.

    The agent must accept POST requests at ``{endpoint}/chat`` (or whatever
    URL ``GAUNTLET_AGENT_ENDPOINT`` is set to) with JSON body::

        {"prompt": "<turn text>"}

    and reply with::

        {
            "text": "<response text>",
            "tool_calls": [{"name": "...", "arguments": {...}}, ...]
        }

    ``tool_calls`` may be absent or empty if the agent made no tool calls.
    """

    def __init__(self, endpoint: str) -> None:
        self._endpoint = endpoint

    async def create_session_async(self) -> _HttpSession:
        return _HttpSession(self._endpoint)

    @property
    def manifest(self) -> AppManifest:
        return AppManifest(
            name="test-agent",
            tools=[
                ToolDeclaration(
                    name="send_email",
                    parameters={"to": "str", "body": "str"},
                )
            ],
        )

    @property
    def observability_profile(self) -> ObservabilityLevel:
        # RAMPART 0.1.0 levels: TOOL_AND_SIDE_EFFECTS, TOOL_ONLY, RESPONSE_ONLY.
        # The canonical agent surfaces tool calls; use TOOL_ONLY so RAMPART's
        # ToolCalled evaluator can inspect the call trace directly.
        return ObservabilityLevel.TOOL_ONLY


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def agent_adapter() -> _HttpAgentAdapter:
    """
    Construct an :class:`_HttpAgentAdapter` from ``GAUNTLET_AGENT_ENDPOINT``.

    Skips the entire suite when the variable is unset — this is the
    expected behaviour in CI and local unit-test runs where no live agent
    is available.
    """
    endpoint = os.environ.get("GAUNTLET_AGENT_ENDPOINT", "")
    if not endpoint:
        pytest.skip(
            "GAUNTLET_AGENT_ENDPOINT is not set — skipping RAMPART XPIA suite. "
            "Set it to a running agent's /chat URL to run these tests."
        )
    return _HttpAgentAdapter(endpoint=endpoint)
