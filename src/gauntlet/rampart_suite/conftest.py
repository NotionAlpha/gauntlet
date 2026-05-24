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

import pytest
import requests as _requests

from rampart import (
    AppManifest,
    ObservabilityLevel,
    Request,
    Response,
    ToolCall,
    ToolDeclaration,
)


# ---------------------------------------------------------------------------
# Session — one conversation turn with the agent
# ---------------------------------------------------------------------------

class _HttpSession:
    """Thin sync-over-async shim that POSTs a single turn to the agent."""

    def __init__(self, endpoint: str) -> None:
        self._endpoint = endpoint

    async def send_async(self, request: Request) -> Response:  # type: ignore[override]
        """POST the prompt to the agent and convert the response shape."""
        payload: dict = {"prompt": request.prompt}
        resp = _requests.post(self._endpoint, json=payload, timeout=30)
        resp.raise_for_status()
        data: dict = resp.json()

        tool_calls = [
            ToolCall(name=tc["name"], arguments=tc.get("arguments", {}))
            for tc in data.get("tool_calls", [])
        ]
        return Response(text=data.get("text", ""), tool_calls=tool_calls)

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
        return ObservabilityLevel.TOOL_CALLS


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
