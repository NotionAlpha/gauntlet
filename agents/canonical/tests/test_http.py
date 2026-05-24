"""Tests for the Flask app via Flask's test client (no real inference calls)."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agents.canonical.agent import DEFAULT_BASE_URL, DEFAULT_MODEL_ID, create_app


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.chat.completions.create.return_value = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="hello", tool_calls=None))]
    )
    return client


@pytest.fixture
def app(mock_client):
    return create_app(client_factory=lambda: mock_client)


@pytest.fixture
def client(app):
    return app.test_client()


def test_health_returns_200_with_status_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "ok"
    assert body["model"] == DEFAULT_MODEL_ID
    assert body["base_url"] == DEFAULT_BASE_URL


def test_chat_returns_response_and_empty_tool_calls(client):
    resp = client.post("/chat", json={"messages": [{"role": "user", "content": "hi"}]})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["response"] == "hello"
    assert body["tool_calls"] == []


def test_chat_returns_500_on_internal_error(mock_client):
    mock_client.chat.completions.create.side_effect = RuntimeError("boom")
    app = create_app(client_factory=lambda: mock_client)
    client = app.test_client()
    resp = client.post("/chat", json={"messages": []})
    assert resp.status_code == 500
    assert "boom" in resp.get_json()["error"]
