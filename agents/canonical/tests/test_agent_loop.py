"""Tests for the run_agent tool-use loop with a mocked OpenAI client."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agents.canonical.agent import DEFAULT_MODEL_ID, SYSTEM_PROMPT, TOOLS, run_agent


def _msg(content=None, tool_calls=None):
    return SimpleNamespace(content=content, tool_calls=tool_calls or None)


def _resp(message):
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def _tc(id_: str, name: str, args: dict):
    """Construct an OpenAI-shaped tool_call object."""
    return SimpleNamespace(
        id=id_,
        type="function",
        function=SimpleNamespace(name=name, arguments=json.dumps(args)),
    )


def test_run_agent_returns_text_when_no_tool_calls():
    client = MagicMock()
    client.chat.completions.create.return_value = _resp(_msg(content="hi there"))
    result = run_agent(client, [{"role": "user", "content": "hello"}])
    assert result == {"response": "hi there", "tool_calls": []}
    client.chat.completions.create.assert_called_once()
    kwargs = client.chat.completions.create.call_args.kwargs
    assert kwargs["model"] == DEFAULT_MODEL_ID
    assert kwargs["tools"] == TOOLS
    # First message in convo must be the system prompt.
    assert kwargs["messages"][0] == {"role": "system", "content": SYSTEM_PROMPT}


def test_run_agent_executes_a_fetch_public_doc_tool_call_then_returns_final_text(monkeypatch):
    client = MagicMock()
    client.chat.completions.create.side_effect = [
        _resp(_msg(content=None, tool_calls=[_tc("t1", "fetch_public_doc", {"url": "https://example.com"})])),
        _resp(_msg(content="done")),
    ]
    monkeypatch.setattr(
        "agents.canonical.agent.fetch_public_doc",
        lambda url: f"BODY-OF:{url}",
    )

    result = run_agent(client, [{"role": "user", "content": "fetch it"}])

    assert result["response"] == "done"
    assert result["tool_calls"] == [
        {"name": "fetch_public_doc", "arguments": {"url": "https://example.com"}}
    ]


def test_run_agent_records_send_email_attempt_in_tool_calls():
    client = MagicMock()
    client.chat.completions.create.side_effect = [
        _resp(_msg(content=None, tool_calls=[_tc(
            "t2", "send_email",
            {"to": "x@y.z", "subject": "s", "body": "b"},
        )])),
        _resp(_msg(content="emailed")),
    ]

    result = run_agent(client, [{"role": "user", "content": "send mail"}])

    assert any(
        tc["name"] == "send_email" and tc["arguments"]["to"] == "x@y.z"
        for tc in result["tool_calls"]
    )


def test_run_agent_raises_after_max_turns(monkeypatch):
    monkeypatch.setattr("agents.canonical.agent.fetch_public_doc", lambda url: "x")
    client = MagicMock()
    client.chat.completions.create.return_value = _resp(_msg(
        content=None,
        tool_calls=[_tc("t", "fetch_public_doc", {"url": "https://example.com"})],
    ))
    with pytest.raises(RuntimeError, match="max_turns"):
        run_agent(client, [{"role": "user", "content": "go"}], max_turns=2)


def test_run_agent_records_failed_tool_as_is_error_in_convo(monkeypatch):
    """If a tool raises, the loop should send an error tool_result, not crash."""
    monkeypatch.setattr(
        "agents.canonical.agent.fetch_public_doc",
        lambda url: (_ for _ in ()).throw(RuntimeError("network down")),
    )
    client = MagicMock()
    client.chat.completions.create.side_effect = [
        _resp(_msg(content=None, tool_calls=[_tc("t", "fetch_public_doc", {"url": "https://example.com"})])),
        _resp(_msg(content="recovered")),
    ]

    result = run_agent(client, [{"role": "user", "content": "fetch"}])

    # Second call's messages should contain a role:tool message with the error string.
    second_call_msgs = client.chat.completions.create.call_args_list[1].kwargs["messages"]
    tool_msg = next(m for m in second_call_msgs if m["role"] == "tool")
    assert "network down" in tool_msg["content"]
    assert result["response"] == "recovered"
