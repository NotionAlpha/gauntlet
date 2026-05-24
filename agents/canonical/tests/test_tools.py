"""Tests for tool schemas and tool implementations (M1.2)."""

from unittest.mock import patch, MagicMock

from agents.canonical.agent import TOOLS, fetch_public_doc


def test_tools_list_has_two_entries_with_canonical_names():
    names = sorted(t["function"]["name"] for t in TOOLS)
    assert names == ["fetch_public_doc", "send_email"]


def test_every_tool_is_in_openai_function_format():
    for tool in TOOLS:
        assert tool["type"] == "function"
        fn = tool["function"]
        assert isinstance(fn["name"], str)
        assert isinstance(fn["description"], str)
        assert fn["parameters"]["type"] == "object"
        assert "properties" in fn["parameters"]
        assert "required" in fn["parameters"]


def test_fetch_public_doc_tool_schema_requires_url():
    tool = next(t for t in TOOLS if t["function"]["name"] == "fetch_public_doc")
    params = tool["function"]["parameters"]
    assert params["required"] == ["url"]
    assert "url" in params["properties"]


def test_send_email_tool_schema_requires_to_subject_body():
    tool = next(t for t in TOOLS if t["function"]["name"] == "send_email")
    params = tool["function"]["parameters"]
    assert set(params["required"]) == {"to", "subject", "body"}


def test_fetch_public_doc_returns_decoded_body():
    fake_resp = MagicMock()
    fake_resp.read.return_value = b"hello world"
    fake_resp.__enter__.return_value = fake_resp
    fake_resp.__exit__.return_value = False
    with patch("agents.canonical.agent.urllib.request.urlopen", return_value=fake_resp):
        result = fetch_public_doc("https://example.com/doc")
    assert result == "hello world"


def test_fetch_public_doc_truncates_at_1mb():
    fake_resp = MagicMock()
    fake_resp.read.return_value = b"x" * 500
    fake_resp.__enter__.return_value = fake_resp
    fake_resp.__exit__.return_value = False
    with patch("agents.canonical.agent.urllib.request.urlopen", return_value=fake_resp):
        fetch_public_doc("https://example.com/doc")
    fake_resp.read.assert_called_with(1_000_000)
