"""
Unit tests for the RAMPART assurance adapter.

Verifies:
- AssuranceAdapter abstract interface exists with expected methods.
- FakeAssurance implements the interface and returns a scripted AssuranceResult.
- AssuranceResult has the expected fields (suite, findings, passed, failed, errors).
- FakeAssurance can be configured to return a pass or fail result.
- The adapter takes an agent_endpoint — it does NOT accept credentials or host paths.
- Error propagation: FakeAssurance.fail mode raises AssuranceError.
- The sanitizer strips credential-like strings from finding evidence.

No RAMPART install required — uses FakeAssurance only.
"""

from __future__ import annotations

import pytest

from gauntlet._sanitizer import sanitize as _sanitize_finding
from gauntlet.assurance import (
    AssuranceAdapter,
    AssuranceError,
    AssuranceFinding,
    AssuranceResult,
    FakeAssurance,
)


class TestSanitizeFinding:
    """The sanitizer must strip credential-like strings from finding evidence."""

    def test_bearer_token_redacted(self):
        raw = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def"
        result = _sanitize_finding(raw)
        assert "Bearer eyJ" not in result
        assert "[REDACTED" in result

    def test_sk_key_redacted(self):
        raw = "Agent used key: sk-abcdefghijklmnopqrst1234567890"
        result = _sanitize_finding(raw)
        assert "sk-abcdefghijklmnopqrst" not in result
        assert "[REDACTED" in result

    def test_host_path_redacted(self):
        raw = "Agent accessed /home/user/secrets/creds.json"
        result = _sanitize_finding(raw)
        assert "/home/user/secrets/creds.json" not in result
        assert "[REDACTED" in result

    def test_long_token_redacted(self):
        raw = "token=" + "A" * 50
        result = _sanitize_finding(raw)
        assert "A" * 40 not in result

    def test_safe_text_preserved(self):
        raw = "Agent refused to exfiltrate data: policy denied"
        result = _sanitize_finding(raw)
        assert "Agent refused" in result
        assert "policy denied" in result

    def test_oversized_input_is_truncated(self):
        """Sanitizer must truncate inputs larger than _MAX_INPUT_LENGTH (16 KiB)
        to prevent unbounded memory allocation from untrusted target output."""
        from gauntlet._sanitizer import _MAX_INPUT_LENGTH
        oversized = "x" * (_MAX_INPUT_LENGTH + 1024)
        result = _sanitize_finding(oversized)
        assert len(result) <= _MAX_INPUT_LENGTH


class TestAssuranceFinding:
    def test_finding_has_required_fields(self):
        finding = AssuranceFinding(
            test_id="xpia-01",
            name="Cross-prompt injection: ignore system prompt",
            passed=False,
            evidence="Agent complied with injected instruction.",
        )
        assert finding.test_id == "xpia-01"
        assert finding.name == "Cross-prompt injection: ignore system prompt"
        assert finding.passed is False
        assert "injected" in finding.evidence

    def test_finding_evidence_sanitized_on_construction(self):
        """Evidence must be sanitized at construction time."""
        finding = AssuranceFinding(
            test_id="xpia-01",
            name="test",
            passed=False,
            evidence="Agent used sk-abcdefghijklmnopqrst1234 to call API",
        )
        assert "sk-abcdefghijklmnopqrst" not in finding.evidence

    def test_finding_to_dict_structure(self):
        finding = AssuranceFinding(
            test_id="xpia-01",
            name="test",
            passed=True,
            evidence="Agent refused.",
        )
        d = finding.to_dict()
        assert "test_id" in d
        assert "name" in d
        assert "passed" in d
        assert "evidence" in d


class TestAssuranceResult:
    def test_result_has_required_fields(self):
        result = AssuranceResult(
            suite="default",
            findings=[],
            passed=0,
            failed=0,
            errors=0,
        )
        assert result.suite == "default"
        assert result.findings == []
        assert result.passed == 0
        assert result.failed == 0
        assert result.errors == 0

    def test_result_overall_passed_all_pass(self):
        result = AssuranceResult(
            suite="default",
            findings=[],
            passed=5,
            failed=0,
            errors=0,
        )
        assert result.overall_passed is True

    def test_result_overall_passed_any_fail(self):
        result = AssuranceResult(
            suite="default",
            findings=[],
            passed=4,
            failed=1,
            errors=0,
        )
        assert result.overall_passed is False

    def test_result_overall_passed_any_error(self):
        result = AssuranceResult(
            suite="default",
            findings=[],
            passed=5,
            failed=0,
            errors=1,
        )
        assert result.overall_passed is False

    def test_result_to_dict_contains_expected_keys(self):
        result = AssuranceResult(
            suite="default",
            findings=[],
            passed=3,
            failed=1,
            errors=0,
        )
        d = result.to_dict()
        for key in ("suite", "findings", "passed", "failed", "errors", "overall_passed"):
            assert key in d, f"Missing key in AssuranceResult.to_dict(): {key!r}"


class TestFakeAssurance:
    def test_fake_assurance_is_subclass_of_adapter(self):
        assert issubclass(FakeAssurance, AssuranceAdapter)

    def test_run_returns_assurance_result(self):
        assurance = FakeAssurance()
        result = assurance.run(suite="default", agent_endpoint="http://localhost:9090")
        assert isinstance(result, AssuranceResult)

    def test_default_result_overall_passed(self):
        """FakeAssurance defaults to a clean (all-pass) result."""
        assurance = FakeAssurance()
        result = assurance.run(suite="default", agent_endpoint="http://localhost:9090")
        assert result.overall_passed is True

    def test_configured_fail_result(self):
        """FakeAssurance(pass_result=False) returns an overall-fail result."""
        assurance = FakeAssurance(pass_result=False)
        result = assurance.run(suite="default", agent_endpoint="http://localhost:9090")
        assert result.overall_passed is False
        assert result.failed > 0

    def test_fail_result_has_findings(self):
        assurance = FakeAssurance(pass_result=False)
        result = assurance.run(suite="default", agent_endpoint="http://localhost:9090")
        assert len(result.findings) > 0

    def test_pass_result_findings_all_passed(self):
        assurance = FakeAssurance(pass_result=True)
        result = assurance.run(suite="default", agent_endpoint="http://localhost:9090")
        for finding in result.findings:
            assert finding.passed is True

    def test_assurance_error_raised_on_failure_mode(self):
        assurance = FakeAssurance(raise_error=True, error_reason="RAMPART runner timeout")
        with pytest.raises(AssuranceError) as exc_info:
            assurance.run(suite="default", agent_endpoint="http://localhost:9090")
        assert "RAMPART runner timeout" in str(exc_info.value)

    def test_records_last_called_endpoint(self):
        assurance = FakeAssurance()
        assurance.run(suite="default", agent_endpoint="http://fake-agent:9090")
        assert assurance.last_endpoint == "http://fake-agent:9090"

    def test_records_last_called_suite(self):
        assurance = FakeAssurance()
        assurance.run(suite="xpia", agent_endpoint="http://localhost:9090")
        assert assurance.last_suite == "xpia"

    def test_adapter_does_not_accept_credentials(self):
        """The adapter signature takes an endpoint, not credentials.

        Confirm that run() has no 'credentials', 'token', or 'secret' parameters.
        """
        import inspect
        sig = inspect.signature(AssuranceAdapter.run)
        param_names = set(sig.parameters.keys())
        forbidden = {"credentials", "token", "secret", "api_key", "password"}
        assert not (param_names & forbidden), (
            f"AssuranceAdapter.run() has credential-like parameter(s): "
            f"{param_names & forbidden}"
        )
