"""
Unit tests for the real RampartAssurance adapter.

Tests the shell-out impl: RampartAssurance.run() invokes pytest against the
bundled rampart_suite, passes the agent endpoint via GAUNTLET_AGENT_ENDPOINT,
parses the pytest-json-report output into AssuranceResult, and raises
AssuranceError on bad outcomes.

No RAMPART install needed — subprocess.run and tempfile.mkstemp are mocked.

Mock pattern:
  patch("gauntlet.assurance.subprocess.run") — controls what pytest "returns"
  patch("gauntlet.assurance.tempfile.mkstemp") — points report path at tmp_path

The fake JSON report is written to tmp_path before calling .run() so the impl
can read it normally.
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from gauntlet.assurance import (
    AssuranceError,
    AssuranceFinding,
    AssuranceResult,
    RampartAssurance,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_report(
    tests: list[dict],
    summary: dict | None = None,
) -> dict:
    """Build a minimal pytest-json-report dict."""
    passed = sum(1 for t in tests if t.get("outcome") == "passed")
    failed = sum(1 for t in tests if t.get("outcome") == "failed")
    errored = sum(1 for t in tests if t.get("outcome") == "error")
    return {
        "tests": tests,
        "summary": summary or {
            "passed": passed,
            "failed": failed,
            "error": errored,
            "total": len(tests),
        },
    }


def _make_test_entry(
    nodeid: str = "rampart_suite/test_xpia.py::test_send_email_xpia_resistance",
    outcome: str = "passed",
    longrepr: str | None = None,
    metadata: dict | None = None,
) -> dict:
    entry: dict = {"nodeid": nodeid, "outcome": outcome}
    if longrepr:
        entry["longrepr"] = longrepr
    if metadata:
        entry["metadata"] = metadata
    return entry


def _run_with_fake_report(
    report: dict,
    tmp_path,
    returncode: int = 0,
    suite: str = "default",
    agent_endpoint: str = "http://localhost:9090",
) -> AssuranceResult:
    """Invoke RampartAssurance.run() with a mocked subprocess and a pre-written report."""
    report_file = tmp_path / "rampart-report.json"
    report_file.write_text(json.dumps(report))

    mock_proc = MagicMock()
    mock_proc.returncode = returncode
    mock_proc.stdout = ""
    mock_proc.stderr = ""

    with (
        patch("gauntlet.assurance.subprocess.run", return_value=mock_proc),
        patch(
            "gauntlet.assurance.tempfile.mkstemp",
            return_value=(None, str(report_file)),
        ),
        patch("os.close"),  # mkstemp returns fd=None in mock; os.close is called on it
    ):
        return RampartAssurance().run(suite=suite, agent_endpoint=agent_endpoint)


# ---------------------------------------------------------------------------
# Step 2: Verify existing stub fails these tests before we implement
# (tests are the spec; they pass after implementation)
# ---------------------------------------------------------------------------


class TestRampartAssuranceInvocation:

    def test_run_invokes_pytest_with_endpoint_env_and_parses_report(self, tmp_path):
        """
        Subprocess must receive GAUNTLET_AGENT_ENDPOINT in its env, and the
        returned AssuranceResult must reflect the counts from the fake report.
        """
        tests = [
            _make_test_entry(outcome="passed"),
            _make_test_entry(
                nodeid="rampart_suite/test_xpia.py::test_tool_call_xpia_resistance",
                outcome="failed",
                longrepr="AssertionError: agent called exfiltration tool",
            ),
        ]
        report = _make_report(tests)
        report_file = tmp_path / "rampart-report.json"
        report_file.write_text(json.dumps(report))

        mock_proc = MagicMock()
        mock_proc.returncode = 1  # 1 = some tests failed (not 5 = no tests collected)
        mock_proc.stdout = ""
        mock_proc.stderr = ""

        captured_env: dict = {}

        def fake_run(cmd, env, **kwargs):
            captured_env.update(env)
            return mock_proc

        with (
            patch("gauntlet.assurance.subprocess.run", side_effect=fake_run),
            patch(
                "gauntlet.assurance.tempfile.mkstemp",
                return_value=(None, str(report_file)),
            ),
            patch("os.close"),
        ):
            result = RampartAssurance().run(
                suite="default", agent_endpoint="http://agent:9090"
            )

        assert "GAUNTLET_AGENT_ENDPOINT" in captured_env
        assert captured_env["GAUNTLET_AGENT_ENDPOINT"] == "http://agent:9090"

        assert isinstance(result, AssuranceResult)
        assert result.suite == "default"
        assert result.passed == 1
        assert result.failed == 1
        assert len(result.findings) == 2

    def test_run_includes_harm_marker_in_pytest_cmd(self, tmp_path):
        """pytest cmd must include '-m harm' to select the RAMPART harm suite."""
        report = _make_report([_make_test_entry()])
        report_file = tmp_path / "rampart-report.json"
        report_file.write_text(json.dumps(report))

        mock_proc = MagicMock()
        mock_proc.returncode = 0

        captured_cmd: list = []

        def fake_run(cmd, **kwargs):
            captured_cmd.extend(cmd)
            return mock_proc

        with (
            patch("gauntlet.assurance.subprocess.run", side_effect=fake_run),
            patch(
                "gauntlet.assurance.tempfile.mkstemp",
                return_value=(None, str(report_file)),
            ),
            patch("os.close"),
        ):
            RampartAssurance().run(suite="default", agent_endpoint="http://x:9090")

        # Find all positions of "-m" to avoid hitting "python -m pytest"
        m_indices = [i for i, arg in enumerate(captured_cmd) if arg == "-m"]
        assert len(m_indices) >= 1, "No -m flag found in pytest cmd"
        # The marker -m comes after "pytest" in the cmd list; the last -m is the marker one
        harm_found = any(
            captured_cmd[i + 1] == "harm"
            for i in m_indices
            if i + 1 < len(captured_cmd)
        )
        assert harm_found, f"No '-m harm' found in cmd: {captured_cmd}"

    def test_run_uses_json_report_flag(self, tmp_path):
        """pytest cmd must include --json-report and --json-report-file=<path>."""
        report = _make_report([_make_test_entry()])
        report_file = tmp_path / "rampart-report.json"
        report_file.write_text(json.dumps(report))

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        captured_cmd: list = []

        def fake_run(cmd, **kwargs):
            captured_cmd.extend(cmd)
            return mock_proc

        with (
            patch("gauntlet.assurance.subprocess.run", side_effect=fake_run),
            patch(
                "gauntlet.assurance.tempfile.mkstemp",
                return_value=(None, str(report_file)),
            ),
            patch("os.close"),
        ):
            RampartAssurance().run(suite="default", agent_endpoint="http://x:9090")

        assert "--json-report" in captured_cmd
        assert any(arg.startswith("--json-report-file=") for arg in captured_cmd)


class TestRampartAssuranceFindings:

    def test_run_marks_findings_failed_when_outcome_failed(self, tmp_path):
        """A test with outcome='failed' must produce passed=False and increment failed count."""
        tests = [
            _make_test_entry(
                nodeid="rampart_suite/test_xpia.py::test_send_email_xpia_resistance",
                outcome="failed",
                longrepr="AssertionError: agent followed injected instruction",
            ),
        ]
        report = _make_report(tests)

        mock_proc = MagicMock()
        mock_proc.returncode = 1

        report_file = tmp_path / "rampart-report.json"
        report_file.write_text(json.dumps(report))

        with (
            patch("gauntlet.assurance.subprocess.run", return_value=mock_proc),
            patch(
                "gauntlet.assurance.tempfile.mkstemp",
                return_value=(None, str(report_file)),
            ),
            patch("os.close"),
        ):
            result = RampartAssurance().run(suite="default", agent_endpoint="http://x:9090")

        assert result.failed == 1
        assert result.passed == 0
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.passed is False

    def test_run_marks_findings_passed_when_outcome_passed(self, tmp_path):
        """A test with outcome='passed' must produce a finding with passed=True."""
        tests = [_make_test_entry(outcome="passed")]
        report = _make_report(tests)
        result = _run_with_fake_report(report, tmp_path)

        assert result.passed == 1
        assert result.failed == 0
        assert result.findings[0].passed is True

    def test_run_derives_test_id_from_nodeid(self, tmp_path):
        """test_id must be the last segment of the nodeid (after ::)."""
        tests = [
            _make_test_entry(
                nodeid="rampart_suite/test_xpia.py::test_send_email_xpia_resistance",
                outcome="passed",
            )
        ]
        report = _make_report(tests)
        result = _run_with_fake_report(report, tmp_path)

        assert result.findings[0].test_id == "test_send_email_xpia_resistance"

    def test_run_derives_human_readable_name_from_test_id(self, tmp_path):
        """name must be a human-readable version of the test function name."""
        tests = [
            _make_test_entry(
                nodeid="rampart_suite/test_xpia.py::test_send_email_xpia_resistance",
                outcome="passed",
            )
        ]
        report = _make_report(tests)
        result = _run_with_fake_report(report, tmp_path)

        # The name must be non-empty and different from the raw test_id
        # (underscores replaced with spaces, "test_" prefix stripped)
        name = result.findings[0].name
        assert name, "name must be non-empty"
        assert "_" not in name, f"name should not contain underscores: {name!r}"

    def test_run_errors_count_comes_from_summary(self, tmp_path):
        """errors in AssuranceResult must use report['summary']['error']."""
        tests = [_make_test_entry(outcome="passed")]
        report = _make_report(tests, summary={"passed": 1, "failed": 0, "error": 3})
        result = _run_with_fake_report(report, tmp_path)

        assert result.errors == 3


class TestRampartAssuranceErrorHandling:

    def test_run_raises_assurance_error_when_no_tests_collected(self, tmp_path):
        """Exit code 5 (no tests collected) must raise AssuranceError with a clear message."""
        report_file = tmp_path / "rampart-report.json"
        # Do NOT write the report — exit code 5 means pytest bailed early

        mock_proc = MagicMock()
        mock_proc.returncode = 5

        with (
            patch("gauntlet.assurance.subprocess.run", return_value=mock_proc),
            patch(
                "gauntlet.assurance.tempfile.mkstemp",
                return_value=(None, str(report_file)),
            ),
            patch("os.close"),
        ):
            with pytest.raises(AssuranceError) as exc_info:
                RampartAssurance().run(suite="default", agent_endpoint="http://x:9090")

        msg = str(exc_info.value).lower()
        assert "no" in msg or "5" in msg or "report" in msg, (
            f"AssuranceError message should mention the failure; got: {exc_info.value!r}"
        )

    def test_run_raises_assurance_error_when_report_missing(self, tmp_path):
        """Missing report file (any exit code) must raise AssuranceError."""
        report_file = tmp_path / "rampart-report-missing.json"
        # report_file intentionally not written

        mock_proc = MagicMock()
        mock_proc.returncode = 0  # pytest says OK but report vanished

        with (
            patch("gauntlet.assurance.subprocess.run", return_value=mock_proc),
            patch(
                "gauntlet.assurance.tempfile.mkstemp",
                return_value=(None, str(report_file)),
            ),
            patch("os.close"),
        ):
            with pytest.raises(AssuranceError):
                RampartAssurance().run(suite="default", agent_endpoint="http://x:9090")

    def test_report_tempfile_cleaned_up_even_on_success(self, tmp_path):
        """The temp report file must be deleted after a successful run."""
        report = _make_report([_make_test_entry()])
        report_file = tmp_path / "rampart-report.json"
        report_file.write_text(json.dumps(report))

        mock_proc = MagicMock()
        mock_proc.returncode = 0

        with (
            patch("gauntlet.assurance.subprocess.run", return_value=mock_proc),
            patch(
                "gauntlet.assurance.tempfile.mkstemp",
                return_value=(None, str(report_file)),
            ),
            patch("os.close"),
        ):
            RampartAssurance().run(suite="default", agent_endpoint="http://x:9090")

        # File must have been unlinked
        assert not report_file.exists(), "temp report file should be deleted after run"

    def test_report_tempfile_cleaned_up_on_assurance_error(self, tmp_path):
        """The temp report file must be deleted even when AssuranceError is raised."""
        report_file = tmp_path / "rampart-report.json"
        # No report written → will raise AssuranceError

        mock_proc = MagicMock()
        mock_proc.returncode = 5

        with (
            patch("gauntlet.assurance.subprocess.run", return_value=mock_proc),
            patch(
                "gauntlet.assurance.tempfile.mkstemp",
                return_value=(None, str(report_file)),
            ),
            patch("os.close"),
        ):
            with pytest.raises(AssuranceError):
                RampartAssurance().run(suite="default", agent_endpoint="http://x:9090")

        # File must not exist (was never written, but Path.unlink(missing_ok=True) is fine)
        assert not report_file.exists()


class TestRampartAssuranceSanitization:

    def test_run_sanitizes_evidence(self, tmp_path):
        """Evidence containing credential-like strings must be sanitized."""
        secret = "sk-abcdefghijklmnopqrst1234567890"
        tests = [
            _make_test_entry(
                outcome="failed",
                longrepr=f"Agent leaked secret: {secret}",
            )
        ]
        report = _make_report(tests)

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        report_file = tmp_path / "rampart-report.json"
        report_file.write_text(json.dumps(report))

        with (
            patch("gauntlet.assurance.subprocess.run", return_value=mock_proc),
            patch(
                "gauntlet.assurance.tempfile.mkstemp",
                return_value=(None, str(report_file)),
            ),
            patch("os.close"),
        ):
            result = RampartAssurance().run(suite="default", agent_endpoint="http://x:9090")

        finding = result.findings[0]
        assert secret not in finding.evidence, (
            "Raw sk- key must not appear in sanitized evidence"
        )
        assert "[REDACTED" in finding.evidence

    def test_run_caps_evidence_at_16_kib(self, tmp_path):
        """Evidence must be capped at 16 KiB (16384 bytes) after sanitization."""
        long_text = "Agent said: " + "x" * 20_000
        tests = [
            _make_test_entry(
                outcome="failed",
                longrepr=long_text,
            )
        ]
        report = _make_report(tests)

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        report_file = tmp_path / "rampart-report.json"
        report_file.write_text(json.dumps(report))

        with (
            patch("gauntlet.assurance.subprocess.run", return_value=mock_proc),
            patch(
                "gauntlet.assurance.tempfile.mkstemp",
                return_value=(None, str(report_file)),
            ),
            patch("os.close"),
        ):
            result = RampartAssurance().run(suite="default", agent_endpoint="http://x:9090")

        finding = result.findings[0]
        assert len(finding.evidence) <= 16_384, (
            f"Evidence must be capped at 16 KiB; got {len(finding.evidence)} bytes"
        )

    def test_run_sanitizes_bearer_token_in_evidence(self, tmp_path):
        """Bearer token in longrepr must not appear in finding evidence."""
        raw_token = "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"
        tests = [
            _make_test_entry(
                outcome="failed",
                longrepr=f"Authorization header: {raw_token}",
            )
        ]
        report = _make_report(tests)

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        report_file = tmp_path / "rampart-report.json"
        report_file.write_text(json.dumps(report))

        with (
            patch("gauntlet.assurance.subprocess.run", return_value=mock_proc),
            patch(
                "gauntlet.assurance.tempfile.mkstemp",
                return_value=(None, str(report_file)),
            ),
            patch("os.close"),
        ):
            result = RampartAssurance().run(suite="default", agent_endpoint="http://x:9090")

        assert "eyJhbGciOiJIUzI1NiJ9" not in result.findings[0].evidence


class TestRampartAssuranceIsAdapter:

    def test_rampart_assurance_is_subclass_of_adapter(self):
        from gauntlet.assurance import AssuranceAdapter

        assert issubclass(RampartAssurance, AssuranceAdapter)

    def test_run_returns_assurance_result_instance(self, tmp_path):
        report = _make_report([_make_test_entry()])
        result = _run_with_fake_report(report, tmp_path)
        assert isinstance(result, AssuranceResult)

    def test_run_suite_passed_through_to_result(self, tmp_path):
        report = _make_report([_make_test_entry()])
        result = _run_with_fake_report(report, tmp_path, suite="xpia")
        assert result.suite == "xpia"
