"""
Unit tests for report.py — structured report output.

Verifies:
- render_report() accepts a SeamResult and returns a non-empty string.
- Report contains the agent image name.
- Report contains the suite name.
- Report contains a PASS or FAIL verdict.
- Report contains sandbox isolation status.
- Report contains assurance finding counts.
- Dry-run report is clearly labeled as a plan (not an execution result).
- Report does not leak secrets, credentials, or raw host paths.
- render_report() also supports JSON output (structured machine-readable).

No RAMPART or OpenShell required.
"""

from __future__ import annotations

import json
import re

import pytest

from gauntlet.assurance import AssuranceFinding, AssuranceResult, FakeAssurance
from gauntlet.report import render_report
from gauntlet.sandbox import FakeSandbox, SandboxPolicy
from gauntlet.seam import SeamResult, run_seam


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_seam_result(pass_result: bool = True, dry_run: bool = False) -> SeamResult:
    return run_seam(
        agent_image="test-agent:v1",
        sandbox=FakeSandbox(),
        assurance=FakeAssurance(pass_result=pass_result),
        policy=SandboxPolicy(),
        suite="default",
        dry_run=dry_run,
    )


# ---------------------------------------------------------------------------
# Human-readable (text) report
# ---------------------------------------------------------------------------

class TestRenderReportText:
    def test_render_returns_nonempty_string(self):
        result = _make_seam_result()
        report = render_report(result)
        assert isinstance(report, str)
        assert len(report.strip()) > 0

    def test_report_contains_agent_image(self):
        result = _make_seam_result()
        report = render_report(result)
        assert "test-agent:v1" in report

    def test_report_contains_suite(self):
        result = _make_seam_result()
        report = render_report(result)
        assert "default" in report

    def test_report_pass_verdict_when_overall_passed(self):
        result = _make_seam_result(pass_result=True)
        report = render_report(result)
        assert "PASS" in report

    def test_report_fail_verdict_when_overall_failed(self):
        result = _make_seam_result(pass_result=False)
        report = render_report(result)
        assert "FAIL" in report

    def test_report_mentions_isolation(self):
        result = _make_seam_result()
        report = render_report(result)
        # The report must state something about isolation / sandbox
        report_lower = report.lower()
        assert "isolat" in report_lower or "sandbox" in report_lower

    def test_report_mentions_finding_counts(self):
        result = _make_seam_result()
        report = render_report(result)
        # Report must include some count/summary of findings
        assert any(word in report.lower() for word in ("passed", "failed", "finding"))

    def test_dry_run_report_labeled_as_plan(self):
        result = _make_seam_result(dry_run=True)
        report = render_report(result)
        report_lower = report.lower()
        assert "dry" in report_lower or "plan" in report_lower

    def test_report_no_host_paths(self):
        result = _make_seam_result()
        report = render_report(result)
        # Must not contain deep absolute paths (4+ levels)
        assert not re.search(r"(?:/[\w.\-]+){4,}", report), (
            "Report leaked a host filesystem path"
        )

    def test_report_no_credentials(self):
        """Report must not contain credential-like tokens."""
        result = _make_seam_result()
        report = render_report(result)
        # Must not contain Bearer tokens or sk- keys
        assert not re.search(r"Bearer\s+[A-Za-z0-9]", report)
        assert not re.search(r"sk-[A-Za-z0-9]{10,}", report)


# ---------------------------------------------------------------------------
# JSON (machine-readable) report
# ---------------------------------------------------------------------------

class TestRenderReportJson:
    def test_json_report_is_valid_json(self):
        result = _make_seam_result()
        report_json = render_report(result, fmt="json")
        # Must parse without error
        data = json.loads(report_json)
        assert isinstance(data, dict)

    def test_json_report_has_agent_image(self):
        result = _make_seam_result()
        data = json.loads(render_report(result, fmt="json"))
        assert data.get("agent_image") == "test-agent:v1"

    def test_json_report_has_suite(self):
        result = _make_seam_result()
        data = json.loads(render_report(result, fmt="json"))
        assert data.get("suite") == "default"

    def test_json_report_has_overall_passed(self):
        result = _make_seam_result(pass_result=True)
        data = json.loads(render_report(result, fmt="json"))
        assert "overall_passed" in data
        assert data["overall_passed"] is True

    def test_json_report_has_findings(self):
        result = _make_seam_result()
        data = json.loads(render_report(result, fmt="json"))
        assert "findings" in data

    def test_json_report_has_sandbox_isolated_field(self):
        result = _make_seam_result()
        data = json.loads(render_report(result, fmt="json"))
        assert "sandbox_isolated" in data

    def test_json_report_dry_run_flag(self):
        result = _make_seam_result(dry_run=True)
        data = json.loads(render_report(result, fmt="json"))
        assert data.get("dry_run") is True

    def test_invalid_fmt_raises_value_error(self):
        result = _make_seam_result()
        with pytest.raises(ValueError):
            render_report(result, fmt="yaml")  # unsupported format
