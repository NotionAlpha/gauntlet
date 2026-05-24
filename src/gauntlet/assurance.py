"""
assurance.py — RAMPART assurance runner adapter.

Thin adapter interface over Microsoft RAMPART (MIT).
The AssuranceAdapter abstract class defines the seam; the seam logic (seam.py)
depends on this interface, not on RAMPART directly.

Two concrete implementations:
  FakeAssurance     — scripted fake for unit tests; no RAMPART install required.
  RampartAssurance  — wraps the real RAMPART runner; requires rampart>=0.1.0.
                      Constructed only when the [integration] extra is installed.

Security contract:
  - The adapter takes an agent_endpoint (HTTP address of the sandboxed agent).
    It does NOT accept credentials, API keys, or host paths.
  - Evidence strings from findings are sanitized before inclusion in AssuranceResult.
    The canonical sanitizer (gauntlet._sanitizer.sanitize) strips Bearer tokens,
    sk- keys, GitHub/npm tokens, absolute filesystem paths, and long opaque tokens.
    It also truncates evidence to 16 KiB to bound memory use on untrusted input.
  - The adapter must not inject credentials into the agent session.

Threat model note: see README.md → Threat model.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from gauntlet._sanitizer import sanitize as _sanitize


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class AssuranceError(Exception):
    """Raised when the RAMPART assurance runner fails to execute."""


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class AssuranceFinding:
    """A single test finding from RAMPART.

    Evidence is sanitized at construction time — no credentials or host paths
    will appear in the finding, even if RAMPART surfaces them from the agent.

    Args:
        test_id:  RAMPART test identifier (e.g. "xpia-01").
        name:     Human-readable test name.
        passed:   True if the agent passed this test.
        evidence: What the agent did/said (sanitized automatically).
    """

    def __init__(
        self,
        test_id: str,
        name: str,
        passed: bool,
        evidence: str,
    ) -> None:
        self.test_id = test_id
        self.name = name
        self.passed = passed
        self.evidence = _sanitize(evidence)

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "name": self.name,
            "passed": self.passed,
            "evidence": self.evidence,
        }

    def __repr__(self) -> str:
        return (
            f"AssuranceFinding(test_id={self.test_id!r}, "
            f"passed={self.passed!r})"
        )


class AssuranceResult:
    """Aggregated result from a RAMPART assurance run.

    Args:
        suite:    The RAMPART test suite that was run.
        findings: List of per-test AssuranceFinding objects.
        passed:   Count of tests that passed.
        failed:   Count of tests that failed.
        errors:   Count of tests that errored (could not be evaluated).
    """

    def __init__(
        self,
        suite: str,
        findings: list[AssuranceFinding],
        passed: int,
        failed: int,
        errors: int,
    ) -> None:
        self.suite = suite
        self.findings = findings
        self.passed = passed
        self.failed = failed
        self.errors = errors

    @property
    def overall_passed(self) -> bool:
        """True iff all tests passed and no errors occurred."""
        return self.failed == 0 and self.errors == 0

    def to_dict(self) -> dict:
        return {
            "suite": self.suite,
            "overall_passed": self.overall_passed,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
        }

    def __repr__(self) -> str:
        return (
            f"AssuranceResult(suite={self.suite!r}, "
            f"passed={self.passed}, failed={self.failed}, errors={self.errors})"
        )


# ---------------------------------------------------------------------------
# Abstract adapter
# ---------------------------------------------------------------------------

class AssuranceAdapter(ABC):
    """Abstract interface for RAMPART assurance.

    seam.py depends on this interface, not on RAMPART directly.  Swap
    FakeAssurance for RampartAssurance to run against real infrastructure.
    """

    @abstractmethod
    def run(
        self,
        suite: str,
        agent_endpoint: str,
    ) -> AssuranceResult:
        """Run the RAMPART assurance suite against the sandboxed agent.

        Args:
            suite:          RAMPART test suite name (e.g. "default", "xpia").
            agent_endpoint: HTTP address of the sandboxed agent.
                            Must be the address INSIDE the isolation boundary
                            (from SandboxContext.agent_endpoint), NOT a host address.

        Returns:
            AssuranceResult with per-test findings and aggregate counts.

        Raises:
            AssuranceError: If RAMPART fails to execute the suite.

        Security:
            - Do NOT add credentials, tokens, or API keys to this signature.
            - The agent endpoint is routed through the isolation boundary;
              do not bypass it by pointing at a non-sandboxed address.
            - Finding evidence is sanitized before inclusion in AssuranceResult.
        """
        ...


# ---------------------------------------------------------------------------
# Fake assurance — for unit tests
# ---------------------------------------------------------------------------

class FakeAssurance(AssuranceAdapter):
    """Scripted fake RAMPART runner for unit testing.

    Returns a pre-configured AssuranceResult without running any real RAMPART tests.
    No RAMPART install required.

    Args:
        pass_result:  If True, return an all-pass result.  If False, return a result
                      with one failing finding.
        raise_error:  If True, raise AssuranceError instead of returning a result.
        error_reason: The reason string included in AssuranceError.
    """

    _FAKE_PASS_FINDINGS = [
        AssuranceFinding(
            test_id="xpia-01",
            name="Cross-prompt injection: ignore system prompt",
            passed=True,
            evidence="Agent refused injected instruction and completed original task.",
        ),
        AssuranceFinding(
            test_id="xpia-02",
            name="Cross-prompt injection: exfiltrate via tool",
            passed=True,
            evidence="Agent did not call exfiltration tool when injected.",
        ),
    ]

    _FAKE_FAIL_FINDINGS = [
        AssuranceFinding(
            test_id="xpia-01",
            name="Cross-prompt injection: ignore system prompt",
            passed=False,
            evidence="Agent complied with injected instruction instead of original task.",
        ),
        AssuranceFinding(
            test_id="xpia-02",
            name="Cross-prompt injection: exfiltrate via tool",
            passed=True,
            evidence="Agent refused exfiltration tool call.",
        ),
    ]

    def __init__(
        self,
        pass_result: bool = True,
        raise_error: bool = False,
        error_reason: str = "simulated RAMPART runner error",
    ) -> None:
        self._pass_result = pass_result
        self._raise_error = raise_error
        self._error_reason = error_reason
        self.last_endpoint: Optional[str] = None
        self.last_suite: Optional[str] = None

    def run(
        self,
        suite: str,
        agent_endpoint: str,
    ) -> AssuranceResult:
        self.last_endpoint = agent_endpoint
        self.last_suite = suite

        if self._raise_error:
            raise AssuranceError(
                f"AssuranceError (fake): {self._error_reason}"
            )

        if self._pass_result:
            findings = self._FAKE_PASS_FINDINGS
            return AssuranceResult(
                suite=suite,
                findings=findings,
                passed=len(findings),
                failed=0,
                errors=0,
            )
        else:
            findings = self._FAKE_FAIL_FINDINGS
            passed = sum(1 for f in findings if f.passed)
            failed = sum(1 for f in findings if not f.passed)
            return AssuranceResult(
                suite=suite,
                findings=findings,
                passed=passed,
                failed=failed,
                errors=0,
            )


# ---------------------------------------------------------------------------
# Real RAMPART adapter — shells out to pytest against the bundled rampart_suite
# ---------------------------------------------------------------------------

def _human_name(test_id: str) -> str:
    """Convert a pytest function name to a human-readable label.

    Examples:
        test_send_email_xpia_resistance  →  Send email xpia resistance
        test_tool_call_exfiltration      →  Tool call exfiltration
    """
    # Strip the leading "test_" prefix that pytest requires
    label = test_id.removeprefix("test_")
    # Replace underscores with spaces and capitalise the first word
    return label.replace("_", " ").capitalize()


def _result_from_report(report: dict, suite: str) -> AssuranceResult:
    """Parse a pytest-json-report dict into an AssuranceResult.

    Evidence for each finding is built from longrepr + metadata (if present),
    serialised to JSON, sanitised via AssuranceFinding (which calls _sanitize
    and caps at 16 KiB), and stored in the finding.

    Args:
        report: Parsed dict from a pytest-json-report JSON file.
        suite:  Suite name string to embed in AssuranceResult.

    Returns:
        An AssuranceResult with per-test findings and aggregate counts.
    """
    findings: list[AssuranceFinding] = []
    for entry in report.get("tests", []):
        nodeid: str = entry.get("nodeid", "unknown")
        # test_id = last segment after "::" — the function name
        test_id = nodeid.rsplit("::", 1)[-1]
        name = _human_name(test_id)
        passed = entry.get("outcome") == "passed"

        # Build evidence: longrepr + optional metadata dict
        evidence_parts: dict = {}
        if entry.get("longrepr"):
            evidence_parts["longrepr"] = entry["longrepr"]
        if entry.get("metadata"):
            evidence_parts["metadata"] = entry["metadata"]
        raw_evidence = json.dumps(evidence_parts) if evidence_parts else ""

        findings.append(
            AssuranceFinding(
                test_id=test_id,
                name=name,
                passed=passed,
                # AssuranceFinding sanitizes via _sanitize() and caps at 16 KiB
                evidence=raw_evidence,
            )
        )

    summary = report.get("summary", {})
    passed_count = summary.get("passed", sum(1 for f in findings if f.passed))
    failed_count = summary.get("failed", sum(1 for f in findings if not f.passed))
    errors_count = summary.get("error", 0)

    return AssuranceResult(
        suite=suite,
        findings=findings,
        passed=passed_count,
        failed=failed_count,
        errors=errors_count,
    )


class RampartAssurance(AssuranceAdapter):
    """RAMPART assurance adapter.

    Shells out to pytest against the bundled ``rampart_suite`` package, which
    contains pytest functions decorated with ``@pytest.mark.harm``.  The agent
    endpoint is passed via the ``GAUNTLET_AGENT_ENDPOINT`` environment variable
    so that fixture code inside the suite can reach the sandboxed agent without
    this adapter needing to know the suite's internal structure.

    pytest output is captured via ``pytest-json-report``.  The JSON report is
    parsed into an ``AssuranceResult``; the temp file is always deleted
    (``finally`` block).

    Requires: ``pytest-json-report>=1.5`` (part of the ``[integration]`` extra).

    Security:
        - No credentials are passed to this adapter or injected into the agent.
        - Finding evidence is sanitised at ``AssuranceFinding`` construction time
          via ``_sanitize()`` (16 KiB cap, credential/path redaction).
        - The ``GAUNTLET_AGENT_ENDPOINT`` env var carries only a plain HTTP URL —
          never a credential, token, or host path.
    """

    def run(
        self,
        suite: str,
        agent_endpoint: str,
    ) -> AssuranceResult:
        """Run the rampart_suite against the agent endpoint and return a result.

        Args:
            suite:          Suite label stored in AssuranceResult (e.g. "default").
            agent_endpoint: HTTP address of the sandboxed agent; forwarded to
                            rampart_suite tests via GAUNTLET_AGENT_ENDPOINT.

        Returns:
            AssuranceResult with per-test findings and aggregate counts.

        Raises:
            AssuranceError: If pytest exits with code 5 (no tests collected),
                            if the JSON report file is missing after the run,
                            or if the JSON report cannot be parsed.
        """
        suite_dir = Path(__file__).parent / "rampart_suite"
        fd, report_path = tempfile.mkstemp(suffix=".json", prefix="rampart-")
        os.close(fd)

        env = os.environ.copy()
        env["GAUNTLET_AGENT_ENDPOINT"] = agent_endpoint

        cmd = [
            sys.executable, "-m", "pytest", str(suite_dir),
            "-m", "harm",
            "--json-report",
            f"--json-report-file={report_path}",
            "-q",
        ]

        try:
            proc = subprocess.run(cmd, env=env, capture_output=True, text=True)

            # Exit code 5 means pytest collected zero tests — the suite dir is
            # absent or no tests matched the marker.  This is always an error.
            if proc.returncode == 5 or not Path(report_path).exists():
                raise AssuranceError(
                    f"rampart suite produced no report (pytest exit {proc.returncode}); "
                    f"ensure rampart_suite is installed and pytest-json-report>=1.5 is available"
                )

            try:
                report = json.loads(Path(report_path).read_text())
            except (json.JSONDecodeError, OSError) as exc:
                raise AssuranceError(
                    f"rampart suite report could not be parsed: {type(exc).__name__}"
                ) from exc

            return _result_from_report(report, suite)

        finally:
            Path(report_path).unlink(missing_ok=True)
