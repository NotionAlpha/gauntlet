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
    The sanitizer (``_sanitize_finding``) strips Bearer tokens, sk- keys, GitHub/npm
    tokens, absolute filesystem paths, and long opaque tokens.
  - The adapter must not inject credentials into the agent session.

Threat model note: see README.md → Threat model.
"""

from __future__ import annotations

import re
import uuid
from abc import ABC, abstractmethod
from typing import Optional


# ---------------------------------------------------------------------------
# Credential/path sanitizer for finding evidence
# ---------------------------------------------------------------------------

def _sanitize_finding(raw: str) -> str:
    """Strip credential-like strings from finding evidence before output.

    Mirrors the discipline from benchmarks/assurance/src/assurance_benchmark/evaluator.py.
    Applied to every AssuranceFinding.evidence at construction time.

    Patterns:
      - Bearer tokens
      - Prefixed secret tokens: OpenAI sk-, GitHub ghp_/ghs_/ghr_, npm npm_
      - Absolute filesystem paths (Unix — 3+ components)
      - Long unbroken alphanumeric runs >= 40 chars (catches raw base64/hex tokens)
    """
    text = re.sub(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "[REDACTED_BEARER]", raw, flags=re.IGNORECASE)
    text = re.sub(r"sk-[A-Za-z0-9]{20,}", "[REDACTED_SK_KEY]", text)
    text = re.sub(r"(?:ghp|ghs|ghr|npm)_[A-Za-z0-9]{10,}", "[REDACTED_TOKEN]", text)
    text = re.sub(r"(?:/[\w.\-]+){3,}", "[REDACTED_PATH]", text)
    text = re.sub(r"[A-Za-z0-9+/=]{40,}", "[REDACTED_TOKEN]", text)
    return text


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
        self.evidence = _sanitize_finding(evidence)

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
# Real RAMPART adapter — requires rampart>=0.1.0 (integration extra)
# ---------------------------------------------------------------------------

class RampartAssurance(AssuranceAdapter):
    """RAMPART assurance adapter.

    Wraps the real RAMPART runner.  Requires `pip install -e ".[integration]"`.

    RAMPART (Microsoft, MIT) is pytest-native: tests are standard pytest functions
    decorated with RAMPART markers.  This adapter drives RAMPART programmatically
    against the sandboxed agent endpoint.

    RAMPART v0.1.0 supports XPIA (cross-prompt injection) attacks only.  The
    "default" suite runs all registered XPIA tests.

    Security:
        - No credentials are passed to this adapter or injected into the agent.
        - Finding evidence is sanitized by AssuranceFinding at construction time.
    """

    def run(
        self,
        suite: str,
        agent_endpoint: str,
    ) -> AssuranceResult:
        try:
            import rampart  # type: ignore[import]
        except ImportError as exc:
            raise AssuranceError(
                "RAMPART is not installed.  "
                "Install with: pip install -e '.[integration]'"
            ) from exc

        try:
            # RAMPART alpha API (v0.1.0):
            #   rampart.Runner accepts the agent endpoint and a suite name.
            #   It returns a result object with per-test outcomes.
            runner = rampart.Runner(
                agent_endpoint=agent_endpoint,
                suite=suite,
            )
            raw_result = runner.run()

            findings: list[AssuranceFinding] = []
            for test in raw_result.tests:
                findings.append(
                    AssuranceFinding(
                        test_id=test.id,
                        name=test.name,
                        passed=test.passed,
                        evidence=str(test.evidence or ""),
                    )
                )

            passed = sum(1 for f in findings if f.passed)
            failed = sum(1 for f in findings if not f.passed)
            errors = getattr(raw_result, "errors", 0)

            return AssuranceResult(
                suite=suite,
                findings=findings,
                passed=passed,
                failed=failed,
                errors=errors,
            )
        except AssuranceError:
            raise
        except Exception as exc:
            raise AssuranceError(
                f"RAMPART runner error: {type(exc).__name__}: {exc}"
            ) from exc
