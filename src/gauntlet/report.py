"""
report.py — structured report output.

Renders a SeamResult into a human-readable text report or a machine-readable
JSON report.  Both formats are sanitized — no secrets, credentials, or host
paths appear in the output.

Usage:
    from gauntlet.report import render_report

    report = render_report(result)           # human-readable text (default)
    report = render_report(result, fmt="json")  # machine-readable JSON

Security:
    All output goes through _sanitize_output() before being returned.  The
    sanitizer strips Bearer tokens, sk- keys, GitHub/npm tokens, absolute
    filesystem paths, and long opaque tokens.  Finding evidence is already
    sanitized at AssuranceFinding construction time; the output-level sanitizer
    is a defence-in-depth layer.

Threat model note: see README.md → Threat model.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from gauntlet._sanitizer import sanitize as _sanitize
from gauntlet.seam import SeamResult


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _render_text(result: SeamResult) -> str:
    """Render a human-readable text report."""
    lines: list[str] = []
    sep = "─" * 60

    lines.append("╔" + "═" * 58 + "╗")
    lines.append("║  Gauntlet — RAMPART-in-OpenShell Seam Report" + " " * 12 + "║")
    lines.append("╚" + "═" * 58 + "╝")
    lines.append("")

    # Dry-run header
    if result.dry_run:
        lines.append("  MODE       : DRY RUN (plan only — nothing was executed)")
        lines.append("")

    # Run metadata
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines.append(f"  Agent image: {result.agent_image}")
    lines.append(f"  Suite      : {result.suite}")
    lines.append(f"  Timestamp  : {ts}")
    lines.append("")

    # Sandbox section
    lines.append(sep)
    lines.append("  Sandbox (OpenShell isolation)")
    lines.append(sep)

    if result.dry_run or result.sandbox_context is None:
        lines.append("  Status     : NOT STARTED (dry run)")
        lines.append("  Isolated   : —")
    else:
        ctx = result.sandbox_context
        isolated_str = "YES — deny-by-default boundary active" if ctx.isolated else "NO (isolation failed)"
        lines.append(f"  Sandbox ID : {ctx.sandbox_id}")
        lines.append(f"  Isolated   : {isolated_str}")
        policy = ctx.policy
        net_allow = policy.network_allow or ["(none — deny-by-default)"]
        lines.append(f"  Net allow  : {', '.join(net_allow)}")

    lines.append("")

    # Assurance section
    lines.append(sep)
    lines.append("  Assurance (RAMPART)")
    lines.append(sep)

    if result.dry_run or result.assurance_result is None:
        lines.append("  Status     : NOT EXECUTED (dry run)")
        lines.append("  Findings   : —")
    else:
        ar = result.assurance_result
        lines.append(f"  Suite      : {ar.suite}")
        lines.append(f"  Passed     : {ar.passed}")
        lines.append(f"  Failed     : {ar.failed}")
        lines.append(f"  Errors     : {ar.errors}")
        lines.append("")

        if ar.findings:
            lines.append("  Findings:")
            for f in ar.findings:
                status = "PASS" if f.passed else "FAIL"
                lines.append(f"    [{status}] {f.test_id}: {f.name}")
                if not f.passed and f.evidence:
                    lines.append(f"           {f.evidence}")
        else:
            lines.append("  Findings   : (none)")

    lines.append("")

    # Verdict
    lines.append("╔" + "═" * 58 + "╗")
    if result.dry_run:
        verdict_line = "║  VERDICT: DRY RUN — execution plan printed above" + " " * 9 + "║"
    elif result.overall_passed:
        verdict_line = "║  VERDICT: PASS — all assurance tests passed" + " " * 14 + "║"
    else:
        verdict_line = "║  VERDICT: FAIL — one or more assurance tests failed" + " " * 6 + "║"
    lines.append(verdict_line)
    lines.append("╚" + "═" * 58 + "╝")
    lines.append("")

    return "\n".join(lines)


def _render_json(result: SeamResult) -> str:
    """Render a machine-readable JSON report."""
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    data: dict = {
        "agent_image": result.agent_image,
        "suite": result.suite,
        "timestamp": ts,
        "dry_run": result.dry_run,
        "overall_passed": result.overall_passed,
        "sandbox_isolated": (
            result.sandbox_context.isolated
            if result.sandbox_context is not None
            else None
        ),
        "sandbox_id": (
            result.sandbox_context.sandbox_id
            if result.sandbox_context is not None
            else None
        ),
        "assurance": (
            result.assurance_result.to_dict()
            if result.assurance_result is not None
            else None
        ),
        "findings": (
            [f.to_dict() for f in result.assurance_result.findings]
            if result.assurance_result is not None
            else []
        ),
    }

    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def render_report(result: SeamResult, fmt: str = "text") -> str:
    """Render a SeamResult as a structured report.

    Args:
        result: The SeamResult from run_seam().
        fmt:    Output format — "text" (human-readable, default) or "json"
                (machine-readable).

    Returns:
        A string containing the rendered report.  Sanitized — no credentials
        or host paths appear in the output.

    Raises:
        ValueError: If fmt is not "text" or "json".
    """
    if fmt == "text":
        raw = _render_text(result)
    elif fmt == "json":
        raw = _render_json(result)
    else:
        raise ValueError(
            f"Unsupported report format: {fmt!r}.  "
            f"Supported formats: 'text', 'json'."
        )
    return _sanitize(raw)
