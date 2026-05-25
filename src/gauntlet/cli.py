"""
gauntlet CLI

The seam artifact: RAMPART assurance executed against an agent running inside
OpenShell isolation — one command.

Commands
--------
gauntlet run    Run RAMPART assurance against an agent in an OpenShell sandbox.
"""

from __future__ import annotations

import sys
from typing import Optional

import typer

from gauntlet import __version__
from gauntlet.assurance import FakeAssurance, RampartAssurance
from gauntlet.direct_runner import DirectDockerRunner
from gauntlet.policy_loader import PolicyLoadError, load_policy
from gauntlet.report import render_report
from gauntlet.sandbox import FakeSandbox, SandboxPolicy
from gauntlet.seam import SeamError, run_seam

app = typer.Typer(
    name="gauntlet",
    help=(
        "The seam artifact: RAMPART assurance executed against an agent running "
        "inside OpenShell isolation.\n\n"
        "Built on Microsoft RAMPART (MIT) and NVIDIA OpenShell (Apache-2.0).\n"
        "Part of the NotionAlpha OSS AI Lab — https://notionalpha.com"
    ),
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"gauntlet {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(  # noqa: FBT001
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Gauntlet — the RAMPART + OpenShell seam artifact."""


def _load_policy_or_exit(policy_path: Optional[str]) -> SandboxPolicy:
    """Load the YAML policy or exit 1 with a sanitized error message.

    Returns an empty (deny-by-default) SandboxPolicy when policy_path is None.
    """
    if policy_path is None:
        return SandboxPolicy()
    try:
        return load_policy(policy_path)
    except PolicyLoadError as exc:
        typer.echo(f"ERROR: policy load failed: {exc}", err=True)
        raise typer.Exit(code=1)


@app.command()
def run(
    agent_image: str = typer.Option(
        ...,
        "--agent-image",
        help="OCI image reference for the agent to place under test (e.g. my-agent:latest).",
    ),
    policy: Optional[str] = typer.Option(
        None,
        "--policy",
        help="Path to the OpenShell declarative YAML policy governing the sandbox.",
    ),
    suite: str = typer.Option(
        "default",
        "--suite",
        help="RAMPART test suite to run against the sandboxed agent.",
    ),
    dry_run: bool = typer.Option(  # noqa: FBT001
        False,
        "--dry-run",
        help="Validate inputs and print the run plan without executing.",
    ),
    output_format: str = typer.Option(
        "text",
        "--output",
        "-o",
        help="Report format: 'text' (human-readable, default) or 'json' (machine-readable).",
    ),
    use_fakes: bool = typer.Option(  # noqa: FBT001
        False,
        "--use-fakes",
        help=(
            "Use fake sandbox and assurance adapters (for development/testing). "
            "Runs without real RAMPART or OpenShell installed."
        ),
        hidden=False,
    ),
    no_sandbox: bool = typer.Option(  # noqa: FBT001
        False,
        "--no-sandbox",
        help=(
            "Use DirectDockerRunner (no kernel isolation) with real RampartAssurance. "
            "Runs without OpenShell installed but still requires RAMPART. "
            "Mutually exclusive with --use-fakes."
        ),
    ),
) -> None:
    """Run RAMPART assurance against an agent inside an OpenShell sandbox.

    This command is the Gauntlet seam: it starts an OpenShell deny-by-default
    isolation boundary around the specified agent image, then drives RAMPART
    assurance tests against the agent executing inside that boundary, and emits
    a structured report.

    The agent image is treated as UNTRUSTED. The sandbox enforces a deny-by-default
    policy — no network egress and no filesystem access are permitted unless
    explicitly listed in the policy file.

    Example (with real RAMPART + OpenShell):

        pip install -e ".[integration]"
        gauntlet run --agent-image my-agent:latest --policy policy.yaml

    Example (with fake adapters, no install required):

        gauntlet run --agent-image my-agent:latest --use-fakes

    Example (dry run — print the plan without executing):

        gauntlet run --agent-image my-agent:latest --dry-run

    Report format:

        gauntlet run --agent-image my-agent:latest --use-fakes --output json
    """
    if no_sandbox and use_fakes:
        typer.echo(
            "ERROR: --no-sandbox and --use-fakes are mutually exclusive.\n"
            "Use --no-sandbox to run DirectDockerRunner + real RampartAssurance,\n"
            "or --use-fakes to run with fake adapters (no RAMPART/OpenShell required).",
            err=True,
        )
        raise typer.Exit(code=1)

    if no_sandbox:
        # DirectDockerRunner doesn't enforce a policy — skip YAML load entirely
        # so that --no-sandbox works regardless of whether --policy points at a
        # real file. The empty SandboxPolicy() is unused downstream.
        sandbox = DirectDockerRunner()
        assurance = RampartAssurance()
        sandbox_policy = SandboxPolicy()
    elif dry_run:
        # Dry-run just prints the plan without executing — skip YAML load so
        # that `gauntlet run --dry-run` works without a policy file present.
        sandbox = FakeSandbox()
        assurance = FakeAssurance()
        sandbox_policy = SandboxPolicy()
    elif use_fakes:
        # Fakes don't enforce the policy, but we DO load the YAML when the user
        # provides one — surfacing YAML errors gives consistent feedback
        # regardless of which downstream adapter runs.
        sandbox = FakeSandbox()
        assurance = FakeAssurance()
        sandbox_policy = _load_policy_or_exit(policy)
    else:
        # Real OpenShell path — requires [integration] extra.
        try:
            from gauntlet.sandbox import OpenShellSandbox  # type: ignore[attr-defined]
        except ImportError:
            typer.echo(
                "ERROR: RAMPART or OpenShell is not installed.\n"
                "Install with: pip install -e '.[integration]'\n\n"
                "To run with fake adapters (no install required), use --use-fakes.\n"
                "To print the run plan without executing, use --dry-run.",
                err=True,
            )
            raise typer.Exit(code=1)
        sandbox_policy = _load_policy_or_exit(policy)
        sandbox = OpenShellSandbox(policy_path=policy or "policy.yaml")  # type: ignore[assignment]
        assurance = RampartAssurance()  # type: ignore[assignment]

    try:
        result = run_seam(
            agent_image=agent_image,
            sandbox=sandbox,
            assurance=assurance,
            policy=sandbox_policy,
            suite=suite,
            dry_run=dry_run,
        )
    except SeamError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(code=1)

    try:
        report = render_report(result, fmt=output_format)
    except ValueError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(code=1)

    typer.echo(report)

    if not dry_run and not result.overall_passed:
        raise typer.Exit(code=1)
