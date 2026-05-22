"""
gauntlet CLI

The seam artifact: RAMPART assurance executed against an agent running inside
OpenShell isolation — one command.

Commands
--------
gauntlet run    Run RAMPART assurance against an agent in an OpenShell sandbox.
                (Stub at D1 scaffold stage — D2 implements the seam.)
"""

from __future__ import annotations

import typer

from gauntlet import __version__

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


@app.command()
def run(
    agent_image: str = typer.Option(
        ...,
        "--agent-image",
        help="OCI image reference for the agent to place under test (e.g. my-agent:latest).",
    ),
    policy: str = typer.Option(
        "policy.yaml",
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
) -> None:
    """Run RAMPART assurance against an agent inside an OpenShell sandbox.

    This command is the Gauntlet seam: it starts an OpenShell sandbox around
    the specified agent image, then drives RAMPART's assurance tests against
    the agent executing inside that sandbox.

    STUB: This command is scaffolded at D1. D2 (seam implementation) wires
    the actual RAMPART + OpenShell integration. Running it now will print the
    planned invocation and exit without executing anything.

    Example (once D2 is complete):

        gauntlet run --agent-image my-agent:latest --policy policy.yaml

    Requires: pip install -e ".\[integration]"
    """
    typer.echo("gauntlet run")
    typer.echo(f"  agent-image : {agent_image}")
    typer.echo(f"  policy      : {policy}")
    typer.echo(f"  suite       : {suite}")
    typer.echo(f"  dry-run     : {dry_run}")
    typer.echo("")
    typer.echo(
        "NOTE: gauntlet run is a stub at D1 scaffold stage.\n"
        "      D2 implements the RAMPART + OpenShell seam.\n"
        "      Run pip install -e '.[integration]' once D2 is complete."
    )
