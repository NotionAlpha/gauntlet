"""
CLI smoke tests for gauntlet.

Verifies:
- `gauntlet --help` exits 0 and prints expected content.
- `gauntlet run --help` exits 0 and prints expected content.
- `gauntlet --version` exits 0 and prints version string.
- `gauntlet run` requires --agent-image (missing argument exits non-zero).
- `gauntlet run --agent-image ... --dry-run` exits 0 and prints the plan.

No RAMPART or OpenShell required — CLI tests exercise the Typer app directly.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from gauntlet import __version__
from gauntlet.cli import app

runner = CliRunner()


class TestHelpCommands:
    def test_root_help_exits_0(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0

    def test_root_help_mentions_rampart(self):
        result = runner.invoke(app, ["--help"])
        assert "RAMPART" in result.output

    def test_root_help_mentions_openshell(self):
        result = runner.invoke(app, ["--help"])
        assert "OpenShell" in result.output

    def test_run_help_exits_0(self):
        result = runner.invoke(app, ["run", "--help"])
        assert result.exit_code == 0

    def test_run_help_mentions_agent_image(self):
        result = runner.invoke(app, ["run", "--help"])
        assert "--agent-image" in result.output

    def test_run_help_mentions_policy(self):
        result = runner.invoke(app, ["run", "--help"])
        assert "--policy" in result.output

    def test_run_help_mentions_stub(self):
        """The help text must document that run is a stub at D1."""
        result = runner.invoke(app, ["run", "--help"])
        assert "stub" in result.output.lower() or "D2" in result.output


class TestVersionFlag:
    def test_version_flag_exits_0(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0

    def test_version_flag_prints_version(self):
        result = runner.invoke(app, ["--version"])
        assert __version__ in result.output


class TestRunCommand:
    def test_run_missing_agent_image_fails(self):
        """--agent-image is required; omitting it must exit non-zero."""
        result = runner.invoke(app, ["run"])
        assert result.exit_code != 0

    def test_run_with_agent_image_exits_0(self):
        """Minimal invocation with required arg exits 0 (stub behaviour)."""
        result = runner.invoke(app, ["run", "--agent-image", "my-agent:latest"])
        assert result.exit_code == 0

    def test_run_dry_run_exits_0(self):
        result = runner.invoke(
            app, ["run", "--agent-image", "my-agent:latest", "--dry-run"]
        )
        assert result.exit_code == 0

    def test_run_prints_agent_image(self):
        result = runner.invoke(app, ["run", "--agent-image", "test-agent:v1"])
        assert "test-agent:v1" in result.output

    def test_run_prints_policy(self):
        result = runner.invoke(
            app, ["run", "--agent-image", "a:b", "--policy", "custom-policy.yaml"]
        )
        assert "custom-policy.yaml" in result.output

    def test_run_prints_suite(self):
        result = runner.invoke(
            app, ["run", "--agent-image", "a:b", "--suite", "xpia"]
        )
        assert "xpia" in result.output

    def test_run_stub_notice_in_output(self):
        """Stub output must inform the user that D2 is needed."""
        result = runner.invoke(app, ["run", "--agent-image", "a:b"])
        assert "stub" in result.output.lower() or "D2" in result.output
