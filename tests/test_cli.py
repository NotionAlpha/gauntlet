"""
CLI smoke tests for gauntlet.

Verifies:
- `gauntlet --help` exits 0 and prints expected content.
- `gauntlet run --help` exits 0 and prints expected content.
- `gauntlet --version` exits 0 and prints version string.
- `gauntlet run` requires --agent-image (missing argument exits non-zero).
- `gauntlet run --agent-image ... --dry-run` exits 0 and prints the plan.
- `gauntlet run --agent-image ... --use-fakes` exits 0 and prints a real report.
- `gauntlet run --agent-image ... --use-fakes --output json` produces valid JSON.

No RAMPART or OpenShell required — all execution tests use --use-fakes or --dry-run.
"""

from __future__ import annotations

import json

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

    def test_run_help_mentions_dry_run(self):
        """Help text must document the --dry-run option."""
        result = runner.invoke(app, ["run", "--help"])
        assert "--dry-run" in result.output

    def test_run_help_mentions_use_fakes(self):
        """Help text must document the --use-fakes option for offline development."""
        result = runner.invoke(app, ["run", "--help"])
        assert "--use-fakes" in result.output

    def test_run_help_mentions_output_format(self):
        result = runner.invoke(app, ["run", "--help"])
        assert "--output" in result.output or "-o" in result.output

    def test_run_help_mentions_untrusted(self):
        """Help text must note that the agent image is treated as UNTRUSTED."""
        result = runner.invoke(app, ["run", "--help"])
        assert "UNTRUSTED" in result.output or "untrusted" in result.output.lower()


class TestVersionFlag:
    def test_version_flag_exits_0(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0

    def test_version_flag_prints_version(self):
        result = runner.invoke(app, ["--version"])
        assert __version__ in result.output


class TestRunCommandDryRun:
    """Tests using --dry-run (no RAMPART/OpenShell required)."""

    def test_run_missing_agent_image_fails(self):
        """--agent-image is required; omitting it must exit non-zero."""
        result = runner.invoke(app, ["run"])
        assert result.exit_code != 0

    def test_run_dry_run_exits_0(self):
        result = runner.invoke(
            app, ["run", "--agent-image", "my-agent:latest", "--dry-run"]
        )
        assert result.exit_code == 0

    def test_dry_run_output_mentions_dry_run(self):
        result = runner.invoke(
            app, ["run", "--agent-image", "my-agent:latest", "--dry-run"]
        )
        assert "dry" in result.output.lower() or "plan" in result.output.lower()

    def test_dry_run_output_mentions_agent_image(self):
        result = runner.invoke(
            app, ["run", "--agent-image", "test-agent:v1", "--dry-run"]
        )
        assert "test-agent:v1" in result.output

    def test_dry_run_output_mentions_suite(self):
        result = runner.invoke(
            app, ["run", "--agent-image", "a:b", "--suite", "xpia", "--dry-run"]
        )
        assert "xpia" in result.output

    def test_dry_run_json_output_is_valid(self):
        result = runner.invoke(
            app,
            ["run", "--agent-image", "a:b", "--dry-run", "--output", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["dry_run"] is True
        assert data["agent_image"] == "a:b"


class TestRunCommandWithFakes:
    """Tests using --use-fakes (full seam execution, no real deps required)."""

    def test_run_with_fakes_exits_0(self):
        result = runner.invoke(
            app, ["run", "--agent-image", "my-agent:latest", "--use-fakes"]
        )
        assert result.exit_code == 0, result.output

    def test_run_with_fakes_prints_agent_image(self):
        result = runner.invoke(
            app, ["run", "--agent-image", "test-agent:v1", "--use-fakes"]
        )
        assert "test-agent:v1" in result.output

    def test_run_with_fakes_prints_pass_verdict(self):
        """FakeAssurance defaults to pass — report must say PASS."""
        result = runner.invoke(
            app, ["run", "--agent-image", "my-agent:latest", "--use-fakes"]
        )
        assert "PASS" in result.output

    def test_run_with_fakes_mentions_isolation(self):
        result = runner.invoke(
            app, ["run", "--agent-image", "my-agent:latest", "--use-fakes"]
        )
        output_lower = result.output.lower()
        assert "isolat" in output_lower or "sandbox" in output_lower

    def test_run_with_fakes_prints_suite(self):
        result = runner.invoke(
            app, ["run", "--agent-image", "a:b", "--suite", "xpia", "--use-fakes"]
        )
        assert "xpia" in result.output

    def test_run_with_fakes_json_output_is_valid(self):
        result = runner.invoke(
            app,
            ["run", "--agent-image", "a:b", "--use-fakes", "--output", "json"],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["agent_image"] == "a:b"
        assert "overall_passed" in data
        assert "findings" in data

    def test_run_with_fakes_json_has_sandbox_isolated(self):
        result = runner.invoke(
            app,
            ["run", "--agent-image", "a:b", "--use-fakes", "--output", "json"],
        )
        data = json.loads(result.output)
        assert data["sandbox_isolated"] is True

    def test_invalid_output_format_exits_nonzero(self):
        result = runner.invoke(
            app,
            ["run", "--agent-image", "a:b", "--use-fakes", "--output", "yaml"],
        )
        assert result.exit_code != 0
