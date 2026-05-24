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
- `gauntlet run --agent-image ... --no-sandbox` selects DirectDockerRunner + RampartAssurance.
- `gauntlet run --agent-image ... --no-sandbox --use-fakes` exits non-zero (mutually exclusive).

No RAMPART or OpenShell required — all execution tests use --use-fakes, --dry-run, or mocks.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

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


class TestNoSandboxFlag:
    """Tests for the --no-sandbox flag (DirectDockerRunner + RampartAssurance, no fakes)."""

    def _make_passing_seam_result(self, agent_image: str = "my-agent:latest"):
        """Return a SeamResult that reports overall pass."""
        from gauntlet.seam import SeamResult
        from gauntlet.assurance import AssuranceResult
        from gauntlet.sandbox import SandboxContext, SandboxPolicy
        assurance_result = AssuranceResult(
            suite="default",
            findings=[],
            passed=1,
            failed=0,
            errors=0,
        )
        ctx = SandboxContext(
            sandbox_id="fake-container-id",
            agent_endpoint="http://localhost:8080",
            policy=SandboxPolicy(),
            isolated=False,
        )
        result = SeamResult(
            agent_image=agent_image,
            suite="default",
            dry_run=False,
            overall_passed=True,
            sandbox_context=ctx,
            assurance_result=assurance_result,
        )
        return result

    def test_no_sandbox_flag_selects_direct_docker_runner(self):
        """--no-sandbox must instantiate DirectDockerRunner as the sandbox adapter."""
        passing_result = self._make_passing_seam_result()

        with (
            patch("gauntlet.cli.DirectDockerRunner") as mock_ddr_cls,
            patch("gauntlet.cli.RampartAssurance"),
            patch("gauntlet.cli.run_seam", return_value=passing_result),
        ):
            mock_ddr_cls.return_value = MagicMock()
            result = runner.invoke(
                app, ["run", "--agent-image", "my-agent:latest", "--no-sandbox"]
            )

        assert result.exit_code == 0, result.output
        mock_ddr_cls.assert_called_once()

    def test_no_sandbox_uses_real_rampart_assurance(self):
        """--no-sandbox must instantiate RampartAssurance (not FakeAssurance)."""
        passing_result = self._make_passing_seam_result()

        with (
            patch("gauntlet.cli.DirectDockerRunner") as mock_ddr_cls,
            patch("gauntlet.cli.RampartAssurance") as mock_rampart_cls,
            patch("gauntlet.cli.run_seam", return_value=passing_result),
        ):
            mock_ddr_cls.return_value = MagicMock()
            mock_rampart_cls.return_value = MagicMock()
            result = runner.invoke(
                app, ["run", "--agent-image", "my-agent:latest", "--no-sandbox"]
            )

        assert result.exit_code == 0, result.output
        mock_rampart_cls.assert_called_once()

    def test_no_sandbox_and_use_fakes_mutually_exclusive(self):
        """--no-sandbox and --use-fakes together must exit non-zero with a clear error."""
        result = runner.invoke(
            app,
            ["run", "--agent-image", "my-agent:latest", "--no-sandbox", "--use-fakes"],
        )
        assert result.exit_code != 0
        combined = (result.output + (result.stderr if hasattr(result, "stderr") and result.stderr else "")).lower()
        assert "mutually exclusive" in combined or "cannot" in combined or "incompatible" in combined

    def test_no_sandbox_without_other_flags_works(self):
        """--no-sandbox alone must exit 0 when run_seam returns a passing SeamResult."""
        passing_result = self._make_passing_seam_result()

        with (
            patch("gauntlet.cli.DirectDockerRunner") as mock_ddr_cls,
            patch("gauntlet.cli.RampartAssurance") as mock_rampart_cls,
            patch("gauntlet.cli.run_seam", return_value=passing_result),
        ):
            mock_ddr_cls.return_value = MagicMock()
            mock_rampart_cls.return_value = MagicMock()
            result = runner.invoke(
                app, ["run", "--agent-image", "my-agent:latest", "--no-sandbox"]
            )

        assert result.exit_code == 0, result.output
