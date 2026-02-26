"""Basic tests for Sentinel CLI."""

from click.testing import CliRunner

from sentinel.cli import cli


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Sentinel" in result.output


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_cve_invalid_id():
    runner = CliRunner()
    result = runner.invoke(cli, ["cve", "not-a-cve"])
    assert result.exit_code != 0
    assert "not a valid CVE ID" in result.output


def test_cve_valid_id_format():
    """Test that a valid CVE ID format is accepted (will fail on network/API)."""
    runner = CliRunner()
    # This will fail because no API key is set, but it should get past validation
    result = runner.invoke(cli, ["cve", "CVE-2024-3094", "--no-cache"])
    # Should either succeed or fail with an API/network error, not a validation error
    assert "not a valid CVE ID" not in (result.output or "")


def test_config_set_and_get():
    runner = CliRunner()
    result = runner.invoke(cli, ["config", "set", "model", "claude-test-model"])
    assert result.exit_code == 0
    assert "Set model" in result.output

    result = runner.invoke(cli, ["config", "get", "model"])
    assert result.exit_code == 0
    assert "claude-test-model" in result.output


def test_cache_clear():
    runner = CliRunner()
    result = runner.invoke(cli, ["cache", "clear"])
    assert result.exit_code == 0
    assert "Cleared" in result.output


def test_config_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["config", "--help"])
    assert result.exit_code == 0


def test_cache_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["cache", "--help"])
    assert result.exit_code == 0
