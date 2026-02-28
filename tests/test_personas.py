"""Tests for persona-based output formatting."""

from click.testing import CliRunner

from sentinel.cli import cli
from sentinel.prompts import (
    DEFAULT_PERSONA,
    VALID_PERSONAS,
    PERSONA_PROMPTS,
    get_persona_prompts,
    SYSTEM_PROMPT,
    EXEC_SYSTEM_PROMPT,
    ENGINEER_SYSTEM_PROMPT,
    DEVOPS_SYSTEM_PROMPT,
)
from sentinel.synthesizer import (
    PERSONA_SECTIONS,
    SECTION_HEADERS,
    ENGINEER_SECTION_HEADERS,
    DEVOPS_SECTION_HEADERS,
    _parse_sections,
)
from sentinel.renderer import (
    PERSONA_SECTION_STYLES,
    SECTION_STYLES,
    ENGINEER_SECTION_STYLES,
    DEVOPS_SECTION_STYLES,
)
from sentinel.formatters import (
    PERSONA_SECTION_MAPS,
    format_slack_blocks,
    format_teams_card,
    format_telegram_md,
    format_plain,
)


# ── Prompt tests ───────────────────────────────────────────────────────────

def test_valid_personas():
    assert VALID_PERSONAS == ("security", "exec", "engineer", "devops")


def test_default_persona():
    assert DEFAULT_PERSONA == "security"


def test_get_persona_prompts_security():
    p = get_persona_prompts("security")
    assert p["system"] == SYSTEM_PROMPT
    assert "{cve_context}" in p["user_template"]


def test_get_persona_prompts_exec():
    p = get_persona_prompts("exec")
    assert p["system"] == EXEC_SYSTEM_PROMPT
    assert "executive" in p["user_template"].lower()


def test_get_persona_prompts_engineer():
    p = get_persona_prompts("engineer")
    assert p["system"] == ENGINEER_SYSTEM_PROMPT
    assert "{cve_context}" in p["user_template"]


def test_get_persona_prompts_devops():
    p = get_persona_prompts("devops")
    assert p["system"] == DEVOPS_SYSTEM_PROMPT
    assert "{cve_context}" in p["user_template"]


def test_get_persona_prompts_invalid():
    import pytest
    with pytest.raises(ValueError, match="Unknown persona"):
        get_persona_prompts("invalid")


def test_all_personas_have_prompts():
    for persona in VALID_PERSONAS:
        p = get_persona_prompts(persona)
        assert "system" in p
        assert "user_template" in p
        assert len(p["system"]) > 50  # non-trivial prompt


# ── Section parsing tests ─────────────────────────────────────────────────

def test_parse_security_sections():
    text = """## 🔍 What it is
A buffer overflow.

## 💥 How to exploit
Send crafted input.

## 🚨 Who should panic
Everyone using v1.0.

## 🛡️ How to patch safely
Upgrade to v2.0.

## ✅ What to test
Run tests."""
    sections = _parse_sections(text, SECTION_HEADERS)
    assert "what_it_is" in sections
    assert "how_to_exploit" in sections
    assert "how_to_patch" in sections
    assert len(sections) == 5


def test_parse_engineer_sections():
    text = """## 📦 Affected Libraries & Versions
libfoo 1.0-1.5.

## 🔧 Code-Level Remediation
pip install libfoo>=1.6

## 🔍 What to Grep For
rg "import libfoo"

## 🧪 How to Test the Fix
pytest test_libfoo.py

## ⚠️ Breaking Changes
None."""
    sections = _parse_sections(text, ENGINEER_SECTION_HEADERS)
    assert "affected_libraries" in sections
    assert "remediation" in sections
    assert "breaking_changes" in sections
    assert len(sections) == 5


def test_parse_devops_sections():
    text = """## 🏗️ Affected Infrastructure
All containers with python:3.11 base.

## 🚀 Deployment Impact
Rolling restart needed.

## 🔄 Rollback Plan
kubectl rollout undo.

## 📊 Monitoring & Detection
Check /var/log/syslog.

## 🚨 Incident Response Steps
1. Contain 2. Assess 3. Patch."""
    sections = _parse_sections(text, DEVOPS_SECTION_HEADERS)
    assert "affected_infra" in sections
    assert "deployment_impact" in sections
    assert "incident_response" in sections
    assert len(sections) == 5


def test_parse_fallback_to_raw():
    text = "Just some text without headers."
    sections = _parse_sections(text, SECTION_HEADERS)
    assert "raw" in sections


# ── Persona sections registry ─────────────────────────────────────────────

def test_persona_sections_registry():
    assert "security" in PERSONA_SECTIONS
    assert "engineer" in PERSONA_SECTIONS
    assert "devops" in PERSONA_SECTIONS
    # exec has no structured sections
    assert "exec" not in PERSONA_SECTIONS


# ── Renderer persona styles ───────────────────────────────────────────────

def test_renderer_persona_styles():
    assert "security" in PERSONA_SECTION_STYLES
    assert "engineer" in PERSONA_SECTION_STYLES
    assert "devops" in PERSONA_SECTION_STYLES


# ── Formatter persona support ─────────────────────────────────────────────

def test_slack_exec_persona():
    result = {
        "cve_id": "CVE-2024-1234",
        "analysis": {
            "sections": {"exec": "🔴 CRITICAL — test"},
            "persona": "exec",
        },
        "sources": {"nvd": {}},
    }
    blocks = format_slack_blocks(result)
    assert any("Executive" in b.get("text", {}).get("text", "") for b in blocks if b.get("type") == "header")


def test_telegram_exec_persona():
    result = {
        "cve_id": "CVE-2024-1234",
        "analysis": {
            "sections": {"exec": "🔴 CRITICAL — test vuln"},
            "persona": "exec",
        },
        "sources": {"nvd": {}},
    }
    text = format_telegram_md(result)
    assert "CRITICAL" in text


def test_plain_exec_persona():
    result = {
        "cve_id": "CVE-2024-1234",
        "analysis": {
            "sections": {"exec": "🔴 CRITICAL — test vuln"},
            "persona": "exec",
        },
        "sources": {"nvd": {}},
    }
    text = format_plain(result)
    assert "CRITICAL" in text


def test_plain_engineer_persona():
    result = {
        "cve_id": "CVE-2024-1234",
        "analysis": {
            "sections": {
                "affected_libraries": "libfoo 1.0",
                "remediation": "pip install libfoo>=2.0",
                "grep_patterns": "rg import libfoo",
                "test_fix": "pytest",
                "breaking_changes": "None",
            },
            "persona": "engineer",
        },
        "sources": {"nvd": {}},
    }
    text = format_plain(result)
    assert "CODE-LEVEL REMEDIATION" in text
    assert "AFFECTED LIBRARIES" in text


def test_plain_devops_persona():
    result = {
        "cve_id": "CVE-2024-1234",
        "analysis": {
            "sections": {
                "affected_infra": "All containers",
                "deployment_impact": "Rolling restart",
                "rollback_plan": "kubectl rollout undo",
                "monitoring": "Check logs",
                "incident_response": "Contain and patch",
            },
            "persona": "devops",
        },
        "sources": {"nvd": {}},
    }
    text = format_plain(result)
    assert "AFFECTED INFRASTRUCTURE" in text
    assert "ROLLBACK PLAN" in text


# ── CLI --format flag tests ───────────────────────────────────────────────

def test_cli_cve_format_option_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["cve", "--help"])
    assert result.exit_code == 0
    assert "--format" in result.output
    assert "-f" in result.output
    assert "exec" in result.output
    assert "engineer" in result.output
    assert "devops" in result.output
    assert "security" in result.output


def test_cli_scan_format_option_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--format" in result.output
    assert "-f" in result.output


def test_cli_cve_invalid_format():
    runner = CliRunner()
    result = runner.invoke(cli, ["cve", "CVE-2024-3094", "--format", "invalid"])
    assert result.exit_code != 0
    assert "Invalid value" in result.output or "invalid" in result.output.lower()
