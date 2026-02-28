"""Claude API integration for CVE analysis.

Builds prompts from fetched CVE data, calls the Anthropic API, and parses responses.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import anthropic

from sentinel.config import get_api_key, get_model
from sentinel.prompts import (
    BRIEF_SYSTEM_PROMPT,
    BRIEF_USER_PROMPT_TEMPLATE,
    DEFAULT_PERSONA,
    SYSTEM_PROMPT,
    USER_PROMPT_TEMPLATE,
    get_persona_prompts,
)

logger = logging.getLogger(__name__)

# Section headers for the security (default) persona
SECTION_HEADERS = [
    ("what_it_is", "🔍 What it is"),
    ("how_to_exploit", "💥 How to exploit"),
    ("who_should_panic", "🚨 Who should panic"),
    ("how_to_patch", "🛡️ How to patch safely"),
    ("what_to_test", "✅ What to test"),
]

# Section headers for the engineer persona
ENGINEER_SECTION_HEADERS = [
    ("affected_libraries", "📦 Affected Libraries & Versions"),
    ("remediation", "🔧 Code-Level Remediation"),
    ("grep_patterns", "🔍 What to Grep For"),
    ("test_fix", "🧪 How to Test the Fix"),
    ("breaking_changes", "⚠️ Breaking Changes"),
]

# Section headers for the devops persona
DEVOPS_SECTION_HEADERS = [
    ("affected_infra", "🏗️ Affected Infrastructure"),
    ("deployment_impact", "🚀 Deployment Impact"),
    ("rollback_plan", "🔄 Rollback Plan"),
    ("monitoring", "📊 Monitoring & Detection"),
    ("incident_response", "🚨 Incident Response Steps"),
]

# Map persona → section headers
PERSONA_SECTIONS: dict[str, list[tuple[str, str]]] = {
    "security": SECTION_HEADERS,
    "engineer": ENGINEER_SECTION_HEADERS,
    "devops": DEVOPS_SECTION_HEADERS,
    # exec has no sections — it's free-form short text
}


def _get_client() -> anthropic.Anthropic:
    """Create an Anthropic client."""
    api_key = get_api_key()
    if not api_key:
        raise ValueError(
            "Anthropic API key not configured. Run:\n"
            "  sentinel config set api-key <your-key>\n"
            "Or set the ANTHROPIC_API_KEY environment variable."
        )
    return anthropic.Anthropic(api_key=api_key)


async def analyze_cve(
    cve_context: str,
    brief: bool = False,
    persona: str = DEFAULT_PERSONA,
) -> dict[str, Any]:
    """Send CVE data to Claude and get the analysis.

    Args:
        cve_context: Formatted text with all fetched CVE data.
        brief: If True, return a single-paragraph summary instead of sections.
        persona: Output persona — 'security', 'exec', 'engineer', or 'devops'.

    Returns:
        Dict with 'raw' (full response text), 'sections' (parsed dict), and 'persona'.
    """
    client = _get_client()
    model = get_model()

    if brief:
        system = BRIEF_SYSTEM_PROMPT
        user_msg = BRIEF_USER_PROMPT_TEMPLATE.format(cve_context=cve_context)
    else:
        prompts = get_persona_prompts(persona)
        system = prompts["system"]
        user_msg = prompts["user_template"].format(cve_context=cve_context)

    logger.info("Calling Claude (%s) for %s analysis...", model, persona)

    message = client.messages.create(
        model=model,
        max_tokens=4096,
        system=system,
        messages=[{"role": "user", "content": user_msg}],
    )

    response_text = message.content[0].text

    if brief:
        return {"raw": response_text, "sections": {"brief": response_text}, "persona": persona}

    # Parse sections based on persona
    if persona == "exec":
        # Exec output is free-form short text, no section parsing needed
        return {"raw": response_text, "sections": {"exec": response_text}, "persona": persona}

    section_headers = PERSONA_SECTIONS.get(persona, SECTION_HEADERS)
    sections = _parse_sections(response_text, section_headers)
    return {"raw": response_text, "sections": sections, "persona": persona}


def _parse_sections(text: str, headers: list[tuple[str, str]] | None = None) -> dict[str, str]:
    """Parse Claude's response into named sections.

    Args:
        text: Raw response text from Claude.
        headers: List of (key, header_text) tuples to parse. Defaults to security headers.
    """
    if headers is None:
        headers = SECTION_HEADERS

    sections: dict[str, str] = {}

    # Build a regex that splits on our known headers
    header_patterns = []
    for key, header in headers:
        escaped = re.escape(header)
        header_patterns.append(f"(?P<{key}>##\\s*{escaped})")

    pattern = "|".join(header_patterns)
    matches = list(re.finditer(pattern, text))

    for i, match in enumerate(matches):
        key = match.lastgroup
        if key is None:
            continue
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        sections[key] = text[start:end].strip()

    # If parsing failed, return the whole text as a single section
    if not sections:
        sections["raw"] = text

    return sections
