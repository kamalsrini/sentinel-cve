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
    SYSTEM_PROMPT,
    USER_PROMPT_TEMPLATE,
)

logger = logging.getLogger(__name__)

# Section headers we expect in Claude's response
SECTION_HEADERS = [
    ("what_it_is", "🔍 What it is"),
    ("how_to_exploit", "💥 How to exploit"),
    ("who_should_panic", "🚨 Who should panic"),
    ("how_to_patch", "🛡️ How to patch safely"),
    ("what_to_test", "✅ What to test"),
]


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
) -> dict[str, Any]:
    """Send CVE data to Claude and get the analysis.

    Args:
        cve_context: Formatted text with all fetched CVE data.
        brief: If True, return a single-paragraph summary instead of 5 sections.

    Returns:
        Dict with 'raw' (full response text) and 'sections' (parsed dict).
    """
    client = _get_client()
    model = get_model()

    if brief:
        system = BRIEF_SYSTEM_PROMPT
        user_msg = BRIEF_USER_PROMPT_TEMPLATE.format(cve_context=cve_context)
    else:
        system = SYSTEM_PROMPT
        user_msg = USER_PROMPT_TEMPLATE.format(cve_context=cve_context)

    logger.info("Calling Claude (%s) for analysis...", model)

    message = client.messages.create(
        model=model,
        max_tokens=4096,
        system=system,
        messages=[{"role": "user", "content": user_msg}],
    )

    response_text = message.content[0].text

    if brief:
        return {"raw": response_text, "sections": {"brief": response_text}}

    sections = _parse_sections(response_text)
    return {"raw": response_text, "sections": sections}


def _parse_sections(text: str) -> dict[str, str]:
    """Parse Claude's response into the 5 named sections."""
    sections: dict[str, str] = {}

    # Build a regex that splits on our known headers
    header_patterns = []
    for key, header in SECTION_HEADERS:
        # Escape the emoji and text for regex
        escaped = re.escape(header)
        header_patterns.append(f"(?P<{key}>##\\s*{escaped})")

    # Find all section boundaries
    pattern = "|".join(header_patterns)
    matches = list(re.finditer(pattern, text))

    for i, match in enumerate(matches):
        # Determine which section this is
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
