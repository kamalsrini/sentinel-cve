"""Output formatting for Sentinel — terminal (rich), JSON, and markdown modes."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text


SECTION_STYLES: dict[str, tuple[str, str]] = {
    "what_it_is":       ("🔍 What it is",        "blue"),
    "how_to_exploit":   ("💥 How to exploit",     "red"),
    "who_should_panic": ("🚨 Who should panic",   "yellow"),
    "how_to_patch":     ("🛡️  How to patch safely", "green"),
    "what_to_test":     ("✅ What to test",        "cyan"),
}


def render_terminal(
    cve_id: str,
    analysis: dict[str, Any],
    sources: dict[str, Any],
    no_color: bool = False,
) -> None:
    """Render the 5-section report to the terminal using rich."""
    console = Console(no_color=no_color)
    sections = analysis.get("sections", {})

    # If brief mode
    if "brief" in sections:
        console.print()
        console.print(Panel(
            Markdown(sections["brief"]),
            title=f"🛡️  SENTINEL — {cve_id} (Brief)",
            border_style="bold cyan",
        ))
        console.print()
        return

    # If raw (parsing failed)
    if "raw" in sections and len(sections) == 1:
        console.print()
        console.print(Panel(
            Markdown(sections["raw"]),
            title=f"🛡️  SENTINEL — {cve_id}",
            border_style="bold cyan",
        ))
        console.print()
        return

    # Header
    console.print()
    source_names = ", ".join(s.upper() for s in sources.keys()) if sources else "N/A"
    console.print(Panel(
        Text(f"CVSS & source details below  │  Sources: {source_names}", style="dim"),
        title=f"🛡️  SENTINEL — {cve_id}",
        border_style="bold cyan",
    ))

    # Each section as a panel
    for key, (title, color) in SECTION_STYLES.items():
        content = sections.get(key, "No data available for this section.")
        console.print(Panel(
            Markdown(content),
            title=title,
            border_style=f"bold {color}",
            padding=(1, 2),
        ))

    console.print()


def render_json(
    cve_id: str,
    analysis: dict[str, Any],
    sources: dict[str, Any],
) -> str:
    """Render the analysis as a JSON string."""
    output = {
        "cve_id": cve_id,
        "sections": analysis.get("sections", {}),
        "sources": list(sources.keys()),
    }
    return json.dumps(output, indent=2, ensure_ascii=False)


def render_markdown(
    cve_id: str,
    analysis: dict[str, Any],
    sources: dict[str, Any],
) -> str:
    """Render the analysis as clean markdown."""
    sections = analysis.get("sections", {})

    # Brief mode
    if "brief" in sections:
        return f"# {cve_id} — Brief Summary\n\n{sections['brief']}\n"

    # Full raw response is already markdown from Claude
    raw = analysis.get("raw", "")
    if raw:
        header = f"# {cve_id} — Vulnerability Briefing\n\n"
        source_names = ", ".join(s.upper() for s in sources.keys())
        footer = f"\n\n---\n*Sources: {source_names}*\n"
        return header + raw + footer

    return f"# {cve_id}\n\nNo analysis available.\n"
