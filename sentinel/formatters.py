"""Channel-specific output formatters for Sentinel results.

Produces Slack Block Kit, Teams Adaptive Cards, Telegram MarkdownV2, and plain text.
"""

from __future__ import annotations

import re
from typing import Any


# ── helpers ────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "#FF0000",
    "HIGH": "#FF4500",
    "MEDIUM": "#FFA500",
    "LOW": "#32CD32",
    "UNKNOWN": "#808080",
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "UNKNOWN": "⚪",
}

STATUS_EMOJI = {
    "AFFECTED": "🚨",
    "NOT_AFFECTED": "✅",
    "UNKNOWN": "⚠️",
}


def _extract_severity(sections: dict[str, str]) -> str:
    """Try to pull severity from analysis sections."""
    raw = sections.get("raw", "") + sections.get("what_it_is", "")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev.lower() in raw.lower():
            return sev
    return "UNKNOWN"


def _truncate(text: str, limit: int = 3000) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


# ── Slack Block Kit ────────────────────────────────────────────────────────

def format_slack_blocks(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Format a CVE analysis result as Slack Block Kit blocks.

    Args:
        result: Dict with keys like cve_id, analysis (with sections), sources.

    Returns:
        List of Slack block dicts.
    """
    cve_id = result.get("cve_id", "Unknown CVE")
    analysis = result.get("analysis", {})
    sections = analysis.get("sections", {})
    sources = result.get("sources", {})
    severity = _extract_severity(sections)
    source_names = ", ".join(s.upper() for s in sources) if sources else "N/A"

    blocks: list[dict[str, Any]] = []

    # Header
    blocks.append({
        "type": "header",
        "text": {"type": "plain_text", "text": f"🛡️ Sentinel — {cve_id}", "emoji": True},
    })
    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": f"Severity: *{severity}* {SEVERITY_EMOJI.get(severity, '')}  |  Sources: {source_names}"}
        ],
    })
    blocks.append({"type": "divider"})

    # Brief mode
    if "brief" in sections:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": _truncate(sections["brief"])},
        })
        return blocks

    # 5 sections
    section_map = [
        ("what_it_is", "🔍 What it is"),
        ("how_to_exploit", "💥 How to exploit"),
        ("who_should_panic", "🚨 Who should panic"),
        ("how_to_patch", "🛡️ How to patch safely"),
        ("what_to_test", "✅ What to test"),
    ]

    for key, title in section_map:
        content = sections.get(key)
        if not content:
            continue
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{title}*\n{_truncate(content, 2900)}"},
        })
        blocks.append({"type": "divider"})

    # Raw fallback
    if "raw" in sections and len(sections) == 1:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": _truncate(sections["raw"])},
        })

    return blocks


def format_slack_scan_blocks(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Format scan results as Slack Block Kit blocks."""
    scan = result.get("scan", {})
    status = scan.get("status", "UNKNOWN")
    cve_id = result.get("cve_id")
    path = result.get("path", "repo")
    emoji = STATUS_EMOJI.get(status, "❓")

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🛡️ Sentinel Scan — {path}", "emoji": True},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"{emoji} *{status}*" + (f" for `{cve_id}`" if cve_id else "")},
        },
        {"type": "divider"},
    ]

    details = scan.get("details", [])
    for d in details[:10]:
        dep = d.get("dependency", "?")
        ver = d.get("your_version", "?")
        fix = d.get("fix_version", "unknown")
        st = d.get("status", "UNKNOWN")
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"• `{dep}` @ `{ver}` → fix: `{fix}` — *{st}*",
            },
        })

    vulns = scan.get("vulnerabilities", [])
    for v in vulns[:10]:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"• `{v.get('cve_id','')}` {SEVERITY_EMOJI.get(v.get('severity',''),'')}"
                        f" `{v.get('package','')}` @ `{v.get('your_version','')}` → fix: `{v.get('fix_version','')}`",
            },
        })

    return blocks


# ── Teams Adaptive Card ────────────────────────────────────────────────────

def format_teams_card(result: dict[str, Any]) -> dict[str, Any]:
    """Format a CVE analysis result as a Teams Adaptive Card."""
    cve_id = result.get("cve_id", "Unknown CVE")
    analysis = result.get("analysis", {})
    sections = analysis.get("sections", {})
    sources = result.get("sources", {})
    severity = _extract_severity(sections)
    source_names = ", ".join(s.upper() for s in sources) if sources else "N/A"

    body: list[dict[str, Any]] = [
        {
            "type": "TextBlock",
            "text": f"🛡️ Sentinel — {cve_id}",
            "size": "Large",
            "weight": "Bolder",
            "wrap": True,
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": "auto",
                    "items": [{"type": "TextBlock", "text": f"Severity: **{severity}**", "wrap": True, "color": "Attention" if severity in ("CRITICAL", "HIGH") else "Default"}],
                },
                {
                    "type": "Column",
                    "width": "auto",
                    "items": [{"type": "TextBlock", "text": f"Sources: {source_names}", "wrap": True, "isSubtle": True}],
                },
            ],
        },
    ]

    if "brief" in sections:
        body.append({"type": "TextBlock", "text": _truncate(sections["brief"], 2000), "wrap": True})
    else:
        section_map = [
            ("what_it_is", "🔍 What it is"),
            ("how_to_exploit", "💥 How to exploit"),
            ("who_should_panic", "🚨 Who should panic"),
            ("how_to_patch", "🛡️ How to patch safely"),
            ("what_to_test", "✅ What to test"),
        ]
        for key, title in section_map:
            content = sections.get(key)
            if not content:
                continue
            body.append({"type": "TextBlock", "text": f"**{title}**", "wrap": True, "size": "Medium", "weight": "Bolder"})
            body.append({"type": "TextBlock", "text": _truncate(content, 2000), "wrap": True})

        if "raw" in sections and len(sections) == 1:
            body.append({"type": "TextBlock", "text": _truncate(sections["raw"], 2000), "wrap": True})

    card = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                    "actions": [
                        {
                            "type": "Action.OpenUrl",
                            "title": "View on NVD",
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        }
                    ],
                },
            }
        ],
    }
    return card


def format_teams_scan_card(result: dict[str, Any]) -> dict[str, Any]:
    """Format scan results as Teams Adaptive Card."""
    scan = result.get("scan", {})
    status = scan.get("status", "UNKNOWN")
    cve_id = result.get("cve_id")
    path = result.get("path", "repo")
    emoji = STATUS_EMOJI.get(status, "❓")

    body: list[dict[str, Any]] = [
        {"type": "TextBlock", "text": f"🛡️ Sentinel Scan — {path}", "size": "Large", "weight": "Bolder", "wrap": True},
        {"type": "TextBlock", "text": f"{emoji} **{status}**" + (f" for `{cve_id}`" if cve_id else ""), "wrap": True},
    ]

    facts = []
    for d in scan.get("details", [])[:10]:
        facts.append({"title": d.get("dependency", "?"), "value": f"{d.get('your_version','?')} → fix: {d.get('fix_version','?')} ({d.get('status','')})"})
    for v in scan.get("vulnerabilities", [])[:10]:
        facts.append({"title": v.get("cve_id", ""), "value": f"{v.get('package','')} @ {v.get('your_version','')} [{v.get('severity','')}]"})

    if facts:
        body.append({"type": "FactSet", "facts": facts})

    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": body,
            },
        }],
    }


# ── Telegram MarkdownV2 ───────────────────────────────────────────────────

def _escape_md2(text: str) -> str:
    """Escape Telegram MarkdownV2 special characters."""
    special = r"_*[]()~`>#+-=|{}.!"
    out = []
    for ch in text:
        if ch in special:
            out.append("\\")
        out.append(ch)
    return "".join(out)


def format_telegram_md(result: dict[str, Any]) -> str:
    """Format CVE analysis result as Telegram MarkdownV2."""
    cve_id = result.get("cve_id", "Unknown CVE")
    analysis = result.get("analysis", {})
    sections = analysis.get("sections", {})
    sources = result.get("sources", {})
    severity = _extract_severity(sections)
    source_names = ", ".join(s.upper() for s in sources) if sources else "N/A"

    lines = [
        f"*🛡️ Sentinel — {_escape_md2(cve_id)}*",
        f"Severity: *{_escape_md2(severity)}* {SEVERITY_EMOJI.get(severity, '')}  \\|  Sources: {_escape_md2(source_names)}",
        "",
    ]

    if "brief" in sections:
        lines.append(_escape_md2(_truncate(sections["brief"], 3500)))
    else:
        section_map = [
            ("what_it_is", "🔍 What it is"),
            ("how_to_exploit", "💥 How to exploit"),
            ("who_should_panic", "🚨 Who should panic"),
            ("how_to_patch", "🛡️ How to patch safely"),
            ("what_to_test", "✅ What to test"),
        ]
        for key, title in section_map:
            content = sections.get(key)
            if not content:
                continue
            lines.append(f"*{_escape_md2(title)}*")
            lines.append(_escape_md2(_truncate(content, 800)))
            lines.append("")

        if "raw" in sections and len(sections) == 1:
            lines.append(_escape_md2(_truncate(sections["raw"], 3500)))

    return "\n".join(lines)


def format_telegram_scan_md(result: dict[str, Any]) -> str:
    """Format scan results as Telegram MarkdownV2."""
    scan = result.get("scan", {})
    status = scan.get("status", "UNKNOWN")
    cve_id = result.get("cve_id")
    path = result.get("path", "repo")
    emoji = STATUS_EMOJI.get(status, "❓")

    lines = [
        f"*🛡️ Sentinel Scan — {_escape_md2(path)}*",
        f"{emoji} *{_escape_md2(status)}*" + (f" for `{_escape_md2(cve_id)}`" if cve_id else ""),
        "",
    ]

    for d in scan.get("details", [])[:10]:
        dep = _escape_md2(d.get("dependency", "?"))
        ver = _escape_md2(d.get("your_version", "?"))
        fix = _escape_md2(d.get("fix_version", "?"))
        st = _escape_md2(d.get("status", ""))
        lines.append(f"• `{dep}` @ `{ver}` → fix: `{fix}` — *{st}*")

    for v in scan.get("vulnerabilities", [])[:10]:
        vid = _escape_md2(v.get("cve_id", ""))
        pkg = _escape_md2(v.get("package", ""))
        ver = _escape_md2(v.get("your_version", ""))
        sev = v.get("severity", "")
        lines.append(f"• `{vid}` {SEVERITY_EMOJI.get(sev, '')} `{pkg}` @ `{ver}`")

    return "\n".join(lines)


# ── Plain text ─────────────────────────────────────────────────────────────

def format_plain(result: dict[str, Any]) -> str:
    """Format CVE analysis result as plain text."""
    cve_id = result.get("cve_id", "Unknown CVE")
    analysis = result.get("analysis", {})
    sections = analysis.get("sections", {})
    sources = result.get("sources", {})
    source_names = ", ".join(s.upper() for s in sources) if sources else "N/A"

    lines = [
        f"SENTINEL — {cve_id}",
        f"Sources: {source_names}",
        "=" * 50,
        "",
    ]

    if "brief" in sections:
        lines.append(sections["brief"])
    else:
        section_map = [
            ("what_it_is", "WHAT IT IS"),
            ("how_to_exploit", "HOW TO EXPLOIT"),
            ("who_should_panic", "WHO SHOULD PANIC"),
            ("how_to_patch", "HOW TO PATCH SAFELY"),
            ("what_to_test", "WHAT TO TEST"),
        ]
        for key, title in section_map:
            content = sections.get(key)
            if not content:
                continue
            lines.append(title)
            lines.append("-" * len(title))
            lines.append(content)
            lines.append("")

        if "raw" in sections and len(sections) == 1:
            lines.append(sections["raw"])

    return "\n".join(lines)


def format_plain_scan(result: dict[str, Any]) -> str:
    """Format scan results as plain text."""
    scan = result.get("scan", {})
    status = scan.get("status", "UNKNOWN")
    cve_id = result.get("cve_id")
    path = result.get("path", "repo")

    lines = [
        f"SENTINEL SCAN — {path}",
        f"Status: {status}" + (f" for {cve_id}" if cve_id else ""),
        "=" * 50,
        "",
    ]

    for d in scan.get("details", []):
        lines.append(f"  {d.get('dependency','?')} @ {d.get('your_version','?')} → fix: {d.get('fix_version','?')} [{d.get('status','')}]")

    for v in scan.get("vulnerabilities", []):
        lines.append(f"  {v.get('cve_id','')} [{v.get('severity','')}] {v.get('package','')} @ {v.get('your_version','')} → fix: {v.get('fix_version','')}")

    return "\n".join(lines)
