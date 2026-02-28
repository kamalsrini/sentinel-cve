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

PERSONA_SECTION_MAPS: dict[str, list[tuple[str, str]]] = {
    "security": [
        ("what_it_is", "🔍 What it is"),
        ("how_to_exploit", "💥 How to exploit"),
        ("who_should_panic", "🚨 Who should panic"),
        ("how_to_patch", "🛡️ How to patch safely"),
        ("what_to_test", "✅ What to test"),
    ],
    "engineer": [
        ("affected_libraries", "📦 Affected Libraries & Versions"),
        ("remediation", "🔧 Code-Level Remediation"),
        ("grep_patterns", "🔍 What to Grep For"),
        ("test_fix", "🧪 How to Test the Fix"),
        ("breaking_changes", "⚠️ Breaking Changes"),
    ],
    "devops": [
        ("affected_infra", "🏗️ Affected Infrastructure"),
        ("deployment_impact", "🚀 Deployment Impact"),
        ("rollback_plan", "🔄 Rollback Plan"),
        ("monitoring", "📊 Monitoring & Detection"),
        ("incident_response", "🚨 Incident Response Steps"),
    ],
}


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
    persona = analysis.get("persona", "security")
    severity = _extract_severity(sections)
    source_names = ", ".join(s.upper() for s in sources) if sources else "N/A"

    blocks: list[dict[str, Any]] = []

    # Header
    persona_label = {"security": "", "exec": " (Executive)", "engineer": " (Engineer)", "devops": " (DevOps)"}.get(persona, "")
    blocks.append({
        "type": "header",
        "text": {"type": "plain_text", "text": f"🛡️ Sentinel — {cve_id}{persona_label}", "emoji": True},
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

    # Exec persona: compact output
    if persona == "exec" and "exec" in sections:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": _truncate(sections["exec"])},
        })
        return blocks

    # Section-based output (security, engineer, devops)
    section_map = PERSONA_SECTION_MAPS.get(persona, PERSONA_SECTION_MAPS["security"])

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

    persona = analysis.get("persona", "security")

    if "brief" in sections:
        body.append({"type": "TextBlock", "text": _truncate(sections["brief"], 2000), "wrap": True})
    elif persona == "exec" and "exec" in sections:
        body.append({"type": "TextBlock", "text": _truncate(sections["exec"], 2000), "wrap": True})
    else:
        section_map = PERSONA_SECTION_MAPS.get(persona, PERSONA_SECTION_MAPS["security"])
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

    persona = analysis.get("persona", "security")

    lines = [
        f"*🛡️ Sentinel — {_escape_md2(cve_id)}*",
        f"Severity: *{_escape_md2(severity)}* {SEVERITY_EMOJI.get(severity, '')}  \\|  Sources: {_escape_md2(source_names)}",
        "",
    ]

    if "brief" in sections:
        lines.append(_escape_md2(_truncate(sections["brief"], 3500)))
    elif persona == "exec" and "exec" in sections:
        lines.append(_escape_md2(_truncate(sections["exec"], 3500)))
    else:
        section_map = PERSONA_SECTION_MAPS.get(persona, PERSONA_SECTION_MAPS["security"])
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


# ── K8s scan formatters ────────────────────────────────────────────────────

EXEC_PATH_VERDICT_EMOJI = {
    "REACHABLE": "🔴",
    "NOT_REACHABLE": "✅",
    "IMPORTED_ONLY": "🟡",
    "INCONCLUSIVE": "🟠",
}


def format_slack_k8s_blocks(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Format K8s scan results as Slack blocks."""
    k8s = result.get("k8s_scan", {})
    ns = k8s.get("namespace") or "all namespaces"
    cve_id = k8s.get("cve_id")

    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"🛡️ K8s Scan — {ns}", "emoji": True}},
        {"type": "divider"},
    ]
    for sr in k8s.get("scan_results", [])[:10]:
        img = sr.get("image", "?")
        vulns = sr.get("vulnerabilities", [])
        text = f"*{img}*: {len(vulns)} vulnerabilities"
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text}})
    return blocks


def format_telegram_k8s_md(result: dict[str, Any]) -> str:
    """Format K8s scan results for Telegram."""
    k8s = result.get("k8s_scan", {})
    ns = k8s.get("namespace") or "all namespaces"
    lines = [f"*🛡️ K8s Scan — {_escape_md2(ns)}*", ""]
    for sr in k8s.get("scan_results", [])[:10]:
        img = _escape_md2(sr.get("image", "?"))
        vulns = sr.get("vulnerabilities", [])
        lines.append(f"• `{img}`: {len(vulns)} vulnerabilities")
    return "\n".join(lines)


def format_slack_exec_path_blocks(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Format execution path results as Slack blocks."""
    ep = result.get("execution_path", {})
    verdict = ep.get("verdict", "UNKNOWN")
    emoji = EXEC_PATH_VERDICT_EMOJI.get(verdict, "❓")
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": "🛡️ Execution Path Analysis", "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"{emoji} *{verdict}* for `{ep.get('cve_id', '')}`\nPackage: `{ep.get('target_package', '')}`"}},
    ]
    for chain in ep.get("call_chains", [])[:5]:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"```{chain}```"}})
    return blocks


def format_telegram_exec_path_md(result: dict[str, Any]) -> str:
    """Format execution path results for Telegram."""
    ep = result.get("execution_path", {})
    verdict = ep.get("verdict", "UNKNOWN")
    emoji = EXEC_PATH_VERDICT_EMOJI.get(verdict, "❓")
    lines = [
        f"*🛡️ Execution Path Analysis*",
        f"{emoji} *{_escape_md2(verdict)}* for `{_escape_md2(ep.get('cve_id', ''))}`",
        f"Package: `{_escape_md2(ep.get('target_package', ''))}`",
    ]
    for chain in ep.get("call_chains", [])[:5]:
        lines.append(f"`{_escape_md2(chain)}`")
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

    persona = analysis.get("persona", "security")

    if "brief" in sections:
        lines.append(sections["brief"])
    elif persona == "exec" and "exec" in sections:
        lines.append(sections["exec"])
    else:
        plain_section_maps: dict[str, list[tuple[str, str]]] = {
            "security": [
                ("what_it_is", "WHAT IT IS"),
                ("how_to_exploit", "HOW TO EXPLOIT"),
                ("who_should_panic", "WHO SHOULD PANIC"),
                ("how_to_patch", "HOW TO PATCH SAFELY"),
                ("what_to_test", "WHAT TO TEST"),
            ],
            "engineer": [
                ("affected_libraries", "AFFECTED LIBRARIES & VERSIONS"),
                ("remediation", "CODE-LEVEL REMEDIATION"),
                ("grep_patterns", "WHAT TO GREP FOR"),
                ("test_fix", "HOW TO TEST THE FIX"),
                ("breaking_changes", "BREAKING CHANGES"),
            ],
            "devops": [
                ("affected_infra", "AFFECTED INFRASTRUCTURE"),
                ("deployment_impact", "DEPLOYMENT IMPACT"),
                ("rollback_plan", "ROLLBACK PLAN"),
                ("monitoring", "MONITORING & DETECTION"),
                ("incident_response", "INCIDENT RESPONSE STEPS"),
            ],
        }
        section_map = plain_section_maps.get(persona, plain_section_maps["security"])
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
