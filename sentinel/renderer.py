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

ENGINEER_SECTION_STYLES: dict[str, tuple[str, str]] = {
    "affected_libraries": ("📦 Affected Libraries & Versions", "blue"),
    "remediation":        ("🔧 Code-Level Remediation",        "green"),
    "grep_patterns":      ("🔍 What to Grep For",              "yellow"),
    "test_fix":           ("🧪 How to Test the Fix",           "cyan"),
    "breaking_changes":   ("⚠️  Breaking Changes",              "red"),
}

DEVOPS_SECTION_STYLES: dict[str, tuple[str, str]] = {
    "affected_infra":     ("🏗️  Affected Infrastructure",  "blue"),
    "deployment_impact":  ("🚀 Deployment Impact",         "yellow"),
    "rollback_plan":      ("🔄 Rollback Plan",             "green"),
    "monitoring":         ("📊 Monitoring & Detection",    "cyan"),
    "incident_response":  ("🚨 Incident Response Steps",   "red"),
}

PERSONA_SECTION_STYLES: dict[str, dict[str, tuple[str, str]]] = {
    "security": SECTION_STYLES,
    "engineer": ENGINEER_SECTION_STYLES,
    "devops": DEVOPS_SECTION_STYLES,
}


def render_terminal(
    cve_id: str,
    analysis: dict[str, Any],
    sources: dict[str, Any],
    no_color: bool = False,
    persona: str = "security",
) -> None:
    """Render the report to the terminal using rich.

    Args:
        cve_id: The CVE identifier.
        analysis: Analysis dict with 'raw', 'sections', and optionally 'persona'.
        sources: Dict of data sources used.
        no_color: Disable colored output.
        persona: Output persona ('security', 'exec', 'engineer', 'devops').
    """
    console = Console(no_color=no_color)
    sections = analysis.get("sections", {})
    # Use persona from analysis if available, fall back to parameter
    persona = analysis.get("persona", persona)

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

    # Exec persona: compact output, no panels
    if persona == "exec" and "exec" in sections:
        console.print()
        console.print(Panel(
            Markdown(sections["exec"]),
            title=f"🛡️  SENTINEL — {cve_id} (Executive Summary)",
            border_style="bold red",
            padding=(1, 2),
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

    # Determine which section styles to use based on persona
    section_styles = PERSONA_SECTION_STYLES.get(persona, SECTION_STYLES)

    # Header
    console.print()
    source_names = ", ".join(s.upper() for s in sources.keys()) if sources else "N/A"
    persona_label = {"security": "Security Analyst", "engineer": "Engineer", "devops": "DevOps/SRE"}.get(persona, persona.title())
    console.print(Panel(
        Text(f"Persona: {persona_label}  │  Sources: {source_names}", style="dim"),
        title=f"🛡️  SENTINEL — {cve_id}",
        border_style="bold cyan",
    ))

    # Each section as a panel
    for key, (title, color) in section_styles.items():
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


## Scan rendering ##

VERDICT_STYLES = {
    "AFFECTED": ("🚨 AFFECTED", "bold red"),
    "NOT_AFFECTED": ("✅ NOT AFFECTED", "bold green"),
    "UNKNOWN": ("⚠️  UNKNOWN", "bold yellow"),
    "POTENTIALLY_AFFECTED": ("⚠️  POTENTIALLY AFFECTED", "bold yellow"),
}


def render_scan_terminal(
    scan_result: Any,
    path_or_url: str,
    cve_id: str | None = None,
    no_color: bool = False,
) -> None:
    """Render scan results to terminal using rich."""
    from rich.table import Table

    console = Console(no_color=no_color)
    console.print()

    # Header
    title = f"🛡️  SENTINEL SCAN — {path_or_url}"
    subtitle = f"Checking: {cve_id}" if cve_id else "Full vulnerability scan"
    console.print(Panel(
        Text(subtitle, style="dim"),
        title=title,
        border_style="bold cyan",
    ))

    # Project info
    if scan_result.project_types:
        console.print(f"  Project type: {', '.join(scan_result.project_types)}")
    console.print(f"  Dependencies found: {scan_result.total_deps}")
    console.print()

    if cve_id:
        # Single CVE mode
        label, style = VERDICT_STYLES.get(scan_result.status, ("❓ UNKNOWN", "bold"))
        console.print(f"  [{style}]{label}[/{style}]")
        console.print()

        if scan_result.details:
            table = Table(show_header=True, header_style="bold")
            table.add_column("Dependency")
            table.add_column("Your Version")
            table.add_column("Affected Range")
            table.add_column("Fix Version")
            table.add_column("Status")
            for d in scan_result.details:
                status = d.get("status", "")
                st = {"AFFECTED": "red", "NOT_AFFECTED": "green", "UNKNOWN": "yellow"}.get(status, "")
                table.add_row(
                    d.get("dependency", ""),
                    d.get("your_version", ""),
                    d.get("affected_range", ""),
                    d.get("fix_version", ""),
                    f"[{st}]{status}[/{st}]" if st else status,
                )
            console.print(table)
    else:
        # Full scan mode
        vulns = scan_result.vulnerabilities
        if not vulns:
            console.print("  [bold green]✅ No known vulnerabilities found![/bold green]")
        else:
            console.print(f"  Found [bold red]{len(vulns)}[/bold red] vulnerabilities:")
            console.print()

            # Group by severity
            by_severity: dict[str, list] = {}
            for v in vulns:
                sev = v.get("severity", "UNKNOWN")
                by_severity.setdefault(sev, []).append(v)

            severity_colors = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green",
                "UNKNOWN": "dim",
            }

            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
                group = by_severity.get(sev, [])
                if not group:
                    continue
                color = severity_colors.get(sev, "")
                console.print(f"  [{color}]{sev} ({len(group)})[/{color}]")
                table = Table(show_header=True, header_style="bold")
                table.add_column("CVE")
                table.add_column("Package")
                table.add_column("Your Version")
                table.add_column("Fix")
                for v in group:
                    table.add_row(
                        v.get("cve_id", ""),
                        v.get("package", ""),
                        v.get("your_version", ""),
                        v.get("fix_version", ""),
                    )
                console.print(table)
                console.print()

        console.print("  Run [bold]sentinel cve <CVE-ID>[/bold] for details.")
    console.print()


def render_scan_json(scan_result: Any, cve_id: str | None = None) -> str:
    """Render scan results as JSON."""
    output = scan_result.to_dict()
    if cve_id:
        output["cve_id"] = cve_id
    # Remove non-serializable Dependency objects from output
    output.pop("dependencies", None)
    return json.dumps(output, indent=2, ensure_ascii=False, default=str)


def render_scan_markdown(scan_result: Any, path_or_url: str, cve_id: str | None = None) -> str:
    """Render scan results as markdown."""
    lines = [f"# Sentinel Scan — {path_or_url}", ""]

    if cve_id:
        label = VERDICT_STYLES.get(scan_result.status, ("UNKNOWN",))[0]
        lines.append(f"**{label}** for {cve_id}")
        lines.append("")
        if scan_result.details:
            lines.append("| Dependency | Your Version | Affected Range | Fix Version | Status |")
            lines.append("|---|---|---|---|---|")
            for d in scan_result.details:
                lines.append(f"| {d.get('dependency','')} | {d.get('your_version','')} | {d.get('affected_range','')} | {d.get('fix_version','')} | {d.get('status','')} |")
    else:
        vulns = scan_result.vulnerabilities
        lines.append(f"Found **{len(vulns)}** vulnerabilities in {scan_result.total_deps} dependencies.")
        lines.append("")
        if vulns:
            lines.append("| CVE | Severity | Package | Your Version | Fix |")
            lines.append("|---|---|---|---|---|")
            for v in vulns:
                lines.append(f"| {v.get('cve_id','')} | {v.get('severity','')} | {v.get('package','')} | {v.get('your_version','')} | {v.get('fix_version','')} |")

    return "\n".join(lines) + "\n"


def render_deep_scan_terminal(
    deep_result: Any,
    no_color: bool = False,
) -> None:
    """Render deep scan results."""
    console = Console(no_color=no_color)
    label, style = VERDICT_STYLES.get(deep_result.status, ("❓ UNKNOWN", "bold"))
    console.print(f"\n  [{style}]{label}[/{style}]")
    console.print()

    if deep_result.usages:
        console.print(f"  Code analysis found {len(deep_result.usages)} usage(s):")
        for u in deep_result.usages[:5]:
            console.print(f"    • {u.file}:{u.line} — {u.import_statement}")
        console.print()

    console.print(Panel(
        Markdown(deep_result.analysis),
        title="Claude Code-Path Analysis",
        border_style="bold cyan",
    ))
    console.print()


## K8s scan rendering ##

def render_k8s_scan_terminal(
    result: Any,
    no_color: bool = False,
) -> None:
    """Render K8s scan results to terminal."""
    from rich.table import Table

    console = Console(no_color=no_color)
    console.print()

    title = "🛡️  SENTINEL K8s SCAN"
    subtitle_parts = []
    if result.namespace:
        subtitle_parts.append(f"Namespace: {result.namespace}")
    else:
        subtitle_parts.append("All namespaces")
    if result.cve_id:
        subtitle_parts.append(f"CVE: {result.cve_id}")
    console.print(Panel(
        Text(" │ ".join(subtitle_parts), style="dim"),
        title=title,
        border_style="bold cyan",
    ))

    if result.errors:
        for err in result.errors:
            console.print(f"  [bold red]Error:[/bold red] {err}")
        console.print()

    if not result.scan_results:
        console.print("  No images found to scan.")
        console.print()
        return

    # Group images by namespace
    by_ns: dict[str, list] = {}
    for img in result.images:
        by_ns.setdefault(img.namespace or "unknown", []).append(img)

    console.print(f"  Images scanned: {len(result.scan_results)}")
    total_vulns = sum(len(r.vulnerabilities) for r in result.scan_results)
    if total_vulns > 0:
        console.print(f"  [bold red]Vulnerabilities found: {total_vulns}[/bold red]")
    else:
        console.print("  [bold green]No vulnerabilities found![/bold green]")
    console.print()

    for scan_res in result.scan_results:
        if not scan_res.vulnerabilities and not scan_res.error:
            continue
        console.print(f"  [bold]{scan_res.image}[/bold]")
        if scan_res.error:
            console.print(f"    [red]Error: {scan_res.error}[/red]")
        if scan_res.vulnerabilities:
            table = Table(show_header=True, header_style="bold", padding=(0, 1))
            table.add_column("Package")
            table.add_column("Version")
            table.add_column("Status")
            table.add_column("Fix")
            for v in scan_res.vulnerabilities[:20]:
                st = v.get("status", "UNKNOWN")
                color = {"AFFECTED": "red", "NOT_AFFECTED": "green"}.get(st, "yellow")
                table.add_row(
                    v.get("dependency", v.get("package", "")),
                    v.get("your_version", ""),
                    f"[{color}]{st}[/{color}]",
                    v.get("fix_version", ""),
                )
            console.print(table)
        console.print()

    console.print()


def render_k8s_scan_json(result: Any) -> str:
    """Render K8s scan results as JSON."""
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False, default=str)


## Execution path rendering ##

EXEC_PATH_VERDICT_STYLES = {
    "REACHABLE": ("🔴 REACHABLE", "bold red"),
    "NOT_REACHABLE": ("✅ NOT REACHABLE", "bold green"),
    "IMPORTED_ONLY": ("🟡 IMPORTED ONLY", "bold yellow"),
    "INCONCLUSIVE": ("🟠 INCONCLUSIVE", "bold bright_red"),
}


def render_execution_path_terminal(
    result: Any,
    no_color: bool = False,
) -> None:
    """Render execution path analysis results."""
    console = Console(no_color=no_color)
    console.print()

    console.print(Panel(
        Text(f"CVE: {result.cve_id} │ Package: {result.target_package}", style="dim"),
        title="🛡️  SENTINEL — Execution Path Analysis",
        border_style="bold cyan",
    ))

    label, style = EXEC_PATH_VERDICT_STYLES.get(
        result.verdict, ("❓ UNKNOWN", "bold")
    )
    console.print(f"\n  [{style}]{label}[/{style}]")
    console.print()

    if result.vulnerable_functions:
        console.print(f"  Vulnerable functions: {', '.join(result.vulnerable_functions)}")

    if result.entry_points:
        console.print(f"  Entry points found: {len(result.entry_points)}")

    if result.imports_found:
        console.print(f"  Package imports found: {len(result.imports_found)}")
        for imp in result.imports_found[:5]:
            console.print(f"    • {imp.file_path}:{imp.line} — {imp.module}")

    if result.call_chains:
        console.print()
        console.print("  [bold]Call chains to vulnerable code:[/bold]")
        for chain in result.call_chains[:5]:
            console.print(f"    {chain}")

    if result.has_dynamic_dispatch:
        console.print()
        console.print("  [yellow]⚠ Dynamic dispatch detected (getattr/eval/exec) — analysis may be incomplete[/yellow]")

    if result.claude_interpretation:
        console.print()
        console.print(Panel(
            Markdown(result.claude_interpretation),
            title="Claude Interpretation",
            border_style="bold cyan",
        ))

    if result.details:
        console.print(f"\n  {result.details}")

    console.print()


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
