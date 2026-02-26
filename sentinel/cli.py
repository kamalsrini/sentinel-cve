"""Sentinel CLI — CVE Explainer powered by Claude.

Usage:
    sentinel cve CVE-2024-3094
    sentinel cve CVE-2024-3094 --json
    sentinel cve CVE-2024-3094 --brief
    sentinel config set api-key <key>
    sentinel cache clear
"""

from __future__ import annotations

import asyncio
import logging
import re
import sys
from typing import Any

import click

from sentinel import __version__


def _validate_cve_id(ctx: click.Context, param: click.Parameter, value: str) -> str:
    """Validate that the CVE ID looks correct."""
    pattern = r"^CVE-\d{4}-\d{4,}$"
    if not re.match(pattern, value, re.IGNORECASE):
        raise click.BadParameter(
            f"'{value}' is not a valid CVE ID. Expected format: CVE-YYYY-NNNNN"
        )
    return value.upper()


@click.group()
@click.version_option(version=__version__, prog_name="sentinel")
@click.option("--no-color", is_flag=True, help="Disable colored output.")
@click.option("--no-cache", is_flag=True, help="Bypass cache, fetch fresh data.")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed logs and timing.")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output.")
@click.pass_context
def cli(ctx: click.Context, no_color: bool, no_cache: bool, verbose: bool, quiet: bool) -> None:
    """🛡️  Sentinel — CVE Explainer CLI powered by Claude.

    Get clear, actionable vulnerability briefings in seconds.
    """
    ctx.ensure_object(dict)
    ctx.obj["no_color"] = no_color
    ctx.obj["no_cache"] = no_cache
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet

    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s" if verbose else "%(message)s",
    )


@cli.command()
@click.argument("cve_id", callback=_validate_cve_id)
@click.option("--json", "output_json", is_flag=True, help="Output as JSON.")
@click.option("--markdown", "output_markdown", is_flag=True, help="Output as Markdown.")
@click.option("--brief", is_flag=True, help="One-paragraph summary only.")
@click.pass_context
def cve(
    ctx: click.Context,
    cve_id: str,
    output_json: bool,
    output_markdown: bool,
    brief: bool,
) -> None:
    """Explain a CVE with a 5-section vulnerability briefing.

    \b
    Examples:
        sentinel cve CVE-2024-3094
        sentinel cve CVE-2024-3094 --json
        sentinel cve CVE-2024-3094 --brief
    """
    asyncio.run(_run_cve(ctx, cve_id, output_json, output_markdown, brief))


async def _run_cve(
    ctx: click.Context,
    cve_id: str,
    output_json: bool,
    output_markdown: bool,
    brief: bool,
) -> None:
    """Async implementation of the cve command."""
    from rich.console import Console
    from rich.status import Status

    from sentinel.cache import cache_get, cache_set
    from sentinel.fetcher import fetch_cve_data
    from sentinel.renderer import render_json, render_markdown, render_terminal
    from sentinel.synthesizer import analyze_cve

    no_cache = ctx.obj.get("no_cache", False)
    no_color = ctx.obj.get("no_color", False)
    quiet = ctx.obj.get("quiet", False)
    console = Console(no_color=no_color, stderr=True)

    try:
        # Check cache for existing analysis
        cache_key = f"analysis:{cve_id}:{'brief' if brief else 'full'}"
        cached: dict[str, Any] | None = None
        if not no_cache:
            cached = await cache_get(cache_key, category="analysis")

        if cached:
            if not quiet:
                console.print(f"[dim]Using cached analysis for {cve_id}[/dim]", highlight=False)
            analysis = cached["analysis"]
            sources = cached["sources"]
        else:
            # Fetch CVE data
            if not quiet:
                console.print(f"[bold cyan]Fetching CVE data for {cve_id}...[/bold cyan]", highlight=False)

            # Check cache for raw CVE data
            data_cache_key = f"data:{cve_id}"
            cve_data: dict[str, Any] | None = None
            if not no_cache:
                cve_data = await cache_get(data_cache_key, category="data")

            if cve_data is None:
                cve_data = await fetch_cve_data(cve_id)
                if not no_cache:
                    await cache_set(data_cache_key, cve_data, category="data")

            sources = cve_data.get("sources", {})
            raw_context = cve_data.get("raw_context", "")

            if not quiet:
                source_names = ", ".join(s.upper() for s in sources.keys())
                console.print(f"[dim]Sources: {source_names}[/dim]", highlight=False)
                console.print("[bold cyan]Analyzing with Claude...[/bold cyan]", highlight=False)

            # Analyze with Claude
            analysis = await analyze_cve(raw_context, brief=brief)

            # Cache the result
            if not no_cache:
                await cache_set(cache_key, {"analysis": analysis, "sources": sources}, category="analysis")

        # Render output
        if output_json:
            click.echo(render_json(cve_id, analysis, sources))
        elif output_markdown:
            click.echo(render_markdown(cve_id, analysis, sources))
        else:
            render_terminal(cve_id, analysis, sources, no_color=no_color)

    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        if ctx.obj.get("verbose"):
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.group()
def config() -> None:
    """Manage Sentinel configuration."""


@config.command("set")
@click.argument("key", type=click.Choice(["api-key", "nvd-key", "model"]))
@click.argument("value")
def config_set(key: str, value: str) -> None:
    """Set a configuration value.

    \b
    Keys:
        api-key   — Anthropic API key
        nvd-key   — NVD API key (optional, for higher rate limits)
        model     — Claude model name
    """
    from sentinel.config import config_set as _config_set

    _config_set(key, value)
    # Mask secrets in output
    display_value = value[:8] + "..." if key.endswith("-key") and len(value) > 8 else value
    click.echo(f"Set {key} = {display_value}")


@config.command("get")
@click.argument("key", type=click.Choice(["api-key", "nvd-key", "model"]))
def config_get(key: str) -> None:
    """Get a configuration value."""
    from sentinel.config import config_get as _config_get

    value = _config_get(key)
    if value is None:
        click.echo(f"{key}: (not set)")
    elif key.endswith("-key"):
        click.echo(f"{key}: {value[:8]}...")
    else:
        click.echo(f"{key}: {value}")


@cli.group()
def cache() -> None:
    """Manage the local cache."""


@cache.command("clear")
def cache_clear_cmd() -> None:
    """Clear all cached data."""
    from sentinel.cache import cache_clear

    count = asyncio.run(cache_clear())
    click.echo(f"Cleared {count} cached entries.")


if __name__ == "__main__":
    cli()
