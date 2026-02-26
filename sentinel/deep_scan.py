"""Deep scan — Claude-powered code-path analysis.

Finds imports/usage of affected dependencies in source files,
collects relevant code snippets, and asks Claude whether the
vulnerable code path is actually exercised.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anthropic

from sentinel.config import get_api_key, get_model

logger = logging.getLogger(__name__)

# Language-specific import patterns
IMPORT_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "npm": [
        re.compile(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
        re.compile(r"""from\s+['"]([^'"]+)['"]\s"""),
        re.compile(r"""import\s+.*?from\s+['"]([^'"]+)['"]"""),
    ],
    "PyPI": [
        re.compile(r"""^\s*import\s+(\S+)""", re.MULTILINE),
        re.compile(r"""^\s*from\s+(\S+)\s+import""", re.MULTILINE),
    ],
    "Go": [
        re.compile(r"""["']([^"']+)["']"""),
    ],
    "crates.io": [
        re.compile(r"""use\s+(\w+)"""),
        re.compile(r"""extern\s+crate\s+(\w+)"""),
    ],
    "RubyGems": [
        re.compile(r"""require\s+['"]([^'"]+)['"]"""),
    ],
}

# File extensions per ecosystem
SOURCE_EXTENSIONS: dict[str, list[str]] = {
    "npm": [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
    "PyPI": [".py"],
    "Go": [".go"],
    "crates.io": [".rs"],
    "RubyGems": [".rb"],
    "Packagist": [".php"],
    "Maven": [".java", ".kt"],
}

# Directories to skip
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".tox", ".venv",
    "venv", "vendor", "dist", "build", ".eggs", "target",
}

MAX_SNIPPET_CHARS = 12000  # Max code to send to Claude


@dataclass
class CodeUsage:
    """A code location where an affected dependency is used."""
    file: str
    line: int
    snippet: str
    import_statement: str


@dataclass
class DeepScanResult:
    """Result of deep code-path analysis."""
    status: str  # "AFFECTED", "POTENTIALLY_AFFECTED", "NOT_AFFECTED"
    verdict: str  # Human-readable verdict
    usages: list[CodeUsage]
    analysis: str  # Claude's full analysis


def find_dependency_usage(
    repo_path: str | Path,
    dep_name: str,
    ecosystem: str,
) -> list[CodeUsage]:
    """Find all imports/usages of a dependency in source files."""
    repo_path = Path(repo_path)
    usages: list[CodeUsage] = []
    extensions = SOURCE_EXTENSIONS.get(ecosystem, [])
    patterns = IMPORT_PATTERNS.get(ecosystem, [])

    if not extensions or not patterns:
        return usages

    # Normalize dep name for matching
    dep_variants = _get_name_variants(dep_name, ecosystem)

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if not any(fname.endswith(ext) for ext in extensions):
                continue
            fpath = Path(root) / fname
            try:
                text = fpath.read_text(errors="replace")
            except OSError:
                continue

            lines = text.splitlines()
            for i, line in enumerate(lines, 1):
                for pattern in patterns:
                    for match in pattern.finditer(line):
                        imported = match.group(1)
                        if any(v in imported.lower() for v in dep_variants):
                            # Get surrounding context (5 lines before/after)
                            start = max(0, i - 6)
                            end = min(len(lines), i + 5)
                            snippet = "\n".join(lines[start:end])
                            rel_path = str(fpath.relative_to(repo_path))
                            usages.append(CodeUsage(
                                file=rel_path,
                                line=i,
                                snippet=snippet,
                                import_statement=line.strip(),
                            ))
    return usages


def _get_name_variants(dep_name: str, ecosystem: str) -> list[str]:
    """Get possible import name variants for a dependency."""
    name = dep_name.lower()
    variants = {name, name.replace("-", "_"), name.replace("_", "-")}
    # For scoped npm packages like @scope/name
    if "/" in name:
        variants.add(name.split("/")[-1])
    # For Python, the import name might differ
    if ecosystem == "PyPI":
        variants.add(name.replace("-", ""))
    return list(variants)


async def deep_scan(
    repo_path: str | Path,
    dep_name: str,
    dep_version: str,
    ecosystem: str,
    cve_id: str,
    cve_summary: str = "",
) -> DeepScanResult:
    """Run deep code-path analysis using Claude.

    Args:
        repo_path: Path to the repository.
        dep_name: Name of the affected dependency.
        dep_version: Version in use.
        ecosystem: Package ecosystem.
        cve_id: CVE identifier.
        cve_summary: Brief description of the vulnerability.

    Returns:
        DeepScanResult with Claude's analysis.
    """
    usages = find_dependency_usage(repo_path, dep_name, ecosystem)

    if not usages:
        return DeepScanResult(
            status="NOT_AFFECTED",
            verdict=f"{dep_name} {dep_version} is in dependencies but not imported/used in source code.",
            usages=[],
            analysis="No usage of the affected dependency found in source files.",
        )

    # Build context for Claude
    code_context = _build_code_context(usages, dep_name, dep_version, cve_id, cve_summary)

    # Call Claude
    api_key = get_api_key()
    if not api_key:
        raise ValueError("Anthropic API key required for --deep mode.")

    client = anthropic.Anthropic(api_key=api_key)
    model = get_model()

    message = client.messages.create(
        model=model,
        max_tokens=2048,
        system=DEEP_SCAN_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": code_context}],
    )

    analysis = message.content[0].text

    # Parse verdict from Claude's response
    status = _parse_verdict(analysis)

    return DeepScanResult(
        status=status,
        verdict=analysis.split("\n")[0] if analysis else "Analysis inconclusive.",
        usages=usages,
        analysis=analysis,
    )


def _build_code_context(
    usages: list[CodeUsage],
    dep_name: str,
    dep_version: str,
    cve_id: str,
    cve_summary: str,
) -> str:
    """Build the context document for Claude's code-path analysis."""
    parts = [
        f"CVE: {cve_id}",
        f"Vulnerability summary: {cve_summary}" if cve_summary else "",
        f"Affected dependency: {dep_name} (version {dep_version} in use)",
        "",
        f"The following {len(usages)} code locations import/use this dependency:",
        "",
    ]

    total_chars = 0
    for usage in usages:
        entry = f"--- {usage.file}:{usage.line} ---\n{usage.snippet}\n"
        if total_chars + len(entry) > MAX_SNIPPET_CHARS:
            parts.append(f"... (truncated, {len(usages)} total usages found)")
            break
        parts.append(entry)
        total_chars += len(entry)

    return "\n".join(parts)


def _parse_verdict(analysis: str) -> str:
    """Parse Claude's response to determine the verdict."""
    lower = analysis.lower()
    if "not affected" in lower or "not vulnerable" in lower:
        return "NOT_AFFECTED"
    if "potentially affected" in lower or "potentially vulnerable" in lower or "unclear" in lower:
        return "POTENTIALLY_AFFECTED"
    return "AFFECTED"


DEEP_SCAN_SYSTEM_PROMPT = """\
You are a security analyst performing code-path analysis for a CVE.

Given the CVE details and code snippets showing where the affected dependency is used,
determine whether the vulnerable code path is actually exercised.

Start your response with ONE of these verdicts on the first line:
- "AFFECTED — [reason]" if the vulnerable functionality is clearly used
- "POTENTIALLY AFFECTED — [reason]" if the dependency is used but it's unclear whether the vulnerable path is hit
- "NOT AFFECTED — [reason]" if the dependency is used but the vulnerable functionality is not called

Then provide a brief analysis explaining your reasoning, referencing specific files and line numbers.
"""
