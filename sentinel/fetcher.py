"""CVE data fetching from multiple sources (NVD, OSV, MITRE).

Uses asyncio + aiohttp for parallel fetching. Gracefully handles source failures.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import aiohttp

from sentinel.config import get_nvd_key

logger = logging.getLogger(__name__)

# Timeouts per request
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=20)


async def _fetch_nvd(session: aiohttp.ClientSession, cve_id: str) -> dict[str, Any] | None:
    """Fetch CVE data from NIST NVD API v2.0."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params: dict[str, str] = {"cveId": cve_id}
    headers: dict[str, str] = {}
    nvd_key = get_nvd_key()
    if nvd_key:
        headers["apiKey"] = nvd_key
    try:
        async with session.get(url, params=params, headers=headers) as resp:
            if resp.status != 200:
                logger.warning("NVD returned status %d for %s", resp.status, cve_id)
                return None
            data = await resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return {"source": "nvd", "data": vulns[0].get("cve", {})}
            return None
    except Exception as exc:
        logger.warning("NVD fetch failed for %s: %s", cve_id, exc)
        return None


async def _fetch_osv(session: aiohttp.ClientSession, cve_id: str) -> dict[str, Any] | None:
    """Fetch CVE data from OSV.dev."""
    url = f"https://api.osv.dev/v1/vulns/{cve_id}"
    try:
        async with session.get(url) as resp:
            if resp.status != 200:
                logger.warning("OSV returned status %d for %s", resp.status, cve_id)
                return None
            data = await resp.json()
            return {"source": "osv", "data": data}
    except Exception as exc:
        logger.warning("OSV fetch failed for %s: %s", cve_id, exc)
        return None


async def _fetch_mitre(session: aiohttp.ClientSession, cve_id: str) -> dict[str, Any] | None:
    """Fetch CVE data from MITRE CVE API."""
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        async with session.get(url) as resp:
            if resp.status != 200:
                logger.warning("MITRE returned status %d for %s", resp.status, cve_id)
                return None
            data = await resp.json()
            return {"source": "mitre", "data": data}
    except Exception as exc:
        logger.warning("MITRE fetch failed for %s: %s", cve_id, exc)
        return None


async def fetch_cve_data(cve_id: str) -> dict[str, Any]:
    """Fetch CVE data from all sources in parallel.

    Args:
        cve_id: CVE identifier (e.g. "CVE-2024-3094").

    Returns:
        Dict with keys: cve_id, sources (dict of source->data), raw_context (formatted string).
    """
    async with aiohttp.ClientSession(timeout=REQUEST_TIMEOUT) as session:
        results = await asyncio.gather(
            _fetch_nvd(session, cve_id),
            _fetch_osv(session, cve_id),
            _fetch_mitre(session, cve_id),
            return_exceptions=True,
        )

    sources: dict[str, Any] = {}
    for result in results:
        if isinstance(result, Exception):
            logger.warning("Fetch error: %s", result)
            continue
        if result is not None:
            sources[result["source"]] = result["data"]

    if not sources:
        raise ValueError(f"No data found for {cve_id} from any source. Check the CVE ID is valid.")

    # Build a combined text context for Claude
    raw_context = _build_context(cve_id, sources)

    return {
        "cve_id": cve_id,
        "sources": sources,
        "raw_context": raw_context,
    }


async def batch_query_osv(dependencies: list[Any]) -> list[dict[str, Any]]:
    """Query OSV.dev batch API for all dependencies at once.

    Args:
        dependencies: List of Dependency objects (with name, version, ecosystem).

    Returns:
        List of vulnerability dicts, each with cve_id, package, version, severity, etc.
    """
    # Build batch query payload
    queries = []
    dep_map: dict[int, Any] = {}
    for i, dep in enumerate(dependencies):
        eco = dep.ecosystem
        # Map our ecosystem names to OSV ecosystem names
        osv_eco = eco  # OSV uses same names mostly
        q: dict[str, Any] = {"package": {"name": dep.name, "ecosystem": osv_eco}}
        if dep.version and dep.version != "*":
            q["version"] = dep.version
        queries.append(q)
        dep_map[i] = dep

    if not queries:
        return []

    vulnerabilities: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    # OSV batch API has a limit, chunk into groups of 1000
    chunk_size = 1000
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60)) as session:
        for start in range(0, len(queries), chunk_size):
            chunk = queries[start:start + chunk_size]
            try:
                async with session.post(
                    "https://api.osv.dev/v1/querybatch",
                    json={"queries": chunk},
                ) as resp:
                    if resp.status != 200:
                        logger.warning("OSV batch query returned status %d", resp.status)
                        continue
                    data = await resp.json()
                    results = data.get("results", [])

                    for idx, result in enumerate(results):
                        vulns = result.get("vulns", [])
                        dep = dep_map.get(start + idx)
                        for vuln in vulns:
                            vuln_id = vuln.get("id", "")
                            if vuln_id in seen_ids:
                                continue
                            seen_ids.add(vuln_id)

                            # Extract severity
                            severity = "UNKNOWN"
                            severity_list = vuln.get("severity", [])
                            if severity_list:
                                score_str = severity_list[0].get("score", "")
                                severity = _cvss_to_severity(score_str)

                            # Find fix version for this specific package
                            fix_version = "unknown"
                            affected_range = "unknown"
                            for affected in vuln.get("affected", []):
                                pkg = affected.get("package", {})
                                if pkg.get("name", "").lower() == (dep.name if dep else "").lower():
                                    for rng in affected.get("ranges", []):
                                        events = rng.get("events", [])
                                        for evt in events:
                                            if "fixed" in evt:
                                                fix_version = evt["fixed"]
                                        parts = []
                                        for evt in events:
                                            if "introduced" in evt:
                                                parts.append(f">= {evt['introduced']}")
                                            if "fixed" in evt:
                                                parts.append(f"< {evt['fixed']}")
                                        affected_range = ", ".join(parts) if parts else "unknown"

                            vulnerabilities.append({
                                "cve_id": vuln_id,
                                "summary": vuln.get("summary", ""),
                                "severity": severity,
                                "package": dep.name if dep else "",
                                "your_version": dep.version if dep else "",
                                "ecosystem": dep.ecosystem if dep else "",
                                "fix_version": fix_version,
                                "affected_range": affected_range,
                            })
            except Exception as exc:
                logger.warning("OSV batch query failed: %s", exc)

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    vulnerabilities.sort(key=lambda v: severity_order.get(v["severity"], 4))

    return vulnerabilities


def _cvss_to_severity(score_str: str) -> str:
    """Convert a CVSS vector string to a severity label."""
    # Try to extract numeric score
    import re as _re
    match = _re.search(r"CVSS:\d+\.\d+/.*?", score_str)
    # Try to get base score from the end
    parts = score_str.split("/")
    try:
        # Try parsing as a float directly
        score = float(score_str)
    except (ValueError, TypeError):
        # Try extracting from CVSS vector
        for part in reversed(parts):
            try:
                score = float(part)
                break
            except ValueError:
                continue
        else:
            return "UNKNOWN"

    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def _build_context(cve_id: str, sources: dict[str, Any]) -> str:
    """Build a structured text document from all fetched data for Claude."""
    parts: list[str] = [f"CVE ID: {cve_id}\n"]

    if "nvd" in sources:
        nvd = sources["nvd"]
        parts.append("=== NIST NVD DATA ===")
        # Description
        descriptions = nvd.get("descriptions", [])
        for d in descriptions:
            if d.get("lang") == "en":
                parts.append(f"Description: {d['value']}")
        # CVSS
        metrics = nvd.get("metrics", {})
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss = metric_list[0].get("cvssData", {})
                parts.append(f"CVSS Score: {cvss.get('baseScore')} ({cvss.get('baseSeverity', 'N/A')})")
                parts.append(f"Attack Vector: {cvss.get('attackVector', 'N/A')}")
                parts.append(f"Attack Complexity: {cvss.get('attackComplexity', 'N/A')}")
                break
        # References
        refs = nvd.get("references", [])
        if refs:
            parts.append("References:")
            for ref in refs[:10]:
                parts.append(f"  - {ref.get('url', '')} ({', '.join(ref.get('tags', []))})")
        # Weaknesses
        weaknesses = nvd.get("weaknesses", [])
        for w in weaknesses:
            for desc in w.get("description", []):
                if desc.get("lang") == "en":
                    parts.append(f"Weakness: {desc['value']}")
        # Configurations (CPE)
        configurations = nvd.get("configurations", [])
        if configurations:
            parts.append("Affected configurations (CPE):")
            for config in configurations[:5]:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        cpe = match.get("criteria", "")
                        version_start = match.get("versionStartIncluding", "")
                        version_end = match.get("versionEndExcluding", match.get("versionEndIncluding", ""))
                        parts.append(f"  - {cpe} [{version_start} - {version_end}]")
        parts.append("")

    if "osv" in sources:
        osv = sources["osv"]
        parts.append("=== OSV.DEV DATA ===")
        parts.append(f"Summary: {osv.get('summary', 'N/A')}")
        parts.append(f"Details: {osv.get('details', 'N/A')[:2000]}")
        # Affected packages
        affected = osv.get("affected", [])
        if affected:
            parts.append("Affected packages:")
            for pkg_info in affected:
                pkg = pkg_info.get("package", {})
                parts.append(f"  - {pkg.get('name', '?')} ({pkg.get('ecosystem', '?')})")
                for rng in pkg_info.get("ranges", []):
                    events = rng.get("events", [])
                    parts.append(f"    Range events: {json.dumps(events)}")
                versions = pkg_info.get("versions", [])
                if versions:
                    parts.append(f"    Versions: {', '.join(versions[:20])}")
        # Severity
        severity = osv.get("severity", [])
        for s in severity:
            parts.append(f"Severity: {s.get('type', '')}: {s.get('score', '')}")
        parts.append("")

    if "mitre" in sources:
        mitre = sources["mitre"]
        parts.append("=== MITRE CVE DATA ===")
        cna = mitre.get("containers", {}).get("cna", {})
        # Description from CNA
        cna_descriptions = cna.get("descriptions", [])
        for d in cna_descriptions:
            if d.get("lang", "").startswith("en"):
                parts.append(f"CNA Description: {d['value']}")
        # Affected from CNA
        cna_affected = cna.get("affected", [])
        for a in cna_affected:
            vendor = a.get("vendor", "?")
            product = a.get("product", "?")
            versions = a.get("versions", [])
            parts.append(f"  Vendor: {vendor}, Product: {product}")
            for v in versions[:10]:
                parts.append(f"    Version: {v.get('version', '?')} status={v.get('status', '?')}")
        # References from CNA
        cna_refs = cna.get("references", [])
        if cna_refs:
            parts.append("CNA References:")
            for ref in cna_refs[:10]:
                parts.append(f"  - {ref.get('url', '')}")
        parts.append("")

    return "\n".join(parts)
