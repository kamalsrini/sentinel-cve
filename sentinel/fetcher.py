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
