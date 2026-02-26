"""Repo scanner — detect dependencies and check CVE impact.

Walks a repository for dependency/lock files, extracts dependencies,
and matches them against CVE affected packages from OSV/GHSA data.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Ecosystem mapping from filename to ecosystem name
DEPENDENCY_FILES: dict[str, str] = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "requirements.txt": "PyPI",
    "Pipfile": "PyPI",
    "Pipfile.lock": "PyPI",
    "pyproject.toml": "PyPI",
    "go.mod": "Go",
    "go.sum": "Go",
    "Cargo.toml": "crates.io",
    "Cargo.lock": "crates.io",
    "pom.xml": "Maven",
    "Gemfile": "RubyGems",
    "Gemfile.lock": "RubyGems",
    "composer.json": "Packagist",
    "composer.lock": "Packagist",
    "mix.exs": "Hex",
}

# Preferred lock files over manifest files
LOCKFILE_PRIORITY = [
    "package-lock.json", "yarn.lock", "Pipfile.lock", "pyproject.toml",
    "requirements.txt", "go.sum", "Cargo.lock", "Gemfile.lock", "composer.lock",
]


@dataclass
class Dependency:
    """A single dependency extracted from a project."""
    name: str
    version: str
    ecosystem: str
    direct: bool = False
    source_file: str = ""


@dataclass
class ScanResult:
    """Result of a repo scan."""
    affected: bool
    status: str  # "AFFECTED", "NOT_AFFECTED", "UNKNOWN"
    project_types: list[str] = field(default_factory=list)
    total_deps: int = 0
    details: list[dict[str, Any]] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def is_github_url(path_or_url: str) -> bool:
    """Check if the input is a GitHub URL."""
    return bool(re.match(r"https?://(www\.)?github\.com/", path_or_url))


def clone_repo(url: str) -> str:
    """Shallow-clone a GitHub repo to a temp directory. Returns the path."""
    tmp = tempfile.mkdtemp(prefix="sentinel-scan-")
    logger.info("Cloning %s to %s", url, tmp)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, tmp],
            check=True, capture_output=True, text=True, timeout=120,
        )
    except subprocess.CalledProcessError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError(f"Failed to clone {url}: {e.stderr.strip()}") from e
    except FileNotFoundError:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError("git is not installed. Install git to scan GitHub URLs.")
    return tmp


def detect_project_type(path: str | Path) -> dict[str, list[str]]:
    """Walk repo for dependency files. Returns {ecosystem: [files_found]}."""
    path = Path(path)
    found: dict[str, list[str]] = {}

    for root, dirs, files in os.walk(path):
        # Skip common non-project dirs
        dirs[:] = [d for d in dirs if d not in {
            ".git", "node_modules", "__pycache__", ".tox", ".venv",
            "venv", "vendor", "dist", "build", ".eggs",
        }]
        for fname in files:
            eco = DEPENDENCY_FILES.get(fname)
            if eco:
                rel = os.path.relpath(os.path.join(root, fname), path)
                found.setdefault(eco, []).append(rel)
            # .csproj files
            if fname.endswith(".csproj"):
                rel = os.path.relpath(os.path.join(root, fname), path)
                found.setdefault("NuGet", []).append(rel)

    return found


def extract_dependencies(path: str | Path) -> list[Dependency]:
    """Parse dependency/lock files and return flat dependency list."""
    path = Path(path)
    project_files = detect_project_type(path)
    deps: list[Dependency] = []
    seen: set[tuple[str, str, str]] = set()

    # For each ecosystem, prefer lockfiles
    parsed_ecosystems: set[str] = set()

    for lock_name in LOCKFILE_PRIORITY:
        eco = DEPENDENCY_FILES.get(lock_name)
        if eco and eco in project_files and eco not in parsed_ecosystems:
            for rel_path in project_files[eco]:
                if os.path.basename(rel_path) == lock_name:
                    file_path = path / rel_path
                    new_deps = _parse_file(file_path, lock_name, eco)
                    for d in new_deps:
                        key = (d.name, d.version, d.ecosystem)
                        if key not in seen:
                            seen.add(key)
                            deps.append(d)
                    if new_deps:
                        parsed_ecosystems.add(eco)

    return deps


def _parse_file(file_path: Path, filename: str, ecosystem: str) -> list[Dependency]:
    """Dispatch to the correct parser based on filename."""
    try:
        text = file_path.read_text(errors="replace")
    except OSError as e:
        logger.warning("Cannot read %s: %s", file_path, e)
        return []

    parsers = {
        "package-lock.json": _parse_package_lock,
        "yarn.lock": _parse_yarn_lock,
        "requirements.txt": _parse_requirements_txt,
        "Pipfile.lock": _parse_pipfile_lock,
        "pyproject.toml": _parse_pyproject_toml,
        "go.sum": _parse_go_sum,
        "Cargo.lock": _parse_cargo_lock,
        "Gemfile.lock": _parse_gemfile_lock,
        "composer.lock": _parse_composer_lock,
    }

    parser = parsers.get(filename)
    if parser is None:
        return []

    try:
        return parser(text, str(file_path))
    except Exception as e:
        logger.warning("Failed to parse %s: %s", file_path, e)
        return []


def _parse_package_lock(text: str, source: str) -> list[Dependency]:
    """Parse package-lock.json (v2/v3)."""
    data = json.loads(text)
    deps: list[Dependency] = []

    # v2/v3 format with "packages"
    packages = data.get("packages", {})
    if packages:
        for pkg_path, info in packages.items():
            if not pkg_path:  # root
                continue
            name = info.get("name") or pkg_path.split("node_modules/")[-1]
            version = info.get("version", "")
            if name and version:
                direct = not info.get("dev", False) and "node_modules/" not in pkg_path.replace("node_modules/" + name, "")
                deps.append(Dependency(name=name, version=version, ecosystem="npm", direct=direct, source_file=source))
        return deps

    # v1 format with "dependencies"
    def _walk_v1(dep_dict: dict, is_direct: bool = True) -> None:
        for name, info in dep_dict.items():
            version = info.get("version", "")
            if name and version:
                deps.append(Dependency(name=name, version=version, ecosystem="npm", direct=is_direct, source_file=source))
            sub = info.get("dependencies", {})
            if sub:
                _walk_v1(sub, False)

    _walk_v1(data.get("dependencies", {}))
    return deps


def _parse_yarn_lock(text: str, source: str) -> list[Dependency]:
    """Parse yarn.lock (v1 format)."""
    deps: list[Dependency] = []
    current_name = ""
    for line in text.splitlines():
        # Entry header: "name@version:"
        if not line.startswith(" ") and not line.startswith("#") and "@" in line:
            # e.g. '"lodash@^4.17.20":'  or  'lodash@^4.17.20:'
            clean = line.strip().strip('"').rstrip(":")
            # Get the package name (everything before the last @)
            at_idx = clean.rfind("@")
            if at_idx > 0:
                current_name = clean[:at_idx]
        elif line.strip().startswith("version "):
            version = line.strip().split('"')[1] if '"' in line else line.strip().split()[-1]
            if current_name and version:
                deps.append(Dependency(name=current_name, version=version, ecosystem="npm", source_file=source))
                current_name = ""
    return deps


def _parse_requirements_txt(text: str, source: str) -> list[Dependency]:
    """Parse requirements.txt."""
    deps: list[Dependency] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle name==version, name>=version, name~=version
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*[=~!><]=?\s*([0-9][A-Za-z0-9_.*-]*)", line)
        if match:
            name, version = match.group(1), match.group(2)
            deps.append(Dependency(name=name.lower(), version=version, ecosystem="PyPI", direct=True, source_file=source))
        else:
            # Just a name with no version
            match2 = re.match(r"^([A-Za-z0-9_.-]+)", line)
            if match2:
                deps.append(Dependency(name=match2.group(1).lower(), version="*", ecosystem="PyPI", direct=True, source_file=source))
    return deps


def _parse_pipfile_lock(text: str, source: str) -> list[Dependency]:
    """Parse Pipfile.lock."""
    data = json.loads(text)
    deps: list[Dependency] = []
    for section in ("default", "develop"):
        packages = data.get(section, {})
        for name, info in packages.items():
            version = info.get("version", "").lstrip("=")
            if version:
                deps.append(Dependency(name=name.lower(), version=version, ecosystem="PyPI", direct=(section == "default"), source_file=source))
    return deps


def _parse_pyproject_toml(text: str, source: str) -> list[Dependency]:
    """Parse pyproject.toml for dependencies (PEP 621 + Poetry)."""
    deps: list[Dependency] = []
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            logger.warning("tomllib/tomli not available, skipping pyproject.toml")
            return []

    data = tomllib.loads(text)

    # PEP 621 dependencies
    for dep_str in data.get("project", {}).get("dependencies", []):
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*[=~!><]=?\s*([0-9][A-Za-z0-9_.*-]*)", dep_str)
        if match:
            deps.append(Dependency(name=match.group(1).lower(), version=match.group(2), ecosystem="PyPI", direct=True, source_file=source))

    # Poetry
    for section_name in ("tool.poetry.dependencies", "tool.poetry.dev-dependencies"):
        keys = section_name.split(".")
        section = data
        for k in keys:
            section = section.get(k, {})
            if not isinstance(section, dict):
                section = {}
                break
        for name, ver_info in section.items():
            if name.lower() == "python":
                continue
            if isinstance(ver_info, str):
                version = ver_info.lstrip("^~>=<!")
                deps.append(Dependency(name=name.lower(), version=version, ecosystem="PyPI", direct=True, source_file=source))
            elif isinstance(ver_info, dict):
                version = str(ver_info.get("version", "*")).lstrip("^~>=<!")
                deps.append(Dependency(name=name.lower(), version=version, ecosystem="PyPI", direct=True, source_file=source))

    return deps


def _parse_go_sum(text: str, source: str) -> list[Dependency]:
    """Parse go.sum."""
    deps: list[Dependency] = []
    seen: set[str] = set()
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            module = parts[0]
            version = parts[1].split("/")[0].lstrip("v")
            key = f"{module}@{version}"
            if key not in seen:
                seen.add(key)
                deps.append(Dependency(name=module, version=version, ecosystem="Go", source_file=source))
    return deps


def _parse_cargo_lock(text: str, source: str) -> list[Dependency]:
    """Parse Cargo.lock (TOML format)."""
    deps: list[Dependency] = []
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            # Fallback: regex parsing
            for match in re.finditer(r'name\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text):
                deps.append(Dependency(name=match.group(1), version=match.group(2), ecosystem="crates.io", source_file=source))
            return deps

    data = tomllib.loads(text)
    for pkg in data.get("package", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        if name and version:
            deps.append(Dependency(name=name, version=version, ecosystem="crates.io", source_file=source))
    return deps


def _parse_gemfile_lock(text: str, source: str) -> list[Dependency]:
    """Parse Gemfile.lock."""
    deps: list[Dependency] = []
    in_specs = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "GEM" or stripped == "PATH":
            in_specs = False
        if stripped == "specs:":
            in_specs = True
            continue
        if in_specs and stripped:
            # Lines like "    rails (7.0.4)" (4 spaces = direct, 6+ = transitive)
            match = re.match(r"^\s{4}(\S+)\s+\(([^)]+)\)", line)
            if match:
                deps.append(Dependency(name=match.group(1), version=match.group(2), ecosystem="RubyGems", direct=True, source_file=source))
            else:
                match = re.match(r"^\s{6,}(\S+)\s+\(([^)]+)\)", line)
                if match:
                    deps.append(Dependency(name=match.group(1), version=match.group(2), ecosystem="RubyGems", source_file=source))
        if stripped in ("PLATFORMS", "DEPENDENCIES", "BUNDLED WITH", "RUBY VERSION"):
            in_specs = False
    return deps


def _parse_composer_lock(text: str, source: str) -> list[Dependency]:
    """Parse composer.lock."""
    data = json.loads(text)
    deps: list[Dependency] = []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            name = pkg.get("name", "")
            version = pkg.get("version", "").lstrip("v")
            if name and version:
                deps.append(Dependency(name=name, version=version, ecosystem="Packagist", direct=(section == "packages"), source_file=source))
    return deps


def check_cve_impact(
    deps: list[Dependency],
    cve_data: dict[str, Any],
) -> ScanResult:
    """Match dependencies against CVE affected packages from OSV/GHSA data.

    Args:
        deps: List of project dependencies.
        cve_data: CVE data dict (from fetch_cve_data), must contain 'sources'.

    Returns:
        ScanResult with affected status and details.
    """
    affected_pkgs = _extract_affected_packages(cve_data)

    if not affected_pkgs:
        return ScanResult(
            affected=False,
            status="UNKNOWN",
            total_deps=len(deps),
            details=[{"message": "Could not determine affected packages from CVE data."}],
            dependencies=deps,
        )

    details: list[dict[str, Any]] = []
    is_affected = False

    for dep in deps:
        for apkg in affected_pkgs:
            if _names_match(dep.name, apkg["name"], dep.ecosystem):
                # Check version
                if dep.version == "*" or dep.version == "":
                    details.append({
                        "dependency": dep.name,
                        "your_version": dep.version,
                        "affected_range": apkg.get("range_str", "unknown"),
                        "fix_version": apkg.get("fixed", "unknown"),
                        "ecosystem": dep.ecosystem,
                        "status": "UNKNOWN",
                        "source_file": dep.source_file,
                    })
                elif _version_in_range(dep.version, apkg.get("events", []), apkg.get("versions", [])):
                    is_affected = True
                    details.append({
                        "dependency": dep.name,
                        "your_version": dep.version,
                        "affected_range": apkg.get("range_str", "unknown"),
                        "fix_version": apkg.get("fixed", "unknown"),
                        "ecosystem": dep.ecosystem,
                        "status": "AFFECTED",
                        "source_file": dep.source_file,
                    })
                else:
                    details.append({
                        "dependency": dep.name,
                        "your_version": dep.version,
                        "affected_range": apkg.get("range_str", "unknown"),
                        "fix_version": apkg.get("fixed", "unknown"),
                        "ecosystem": dep.ecosystem,
                        "status": "NOT_AFFECTED",
                        "source_file": dep.source_file,
                    })

    status = "AFFECTED" if is_affected else ("UNKNOWN" if any(d["status"] == "UNKNOWN" for d in details) else "NOT_AFFECTED")

    return ScanResult(
        affected=is_affected,
        status=status,
        total_deps=len(deps),
        details=details,
        dependencies=deps,
    )


def _extract_affected_packages(cve_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract affected package info from CVE sources (primarily OSV)."""
    packages: list[dict[str, Any]] = []
    sources = cve_data.get("sources", {})

    # OSV is the best source for package-level data
    osv = sources.get("osv", {})
    for affected in osv.get("affected", []):
        pkg = affected.get("package", {})
        name = pkg.get("name", "")
        ecosystem = pkg.get("ecosystem", "")

        for rng in affected.get("ranges", []):
            events = rng.get("events", [])
            range_str = _events_to_range_str(events)
            fixed = ""
            for evt in events:
                if "fixed" in evt:
                    fixed = evt["fixed"]

            packages.append({
                "name": name,
                "ecosystem": ecosystem,
                "events": events,
                "versions": affected.get("versions", []),
                "range_str": range_str,
                "fixed": fixed,
            })

    return packages


def _events_to_range_str(events: list[dict[str, str]]) -> str:
    """Convert OSV range events to a human-readable string."""
    parts = []
    for evt in events:
        if "introduced" in evt:
            parts.append(f">= {evt['introduced']}" if evt["introduced"] != "0" else ">= 0")
        if "fixed" in evt:
            parts.append(f"< {evt['fixed']}")
        if "last_affected" in evt:
            parts.append(f"<= {evt['last_affected']}")
    return ", ".join(parts) if parts else "unknown"


def _names_match(dep_name: str, cve_pkg_name: str, ecosystem: str) -> bool:
    """Check if dependency name matches CVE package name (case-insensitive, normalized)."""
    a = dep_name.lower().replace("-", "_").replace(".", "_")
    b = cve_pkg_name.lower().replace("-", "_").replace(".", "_")
    return a == b


def _version_in_range(version: str, events: list[dict[str, str]], explicit_versions: list[str]) -> bool:
    """Check if a version falls within the affected range."""
    # If explicit versions listed, check those first
    if explicit_versions and version in explicit_versions:
        return True

    # Parse events to determine range
    from packaging.version import Version, InvalidVersion

    try:
        ver = Version(version)
    except InvalidVersion:
        # Can't parse, check explicit list only
        return version in explicit_versions if explicit_versions else False

    introduced = None
    fixed = None
    last_affected = None

    for evt in events:
        if "introduced" in evt:
            try:
                introduced = Version(evt["introduced"]) if evt["introduced"] != "0" else Version("0")
            except InvalidVersion:
                introduced = Version("0")
        if "fixed" in evt:
            try:
                fixed = Version(evt["fixed"])
            except InvalidVersion:
                pass
        if "last_affected" in evt:
            try:
                last_affected = Version(evt["last_affected"])
            except InvalidVersion:
                pass

    if introduced is not None and ver < introduced:
        return False
    if fixed is not None and ver >= fixed:
        return False
    if last_affected is not None and ver > last_affected:
        return False
    if introduced is not None:
        return True

    return False


async def scan_repo(
    path_or_url: str,
    cve_id: str | None = None,
    no_cache: bool = False,
) -> ScanResult:
    """Full scan pipeline: detect → extract → check.

    Args:
        path_or_url: Local path or GitHub URL.
        cve_id: If provided, check this specific CVE. If None, do full scan.
        no_cache: Bypass cache for CVE data fetching.

    Returns:
        ScanResult with findings.
    """
    from sentinel.fetcher import batch_query_osv, fetch_cve_data
    from sentinel.cache import cache_get, cache_set

    tmp_dir = None
    try:
        # Handle GitHub URLs
        if is_github_url(path_or_url):
            tmp_dir = clone_repo(path_or_url)
            scan_path = tmp_dir
        else:
            scan_path = path_or_url

        path = Path(scan_path)
        if not path.exists():
            raise ValueError(f"Path does not exist: {scan_path}")

        # Detect and extract
        project_types = detect_project_type(path)
        deps = extract_dependencies(path)

        if not deps:
            return ScanResult(
                affected=False,
                status="UNKNOWN",
                project_types=list(project_types.keys()),
                total_deps=0,
                details=[{"message": "No dependencies found. Missing lockfile?"}],
            )

        if cve_id:
            # Single CVE check
            data_cache_key = f"data:{cve_id}"
            cve_data = None
            if not no_cache:
                cve_data = await cache_get(data_cache_key, category="data")
            if cve_data is None:
                cve_data = await fetch_cve_data(cve_id)
                if not no_cache:
                    await cache_set(data_cache_key, cve_data, category="data")

            result = check_cve_impact(deps, cve_data)
            result.project_types = list(project_types.keys())
            return result
        else:
            # Full scan — batch query OSV
            vulns = await batch_query_osv(deps)
            result = ScanResult(
                affected=len(vulns) > 0,
                status="AFFECTED" if vulns else "NOT_AFFECTED",
                project_types=list(project_types.keys()),
                total_deps=len(deps),
                dependencies=deps,
                vulnerabilities=vulns,
            )
            return result

    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
