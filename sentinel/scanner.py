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
    # Mobile ecosystems
    "build.gradle": "Maven",
    "build.gradle.kts": "Maven",
    "Podfile": "CocoaPods",
    "Podfile.lock": "CocoaPods",
    "Package.swift": "SwiftPM",
    "Package.resolved": "SwiftPM",
    "pubspec.yaml": "Pub",
    "pubspec.lock": "Pub",
}

# Preferred lock files over manifest files
LOCKFILE_PRIORITY = [
    "package-lock.json", "yarn.lock", "Pipfile.lock", "pyproject.toml",
    "requirements.txt", "go.sum", "Cargo.lock", "Gemfile.lock", "composer.lock",
    "Podfile.lock", "Package.resolved", "pubspec.lock",
]

# Mobile-specific files that need special detection (not just filename match)
MOBILE_MANIFEST_FILES = {
    "build.gradle", "build.gradle.kts", "Podfile", "Package.swift",
    "pubspec.yaml", "settings.gradle", "settings.gradle.kts",
}

# Gradle version catalog path
GRADLE_VERSION_CATALOG = "gradle/libs.versions.toml"


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

        # Check for Gradle version catalog
        catalog = os.path.join(root, "gradle", "libs.versions.toml")
        if os.path.isfile(catalog):
            rel = os.path.relpath(catalog, path)
            found.setdefault("Maven", []).append(rel)

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

    # Parse mobile manifest files if lockfiles didn't cover the ecosystem
    # For Maven (Gradle), parse build.gradle files and version catalogs
    if "Maven" in project_files and "Maven" not in parsed_ecosystems:
        for rel_path in project_files["Maven"]:
            fname = os.path.basename(rel_path)
            file_path = path / rel_path
            if fname in ("build.gradle", "build.gradle.kts"):
                new_deps = _parse_build_gradle(file_path, path)
                for d in new_deps:
                    key = (d.name, d.version, d.ecosystem)
                    if key not in seen:
                        seen.add(key)
                        deps.append(d)
            elif fname == "libs.versions.toml":
                new_deps = _parse_gradle_version_catalog(file_path)
                for d in new_deps:
                    key = (d.name, d.version, d.ecosystem)
                    if key not in seen:
                        seen.add(key)
                        deps.append(d)

    # CocoaPods: Podfile (if no Podfile.lock)
    if "CocoaPods" in project_files and "CocoaPods" not in parsed_ecosystems:
        for rel_path in project_files["CocoaPods"]:
            fname = os.path.basename(rel_path)
            file_path = path / rel_path
            if fname == "Podfile":
                try:
                    text = file_path.read_text(errors="replace")
                    new_deps = _parse_podfile(text, str(file_path))
                except OSError:
                    new_deps = []
                for d in new_deps:
                    key = (d.name, d.version, d.ecosystem)
                    if key not in seen:
                        seen.add(key)
                        deps.append(d)

    # SwiftPM: Package.swift (if no Package.resolved)
    if "SwiftPM" in project_files and "SwiftPM" not in parsed_ecosystems:
        for rel_path in project_files["SwiftPM"]:
            fname = os.path.basename(rel_path)
            file_path = path / rel_path
            if fname == "Package.swift":
                try:
                    text = file_path.read_text(errors="replace")
                    new_deps = _parse_package_swift(text, str(file_path))
                except OSError:
                    new_deps = []
                for d in new_deps:
                    key = (d.name, d.version, d.ecosystem)
                    if key not in seen:
                        seen.add(key)
                        deps.append(d)

    # Pub (Flutter): pubspec.yaml (if no pubspec.lock)
    if "Pub" in project_files and "Pub" not in parsed_ecosystems:
        for rel_path in project_files["Pub"]:
            fname = os.path.basename(rel_path)
            file_path = path / rel_path
            if fname == "pubspec.yaml":
                try:
                    text = file_path.read_text(errors="replace")
                    new_deps = _parse_pubspec_yaml(text, str(file_path))
                except OSError:
                    new_deps = []
                for d in new_deps:
                    key = (d.name, d.version, d.ecosystem)
                    if key not in seen:
                        seen.add(key)
                        deps.append(d)

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
        "Podfile.lock": _parse_podfile_lock,
        "Package.resolved": _parse_package_resolved,
        "pubspec.lock": _parse_pubspec_lock,
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


# ---------------------------------------------------------------------------
# Mobile SDK parsers
# ---------------------------------------------------------------------------

# Regex for Gradle dependency declarations (Groovy and Kotlin DSL)
_GRADLE_DEP_CONFIGS = r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath|kapt|annotationProcessor|ksp)"
_GRADLE_DEP_PATTERN = re.compile(
    rf"""(?:^|\s){_GRADLE_DEP_CONFIGS}\s*[\(]?\s*['"]([^'"]+:[^'"]+:[^'"]+)['"]""",
    re.MULTILINE,
)
# Kotlin DSL: implementation("group:artifact:version")
_GRADLE_DEP_PATTERN_KTS = re.compile(
    rf"""(?:^|\s){_GRADLE_DEP_CONFIGS}\s*\(\s*['"]([^'"]+:[^'"]+:[^'"]+)['"]\s*\)""",
    re.MULTILINE,
)
# Variable reference: $varName or ${varName}
_GRADLE_VAR_REF = re.compile(r"\$\{?(\w+)\}?")
# ext block variable: def firebaseBomVersion = "32.7.0" or val x = "1.0"
_GRADLE_EXT_VAR = re.compile(r"""(?:def|val|var|set\()\s*['"]?(\w+)['"]?\s*[=,]\s*['"]([^'"]+)['"]""")
# gradle.properties: key=value
_GRADLE_PROPS = re.compile(r"^(\w[\w.]*)\s*=\s*(.+)$", re.MULTILINE)


def _resolve_gradle_variables(version: str, variables: dict[str, str]) -> str:
    """Resolve $variable or ${variable} references in a Gradle version string."""
    def replacer(m: re.Match) -> str:
        return variables.get(m.group(1), m.group(0))
    resolved = _GRADLE_VAR_REF.sub(replacer, version)
    return resolved


def _load_gradle_properties(project_root: Path) -> dict[str, str]:
    """Load variables from gradle.properties if it exists."""
    props: dict[str, str] = {}
    for name in ("gradle.properties",):
        p = project_root / name
        if p.is_file():
            try:
                text = p.read_text(errors="replace")
                for m in _GRADLE_PROPS.finditer(text):
                    props[m.group(1)] = m.group(2).strip()
            except OSError:
                pass
    return props


def _extract_ext_variables(text: str) -> dict[str, str]:
    """Extract variables from ext {} blocks and top-level def/val assignments."""
    variables: dict[str, str] = {}
    for m in _GRADLE_EXT_VAR.finditer(text):
        variables[m.group(1)] = m.group(2)
    return variables


def _parse_build_gradle(file_path: Path, project_root: Path) -> list[Dependency]:
    """Parse build.gradle / build.gradle.kts for dependencies."""
    try:
        text = file_path.read_text(errors="replace")
    except OSError:
        return []

    # Collect variables for resolution
    variables = _load_gradle_properties(project_root)
    variables.update(_extract_ext_variables(text))

    deps: list[Dependency] = []
    seen: set[str] = set()
    source = str(file_path)

    for pattern in (_GRADLE_DEP_PATTERN, _GRADLE_DEP_PATTERN_KTS):
        for m in pattern.finditer(text):
            coord = m.group(1)
            parts = coord.split(":")
            if len(parts) >= 3:
                group, artifact, version = parts[0], parts[1], parts[2]
                version = _resolve_gradle_variables(version, variables)
                name = f"{group}:{artifact}"
                # Skip if version is still a variable reference
                if "$" in version:
                    version = "*"
                key = name
                if key not in seen:
                    seen.add(key)
                    deps.append(Dependency(
                        name=name, version=version, ecosystem="Maven",
                        direct=True, source_file=source,
                    ))
            elif len(parts) == 2:
                # No version (BOM-managed)
                name = f"{parts[0]}:{parts[1]}"
                if name not in seen:
                    seen.add(name)
                    deps.append(Dependency(
                        name=name, version="*", ecosystem="Maven",
                        direct=True, source_file=source,
                    ))

    return deps


def _parse_gradle_version_catalog(file_path: Path) -> list[Dependency]:
    """Parse gradle/libs.versions.toml (Gradle version catalogs)."""
    try:
        text = file_path.read_text(errors="replace")
    except OSError:
        return []

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return _parse_gradle_version_catalog_regex(text, str(file_path))

    try:
        data = tomllib.loads(text)
    except Exception:
        return _parse_gradle_version_catalog_regex(text, str(file_path))

    versions = data.get("versions", {})
    libraries = data.get("libraries", {})
    plugins = data.get("plugins", {})
    deps: list[Dependency] = []
    source = str(file_path)

    for _alias, lib in libraries.items():
        if isinstance(lib, str):
            # Short notation: "group:artifact:version"
            parts = lib.split(":")
            if len(parts) >= 3:
                deps.append(Dependency(
                    name=f"{parts[0]}:{parts[1]}", version=parts[2],
                    ecosystem="Maven", direct=True, source_file=source,
                ))
            continue
        module = lib.get("module", "")
        group = lib.get("group", "")
        name_part = lib.get("name", "")
        if module:
            name = module
        elif group and name_part:
            name = f"{group}:{name_part}"
        else:
            continue
        # Resolve version
        ver = lib.get("version", "")
        if isinstance(ver, dict):
            ref = ver.get("ref", "")
            ver = versions.get(ref, "*") if ref else ver.get("strictly", ver.get("prefer", "*"))
        elif isinstance(ver, str) and not ver:
            ver_ref = lib.get("version.ref", "")
            ver = versions.get(ver_ref, "*") if ver_ref else "*"
        deps.append(Dependency(
            name=name, version=str(ver), ecosystem="Maven",
            direct=True, source_file=source,
        ))

    for _alias, plug in plugins.items():
        if isinstance(plug, str):
            parts = plug.split(":")
            if len(parts) >= 2:
                deps.append(Dependency(
                    name=parts[0], version=parts[1],
                    ecosystem="Maven", direct=True, source_file=source,
                ))
            continue
        pid = plug.get("id", "")
        ver = plug.get("version", "")
        if isinstance(ver, dict):
            ref = ver.get("ref", "")
            ver = versions.get(ref, "*") if ref else "*"
        if pid:
            deps.append(Dependency(
                name=pid, version=str(ver), ecosystem="Maven",
                direct=True, source_file=source,
            ))

    return deps


def _parse_gradle_version_catalog_regex(text: str, source: str) -> list[Dependency]:
    """Fallback regex parser for libs.versions.toml when tomllib unavailable."""
    versions: dict[str, str] = {}
    deps: list[Dependency] = []
    section = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line.strip("[]").strip()
            continue
        if not line or line.startswith("#"):
            continue
        if section == "versions":
            m = re.match(r"""(\S+)\s*=\s*['"]([^'"]+)['"]""", line)
            if m:
                versions[m.group(1)] = m.group(2)
        elif section == "libraries":
            # module key
            m_mod = re.search(r"""module\s*=\s*['"]([^'"]+)['"]""", line)
            m_ver = re.search(r"""version\.ref\s*=\s*['"]([^'"]+)['"]""", line)
            m_ver_direct = re.search(r"""version\s*=\s*['"]([^'"]+)['"]""", line)
            if m_mod:
                module = m_mod.group(1)
                ver = "*"
                if m_ver:
                    ver = versions.get(m_ver.group(1), "*")
                elif m_ver_direct:
                    ver = m_ver_direct.group(1)
                deps.append(Dependency(
                    name=module, version=ver, ecosystem="Maven",
                    direct=True, source_file=source,
                ))
    return deps


# CocoaPods parsers

_PODFILE_POD_PATTERN = re.compile(
    r"""pod\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*)['"]\s*)?""",
)


def _parse_podfile(text: str, source: str) -> list[Dependency]:
    """Parse a Podfile for pod declarations."""
    deps: list[Dependency] = []
    for m in _PODFILE_POD_PATTERN.finditer(text):
        pod_name = m.group(1)
        version = m.group(2) or "*"
        # Normalize version: strip operators like ~>, >=, etc. for base version
        version_clean = re.sub(r"^[~><=!]+\s*", "", version).strip()
        if not version_clean:
            version_clean = "*"
        deps.append(Dependency(
            name=pod_name, version=version_clean, ecosystem="CocoaPods",
            direct=True, source_file=source,
        ))
    return deps


def _parse_podfile_lock(text: str, source: str) -> list[Dependency]:
    """Parse Podfile.lock for resolved pod versions."""
    deps: list[Dependency] = []
    in_pods = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "PODS:":
            in_pods = True
            continue
        if in_pods:
            # End of PODS section: non-indented non-empty line or another section
            if stripped and not stripped.startswith("-") and stripped.endswith(":") and stripped != "PODS:":
                in_pods = False
                continue
            if not stripped:
                continue
            # Match "- PodName (version):" or "- PodName (version)"
            m = re.match(r"^-\s+([^\s(]+)\s+\(([^)]+)\)", stripped)
            if m:
                pod_name = m.group(1)
                version = m.group(2)
                # Check if this is a top-level pod (not a transitive sub-dep)
                # In Podfile.lock, top-level pods have 2-space indent, sub-deps have 4+
                # But we normalize by checking if it starts with "  - " vs "    - "
                raw_indent = line[:len(line) - len(line.lstrip())]
                indent_len = len(raw_indent)
                deps.append(Dependency(
                    name=pod_name, version=version, ecosystem="CocoaPods",
                    direct=(indent_len <= 4), source_file=source,
                ))
    return deps


# Swift Package Manager parsers

def _parse_package_swift(text: str, source: str) -> list[Dependency]:
    """Parse Package.swift for .package(url:...) declarations."""
    deps: list[Dependency] = []
    # .package(url: "https://github.com/user/repo", from: "1.0.0")
    # .package(url: "...", .upToNextMajor(from: "1.0.0"))
    # .package(url: "...", exact: "1.0.0")
    pattern = re.compile(
        r"""\.package\s*\(\s*url:\s*['"]([^'"]+)['"].*?(?:from:\s*['"]([^'"]+)['"]|exact:\s*['"]([^'"]+)['"]|"""
        r"""\.upToNextMajor\s*\(\s*from:\s*['"]([^'"]+)['"]|\.upToNextMinor\s*\(\s*from:\s*['"]([^'"]+)['"])""",
        re.DOTALL,
    )
    for m in pattern.finditer(text):
        url = m.group(1)
        version = m.group(2) or m.group(3) or m.group(4) or m.group(5) or "*"
        # Extract package name from URL
        name = url.rstrip("/").split("/")[-1]
        if name.endswith(".git"):
            name = name[:-4]
        deps.append(Dependency(
            name=name, version=version, ecosystem="SwiftPM",
            direct=True, source_file=source,
        ))
    return deps


def _parse_package_resolved(text: str, source: str) -> list[Dependency]:
    """Parse Package.resolved (Swift PM lock file, v1 and v2 format)."""
    deps: list[Dependency] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    # v2 format: {"pins": [...]}
    pins = data.get("pins", [])
    # v1 format: {"object": {"pins": [...]}}
    if not pins:
        pins = data.get("object", {}).get("pins", [])

    for pin in pins:
        identity = pin.get("identity", "") or pin.get("package", "")
        state = pin.get("state", {})
        version = state.get("version") or state.get("revision", "*")
        if not version:
            version = "*"
        deps.append(Dependency(
            name=identity, version=version, ecosystem="SwiftPM",
            direct=True, source_file=source,
        ))
    return deps


# Flutter/Dart parsers

def _parse_pubspec_yaml(text: str, source: str) -> list[Dependency]:
    """Parse pubspec.yaml for Flutter/Dart dependencies."""
    deps: list[Dependency] = []
    try:
        import yaml
    except ImportError:
        # Fallback regex parsing
        return _parse_pubspec_yaml_regex(text, source)

    try:
        data = yaml.safe_load(text)
    except Exception:
        return _parse_pubspec_yaml_regex(text, source)

    if not isinstance(data, dict):
        return []

    for section in ("dependencies", "dev_dependencies"):
        section_data = data.get(section, {})
        if not isinstance(section_data, dict):
            continue
        for name, ver_info in section_data.items():
            if isinstance(ver_info, str):
                version = re.sub(r"^[\^~>=<!\s]+", "", ver_info).strip() or "*"
            elif isinstance(ver_info, dict):
                version = str(ver_info.get("version", "*"))
                version = re.sub(r"^[\^~>=<!\s]+", "", version).strip() or "*"
            else:
                version = "*"
            deps.append(Dependency(
                name=name, version=version, ecosystem="Pub",
                direct=(section == "dependencies"), source_file=source,
            ))
    return deps


def _parse_pubspec_yaml_regex(text: str, source: str) -> list[Dependency]:
    """Fallback regex parser for pubspec.yaml."""
    deps: list[Dependency] = []
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped in ("dependencies:", "dev_dependencies:"):
            in_deps = True
            continue
        if in_deps:
            if not line.startswith(" ") and not line.startswith("\t"):
                in_deps = False
                continue
            m = re.match(r"^\s+(\w[\w_-]*):\s*(.+)?$", line)
            if m:
                name = m.group(1)
                ver_raw = (m.group(2) or "").strip()
                version = re.sub(r"^[\^~>=<!\s]+", "", ver_raw).strip() or "*"
                deps.append(Dependency(
                    name=name, version=version, ecosystem="Pub",
                    direct=True, source_file=source,
                ))
    return deps


def _parse_pubspec_lock(text: str, source: str) -> list[Dependency]:
    """Parse pubspec.lock for resolved Flutter/Dart dependencies."""
    deps: list[Dependency] = []
    try:
        import yaml
    except ImportError:
        return _parse_pubspec_lock_regex(text, source)

    try:
        data = yaml.safe_load(text)
    except Exception:
        return _parse_pubspec_lock_regex(text, source)

    if not isinstance(data, dict):
        return []

    packages = data.get("packages", {})
    if not isinstance(packages, dict):
        return []

    for name, info in packages.items():
        if not isinstance(info, dict):
            continue
        version = str(info.get("version", "*"))
        dep_type = info.get("dependency", "")
        direct = "direct" in str(dep_type).lower()
        deps.append(Dependency(
            name=name, version=version, ecosystem="Pub",
            direct=direct, source_file=source,
        ))
    return deps


def _parse_pubspec_lock_regex(text: str, source: str) -> list[Dependency]:
    """Fallback regex parser for pubspec.lock."""
    deps: list[Dependency] = []
    current_name = ""
    for line in text.splitlines():
        # Package name at 2-space indent
        m_name = re.match(r"^  (\w[\w_-]*):", line)
        if m_name:
            current_name = m_name.group(1)
            continue
        if current_name:
            m_ver = re.match(r'^\s+version:\s*"([^"]+)"', line)
            if m_ver:
                deps.append(Dependency(
                    name=current_name, version=m_ver.group(1), ecosystem="Pub",
                    source_file=source,
                ))
                current_name = ""
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
