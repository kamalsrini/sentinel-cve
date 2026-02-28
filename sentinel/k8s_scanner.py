"""Kubernetes Runtime BOM Scanner.

Scans running K8s cluster images for vulnerabilities and generates SBOMs.
READ-ONLY: never writes to cluster, never execs into pods.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ── Data models ────────────────────────────────────────────────────────────

@dataclass
class ContainerImage:
    """A container image discovered in the cluster."""
    image: str
    namespace: str = ""
    pod: str = ""
    container: str = ""
    deployment: str = ""

    @property
    def name_tag(self) -> str:
        """Return image without registry prefix for display."""
        return self.image.split("/")[-1] if "/" in self.image else self.image


@dataclass
class ImagePackage:
    """A package found inside a container image."""
    name: str
    version: str
    ecosystem: str  # "deb", "apk", "rpm", "unknown"


@dataclass
class ImageScanResult:
    """Scan result for a single image."""
    image: str
    packages: list[ImagePackage] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None


@dataclass
class K8sScanResult:
    """Full cluster scan result."""
    images: list[ContainerImage] = field(default_factory=list)
    scan_results: list[ImageScanResult] = field(default_factory=list)
    namespace: str | None = None
    cve_id: str | None = None
    timestamp: str = ""
    errors: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "images": [asdict(i) for i in self.images],
            "scan_results": [
                {
                    "image": r.image,
                    "packages": [asdict(p) for p in r.packages],
                    "vulnerabilities": r.vulnerabilities,
                    "error": r.error,
                }
                for r in self.scan_results
            ],
            "namespace": self.namespace,
            "cve_id": self.cve_id,
            "timestamp": self.timestamp,
            "errors": self.errors,
        }


# ── Credential redaction ──────────────────────────────────────────────────

_CREDENTIAL_PATTERNS = [
    re.compile(r"(https?://)([^:]+):([^@]+)@"),  # user:pass@host
    re.compile(r"(password|token|secret|credential)[\s=:]+\S+", re.IGNORECASE),
]


def _redact_credentials(text: str) -> str:
    """Redact any credentials from log text."""
    result = text
    for pat in _CREDENTIAL_PATTERNS:
        if pat.groups >= 3:
            result = pat.sub(r"\1***:***@", result)
        else:
            result = pat.sub("[REDACTED]", result)
    return result


# ── K8s client helpers ─────────────────────────────────────────────────────

def _get_k8s_client() -> Any:
    """Get a Kubernetes CoreV1Api client. Detects in-cluster vs kubeconfig."""
    try:
        from kubernetes import client, config as k8s_config
    except ImportError:
        raise RuntimeError(
            "kubernetes package not installed. Run: pip install kubernetes"
        )

    try:
        # Try in-cluster first (ServiceAccount)
        k8s_config.load_incluster_config()
        logger.info("Using in-cluster Kubernetes configuration")
    except k8s_config.ConfigException:
        try:
            k8s_config.load_kube_config()
            logger.info("Using kubeconfig Kubernetes configuration")
        except (k8s_config.ConfigException, FileNotFoundError) as e:
            raise RuntimeError(
                f"Cannot connect to Kubernetes cluster. "
                f"No in-cluster config and no kubeconfig found: {e}\n"
                f"Make sure kubectl is configured or run inside a cluster."
            )

    return client.CoreV1Api()


def _get_apps_client() -> Any:
    """Get Kubernetes AppsV1Api client (assumes config already loaded)."""
    from kubernetes import client
    return client.AppsV1Api()


# ── Image listing ──────────────────────────────────────────────────────────

def list_running_images(namespace: str | None = None) -> list[ContainerImage]:
    """List all unique container images running in the cluster.

    Args:
        namespace: If provided, only scan this namespace. Otherwise scan all.

    Returns:
        List of ContainerImage with namespace/pod/container metadata.
    """
    v1 = _get_k8s_client()

    if namespace:
        pods = v1.list_namespaced_pod(namespace)
    else:
        pods = v1.list_pod_for_all_namespaces()

    images: list[ContainerImage] = []
    seen: set[tuple[str, str]] = set()  # (namespace, image) dedup

    for pod in pods.items:
        ns = pod.metadata.namespace
        pod_name = pod.metadata.name

        # Try to find owning deployment
        deployment = ""
        if pod.metadata.owner_references:
            for ref in pod.metadata.owner_references:
                if ref.kind == "ReplicaSet":
                    # Strip the RS hash suffix to get deployment name
                    parts = ref.name.rsplit("-", 1)
                    if len(parts) == 2:
                        deployment = parts[0]

        containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])
        for container in containers:
            img = container.image
            if not img:
                continue
            key = (ns, img)
            if key not in seen:
                seen.add(key)
                images.append(ContainerImage(
                    image=img,
                    namespace=ns,
                    pod=pod_name,
                    container=container.name,
                    deployment=deployment,
                ))

    logger.info("Found %d unique images across %s", len(images),
                f"namespace '{namespace}'" if namespace else "all namespaces")
    return images


# ── Package extraction ─────────────────────────────────────────────────────

def _detect_container_runtime() -> str | None:
    """Detect available container runtime (docker, podman, nerdctl)."""
    for runtime in ("docker", "podman", "nerdctl"):
        if shutil.which(runtime):
            return runtime
    return None


def _run_in_container(image: str, cmd: str, runtime: str = "docker") -> str | None:
    """Run a command in a container with overridden entrypoint. Returns stdout or None."""
    redacted_image = _redact_credentials(image)
    try:
        result = subprocess.run(
            [runtime, "run", "--rm", "--entrypoint", "/bin/sh", image, "-c", cmd],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            return result.stdout
        logger.debug("Command failed in %s (exit %d): %s",
                      redacted_image, result.returncode, result.stderr[:200])
        return None
    except subprocess.TimeoutExpired:
        logger.warning("Timeout extracting packages from %s", redacted_image)
        return None
    except FileNotFoundError:
        logger.warning("Container runtime '%s' not found", runtime)
        return None


def extract_packages_from_image(image: str) -> list[ImagePackage]:
    """Extract installed packages from a container image.

    Tries dpkg (debian/ubuntu), apk (alpine), rpm (rhel/centos).
    Falls back gracefully if no runtime is available.

    Args:
        image: Full image reference (e.g., nginx:1.25).

    Returns:
        List of ImagePackage.
    """
    runtime = _detect_container_runtime()
    if not runtime:
        logger.warning("No container runtime available (docker/podman/nerdctl). "
                       "Cannot extract packages from images.")
        return []

    packages: list[ImagePackage] = []

    # Try dpkg (Debian/Ubuntu)
    output = _run_in_container(
        image,
        "dpkg-query -W -f '${Package}\\t${Version}\\n' 2>/dev/null",
        runtime,
    )
    if output and output.strip():
        for line in output.strip().splitlines():
            parts = line.split("\t", 1)
            if len(parts) == 2 and parts[0].strip():
                packages.append(ImagePackage(
                    name=parts[0].strip(),
                    version=parts[1].strip(),
                    ecosystem="deb",
                ))
        if packages:
            return packages

    # Try apk (Alpine)
    output = _run_in_container(
        image,
        "apk list --installed 2>/dev/null",
        runtime,
    )
    if output and output.strip():
        for line in output.strip().splitlines():
            # Format: "package-name-1.2.3-r0 x86_64 {origin} ..."
            match = re.match(r"^(.+?)-(\d\S*)\s", line)
            if match:
                packages.append(ImagePackage(
                    name=match.group(1),
                    version=match.group(2),
                    ecosystem="apk",
                ))
        if packages:
            return packages

    # Try rpm (RHEL/CentOS/Fedora)
    output = _run_in_container(
        image,
        "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null",
        runtime,
    )
    if output and output.strip():
        for line in output.strip().splitlines():
            parts = line.split("\t", 1)
            if len(parts) == 2 and parts[0].strip():
                packages.append(ImagePackage(
                    name=parts[0].strip(),
                    version=parts[1].strip(),
                    ecosystem="rpm",
                ))
        if packages:
            return packages

    logger.info("Could not extract packages from %s (distroless or unsupported)",
                _redact_credentials(image))
    return packages


def inspect_image_packages(image: str) -> list[ImagePackage]:
    """Inspect image using skopeo/crane if available, else fall back to extract.

    Args:
        image: Full image reference.

    Returns:
        List of ImagePackage.
    """
    # Try skopeo inspect for metadata
    if shutil.which("skopeo"):
        try:
            result = subprocess.run(
                ["skopeo", "inspect", f"docker://{image}"],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                labels = data.get("Labels", {})
                logger.debug("Image labels for %s: %s",
                             _redact_credentials(image), list(labels.keys()))
        except Exception as e:
            logger.debug("skopeo inspect failed: %s", e)

    # Fall back to package extraction
    return extract_packages_from_image(image)


# ── SBOM generation ────────────────────────────────────────────────────────

def generate_sbom(image: str, format: str = "cyclonedx") -> dict[str, Any]:
    """Generate a CycloneDX or SPDX-lite SBOM from extracted packages.

    Args:
        image: Full image reference.
        format: "cyclonedx" or "spdx".

    Returns:
        SBOM dict.
    """
    packages = inspect_image_packages(image)

    if format == "spdx":
        return _generate_spdx(image, packages)
    return _generate_cyclonedx(image, packages)


def _generate_cyclonedx(image: str, packages: list[ImagePackage]) -> dict[str, Any]:
    """Generate CycloneDX 1.5 SBOM."""
    components = []
    for pkg in packages:
        purl_type = {"deb": "deb", "apk": "apk", "rpm": "rpm"}.get(pkg.ecosystem, "generic")
        components.append({
            "type": "library",
            "name": pkg.name,
            "version": pkg.version,
            "purl": f"pkg:{purl_type}/{pkg.name}@{pkg.version}",
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:sentinel-{image.replace(':', '-').replace('/', '-')}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "sentinel", "name": "sentinel-cve", "version": "0.1.0"}],
            "component": {
                "type": "container",
                "name": image,
            },
        },
        "components": components,
    }


def _generate_spdx(image: str, packages: list[ImagePackage]) -> dict[str, Any]:
    """Generate SPDX-lite SBOM."""
    spdx_packages = []
    for pkg in packages:
        spdx_packages.append({
            "SPDXID": f"SPDXRef-{pkg.name}",
            "name": pkg.name,
            "versionInfo": pkg.version,
            "downloadLocation": "NOASSERTION",
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"sentinel-sbom-{image}",
        "documentNamespace": f"https://sentinel.dev/sbom/{image}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat(),
            "creators": ["Tool: sentinel-cve-0.1.0"],
        },
        "packages": spdx_packages,
    }


# ── CVE checking ───────────────────────────────────────────────────────────

async def _check_packages_for_cve(
    packages: list[ImagePackage],
    cve_id: str | None = None,
) -> list[dict[str, Any]]:
    """Check packages against CVE data via OSV.

    Args:
        packages: List of image packages.
        cve_id: If provided, check only this CVE.

    Returns:
        List of vulnerability dicts.
    """
    if not packages:
        return []

    if cve_id:
        from sentinel.fetcher import fetch_cve_data
        from sentinel.scanner import Dependency, check_cve_impact

        deps = [
            Dependency(
                name=p.name,
                version=p.version,
                ecosystem=_ecosystem_to_osv(p.ecosystem),
                source_file=f"image:{p.ecosystem}",
            )
            for p in packages
        ]
        cve_data = await fetch_cve_data(cve_id)
        result = check_cve_impact(deps, cve_data)
        return result.details
    else:
        # Batch query OSV for all packages
        from sentinel.fetcher import batch_query_osv
        from sentinel.scanner import Dependency

        deps = [
            Dependency(
                name=p.name,
                version=p.version,
                ecosystem=_ecosystem_to_osv(p.ecosystem),
                source_file=f"image:{p.ecosystem}",
            )
            for p in packages
        ]
        return await batch_query_osv(deps)


def _ecosystem_to_osv(ecosystem: str) -> str:
    """Map internal ecosystem names to OSV ecosystem names."""
    return {
        "deb": "Debian",
        "apk": "Alpine",
        "rpm": "Red Hat",
    }.get(ecosystem, ecosystem)


# ── Full cluster scan ──────────────────────────────────────────────────────

async def scan_cluster(
    namespace: str | None = None,
    cve_id: str | None = None,
) -> K8sScanResult:
    """Full K8s scan pipeline: list images → extract packages → check CVEs.

    Args:
        namespace: Scan specific namespace, or all if None.
        cve_id: Check specific CVE, or all known vulns if None.

    Returns:
        K8sScanResult with all findings.
    """
    result = K8sScanResult(namespace=namespace, cve_id=cve_id)

    try:
        images = list_running_images(namespace=namespace)
    except RuntimeError as e:
        result.errors.append(str(e))
        return result

    result.images = images

    # Deduplicate by image name for scanning
    unique_images: dict[str, ContainerImage] = {}
    for img in images:
        if img.image not in unique_images:
            unique_images[img.image] = img

    for img_ref, img_obj in unique_images.items():
        logger.info("Scanning image: %s", _redact_credentials(img_ref))
        scan = ImageScanResult(image=img_ref)
        try:
            scan.packages = inspect_image_packages(img_ref)
            if scan.packages:
                scan.vulnerabilities = await _check_packages_for_cve(
                    scan.packages, cve_id=cve_id
                )
        except Exception as e:
            scan.error = str(e)
            result.errors.append(f"{_redact_credentials(img_ref)}: {e}")

        result.scan_results.append(scan)

    return result


async def scan_single_image(
    image: str,
    cve_id: str | None = None,
    generate_sbom_flag: bool = False,
) -> K8sScanResult:
    """Scan a single image without cluster connection.

    Args:
        image: Image reference (e.g., nginx:1.25).
        cve_id: Check specific CVE.
        generate_sbom_flag: Generate SBOM.

    Returns:
        K8sScanResult.
    """
    result = K8sScanResult(cve_id=cve_id)
    img_obj = ContainerImage(image=image)
    result.images = [img_obj]

    scan = ImageScanResult(image=image)
    try:
        scan.packages = inspect_image_packages(image)
        if scan.packages:
            scan.vulnerabilities = await _check_packages_for_cve(
                scan.packages, cve_id=cve_id
            )
    except Exception as e:
        scan.error = str(e)
        result.errors.append(str(e))

    result.scan_results.append(scan)
    return result
