"""Tests for K8s Runtime BOM Scanner."""

from __future__ import annotations

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from sentinel.k8s_scanner import (
    ContainerImage,
    ImagePackage,
    ImageScanResult,
    K8sScanResult,
    _redact_credentials,
    _generate_cyclonedx,
    _generate_spdx,
    extract_packages_from_image,
    list_running_images,
)


# ── Credential redaction ──────────────────────────────────────────────────

def test_redact_credentials_url():
    text = "Pulling from https://user:secretpass@registry.example.com/image"
    result = _redact_credentials(text)
    assert "secretpass" not in result
    assert "***" in result


def test_redact_credentials_no_creds():
    text = "Pulling from nginx:1.25"
    result = _redact_credentials(text)
    assert result == text


def test_redact_credentials_token():
    text = "password=mysecrettoken"
    result = _redact_credentials(text)
    assert "mysecrettoken" not in result


# ── Image package parsing ─────────────────────────────────────────────────

def test_image_package_dataclass():
    pkg = ImagePackage(name="nginx", version="1.25.0", ecosystem="deb")
    assert pkg.name == "nginx"
    assert pkg.version == "1.25.0"
    assert pkg.ecosystem == "deb"


def test_container_image_name_tag():
    img = ContainerImage(image="registry.example.com/myapp:v1.0", namespace="prod")
    assert img.name_tag == "myapp:v1.0"


def test_container_image_simple():
    img = ContainerImage(image="nginx:latest")
    assert img.name_tag == "nginx:latest"


# ── SBOM generation ────────────────────────────────────────────────────────

def test_cyclonedx_sbom_structure():
    packages = [
        ImagePackage(name="openssl", version="3.0.2", ecosystem="deb"),
        ImagePackage(name="zlib", version="1.2.11", ecosystem="deb"),
    ]
    sbom = _generate_cyclonedx("nginx:1.25", packages)
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert len(sbom["components"]) == 2
    assert sbom["components"][0]["name"] == "openssl"
    assert sbom["components"][0]["purl"] == "pkg:deb/openssl@3.0.2"
    assert sbom["metadata"]["component"]["type"] == "container"


def test_spdx_sbom_structure():
    packages = [
        ImagePackage(name="bash", version="5.1", ecosystem="apk"),
    ]
    sbom = _generate_spdx("alpine:3.18", packages)
    assert sbom["spdxVersion"] == "SPDX-2.3"
    assert len(sbom["packages"]) == 1
    assert sbom["packages"][0]["name"] == "bash"


def test_empty_sbom():
    sbom = _generate_cyclonedx("empty:latest", [])
    assert sbom["components"] == []


# ── K8sScanResult ──────────────────────────────────────────────────────────

def test_scan_result_to_dict():
    result = K8sScanResult(
        images=[ContainerImage(image="nginx:1.25", namespace="default")],
        scan_results=[ImageScanResult(image="nginx:1.25", packages=[])],
        namespace="default",
    )
    d = result.to_dict()
    assert d["namespace"] == "default"
    assert len(d["images"]) == 1
    assert d["images"][0]["image"] == "nginx:1.25"


# ── RBAC manifest validation ──────────────────────────────────────────────

def test_rbac_manifest_exists():
    rbac_path = Path(__file__).parent.parent / "config" / "k8s-rbac.yaml"
    assert rbac_path.exists(), "k8s-rbac.yaml should exist in config/"


def test_rbac_manifest_content():
    rbac_path = Path(__file__).parent.parent / "config" / "k8s-rbac.yaml"
    content = rbac_path.read_text()
    assert "ClusterRole" in content
    assert "sentinel-readonly" in content
    assert '"get"' in content or "'get'" in content or "get" in content
    assert '"list"' in content or "'list'" in content or "list" in content
    # Must NOT have write/create/delete verbs
    assert '"create"' not in content
    assert '"delete"' not in content
    assert '"update"' not in content
    assert '"patch"' not in content
    assert "ServiceAccount" in content
    assert "ClusterRoleBinding" in content


# ── K8s client graceful failure ────────────────────────────────────────────

def test_list_images_no_k8s_graceful():
    """Should raise RuntimeError with clear message when K8s unavailable."""
    with patch("sentinel.k8s_scanner._get_k8s_client") as mock:
        mock.side_effect = RuntimeError("Cannot connect to Kubernetes cluster.")
        with pytest.raises(RuntimeError, match="Cannot connect"):
            list_running_images()


# ── Mock K8s client ────────────────────────────────────────────────────────

def test_list_images_with_mock_client():
    """Test image listing with mocked K8s client."""
    mock_pod = MagicMock()
    mock_pod.metadata.namespace = "default"
    mock_pod.metadata.name = "web-abc123"
    mock_pod.metadata.owner_references = []
    mock_container = MagicMock()
    mock_container.image = "nginx:1.25"
    mock_container.name = "nginx"
    mock_pod.spec.containers = [mock_container]
    mock_pod.spec.init_containers = []

    mock_pods = MagicMock()
    mock_pods.items = [mock_pod]

    with patch("sentinel.k8s_scanner._get_k8s_client") as mock_client:
        mock_v1 = MagicMock()
        mock_v1.list_pod_for_all_namespaces.return_value = mock_pods
        mock_client.return_value = mock_v1

        images = list_running_images()
        assert len(images) == 1
        assert images[0].image == "nginx:1.25"
        assert images[0].namespace == "default"


# ── Package extraction without runtime ─────────────────────────────────────

def test_extract_packages_no_runtime():
    """Should return empty list when no container runtime available."""
    with patch("sentinel.k8s_scanner._detect_container_runtime", return_value=None):
        result = extract_packages_from_image("nginx:1.25")
        assert result == []
