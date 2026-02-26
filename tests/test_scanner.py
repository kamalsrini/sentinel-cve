"""Tests for the repo scanner module."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from sentinel.scanner import (
    Dependency,
    detect_project_type,
    extract_dependencies,
    check_cve_impact,
    _parse_package_lock,
    _parse_yarn_lock,
    _parse_requirements_txt,
    _parse_pipfile_lock,
    _parse_go_sum,
    _parse_cargo_lock,
    _parse_gemfile_lock,
    _parse_composer_lock,
    _version_in_range,
    _names_match,
)


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    """Create a temporary repo with various dependency files."""
    return tmp_path


class TestDetectProjectType:
    def test_detects_npm(self, tmp_repo: Path) -> None:
        (tmp_repo / "package.json").write_text("{}")
        (tmp_repo / "package-lock.json").write_text("{}")
        result = detect_project_type(tmp_repo)
        assert "npm" in result
        assert len(result["npm"]) == 2

    def test_detects_python(self, tmp_repo: Path) -> None:
        (tmp_repo / "requirements.txt").write_text("flask==2.0.0")
        result = detect_project_type(tmp_repo)
        assert "PyPI" in result

    def test_detects_multiple(self, tmp_repo: Path) -> None:
        (tmp_repo / "package.json").write_text("{}")
        (tmp_repo / "requirements.txt").write_text("")
        (tmp_repo / "go.mod").write_text("")
        result = detect_project_type(tmp_repo)
        assert "npm" in result
        assert "PyPI" in result
        assert "Go" in result

    def test_skips_node_modules(self, tmp_repo: Path) -> None:
        nm = tmp_repo / "node_modules" / "foo"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text("{}")
        result = detect_project_type(tmp_repo)
        assert "npm" not in result

    def test_detects_csproj(self, tmp_repo: Path) -> None:
        (tmp_repo / "MyApp.csproj").write_text("<Project/>")
        result = detect_project_type(tmp_repo)
        assert "NuGet" in result

    def test_empty_repo(self, tmp_repo: Path) -> None:
        result = detect_project_type(tmp_repo)
        assert result == {}


class TestParsers:
    def test_parse_package_lock_v2(self) -> None:
        data = json.dumps({
            "packages": {
                "": {"name": "myapp", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/express": {"version": "4.18.2"},
            }
        })
        deps = _parse_package_lock(data, "package-lock.json")
        assert len(deps) == 2
        names = {d.name for d in deps}
        assert "lodash" in names
        assert "express" in names

    def test_parse_package_lock_v1(self) -> None:
        data = json.dumps({
            "dependencies": {
                "lodash": {"version": "4.17.21"},
                "express": {
                    "version": "4.18.2",
                    "dependencies": {
                        "accepts": {"version": "1.3.8"}
                    }
                },
            }
        })
        deps = _parse_package_lock(data, "package-lock.json")
        assert len(deps) == 3

    def test_parse_yarn_lock(self) -> None:
        text = '''"lodash@^4.17.20":
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

"express@^4.18.0":
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
'''
        deps = _parse_yarn_lock(text, "yarn.lock")
        assert len(deps) == 2
        assert deps[0].name == "lodash"
        assert deps[0].version == "4.17.21"

    def test_parse_requirements_txt(self) -> None:
        text = """flask==2.0.0
requests>=2.28.0
# comment
-r other.txt
numpy~=1.24.0
boto3
"""
        deps = _parse_requirements_txt(text, "requirements.txt")
        assert len(deps) == 4
        assert deps[0].name == "flask"
        assert deps[0].version == "2.0.0"
        assert deps[3].name == "boto3"
        assert deps[3].version == "*"

    def test_parse_pipfile_lock(self) -> None:
        data = json.dumps({
            "_meta": {},
            "default": {
                "flask": {"version": "==2.0.0"},
                "requests": {"version": "==2.28.1"},
            },
            "develop": {
                "pytest": {"version": "==7.4.0"},
            },
        })
        deps = _parse_pipfile_lock(data, "Pipfile.lock")
        assert len(deps) == 3
        assert deps[0].version == "2.0.0"

    def test_parse_go_sum(self) -> None:
        text = """github.com/gin-gonic/gin v1.9.1 h1:abc=
github.com/gin-gonic/gin v1.9.1/go.mod h1:def=
golang.org/x/text v0.12.0 h1:ghi=
"""
        deps = _parse_go_sum(text, "go.sum")
        assert len(deps) == 2  # deduplicated
        assert deps[0].name == "github.com/gin-gonic/gin"
        assert deps[0].version == "1.9.1"

    def test_parse_cargo_lock(self) -> None:
        text = """[[package]]
name = "serde"
version = "1.0.188"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.32.0"
"""
        deps = _parse_cargo_lock(text, "Cargo.lock")
        assert len(deps) == 2
        assert deps[0].name == "serde"

    def test_parse_gemfile_lock(self) -> None:
        text = """GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.4)
      actioncable (= 7.0.4)
    actioncable (7.0.4)

PLATFORMS
  ruby
"""
        deps = _parse_gemfile_lock(text, "Gemfile.lock")
        assert len(deps) >= 1
        assert deps[0].name == "rails"

    def test_parse_composer_lock(self) -> None:
        data = json.dumps({
            "packages": [
                {"name": "laravel/framework", "version": "v10.0.0"},
                {"name": "guzzlehttp/guzzle", "version": "v7.8.0"},
            ],
            "packages-dev": [
                {"name": "phpunit/phpunit", "version": "v10.3.0"},
            ],
        })
        deps = _parse_composer_lock(data, "composer.lock")
        assert len(deps) == 3
        assert deps[0].version == "10.0.0"  # v stripped


class TestExtractDependencies:
    def test_extract_from_requirements(self, tmp_repo: Path) -> None:
        (tmp_repo / "requirements.txt").write_text("flask==2.0.0\nrequests==2.28.0\n")
        deps = extract_dependencies(tmp_repo)
        assert len(deps) == 2
        assert all(d.ecosystem == "PyPI" for d in deps)

    def test_extract_prefers_lockfile(self, tmp_repo: Path) -> None:
        (tmp_repo / "package.json").write_text('{"dependencies": {"lodash": "^4.17.20"}}')
        (tmp_repo / "package-lock.json").write_text(json.dumps({
            "packages": {
                "": {"name": "app"},
                "node_modules/lodash": {"version": "4.17.21"},
            }
        }))
        deps = extract_dependencies(tmp_repo)
        # Should get from lockfile, not manifest
        assert any(d.version == "4.17.21" for d in deps)


class TestVersionMatching:
    def test_version_in_range_basic(self) -> None:
        events = [{"introduced": "0"}, {"fixed": "2.0.0"}]
        assert _version_in_range("1.5.0", events, []) is True
        assert _version_in_range("2.0.0", events, []) is False
        assert _version_in_range("2.1.0", events, []) is False

    def test_version_in_range_with_introduced(self) -> None:
        events = [{"introduced": "1.0.0"}, {"fixed": "1.5.0"}]
        assert _version_in_range("0.9.0", events, []) is False
        assert _version_in_range("1.2.0", events, []) is True
        assert _version_in_range("1.5.0", events, []) is False

    def test_version_in_explicit_list(self) -> None:
        assert _version_in_range("1.2.3", [], ["1.2.3", "1.2.4"]) is True
        assert _version_in_range("1.2.5", [], ["1.2.3", "1.2.4"]) is False

    def test_names_match(self) -> None:
        assert _names_match("flask", "Flask", "PyPI") is True
        assert _names_match("my-package", "my_package", "npm") is True
        assert _names_match("foo", "bar", "npm") is False


class TestCheckCveImpact:
    def test_affected(self) -> None:
        deps = [Dependency(name="lxml", version="4.9.1", ecosystem="PyPI")]
        cve_data = {
            "sources": {
                "osv": {
                    "affected": [{
                        "package": {"name": "lxml", "ecosystem": "PyPI"},
                        "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.9.3"}]}],
                        "versions": [],
                    }]
                }
            }
        }
        result = check_cve_impact(deps, cve_data)
        assert result.affected is True
        assert result.status == "AFFECTED"
        assert result.details[0]["fix_version"] == "4.9.3"

    def test_not_affected_patched(self) -> None:
        deps = [Dependency(name="lxml", version="4.9.3", ecosystem="PyPI")]
        cve_data = {
            "sources": {
                "osv": {
                    "affected": [{
                        "package": {"name": "lxml", "ecosystem": "PyPI"},
                        "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.9.3"}]}],
                        "versions": [],
                    }]
                }
            }
        }
        result = check_cve_impact(deps, cve_data)
        assert result.affected is False
        assert result.status == "NOT_AFFECTED"

    def test_no_matching_dep(self) -> None:
        deps = [Dependency(name="requests", version="2.28.0", ecosystem="PyPI")]
        cve_data = {
            "sources": {
                "osv": {
                    "affected": [{
                        "package": {"name": "lxml", "ecosystem": "PyPI"},
                        "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.9.3"}]}],
                        "versions": [],
                    }]
                }
            }
        }
        result = check_cve_impact(deps, cve_data)
        assert result.affected is False
        assert result.status == "NOT_AFFECTED"

    def test_no_osv_data(self) -> None:
        deps = [Dependency(name="lxml", version="4.9.1", ecosystem="PyPI")]
        cve_data = {"sources": {"nvd": {}}}
        result = check_cve_impact(deps, cve_data)
        assert result.status == "UNKNOWN"
