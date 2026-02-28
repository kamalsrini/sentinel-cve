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
    _parse_build_gradle,
    _parse_gradle_version_catalog,
    _parse_podfile,
    _parse_podfile_lock,
    _parse_package_swift,
    _parse_package_resolved,
    _parse_pubspec_yaml,
    _parse_pubspec_lock,
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


class TestDetectMobileProjectTypes:
    def test_detects_android(self, tmp_repo: Path) -> None:
        (tmp_repo / "build.gradle").write_text("apply plugin: 'com.android.application'")
        result = detect_project_type(tmp_repo)
        assert "Maven" in result

    def test_detects_ios_cocoapods(self, tmp_repo: Path) -> None:
        (tmp_repo / "Podfile").write_text("pod 'Firebase'")
        result = detect_project_type(tmp_repo)
        assert "CocoaPods" in result

    def test_detects_ios_spm(self, tmp_repo: Path) -> None:
        (tmp_repo / "Package.resolved").write_text('{"pins": []}')
        result = detect_project_type(tmp_repo)
        assert "SwiftPM" in result

    def test_detects_flutter(self, tmp_repo: Path) -> None:
        (tmp_repo / "pubspec.yaml").write_text("name: myapp")
        result = detect_project_type(tmp_repo)
        assert "Pub" in result

    def test_detects_gradle_version_catalog(self, tmp_repo: Path) -> None:
        gradle_dir = tmp_repo / "gradle"
        gradle_dir.mkdir()
        (gradle_dir / "libs.versions.toml").write_text("[versions]\n")
        result = detect_project_type(tmp_repo)
        assert "Maven" in result


class TestBuildGradleParser:
    def test_parse_groovy_single_quotes(self, tmp_repo: Path) -> None:
        gradle = tmp_repo / "build.gradle"
        gradle.write_text("""
dependencies {
    implementation 'com.google.firebase:firebase-analytics:21.5.0'
    implementation "com.adjust.sdk:adjust-android:4.38.1"
    api 'com.facebook.android:facebook-android-sdk:16.3.0'
    testImplementation 'junit:junit:4.13.2'
}
""")
        deps = _parse_build_gradle(gradle, tmp_repo)
        assert len(deps) == 4
        names = {d.name for d in deps}
        assert "com.google.firebase:firebase-analytics" in names
        assert "com.adjust.sdk:adjust-android" in names
        assert "com.facebook.android:facebook-android-sdk" in names
        assert deps[0].ecosystem == "Maven"

    def test_parse_kotlin_dsl(self, tmp_repo: Path) -> None:
        gradle = tmp_repo / "build.gradle.kts"
        gradle.write_text("""
dependencies {
    implementation("com.google.firebase:firebase-analytics:21.5.0")
    implementation("com.adjust.sdk:adjust-android:4.38.1")
}
""")
        deps = _parse_build_gradle(gradle, tmp_repo)
        assert len(deps) == 2

    def test_variable_resolution_from_ext(self, tmp_repo: Path) -> None:
        gradle = tmp_repo / "build.gradle"
        gradle.write_text("""
ext {
    def firebaseBomVersion = "32.7.0"
}
dependencies {
    implementation "com.google.firebase:firebase-bom:$firebaseBomVersion"
}
""")
        deps = _parse_build_gradle(gradle, tmp_repo)
        assert len(deps) == 1
        assert deps[0].version == "32.7.0"

    def test_variable_resolution_from_gradle_properties(self, tmp_repo: Path) -> None:
        (tmp_repo / "gradle.properties").write_text("adjustVersion=4.38.1\n")
        gradle = tmp_repo / "build.gradle"
        gradle.write_text("""
dependencies {
    implementation "com.adjust.sdk:adjust-android:$adjustVersion"
}
""")
        deps = _parse_build_gradle(gradle, tmp_repo)
        assert len(deps) == 1
        assert deps[0].version == "4.38.1"

    def test_buildscript_classpath(self, tmp_repo: Path) -> None:
        gradle = tmp_repo / "build.gradle"
        gradle.write_text("""
buildscript {
    dependencies {
        classpath 'com.google.gms:google-services:4.4.0'
    }
}
""")
        deps = _parse_build_gradle(gradle, tmp_repo)
        assert len(deps) == 1
        assert deps[0].name == "com.google.gms:google-services"


class TestGradleVersionCatalog:
    def test_parse_version_catalog(self, tmp_repo: Path) -> None:
        catalog = tmp_repo / "libs.versions.toml"
        catalog.write_text("""
[versions]
firebase-bom = "32.7.0"
adjust = "4.38.1"

[libraries]
firebase-analytics = { module = "com.google.firebase:firebase-analytics", version.ref = "firebase-bom" }
adjust-android = { module = "com.adjust.sdk:adjust-android", version.ref = "adjust" }

[plugins]
android-application = { id = "com.android.application", version = "8.2.0" }
""")
        deps = _parse_gradle_version_catalog(catalog)
        assert len(deps) >= 2
        fb = [d for d in deps if "firebase-analytics" in d.name]
        assert len(fb) == 1
        assert fb[0].version == "32.7.0"
        adj = [d for d in deps if "adjust-android" in d.name]
        assert len(adj) == 1
        assert adj[0].version == "4.38.1"


class TestPodfileParsers:
    def test_parse_podfile(self) -> None:
        text = """
target 'MyApp' do
  pod 'Firebase/Analytics', '~> 10.0'
  pod 'Adjust', '4.37.0'
  pod 'FBSDKCoreKit', '~> 16.0'
  pod 'Alamofire'
end
"""
        deps = _parse_podfile(text, "Podfile")
        assert len(deps) == 4
        assert deps[0].name == "Firebase/Analytics"
        assert deps[0].version == "10.0"
        assert deps[0].ecosystem == "CocoaPods"
        assert deps[1].version == "4.37.0"
        assert deps[3].version == "*"

    def test_parse_podfile_lock(self) -> None:
        text = """PODS:
  - Adjust (4.37.0)
  - Firebase/Analytics (10.21.0):
    - Firebase/Core
    - FirebaseAnalytics (~> 10.21.0)
  - Firebase/Core (10.21.0):
    - FirebaseCore (= 10.21.0)
  - FBSDKCoreKit (16.3.1)

DEPENDENCIES:
  - Adjust (= 4.37.0)

SPEC REPOS:
  trunk:
    - Adjust
"""
        deps = _parse_podfile_lock(text, "Podfile.lock")
        assert len(deps) >= 3
        adj = [d for d in deps if d.name == "Adjust"]
        assert len(adj) == 1
        assert adj[0].version == "4.37.0"
        fb = [d for d in deps if d.name == "Firebase/Analytics"]
        assert len(fb) == 1
        assert fb[0].version == "10.21.0"


class TestSwiftPMParsers:
    def test_parse_package_swift(self) -> None:
        text = """
let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/firebase/firebase-ios-sdk.git", from: "10.21.0"),
        .package(url: "https://github.com/adjust/ios_sdk", exact: "4.37.0"),
        .package(url: "https://github.com/Alamofire/Alamofire.git", .upToNextMajor(from: "5.8.0")),
    ]
)
"""
        deps = _parse_package_swift(text, "Package.swift")
        assert len(deps) == 3
        assert deps[0].name == "firebase-ios-sdk"
        assert deps[0].version == "10.21.0"
        assert deps[0].ecosystem == "SwiftPM"
        assert deps[1].name == "ios_sdk"
        assert deps[1].version == "4.37.0"
        assert deps[2].version == "5.8.0"

    def test_parse_package_resolved_v2(self) -> None:
        text = json.dumps({
            "pins": [
                {
                    "identity": "firebase-ios-sdk",
                    "state": {"version": "10.21.0"},
                },
                {
                    "identity": "alamofire",
                    "state": {"version": "5.8.1"},
                },
            ]
        })
        deps = _parse_package_resolved(text, "Package.resolved")
        assert len(deps) == 2
        assert deps[0].name == "firebase-ios-sdk"
        assert deps[0].version == "10.21.0"
        assert deps[0].ecosystem == "SwiftPM"

    def test_parse_package_resolved_v1(self) -> None:
        text = json.dumps({
            "object": {
                "pins": [
                    {"package": "Alamofire", "state": {"version": "5.8.1"}},
                ]
            }
        })
        deps = _parse_package_resolved(text, "Package.resolved")
        assert len(deps) == 1
        assert deps[0].name == "Alamofire"


class TestPubspecParsers:
    def test_parse_pubspec_lock(self) -> None:
        text = """
packages:
  firebase_core:
    dependency: "direct main"
    version: "2.24.2"
  cupertino_icons:
    dependency: "direct main"
    version: "1.0.6"
  collection:
    dependency: transitive
    version: "1.18.0"
"""
        deps = _parse_pubspec_lock(text, "pubspec.lock")
        assert len(deps) == 3
        fb = [d for d in deps if d.name == "firebase_core"]
        assert len(fb) == 1
        assert fb[0].version == "2.24.2"
        assert fb[0].ecosystem == "Pub"

    def test_parse_pubspec_yaml(self) -> None:
        text = """
name: my_app
dependencies:
  firebase_core: ^2.24.2
  cupertino_icons: ^1.0.2

dev_dependencies:
  flutter_test:
    sdk: flutter
"""
        deps = _parse_pubspec_yaml(text, "pubspec.yaml")
        assert len(deps) >= 2
        fb = [d for d in deps if d.name == "firebase_core"]
        assert len(fb) == 1
        assert fb[0].version == "2.24.2"
        assert fb[0].ecosystem == "Pub"


class TestMobileExtractDependencies:
    def test_extract_from_podfile_lock(self, tmp_repo: Path) -> None:
        (tmp_repo / "Podfile").write_text("pod 'Firebase', '~> 10.0'")
        (tmp_repo / "Podfile.lock").write_text("""PODS:
  - Firebase/CoreOnly (10.21.0):
    - FirebaseCore (= 10.21.0)

DEPENDENCIES:
  - Firebase (~> 10.0)
""")
        deps = extract_dependencies(tmp_repo)
        assert len(deps) >= 1
        assert all(d.ecosystem == "CocoaPods" for d in deps)

    def test_extract_from_package_resolved(self, tmp_repo: Path) -> None:
        (tmp_repo / "Package.resolved").write_text(json.dumps({
            "pins": [
                {"identity": "alamofire", "state": {"version": "5.8.1"}},
            ]
        }))
        deps = extract_dependencies(tmp_repo)
        assert len(deps) == 1
        assert deps[0].ecosystem == "SwiftPM"

    def test_extract_prefers_podfile_lock_over_podfile(self, tmp_repo: Path) -> None:
        (tmp_repo / "Podfile").write_text("pod 'Firebase', '~> 10.0'")
        (tmp_repo / "Podfile.lock").write_text("""PODS:
  - Firebase/CoreOnly (10.21.0)

DEPENDENCIES:
  - Firebase (~> 10.0)
""")
        deps = extract_dependencies(tmp_repo)
        # Should use lockfile version (10.21.0), not manifest (~> 10.0 → 10.0)
        assert any(d.version == "10.21.0" for d in deps)
