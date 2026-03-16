"""Tests for SBOMGenerator — scanning, parsing, and export."""

import json
import tempfile
from pathlib import Path

import pytest

from tibet_sbom.generator import SBOMGenerator, Component, Vulnerability, SBOMDocument


@pytest.fixture
def sample_pyproject(tmp_path):
    """Create a sample pyproject.toml for testing."""
    content = """\
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "test-project"
version = "1.0.0"
dependencies = [
    "requests>=2.28.0",
    "flask>=3.0.0",
]

[project.optional-dependencies]
dev = ["pytest>=7.0", "ruff>=0.1.0"]
full = ["redis>=5.0.0"]

[tool.hatch.build.targets.sdist]
include = ["/src"]

[tool.hatch.build.targets.wheel]
packages = ["src/test_project"]
"""
    f = tmp_path / "pyproject.toml"
    f.write_text(content)
    return tmp_path


@pytest.fixture
def sample_requirements(tmp_path):
    """Create a sample requirements.txt."""
    content = """\
# Core deps
requests==2.31.0
flask>=3.0.0
numpy==1.26.4
# Dev
-e .
"""
    f = tmp_path / "requirements.txt"
    f.write_text(content)
    return tmp_path


@pytest.fixture
def sample_cargo(tmp_path):
    """Create a sample Cargo.toml."""
    content = """\
[package]
name = "my-crate"
version = "0.5.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.35", features = ["full"] }

[dev-dependencies]
criterion = "0.5"
"""
    f = tmp_path / "Cargo.toml"
    f.write_text(content)
    return tmp_path


@pytest.fixture
def sample_package_json(tmp_path):
    """Create a sample package.json."""
    content = json.dumps({
        "name": "my-app",
        "version": "2.0.0",
        "dependencies": {
            "express": "^4.18.0",
            "lodash": "~4.17.21",
        },
        "devDependencies": {
            "jest": "^29.0.0",
        },
    })
    f = tmp_path / "package.json"
    f.write_text(content)
    return tmp_path


@pytest.fixture
def sample_gomod(tmp_path):
    """Create a sample go.mod."""
    content = """\
module github.com/example/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/go-sql-driver/mysql v1.7.1
)

require github.com/stretchr/testify v1.8.4
"""
    f = tmp_path / "go.mod"
    f.write_text(content)
    return tmp_path


class TestPyprojectParsing:
    def test_parses_project_name_and_version(self, sample_pyproject):
        gen = SBOMGenerator()
        sbom = gen.scan(str(sample_pyproject))
        assert sbom.project_name == "test-project"
        assert sbom.version == "1.0.0"

    def test_finds_direct_dependencies(self, sample_pyproject):
        gen = SBOMGenerator()
        sbom = gen.scan(str(sample_pyproject))
        names = {c.name for c in sbom.components if c.direct}
        assert "requests" in names
        assert "flask" in names

    def test_finds_optional_dependencies(self, sample_pyproject):
        gen = SBOMGenerator()
        sbom = gen.scan(str(sample_pyproject))
        names = {c.name for c in sbom.components}
        assert "pytest" in names
        assert "ruff" in names
        assert "redis" in names

    def test_excludes_paths_from_tool_sections(self, sample_pyproject):
        """Tool sections like [tool.hatch] should NOT produce components."""
        gen = SBOMGenerator()
        sbom = gen.scan(str(sample_pyproject))
        names = {c.name for c in sbom.components}
        assert "/src" not in names
        assert "src/test_project" not in names
        # Nothing starting with src
        assert not any(n.startswith("src") for n in names)


class TestRequirementsParsing:
    def test_parses_pinned_versions(self, sample_requirements):
        gen = SBOMGenerator()
        sbom = gen.scan(str(sample_requirements))
        comps = {c.name: c for c in sbom.components}
        assert "requests" in comps
        assert comps["requests"].version == "2.31.0"

    def test_parses_unpinned_versions(self, sample_requirements):
        gen = SBOMGenerator()
        sbom = gen.scan(str(sample_requirements))
        comps = {c.name: c for c in sbom.components}
        assert "flask" in comps

    def test_skips_flags_and_comments(self, sample_requirements):
        gen = SBOMGenerator()
        sbom = gen.scan(str(sample_requirements))
        names = {c.name for c in sbom.components}
        assert "-e" not in names
        assert "." not in names


class TestCargoParsing:
    def test_parses_cargo_deps(self, sample_cargo):
        gen = SBOMGenerator()
        sbom = gen.scan(str(sample_cargo))
        assert sbom.project_name == "my-crate"
        assert sbom.version == "0.5.0"
        names = {c.name for c in sbom.components}
        assert "serde" in names
        assert "tokio" in names
        assert "criterion" in names

    def test_cargo_source_is_crates(self, sample_cargo):
        gen = SBOMGenerator()
        sbom = gen.scan(str(sample_cargo))
        for comp in sbom.components:
            assert comp.source == "crates"


class TestPackageJsonParsing:
    def test_parses_npm_deps(self, sample_package_json):
        gen = SBOMGenerator()
        sbom = gen.scan(str(sample_package_json))
        assert sbom.project_name == "my-app"
        comps = {c.name: c for c in sbom.components}
        assert "express" in comps
        assert "lodash" in comps
        assert "jest" in comps

    def test_strips_version_prefixes(self, sample_package_json):
        gen = SBOMGenerator()
        sbom = gen.scan(str(sample_package_json))
        comps = {c.name: c for c in sbom.components}
        assert comps["express"].version == "4.18.0"
        assert comps["lodash"].version == "4.17.21"


class TestGoModParsing:
    def test_parses_go_deps(self, sample_gomod):
        gen = SBOMGenerator()
        sbom = gen.scan(str(sample_gomod))
        names = {c.name for c in sbom.components}
        assert "github.com/gin-gonic/gin" in names
        assert "github.com/go-sql-driver/mysql" in names
        assert "github.com/stretchr/testify" in names


class TestComponentProperties:
    def test_purl_generation(self):
        c = Component(name="requests", version="2.31.0", source="pypi")
        assert c.purl == "pkg:pypi/requests@2.31.0"

    def test_purl_npm(self):
        c = Component(name="express", version="4.18.0", source="npm")
        assert c.purl == "pkg:npm/express@4.18.0"

    def test_purl_empty_without_version(self):
        c = Component(name="requests", version="", source="pypi")
        assert c.purl == ""

    def test_to_dict(self):
        c = Component(name="foo", version="1.0", source="pypi", hash_sha256="abc123")
        d = c.to_dict()
        assert d["name"] == "foo"
        assert d["version"] == "1.0"
        assert d["hash_sha256"] == "abc123"


class TestSBOMDocument:
    def test_auto_generates_doc_id(self):
        doc = SBOMDocument()
        assert doc.doc_id.startswith("sbom-")

    def test_auto_generates_timestamp(self):
        doc = SBOMDocument()
        assert doc.timestamp  # non-empty


class TestVulnerabilityCheck:
    def test_detects_known_vuln(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        gen = SBOMGenerator()
        gen.scan(str(tmp_path))
        vulns = gen.check_vulnerabilities()
        assert len(vulns) >= 1
        assert any(v.cve_id == "CVE-2024-35195" for v in vulns)

    def test_no_false_positive_for_safe_version(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.32.0\n")
        gen = SBOMGenerator()
        gen.scan(str(tmp_path))
        vulns = gen.check_vulnerabilities()
        assert not any(v.cve_id == "CVE-2024-35195" for v in vulns)


class TestExportFormats:
    @pytest.fixture
    def scanned_gen(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask>=3.0.0\n")
        gen = SBOMGenerator()
        gen.scan(str(tmp_path))
        return gen

    def test_cyclonedx_structure(self, scanned_gen):
        cdx = scanned_gen.export_cyclonedx()
        assert cdx["bomFormat"] == "CycloneDX"
        assert cdx["specVersion"] == "1.5"
        assert len(cdx["components"]) >= 2
        assert "x-tibet" in cdx

    def test_spdx_structure(self, scanned_gen):
        spdx = scanned_gen.export_spdx()
        assert spdx["spdxVersion"] == "SPDX-2.3"
        assert spdx["dataLicense"] == "CC0-1.0"
        assert len(spdx["packages"]) >= 2

    def test_tibet_structure(self, scanned_gen):
        tibet = scanned_gen.export_tibet()
        assert tibet["format"] == "TIBET-SBOM"
        assert tibet["version"] == "0.1.0"
        assert tibet["chain_length"] >= 2
        assert len(tibet["provenance_chain"]) >= 2

    def test_tibet_includes_provenance_per_component(self, scanned_gen):
        tibet = scanned_gen.export_tibet()
        for comp in tibet["components"]:
            assert "tibet_provenance" in comp
            prov = comp["tibet_provenance"]
            assert "erin" in prov
            assert "eraan" in prov
            assert "eromheen" in prov
            assert "erachter" in prov


class TestProvenance:
    def test_tokens_created_for_each_component(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask>=3.0.0\n")
        gen = SBOMGenerator()
        sbom = gen.scan(str(tmp_path))
        # At least the 2 direct deps should have tokens
        with_tokens = [c for c in sbom.components if c.tibet_token_id]
        assert len(with_tokens) >= 2

    def test_hash_is_full_sha256(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        gen = SBOMGenerator()
        sbom = gen.scan(str(tmp_path))
        for comp in sbom.components:
            if comp.hash_sha256:
                assert len(comp.hash_sha256) == 64  # Full SHA-256


class TestPackageNameValidation:
    def test_rejects_paths(self):
        assert not SBOMGenerator._is_valid_package_name("/src")
        assert not SBOMGenerator._is_valid_package_name("src/tibet_core")
        assert not SBOMGenerator._is_valid_package_name("./lib")

    def test_accepts_valid_names(self):
        assert SBOMGenerator._is_valid_package_name("requests")
        assert SBOMGenerator._is_valid_package_name("flask")
        assert SBOMGenerator._is_valid_package_name("tibet-core")
        assert SBOMGenerator._is_valid_package_name("pydantic")

    def test_rejects_empty(self):
        assert not SBOMGenerator._is_valid_package_name("")
