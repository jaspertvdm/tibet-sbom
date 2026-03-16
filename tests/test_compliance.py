"""Tests for compliance checks (CRA, EO 14028)."""

import pytest

from tibet_sbom.generator import SBOMGenerator, SBOMDocument, Component
from tibet_sbom.compliance import check_cra, check_eo14028, ComplianceResult


@pytest.fixture
def compliant_sbom():
    """Create a fully compliant SBOM with controlled components (no env deps)."""
    doc = SBOMDocument(
        project_name="test-project",
        version="1.0.0",
        components=[
            Component(
                name="requests",
                version="2.32.0",
                source="pypi",
                hash_sha256="a" * 64,
                tibet_token_id="tok_1",
            ),
            Component(
                name="flask",
                version="3.0.0",
                source="pypi",
                hash_sha256="b" * 64,
                tibet_token_id="tok_2",
            ),
        ],
        metadata={"scanner": "tibet-sbom"},
    )
    return doc


@pytest.fixture
def incomplete_sbom():
    """Create an SBOM with gaps."""
    doc = SBOMDocument(
        project_name="bad-project",
        version="1.0.0",
        components=[
            Component(name="mystery", version="", source="unknown"),
        ],
        metadata={"scanner": "tibet-sbom"},
    )
    return doc


class TestCRA:
    def test_compliant_sbom_passes(self, compliant_sbom):
        result = check_cra(compliant_sbom)
        assert result.compliant
        assert result.score == 1.0
        assert len(result.gaps) == 0

    def test_incomplete_sbom_fails(self, incomplete_sbom):
        result = check_cra(incomplete_sbom)
        assert not result.compliant
        assert result.score < 1.0
        assert len(result.gaps) > 0

    def test_empty_sbom(self):
        doc = SBOMDocument()
        result = check_cra(doc)
        assert not result.compliant

    def test_result_to_dict(self, compliant_sbom):
        result = check_cra(compliant_sbom)
        d = result.to_dict()
        assert "standard" in d
        assert "compliant" in d
        assert "score" in d
        assert "details" in d


class TestEO14028:
    def test_compliant_sbom_passes(self, compliant_sbom):
        result = check_eo14028(compliant_sbom)
        assert result.compliant
        assert result.score == 1.0

    def test_no_hash_flags_gap(self, incomplete_sbom):
        result = check_eo14028(incomplete_sbom)
        assert not result.compliant
        gap_text = " ".join(result.gaps)
        assert "hash" in gap_text.lower() or "PURL" in gap_text

    def test_standard_name(self, compliant_sbom):
        result = check_eo14028(compliant_sbom)
        assert "14028" in result.standard
