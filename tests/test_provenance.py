"""Tests for SBOM provenance token creation."""

from tibet_sbom.provenance import SBOMProvenance, SBOMToken


class TestSBOMProvenance:
    def test_creates_token(self):
        prov = SBOMProvenance()
        token = prov.create_token(
            component_name="requests",
            component_version="2.31.0",
            component_hash="abc123",
            source="pypi",
            parent_component="myapp",
            scan_path="/tmp/test",
        )
        assert isinstance(token, SBOMToken)
        assert token.component_name == "requests"
        assert token.component_version == "2.31.0"

    def test_erin_populated(self):
        prov = SBOMProvenance()
        token = prov.create_token("flask", "3.0.0", "hash", "pypi", "app", "/tmp")
        assert token.erin["component"] == "flask"
        assert token.erin["version"] == "3.0.0"
        assert token.erin["source"] == "pypi"

    def test_eraan_populated(self):
        prov = SBOMProvenance()
        token = prov.create_token("flask", "3.0.0", "hash", "pypi", "myapp", "/tmp")
        assert token.eraan["parent_component"] == "myapp"
        assert "myapp -> flask" in token.eraan["dependency_chain"]
        assert token.eraan["component_jis"] == "jis:pypi:flask:3.0.0"

    def test_eromheen_populated(self):
        prov = SBOMProvenance()
        token = prov.create_token("flask", "3.0.0", "hash", "pypi", "app", "/tmp/proj")
        assert token.eromheen["scan_path"] == "/tmp/proj"
        assert token.eromheen["scanner"] == "tibet-sbom"

    def test_erachter_populated(self):
        prov = SBOMProvenance()
        token = prov.create_token("flask", "3.0.0", "hash", "pypi", "app", "/tmp")
        assert "flask" in token.erachter["intent"]
        assert "EU CRA" in token.erachter["compliance_context"]

    def test_chain_links(self):
        prov = SBOMProvenance()
        t1 = prov.create_token("a", "1.0", "", "pypi", "proj", "/tmp")
        t2 = prov.create_token("b", "2.0", "", "pypi", "proj", "/tmp")
        assert t2.parent_id == t1.token_id

    def test_chain_export(self):
        prov = SBOMProvenance()
        prov.create_token("a", "1.0", "", "pypi", "proj", "/tmp")
        prov.create_token("b", "2.0", "", "pypi", "proj", "/tmp")
        chain = prov.chain()
        assert len(chain) == 2
        assert chain[0]["component_name"] == "a"
        assert chain[1]["component_name"] == "b"

    def test_token_to_dict(self):
        prov = SBOMProvenance()
        token = prov.create_token("x", "1.0", "hash", "pypi", "proj", "/tmp")
        d = token.to_dict()
        assert d["type"] == "sbom_component"
        assert "erin" in d
        assert "eraan" in d
        assert "eromheen" in d
        assert "erachter" in d
