"""Tests for tibet-sbom CLI."""

import json
import subprocess
import sys

import pytest


def run_cli(*args):
    """Run tibet-sbom CLI and return (stdout, stderr, returncode)."""
    result = subprocess.run(
        [sys.executable, "-m", "tibet_sbom"] + list(args),
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout, result.stderr, result.returncode


class TestCLIBasic:
    def test_help(self):
        stdout, _, rc = run_cli("--help")
        assert rc == 0
        assert "tibet-sbom" in stdout.lower() or "SBOM" in stdout

    def test_info(self):
        stdout, _, rc = run_cli("info")
        assert rc == 0
        assert "CRA" in stdout
        assert "EO 14028" in stdout or "14028" in stdout

    def test_no_command_shows_help(self):
        stdout, _, rc = run_cli()
        assert rc == 0
        assert "scan" in stdout


class TestCLIScan:
    def test_scan_nonexistent_path(self):
        _, stderr, rc = run_cli("scan", "/nonexistent/path")
        assert rc == 1

    def test_scan_real_project(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        stdout, _, rc = run_cli("scan", str(tmp_path))
        assert rc == 0
        assert "requests" in stdout

    def test_scan_json_output(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")
        stdout, _, rc = run_cli("scan", str(tmp_path), "--json")
        assert rc == 0
        data = json.loads(stdout)
        assert "components" in data


class TestCLIExport:
    def test_export_cyclonedx(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        stdout, _, rc = run_cli("export", str(tmp_path), "--format", "cyclonedx")
        assert rc == 0
        data = json.loads(stdout)
        assert data["bomFormat"] == "CycloneDX"

    def test_export_spdx(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        stdout, _, rc = run_cli("export", str(tmp_path), "--format", "spdx")
        assert rc == 0
        data = json.loads(stdout)
        assert data["spdxVersion"] == "SPDX-2.3"

    def test_export_tibet(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        stdout, _, rc = run_cli("export", str(tmp_path), "--format", "tibet")
        assert rc == 0
        data = json.loads(stdout)
        assert data["format"] == "TIBET-SBOM"


class TestCLICheck:
    def test_check_compliant(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.32.0\n")
        stdout, _, rc = run_cli("check", str(tmp_path))
        assert rc == 0
        assert "COMPLIANT" in stdout

    def test_check_json(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.32.0\n")
        stdout, _, rc = run_cli("check", str(tmp_path), "--json")
        assert rc == 0
        data = json.loads(stdout)
        assert "cra" in data
        assert "eo14028" in data


class TestCLIDemo:
    def test_demo_runs(self):
        stdout, _, rc = run_cli("demo")
        assert rc == 0
        assert "Step 1" in stdout
        assert "Step 5" in stdout
        assert "provenance" in stdout.lower()
