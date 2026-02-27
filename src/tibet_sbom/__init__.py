"""
tibet-sbom — Software Bill of Materials + TIBET Provenance
==========================================================

Every dependency traced. Every build proven.

The EU Cyber Resilience Act requires SBOMs. Existing tools generate lists.
tibet-sbom adds provenance. Every dependency becomes a TIBET token:
what it is, where it came from, the build context, why this version.

Compatible with CycloneDX and SPDX. Adds TIBET provenance on top.

Usage::

    from tibet_sbom import SBOMGenerator

    gen = SBOMGenerator()
    sbom = gen.scan("/path/to/project")

    print(f"Found {len(sbom.components)} components")

    cyclonedx = gen.export_cyclonedx()
    tibet = gen.export_tibet()

Authors: J. van de Meent & R. AI (Root AI)
License: MIT — Humotica AI Lab 2025-2026
"""

from .generator import SBOMGenerator, SBOMDocument, Component, Vulnerability
from .provenance import SBOMProvenance

__version__ = "0.1.0"

__all__ = [
    "SBOMGenerator",
    "SBOMDocument",
    "Component",
    "Vulnerability",
    "SBOMProvenance",
]
