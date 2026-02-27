# tibet-sbom — Software Bill of Materials + TIBET Provenance

**Every dependency traced. Every build proven.**

The EU Cyber Resilience Act (CRA) requires Software Bills of Materials for
all products with digital elements sold in the EU. The US Executive Order
14028 mandates machine-readable SBOMs for government software. Existing
tools like Syft and CycloneDX generate dependency lists — but a list alone
proves nothing about *where* a component came from, *why* that version was
chosen, or *what* the build context was.

tibet-sbom adds **TIBET provenance** to SBOMs. Every dependency becomes a
TIBET token with four dimensions:

| Dimension   | SBOM Meaning                                       |
|-------------|-----------------------------------------------------|
| **ERIN**    | Component name, version, hash, source registry      |
| **ERAAN**   | Parent component, dependency chain, `jis:` URI       |
| **EROMHEEN**| Scan environment, timestamp, scanner version         |
| **ERACHTER**| Why this component, why this version, build context  |

## Compatible Formats

- **CycloneDX** — OWASP standard, JSON/XML
- **SPDX** — Linux Foundation standard, ISO/IEC 5962
- **TIBET** — Full provenance chain per component

## Installation

```bash
pip install tibet-sbom
```

With rich terminal output:

```bash
pip install tibet-sbom[full]
```

## Quick Start

```python
from tibet_sbom import SBOMGenerator

gen = SBOMGenerator()
sbom = gen.scan("/path/to/project")

print(f"Found {len(sbom.components)} components")
print(f"TIBET chain: {sbom.tibet_chain_length} tokens")

# Export as CycloneDX
cyclonedx = gen.export_cyclonedx()

# Export with full TIBET provenance
tibet = gen.export_tibet()
```

## CLI Usage

```bash
# Concept overview — what tibet-sbom does and why
tibet-sbom info

# Scan a project and print SBOM summary
tibet-sbom scan /path/to/project

# Export in specific format
tibet-sbom export /path/to/project --format cyclonedx
tibet-sbom export /path/to/project --format spdx
tibet-sbom export /path/to/project --format tibet

# Compliance check against CRA and EO 14028
tibet-sbom check /path/to/project

# Demo with sample project
tibet-sbom demo
```

All commands support `--json` for machine-readable output.

## Why Not Just Syft/CycloneDX?

Those tools answer: *"What dependencies does this project have?"*

tibet-sbom answers: *"What dependencies does this project have, where did
each one come from, what was the build environment when it was scanned,
and can you cryptographically prove the chain of custody?"*

A dependency list without provenance is a checklist. A dependency list
with TIBET provenance is **evidence**.

## Regulatory Context

- **EU CRA** (Cyber Resilience Act) — Regulation (EU) 2024/2847.
  Requires manufacturers to identify and document vulnerabilities and
  components, maintain SBOMs, and provide security updates.
- **US EO 14028** — Executive Order on Improving the Nation's
  Cybersecurity. Requires machine-readable SBOMs, supplier
  identification, and integrity verification for government software.

## License

MIT — Humotica AI Lab 2025-2026

Part of the [TIBET protocol](https://pypi.org/project/tibet-core/) family.
