"""
SBOM Generator — the core scanning and export engine.

Scans projects for dependencies across ecosystems (Python, Node, Rust, Go).
Generates SBOMDocument with full component inventory. Exports to CycloneDX,
SPDX, or TIBET provenance format.

Other tools answer: "What dependencies does this project have?"
tibet-sbom answers: "What, from where, in what context, and can you prove it?"
"""

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from .provenance import SBOMProvenance


@dataclass
class Vulnerability:
    """
    A known vulnerability associated with a component.

    Mapped from CVE databases or pattern-based detection.
    """
    cve_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    affected_versions: str = ""
    fixed_in: str = ""

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "description": self.description,
            "affected_versions": self.affected_versions,
            "fixed_in": self.fixed_in,
        }


@dataclass
class Component:
    """
    A single dependency in the SBOM.

    Each component maps to a TIBET token via tibet_token_id. The token
    records the full provenance: what the component is, where it came
    from, the scan context, and why it was included.
    """
    name: str
    version: str
    purl: str = ""  # Package URL (pkg:pypi/requests@2.31.0)
    source: str = "unknown"  # pypi, npm, crates, maven, golang, system
    license: str = ""
    hash_sha256: str = ""
    direct: bool = True  # Direct dependency (True) or transitive (False)
    tibet_token_id: str = ""
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.purl and self.name and self.version:
            source_map = {
                "pypi": "pypi",
                "npm": "npm",
                "crates": "cargo",
                "maven": "maven",
                "golang": "golang",
            }
            purl_type = source_map.get(self.source, self.source)
            self.purl = f"pkg:{purl_type}/{self.name}@{self.version}"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "source": self.source,
            "license": self.license,
            "hash_sha256": self.hash_sha256,
            "direct": self.direct,
            "tibet_token_id": self.tibet_token_id,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }


@dataclass
class SBOMDocument:
    """
    Complete Software Bill of Materials for a project.

    Contains all discovered components, metadata, and TIBET chain info.
    """
    doc_id: str = ""
    project_name: str = ""
    version: str = ""
    timestamp: str = ""
    components: list[Component] = field(default_factory=list)
    format: str = "tibet"  # tibet, cyclonedx, spdx
    tibet_chain_length: int = 0
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.doc_id:
            self.doc_id = f"sbom-{uuid4().hex[:12]}"
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "doc_id": self.doc_id,
            "project_name": self.project_name,
            "version": self.version,
            "timestamp": self.timestamp,
            "components": [c.to_dict() for c in self.components],
            "component_count": len(self.components),
            "format": self.format,
            "tibet_chain_length": self.tibet_chain_length,
            "metadata": self.metadata,
        }


# --- Known vulnerability patterns (offline heuristic) ---

_KNOWN_PATTERNS: list[dict] = [
    {
        "name": "requests",
        "below": "2.32.0",
        "cve": "CVE-2024-35195",
        "severity": "MEDIUM",
        "desc": "Incorrect certificate verification in requests",
        "fixed_in": "2.32.0",
    },
    {
        "name": "urllib3",
        "below": "2.0.7",
        "cve": "CVE-2023-45803",
        "severity": "MEDIUM",
        "desc": "Request body not stripped on redirect in urllib3",
        "fixed_in": "2.0.7",
    },
    {
        "name": "cryptography",
        "below": "41.0.6",
        "cve": "CVE-2023-49083",
        "severity": "HIGH",
        "desc": "NULL dereference in PKCS12 parsing in cryptography",
        "fixed_in": "41.0.6",
    },
    {
        "name": "setuptools",
        "below": "70.0.0",
        "cve": "CVE-2024-6345",
        "severity": "HIGH",
        "desc": "Remote code execution via download functions in setuptools",
        "fixed_in": "70.0.0",
    },
    {
        "name": "pillow",
        "below": "10.3.0",
        "cve": "CVE-2024-28219",
        "severity": "HIGH",
        "desc": "Buffer overflow in Pillow image processing",
        "fixed_in": "10.3.0",
    },
    {
        "name": "lodash",
        "below": "4.17.21",
        "cve": "CVE-2021-23337",
        "severity": "HIGH",
        "desc": "Command injection via template function in lodash",
        "fixed_in": "4.17.21",
    },
    {
        "name": "express",
        "below": "4.20.0",
        "cve": "CVE-2024-29041",
        "severity": "MEDIUM",
        "desc": "Open redirect in express via malformed URLs",
        "fixed_in": "4.20.0",
    },
]


def _version_tuple(v: str) -> tuple:
    """Parse version string into comparable tuple."""
    parts = []
    for segment in re.split(r"[.\-]", v):
        try:
            parts.append(int(segment))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _is_below(current: str, threshold: str) -> bool:
    """Check if current version is below threshold."""
    try:
        return _version_tuple(current) < _version_tuple(threshold)
    except Exception:
        return False


class SBOMGenerator:
    """
    SBOM Generator with TIBET provenance.

    Scans projects for dependencies, builds a complete component inventory,
    and attaches TIBET provenance tokens to every component.

    Usage::

        gen = SBOMGenerator()
        sbom = gen.scan("/path/to/project")
        cyclonedx = gen.export_cyclonedx()
        tibet = gen.export_tibet()
    """

    def __init__(self, actor: str = "tibet-sbom"):
        self.actor = actor
        self.provenance = SBOMProvenance(actor=actor)
        self._components: list[Component] = []
        self._document: Optional[SBOMDocument] = None
        self._scan_path: str = ""

    def scan(self, path: str) -> SBOMDocument:
        """
        Scan a project for all dependencies.

        Detects: pyproject.toml, requirements.txt, package.json,
        Cargo.toml, go.mod. For Python projects, also reads installed
        package metadata via importlib.metadata when available.

        Args:
            path: Project root directory

        Returns:
            SBOMDocument with all discovered components
        """
        self._scan_path = str(Path(path).resolve())
        self._components = []

        project_name = Path(path).name
        project_version = "0.0.0"

        p = Path(path)

        # --- Python: pyproject.toml ---
        pyproject = p / "pyproject.toml"
        if pyproject.exists():
            name, version, deps = self._parse_pyproject(pyproject)
            if name:
                project_name = name
            if version:
                project_version = version
            for dep_name, dep_version in deps:
                self._add_discovered(dep_name, dep_version, "pypi", direct=True)

        # --- Python: requirements.txt ---
        requirements = p / "requirements.txt"
        if requirements.exists():
            deps = self._parse_requirements(requirements)
            for dep_name, dep_version in deps:
                self._add_discovered(dep_name, dep_version, "pypi", direct=True)

        # --- Node: package.json ---
        package_json = p / "package.json"
        if package_json.exists():
            name, version, deps = self._parse_package_json(package_json)
            if name and not pyproject.exists():
                project_name = name
            if version and not pyproject.exists():
                project_version = version
            for dep_name, dep_version in deps:
                self._add_discovered(dep_name, dep_version, "npm", direct=True)

        # --- Rust: Cargo.toml ---
        cargo = p / "Cargo.toml"
        if cargo.exists():
            name, version, deps = self._parse_cargo(cargo)
            if name and not pyproject.exists():
                project_name = name
            if version and not pyproject.exists():
                project_version = version
            for dep_name, dep_version in deps:
                self._add_discovered(dep_name, dep_version, "crates", direct=True)

        # --- Go: go.mod ---
        gomod = p / "go.mod"
        if gomod.exists():
            name, deps = self._parse_gomod(gomod)
            if name and not pyproject.exists():
                project_name = name
            for dep_name, dep_version in deps:
                self._add_discovered(dep_name, dep_version, "golang", direct=True)

        # --- Python: try importlib.metadata for installed packages ---
        if pyproject.exists() or requirements.exists():
            self._enrich_python_metadata()

        # Create TIBET tokens for all components
        for comp in self._components:
            token = self.provenance.create_token(
                component_name=comp.name,
                component_version=comp.version,
                component_hash=comp.hash_sha256,
                source=comp.source,
                parent_component=project_name,
                scan_path=self._scan_path,
            )
            comp.tibet_token_id = token.token_id

        self._document = SBOMDocument(
            project_name=project_name,
            version=project_version,
            components=list(self._components),
            tibet_chain_length=len(self.provenance.tokens),
            metadata={
                "scanner": "tibet-sbom",
                "scanner_version": "0.2.0",
                "scan_path": self._scan_path,
                "scan_node": os.uname().nodename,
            },
        )
        return self._document

    def add_component(self, component: Component) -> None:
        """
        Manually add a component to the inventory.

        Use this for components that cannot be auto-detected.
        """
        # Deduplicate by name+version
        for existing in self._components:
            if existing.name == component.name and existing.version == component.version:
                return

        token = self.provenance.create_token(
            component_name=component.name,
            component_version=component.version,
            component_hash=component.hash_sha256,
            source=component.source,
            parent_component="manual",
            scan_path=self._scan_path or "manual",
        )
        component.tibet_token_id = token.token_id
        self._components.append(component)

        if self._document:
            self._document.components = list(self._components)
            self._document.tibet_chain_length = len(self.provenance.tokens)

    def check_vulnerabilities(self) -> list[Vulnerability]:
        """
        Cross-reference components against known vulnerability patterns.

        This is a local heuristic check. For production use, integrate
        with OSV, NVD, or a commercial vulnerability database.

        Returns:
            List of vulnerabilities found across all components
        """
        found: list[Vulnerability] = []

        for comp in self._components:
            for pattern in _KNOWN_PATTERNS:
                if comp.name.lower() == pattern["name"].lower():
                    if comp.version and _is_below(comp.version, pattern["below"]):
                        vuln = Vulnerability(
                            cve_id=pattern["cve"],
                            severity=pattern["severity"],
                            description=pattern["desc"],
                            affected_versions=f"< {pattern['below']}",
                            fixed_in=pattern.get("fixed_in", ""),
                        )
                        comp.vulnerabilities.append(vuln)
                        found.append(vuln)

        return found

    def export_cyclonedx(self) -> dict:
        """
        Export SBOM as CycloneDX-compatible dict.

        Follows CycloneDX 1.5 JSON schema structure.
        """
        doc = self._document or SBOMDocument()

        components = []
        for comp in self._components:
            entry: dict = {
                "type": "library",
                "name": comp.name,
                "version": comp.version,
                "purl": comp.purl,
            }
            if comp.license:
                entry["licenses"] = [{"license": {"id": comp.license}}]
            if comp.hash_sha256:
                entry["hashes"] = [{"alg": "SHA-256", "content": comp.hash_sha256}]
            if comp.vulnerabilities:
                entry["x-tibet-vulnerabilities"] = [
                    v.to_dict() for v in comp.vulnerabilities
                ]
            components.append(entry)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{doc.doc_id}",
            "version": 1,
            "metadata": {
                "timestamp": doc.timestamp,
                "tools": [{"name": "tibet-sbom", "version": "0.1.0"}],
                "component": {
                    "type": "application",
                    "name": doc.project_name,
                    "version": doc.version,
                },
            },
            "components": components,
            "x-tibet": {
                "chain_length": doc.tibet_chain_length,
                "provenance_format": "TIBET",
                "token_count": len(self.provenance.tokens),
            },
        }

    def export_spdx(self) -> dict:
        """
        Export SBOM as SPDX-compatible dict.

        Follows SPDX 2.3 JSON structure.
        """
        doc = self._document or SBOMDocument()

        packages = []
        for comp in self._components:
            pkg: dict = {
                "SPDXID": f"SPDXRef-{comp.name.replace('.', '-').replace('/', '-')}",
                "name": comp.name,
                "versionInfo": comp.version,
                "downloadLocation": comp.purl or "NOASSERTION",
                "supplier": f"Organization: {comp.source}",
            }
            if comp.license:
                pkg["licenseConcluded"] = comp.license
                pkg["licenseDeclared"] = comp.license
            else:
                pkg["licenseConcluded"] = "NOASSERTION"
                pkg["licenseDeclared"] = "NOASSERTION"
            if comp.hash_sha256:
                pkg["checksums"] = [
                    {"algorithm": "SHA256", "checksumValue": comp.hash_sha256}
                ]
            pkg["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": comp.purl,
                }
            ]
            packages.append(pkg)

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": doc.project_name,
            "documentNamespace": f"https://humotica.com/spdx/{doc.doc_id}",
            "creationInfo": {
                "created": doc.timestamp,
                "creators": ["Tool: tibet-sbom-0.1.0"],
            },
            "packages": packages,
            "x-tibet": {
                "chain_length": doc.tibet_chain_length,
                "provenance_format": "TIBET",
                "token_count": len(self.provenance.tokens),
            },
        }

    def export_tibet(self) -> dict:
        """
        Export SBOM with full TIBET provenance per component.

        This is the richest format: every component has its complete
        ERIN/ERAAN/EROMHEEN/ERACHTER provenance token.
        """
        doc = self._document or SBOMDocument()

        components_with_provenance = []
        token_map = {t.token_id: t for t in self.provenance.tokens}

        for comp in self._components:
            entry = comp.to_dict()
            token = token_map.get(comp.tibet_token_id)
            if token:
                entry["tibet_provenance"] = token.to_dict()
            components_with_provenance.append(entry)

        return {
            "format": "TIBET-SBOM",
            "version": "0.1.0",
            "doc_id": doc.doc_id,
            "project": {
                "name": doc.project_name,
                "version": doc.version,
            },
            "timestamp": doc.timestamp,
            "components": components_with_provenance,
            "component_count": len(components_with_provenance),
            "provenance_chain": self.provenance.chain(),
            "chain_length": doc.tibet_chain_length,
            "metadata": doc.metadata,
        }

    # --- Internal parsers ---

    def _add_discovered(
        self,
        name: str,
        version: str,
        source: str,
        direct: bool = True,
    ) -> None:
        """Add a discovered component, deduplicating by name."""
        name = name.strip().lower()
        if not name:
            return
        if not self._is_valid_package_name(name, source=source):
            return

        for existing in self._components:
            if existing.name == name:
                # Update version if we found a more specific one
                if version and not existing.version:
                    existing.version = version
                return

        content_hash = ""
        if name and version:
            raw = f"{source}:{name}:{version}"
            content_hash = hashlib.sha256(raw.encode()).hexdigest()

        self._components.append(
            Component(
                name=name,
                version=version,
                source=source,
                direct=direct,
                hash_sha256=content_hash,
            )
        )

    def _parse_pyproject(self, path: Path) -> tuple[str, str, list[tuple[str, str]]]:
        """
        Parse pyproject.toml for project info and dependencies.

        Handles both PEP 621 [project] dependencies and poetry-style.
        Uses basic TOML parsing to avoid external dependency.
        """
        text = path.read_text(encoding="utf-8")
        name = ""
        version = ""
        deps: list[tuple[str, str]] = []

        # Find the [project] section boundaries
        project_start = None
        project_end = len(text)
        for m in re.finditer(r"^\[([^\]]+)\]", text, re.MULTILINE):
            section = m.group(1).strip()
            if section == "project":
                project_start = m.end()
            elif project_start is not None and not section.startswith("project."):
                project_end = m.start()
                break

        project_text = text[project_start:project_end] if project_start is not None else ""

        # Extract project name from [project] section only
        m = re.search(r'^\s*name\s*=\s*"([^"]+)"', project_text, re.MULTILINE)
        if m:
            name = m.group(1)

        # Extract version from [project] section only
        m = re.search(r'^\s*version\s*=\s*"([^"]+)"', project_text, re.MULTILINE)
        if m:
            version = m.group(1)

        # Extract dependencies array from [project] section only
        dep_match = re.search(
            r"^\s*dependencies\s*=\s*\[(.*?)\]",
            project_text,
            re.MULTILINE | re.DOTALL,
        )
        if dep_match:
            dep_block = dep_match.group(1)
            for dep_str in re.findall(r'"([^"]+)"', dep_block):
                dep_name, dep_ver = self._parse_dep_spec(dep_str)
                if self._is_valid_package_name(dep_name):
                    deps.append((dep_name, dep_ver))

        # Find [project.optional-dependencies] section
        opt_start = None
        opt_end = len(text)
        for m in re.finditer(r"^\[([^\]]+)\]", text, re.MULTILINE):
            section = m.group(1).strip()
            if section == "project.optional-dependencies":
                opt_start = m.end()
            elif opt_start is not None and section != "project.optional-dependencies":
                opt_end = m.start()
                break

        if opt_start is not None:
            opt_text = text[opt_start:opt_end]
            for opt_match in re.finditer(
                r"^\s*\w+\s*=\s*\[(.*?)\]",
                opt_text,
                re.MULTILINE | re.DOTALL,
            ):
                block = opt_match.group(1)
                for dep_str in re.findall(r'"([^"]+)"', block):
                    dep_name, dep_ver = self._parse_dep_spec(dep_str)
                    if self._is_valid_package_name(dep_name):
                        deps.append((dep_name, dep_ver))

        return name, version, deps

    @staticmethod
    def _is_valid_package_name(name: str, source: str = "") -> bool:
        """Check if a string looks like a valid package name (not a path)."""
        if not name:
            return False
        # Absolute paths are never package names
        if name.startswith("/") or name.startswith("."):
            return False
        # Go modules use URL-style names with slashes — that's valid
        if source == "golang" and "/" in name:
            return True
        # For non-Go: reject strings that look like file paths
        if "/" in name:
            return False
        # Must match PEP 508 / npm / cargo package name pattern
        return bool(re.match(r"^[a-zA-Z0-9@]([a-zA-Z0-9._\-/@]*[a-zA-Z0-9])?$", name))

    def _parse_requirements(self, path: Path) -> list[tuple[str, str]]:
        """Parse requirements.txt for dependencies."""
        deps: list[tuple[str, str]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            dep_name, dep_ver = self._parse_dep_spec(line)
            deps.append((dep_name, dep_ver))
        return deps

    def _parse_package_json(
        self, path: Path
    ) -> tuple[str, str, list[tuple[str, str]]]:
        """Parse package.json for project info and dependencies."""
        data = json.loads(path.read_text(encoding="utf-8"))
        name = data.get("name", "")
        version = data.get("version", "")
        deps: list[tuple[str, str]] = []

        for section in ("dependencies", "devDependencies"):
            for dep_name, dep_ver in data.get(section, {}).items():
                # Strip version prefixes (^, ~, >=)
                clean_ver = re.sub(r"^[^0-9]*", "", str(dep_ver))
                deps.append((dep_name, clean_ver))

        return name, version, deps

    def _parse_cargo(self, path: Path) -> tuple[str, str, list[tuple[str, str]]]:
        """
        Parse Cargo.toml for project info and dependencies.

        Handles both inline version strings and table-style dependencies.
        """
        text = path.read_text(encoding="utf-8")
        name = ""
        version = ""
        deps: list[tuple[str, str]] = []

        m = re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.MULTILINE)
        if m:
            name = m.group(1)

        m = re.search(r'^\s*version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        if m:
            version = m.group(1)

        in_deps = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("[dependencies]") or stripped.startswith(
                "[dev-dependencies]"
            ):
                in_deps = True
                continue
            if stripped.startswith("[") and in_deps:
                in_deps = False
                continue
            if in_deps and "=" in stripped:
                # name = "version" or name = { version = "..." }
                m = re.match(r'(\S+)\s*=\s*"([^"]+)"', stripped)
                if m:
                    deps.append((m.group(1), m.group(2)))
                else:
                    m = re.match(
                        r'(\S+)\s*=\s*\{.*version\s*=\s*"([^"]+)"',
                        stripped,
                    )
                    if m:
                        deps.append((m.group(1), m.group(2)))

        return name, version, deps

    def _parse_gomod(self, path: Path) -> tuple[str, list[tuple[str, str]]]:
        """Parse go.mod for module name and dependencies."""
        text = path.read_text(encoding="utf-8")
        name = ""
        deps: list[tuple[str, str]] = []

        m = re.search(r"^module\s+(\S+)", text, re.MULTILINE)
        if m:
            name = m.group(1)

        in_require = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_require = True
                continue
            if stripped == ")" and in_require:
                in_require = False
                continue
            if in_require:
                parts = stripped.split()
                if len(parts) >= 2:
                    dep_name = parts[0]
                    dep_ver = parts[1].lstrip("v")
                    deps.append((dep_name, dep_ver))
            elif stripped.startswith("require "):
                parts = stripped.split()
                if len(parts) >= 3:
                    deps.append((parts[1], parts[2].lstrip("v")))

        return name, deps

    def _parse_dep_spec(self, spec: str) -> tuple[str, str]:
        """
        Parse a dependency specifier like 'requests>=2.28.0' into (name, version).

        Handles: ==, >=, <=, ~=, !=, >, <, and bare names.
        """
        spec = spec.strip()
        # Remove extras like [security]
        spec = re.sub(r"\[.*?\]", "", spec)
        # Split on version operator
        m = re.match(r"([a-zA-Z0-9_\-\.]+)\s*([><=!~]+)\s*([\S]+)", spec)
        if m:
            return m.group(1).strip(), m.group(3).strip().rstrip(",")
        return spec.strip().rstrip(","), ""

    def _enrich_python_metadata(self) -> None:
        """
        Try to read installed package metadata for Python components.

        Uses importlib.metadata to get license and version info for
        packages that are installed in the current environment.
        Also discovers transitive dependencies from installed requires.
        """
        try:
            from importlib.metadata import distributions
        except ImportError:
            return

        installed: dict[str, dict] = {}
        try:
            for dist in distributions():
                meta = dist.metadata
                dist_name = (meta["Name"] or "").lower().replace("_", "-")
                installed[dist_name] = {
                    "version": meta["Version"] or "",
                    "license": meta.get("License", "") or "",
                    "requires": dist.requires or [],
                }
        except Exception:
            return

        # Normalize existing component names for lookup
        known_names = {c.name.lower().replace("_", "-") for c in self._components}

        for comp in self._components:
            if comp.source != "pypi":
                continue
            norm = comp.name.lower().replace("_", "-")
            info = installed.get(norm)
            if info:
                if not comp.version and info["version"]:
                    comp.version = info["version"]
                if not comp.license and info["license"]:
                    comp.license = info["license"]

                # Discover transitive deps from requires
                for req_str in info["requires"]:
                    # Skip extras-only requirements like 'foo; extra == "dev"'
                    if "extra ==" in req_str:
                        continue
                    # Strip environment markers
                    req_clean = req_str.split(";")[0].strip()
                    dep_name, dep_ver = self._parse_dep_spec(req_clean)
                    dep_norm = dep_name.lower().replace("_", "-")
                    if dep_norm not in known_names and self._is_valid_package_name(dep_name):
                        dep_info = installed.get(dep_norm)
                        if dep_info:
                            # Only add transitive deps we can fully resolve
                            actual_ver = dep_info["version"]
                            self._add_discovered(dep_name, actual_ver, "pypi", direct=False)
                            known_names.add(dep_norm)
