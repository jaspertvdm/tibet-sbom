"""
tibet-sbom CLI — Software Bill of Materials + TIBET Provenance.

Usage::

    tibet-sbom info                     Concept overview
    tibet-sbom scan [path]              Scan project, generate SBOM
    tibet-sbom export [path] --format   Export SBOM (cyclonedx/spdx/tibet)
    tibet-sbom check [path]             Compliance check (CRA + EO 14028)
    tibet-sbom demo                     Demo with sample project
"""

import argparse
import json
import sys
import tempfile
from pathlib import Path

from .generator import SBOMGenerator, Component
from .compliance import check_cra, check_eo14028


def cmd_info(args: argparse.Namespace) -> int:
    """Concept overview: what tibet-sbom does and why it exists."""
    print()
    print("=" * 64)
    print("  TIBET-SBOM -- Software Bill of Materials + TIBET Provenance")
    print("=" * 64)
    print()
    print("The Regulatory Reality:")
    print("  EU Cyber Resilience Act (CRA) -- Regulation (EU) 2024/2847")
    print("  US Executive Order 14028 -- Improving Cybersecurity")
    print()
    print("  Both REQUIRE Software Bills of Materials.")
    print("  A dependency list is not enough. You need PROVENANCE.")
    print()
    print("What existing tools produce:")
    print("  +------------------+----------+---------+")
    print("  | Component        | Version  | License |")
    print("  +------------------+----------+---------+")
    print("  | requests         | 2.31.0   | Apache  |")
    print("  | numpy            | 1.26.4   | BSD     |")
    print("  +------------------+----------+---------+")
    print("  A list. No proof. No chain of custody.")
    print()
    print("What tibet-sbom adds:")
    print("  Every component = TIBET token with 4 dimensions:")
    print()
    print("  ERIN      What is it?")
    print("            -> name, version, hash, source registry")
    print()
    print("  ERAAN     Where does it come from?")
    print("            -> parent, dependency chain, jis: URI")
    print()
    print("  EROMHEEN  What was the context?")
    print("            -> scan node, timestamp, scanner version")
    print()
    print("  ERACHTER  Why this component?")
    print("            -> reason for inclusion, compliance context")
    print()
    print("  Together: cryptographic proof of your supply chain.")
    print()
    print("Compliance coverage:")
    print("  CRA requirements:")
    print("    [x] All components identified (Art. 13)")
    print("    [x] Provenance chain complete (Annex I)")
    print("    [x] Vulnerability assessment (Art. 13(8))")
    print("    [x] Machine-readable format (Annex I)")
    print("    [x] Supplier information (Annex VII)")
    print("    [x] Hash integrity verification")
    print()
    print("  EO 14028 requirements:")
    print("    [x] Machine-readable SBOM (Sec. 4)")
    print("    [x] Supplier identified (NTIA)")
    print("    [x] Component integrity (Sec. 4(e))")
    print("    [x] Unique identification via PURL")
    print("    [x] Dependency relationships")
    print("    [x] Automated generation")
    print()
    print("Formats: CycloneDX 1.5, SPDX 2.3, TIBET-SBOM 0.1")
    print()
    print("=" * 64)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan a project and print SBOM summary."""
    path = args.path or "."

    if not Path(path).exists():
        print(f"Error: path does not exist: {path}", file=sys.stderr)
        return 1

    gen = SBOMGenerator()
    sbom = gen.scan(path)
    vulns = gen.check_vulnerabilities()

    if args.json:
        print(json.dumps(sbom.to_dict(), indent=2))
        return 0

    print()
    print(f"  Project: {sbom.project_name} v{sbom.version}")
    print(f"  Path:    {path}")
    print(f"  Scanned: {sbom.timestamp[:19]}Z")
    print(f"  Doc ID:  {sbom.doc_id}")
    print()

    if not sbom.components:
        print("  No components found.")
        print("  Supported: pyproject.toml, requirements.txt, package.json,")
        print("             Cargo.toml, go.mod")
        print()
        return 0

    # Component table
    print(f"  Components ({len(sbom.components)}):")
    print(f"  {'Name':<30} {'Version':<14} {'Source':<8} {'Direct':<7} {'Vulns'}")
    print(f"  {'-' * 30} {'-' * 14} {'-' * 8} {'-' * 7} {'-' * 5}")

    for comp in sbom.components:
        direct = "yes" if comp.direct else "  -"
        vuln_count = str(len(comp.vulnerabilities)) if comp.vulnerabilities else "  -"
        name_display = comp.name[:29]
        ver_display = (comp.version or "-")[:13]
        print(
            f"  {name_display:<30} {ver_display:<14} {comp.source:<8} "
            f"{direct:<7} {vuln_count}"
        )

    print()

    # Vulnerability summary
    if vulns:
        severity_counts = {}
        for v in vulns:
            severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1
        severity_str = ", ".join(
            f"{count} {sev}" for sev, count in sorted(severity_counts.items())
        )
        print(f"  Vulnerabilities: {len(vulns)} found ({severity_str})")
        for v in vulns:
            print(f"    [{v.severity}] {v.cve_id}: {v.description}")
            if v.fixed_in:
                print(f"           Fixed in: {v.fixed_in}")
        print()

    print(f"  TIBET chain: {sbom.tibet_chain_length} provenance tokens")
    print()
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Export SBOM in specified format."""
    path = args.path or "."

    if not Path(path).exists():
        print(f"Error: path does not exist: {path}", file=sys.stderr)
        return 1

    gen = SBOMGenerator()
    gen.scan(path)
    gen.check_vulnerabilities()

    fmt = args.format or "tibet"

    if fmt == "cyclonedx":
        data = gen.export_cyclonedx()
    elif fmt == "spdx":
        data = gen.export_spdx()
    elif fmt == "tibet":
        data = gen.export_tibet()
    else:
        print(f"Error: unknown format: {fmt}", file=sys.stderr)
        print("Supported: cyclonedx, spdx, tibet", file=sys.stderr)
        return 1

    print(json.dumps(data, indent=2))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Run compliance checks against CRA and EO 14028."""
    path = args.path or "."

    if not Path(path).exists():
        print(f"Error: path does not exist: {path}", file=sys.stderr)
        return 1

    gen = SBOMGenerator()
    sbom = gen.scan(path)
    gen.check_vulnerabilities()

    cra = check_cra(sbom)
    eo = check_eo14028(sbom)

    if args.json:
        print(json.dumps({"cra": cra.to_dict(), "eo14028": eo.to_dict()}, indent=2))
        return 0

    print()
    print(f"  Project: {sbom.project_name} v{sbom.version}")
    print(f"  Components: {len(sbom.components)}")
    print()

    for result in [cra, eo]:
        status = "COMPLIANT" if result.compliant else "NOT COMPLIANT"
        indicator = "[OK]" if result.compliant else "[!!]"
        print(f"  {indicator} {result.standard}")
        print(f"      Status: {status} ({result.score:.0%})")

        if result.gaps:
            print(f"      Gaps ({len(result.gaps)}):")
            for gap in result.gaps:
                print(f"        - {gap}")

        if result.recommendations:
            print(f"      Recommendations:")
            for rec in result.recommendations:
                print(f"        - {rec}")

        print()

    return 0 if (cra.compliant and eo.compliant) else 1


def cmd_demo(args: argparse.Namespace) -> int:
    """Demo with a sample project showing the full flow."""
    print()
    print("  TIBET-SBOM Demo: Full SBOM Flow")
    print("  " + "=" * 40)
    print()

    # Create a temporary sample project
    with tempfile.TemporaryDirectory(prefix="tibet-sbom-demo-") as tmpdir:
        # Write a sample pyproject.toml
        sample_pyproject = Path(tmpdir) / "pyproject.toml"
        sample_pyproject.write_text(
            '[project]\n'
            'name = "demo-webapp"\n'
            'version = "1.2.0"\n'
            'dependencies = [\n'
            '    "requests>=2.28.0",\n'
            '    "flask>=3.0.0",\n'
            '    "cryptography>=41.0.0",\n'
            '    "sqlalchemy>=2.0.0",\n'
            '    "pydantic>=2.5.0",\n'
            ']\n',
            encoding="utf-8",
        )

        # Write a sample requirements.txt with transitive deps
        sample_reqs = Path(tmpdir) / "requirements.txt"
        sample_reqs.write_text(
            "# Transitive dependencies\n"
            "urllib3==2.0.4\n"
            "certifi==2024.2.2\n"
            "idna==3.6\n"
            "charset-normalizer==3.3.2\n"
            "jinja2==3.1.3\n"
            "werkzeug==3.0.1\n"
            "markupsafe==2.1.5\n"
            "click==8.1.7\n",
            encoding="utf-8",
        )

        print("  Step 1: Scan project")
        print("  " + "-" * 40)

        gen = SBOMGenerator()
        sbom = gen.scan(tmpdir)

        print(f"    Project: {sbom.project_name} v{sbom.version}")
        print(f"    Found {len(sbom.components)} components")
        print()

        for comp in sbom.components:
            direct = "direct" if comp.direct else "transitive"
            print(f"    {comp.name:<25} {comp.version:<12} ({direct})")

        print()

        # Step 2: Check vulnerabilities
        print("  Step 2: Vulnerability check")
        print("  " + "-" * 40)

        vulns = gen.check_vulnerabilities()
        if vulns:
            for v in vulns:
                print(f"    [{v.severity}] {v.cve_id}")
                print(f"      {v.description}")
                if v.fixed_in:
                    print(f"      Fix: upgrade to >= {v.fixed_in}")
            print()
        else:
            print("    No known vulnerabilities detected.")
            print()

        # Step 3: TIBET provenance
        print("  Step 3: TIBET provenance")
        print("  " + "-" * 40)
        print(f"    Chain length: {len(gen.provenance.tokens)} tokens")
        print()

        # Show one token as example
        if gen.provenance.tokens:
            token = gen.provenance.tokens[0]
            print(f"    Example token ({token.component_name}):")
            print(f"      ERIN:      {token.erin['component']} v{token.erin['version']}")
            print(f"                 source={token.erin['source']}")
            print(f"      ERAAN:     {token.eraan['dependency_chain']}")
            print(f"                 {token.eraan['component_jis']}")
            print(f"      EROMHEEN:  node={token.eromheen['scan_node']}")
            print(f"                 scanner={token.eromheen['scanner']}")
            print(f"      ERACHTER:  {token.erachter['intent']}")
            print()

        # Step 4: Compliance check
        print("  Step 4: Compliance check")
        print("  " + "-" * 40)

        cra = check_cra(sbom)
        eo = check_eo14028(sbom)

        for result in [cra, eo]:
            status = "COMPLIANT" if result.compliant else "NOT COMPLIANT"
            print(f"    {result.standard}")
            print(f"      {status} ({result.score:.0%})")
            if result.gaps:
                for gap in result.gaps:
                    print(f"      Gap: {gap}")
            print()

        # Step 5: Export formats
        print("  Step 5: Export formats")
        print("  " + "-" * 40)

        cyclonedx = gen.export_cyclonedx()
        spdx = gen.export_spdx()
        tibet = gen.export_tibet()

        print(f"    CycloneDX: {len(cyclonedx['components'])} components, "
              f"spec {cyclonedx['specVersion']}")
        print(f"    SPDX:      {len(spdx['packages'])} packages, "
              f"version {spdx['spdxVersion']}")
        print(f"    TIBET:     {tibet['component_count']} components, "
              f"{tibet['chain_length']} tokens")
        print()

        if args.json:
            print("  Full TIBET export:")
            print(json.dumps(tibet, indent=2))

    print("  " + "=" * 40)
    print("  A list without provenance is a checklist.")
    print("  A list with TIBET provenance is evidence.")
    print()
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="tibet-sbom",
        description="Software Bill of Materials + TIBET Provenance",
    )
    sub = parser.add_subparsers(dest="command")

    # info
    sub.add_parser("info", help="Concept overview (CRA, EO 14028 context)")

    # scan
    p_scan = sub.add_parser("scan", help="Scan project, generate SBOM")
    p_scan.add_argument("path", nargs="?", default=".", help="Project root path")
    p_scan.add_argument("-j", "--json", action="store_true", help="JSON output")

    # export
    p_export = sub.add_parser("export", help="Export SBOM in specific format")
    p_export.add_argument("path", nargs="?", default=".", help="Project root path")
    p_export.add_argument(
        "-f", "--format",
        choices=["cyclonedx", "spdx", "tibet"],
        default="tibet",
        help="Export format (default: tibet)",
    )

    # check
    p_check = sub.add_parser("check", help="Compliance check (CRA + EO 14028)")
    p_check.add_argument("path", nargs="?", default=".", help="Project root path")
    p_check.add_argument("-j", "--json", action="store_true", help="JSON output")

    # demo
    p_demo = sub.add_parser("demo", help="Demo with sample project")
    p_demo.add_argument("-j", "--json", action="store_true", help="Include full JSON export")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    commands = {
        "info": cmd_info,
        "scan": cmd_scan,
        "export": cmd_export,
        "check": cmd_check,
        "demo": cmd_demo,
    }
    sys.exit(commands[args.command](args))
