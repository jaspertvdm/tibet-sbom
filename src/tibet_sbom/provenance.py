"""
TIBET provenance for SBOM components.

Every dependency scanned, every component identified, every export
generated is recorded as a TIBET token. The chain is the supply
chain audit trail that regulators require.
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class SBOMToken:
    """
    TIBET provenance token for an SBOM component.

    Four dimensions:
        ERIN:      Component name, version, hash, source
        ERAAN:     Parent component, dependency chain, jis: URI
        EROMHEEN:  Scan environment, timestamp, scanner version
        ERACHTER:  Why this component was included
    """
    token_id: str
    timestamp: str
    component_name: str
    component_version: str
    source: str
    erin: dict = field(default_factory=dict)
    eraan: dict = field(default_factory=dict)
    eromheen: dict = field(default_factory=dict)
    erachter: dict = field(default_factory=dict)
    parent_id: Optional[str] = None
    content_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "token_id": self.token_id,
            "timestamp": self.timestamp,
            "type": "sbom_component",
            "component_name": self.component_name,
            "component_version": self.component_version,
            "source": self.source,
            "erin": self.erin,
            "eraan": self.eraan,
            "eromheen": self.eromheen,
            "erachter": self.erachter,
            "parent_id": self.parent_id,
            "content_hash": self.content_hash,
        }


class SBOMProvenance:
    """
    TIBET provenance chain for SBOM scans.

    Creates a linked chain of tokens — one per component discovered.
    The chain proves: what was scanned, when, where, and by whom.
    """

    def __init__(self, actor: str = "tibet-sbom"):
        self.actor = actor
        self.tokens: list[SBOMToken] = []
        self._last_id: str | None = None

    def create_token(
        self,
        component_name: str,
        component_version: str,
        component_hash: str,
        source: str,
        parent_component: str = "",
        scan_path: str = "",
    ) -> SBOMToken:
        """
        Create a TIBET token for a discovered SBOM component.

        Args:
            component_name: Package/library name
            component_version: Version string
            component_hash: SHA-256 hash of the component identifier
            source: Registry source (pypi, npm, crates, maven, golang)
            parent_component: The project that depends on this component
            scan_path: Filesystem path that was scanned

        Returns:
            SBOMToken with full ERIN/ERAAN/EROMHEEN/ERACHTER provenance
        """
        now = datetime.now(timezone.utc).isoformat()

        erin = {
            "component": component_name,
            "version": component_version,
            "hash_sha256": component_hash,
            "source": source,
        }

        eraan = {
            "parent_token": self._last_id,
            "parent_component": parent_component,
            "dependency_chain": f"{parent_component} -> {component_name}",
            "component_jis": f"jis:{source}:{component_name}:{component_version}",
        }

        eromheen = {
            "scan_node": os.uname().nodename,
            "scan_path": scan_path,
            "timestamp": now,
            "scanner": self.actor,
            "scanner_version": "0.2.0",
        }

        erachter = {
            "intent": f"SBOM scan: {component_name} from {source}",
            "reason": f"Dependency of {parent_component}",
            "compliance_context": "EU CRA / US EO 14028",
        }

        content = json.dumps({"erin": erin}, sort_keys=True)
        token_id = hashlib.sha256(
            f"{source}:{component_name}:{component_version}:{now}".encode()
        ).hexdigest()[:16]
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:32]

        token = SBOMToken(
            token_id=token_id,
            timestamp=now,
            component_name=component_name,
            component_version=component_version,
            source=source,
            erin=erin,
            eraan=eraan,
            eromheen=eromheen,
            erachter=erachter,
            parent_id=self._last_id,
            content_hash=content_hash,
        )
        self.tokens.append(token)
        self._last_id = token.token_id
        return token

    def chain(self) -> list[dict]:
        """Return the full provenance chain as a list of dicts."""
        return [t.to_dict() for t in self.tokens]
