"""
Attestation record schema -- the data model for compliance attestations.

An attestation is a signed, timestamped proof that an AI system was scanned
for compliance across one or more regulatory frameworks. It contains enough
information for independent verification without revealing source code or
detailed scan findings.

Schema version: 1.0
Designed to be compatible with future blockchain anchoring and federated registries.
"""

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List

# Attestation ID prefix for namespacing
ATTESTATION_PREFIX = "air-att"

# Schema version (bump on breaking changes)
SCHEMA_VERSION = "1.0"

# Schema URL (will be published at this location)
SCHEMA_URL = "https://airblackbox.ai/schemas/attestation-v1.json"


def generate_attestation_id() -> str:
    """Generate a unique attestation ID.

    Format: air-att-YYYY-MM-DD-<8 hex chars>
    Example: air-att-2026-04-12-a7f3c2e1
    """
    date_part = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    random_part = secrets.token_hex(4)
    return f"{ATTESTATION_PREFIX}-{date_part}-{random_part}"


@dataclass
class SubjectInfo:
    """Information about the AI system that was scanned.

    Only hashes are stored -- no source code or file paths are published.
    """

    system_hash: str  # SHA-256 of scanned codebase (file content hashes)
    system_name: str = ""  # Optional human-readable name (provider-supplied)
    system_version: str = ""  # Optional version string
    files_scanned: int = 0  # Number of files included in the hash


@dataclass
class ScanInfo:
    """Summary of the compliance scan results.

    Contains pass/fail counts but not specific findings or code references.
    """

    scanner_version: str  # e.g. "air-blackbox 1.10.0"
    frameworks: List[str]  # e.g. ["eu_ai_act", "iso_42001", "nist_rmf", "colorado_sb205"]
    checks_passed: int = 0
    checks_warned: int = 0
    checks_failed: int = 0
    checks_total: int = 0
    risk_classification: str = ""  # e.g. "high_risk_annex_iii", "limited_risk", "minimal_risk"


@dataclass
class EvidenceInfo:
    """Hashes linking the attestation to the full evidence bundle.

    The attestation references (but does not contain) the detailed evidence.
    An auditor can match a bundle to its attestation by comparing these hashes.
    """

    bundle_hash: str = ""  # SHA-256 of the .air-evidence ZIP file
    audit_chain_hash: str = ""  # SHA-256 of the HMAC audit chain


@dataclass
class CryptoInfo:
    """Cryptographic proof that this attestation is authentic.

    The signature covers the canonical JSON encoding of the attestation
    (excluding the crypto.signature field itself).
    """

    algorithm: str = "ML-DSA-65"
    public_key_fingerprint: str = ""  # SHA-256 of the signer's public key
    signature: str = ""  # Hex-encoded ML-DSA-65 signature


@dataclass
class VerificationInfo:
    """URLs for online verification (populated when published to registry)."""

    verify_url: str = ""  # e.g. https://airblackbox.ai/verify/air-att-...
    badge_url: str = ""  # e.g. https://airblackbox.ai/badge/air-att-....svg


@dataclass
class AttestationRecord:
    """A complete attestation record.

    This is the core data model for Phase 2D. It contains everything needed
    to prove that an AI system was scanned for compliance, without revealing
    any source code or detailed findings.

    The record is designed to be:
    - Self-contained: all verification data is in the record
    - Signable: canonical JSON encoding for deterministic signatures
    - Anchorable: the record hash can be published to a blockchain
    - Extensible: new fields can be added without breaking existing records
    """

    attestation_id: str = field(default_factory=generate_attestation_id)
    schema_version: str = SCHEMA_VERSION
    schema_url: str = SCHEMA_URL
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    subject: SubjectInfo = field(default_factory=lambda: SubjectInfo(system_hash=""))
    scan: ScanInfo = field(default_factory=lambda: ScanInfo(scanner_version="", frameworks=[]))
    evidence: EvidenceInfo = field(default_factory=EvidenceInfo)
    crypto: CryptoInfo = field(default_factory=CryptoInfo)
    verification: VerificationInfo = field(default_factory=VerificationInfo)

    def to_dict(self) -> Dict:
        """Convert to a plain dict (JSON-serializable)."""
        return asdict(self)

    def to_canonical_bytes(self) -> bytes:
        """Canonical JSON encoding for signing.

        Excludes the crypto.signature field so the signature can be computed
        over the rest of the record. Uses sorted keys and compact separators
        for deterministic output.
        """
        d = self.to_dict()
        # Remove the signature before signing (it gets filled in after)
        d["crypto"]["signature"] = ""
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_json(self, indent: int = 2) -> str:
        """Pretty-print JSON representation."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def record_hash(self) -> str:
        """SHA-256 hash of the canonical record (for blockchain anchoring).

        This hash covers the full record INCLUDING the signature, so it
        uniquely identifies this specific signed attestation.
        """
        full_bytes = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(full_bytes).hexdigest()

    @classmethod
    def from_dict(cls, data: Dict) -> "AttestationRecord":
        """Reconstruct an AttestationRecord from a dict."""
        return cls(
            attestation_id=data.get("attestation_id", generate_attestation_id()),
            schema_version=data.get("schema_version", SCHEMA_VERSION),
            schema_url=data.get("schema_url", SCHEMA_URL),
            created_at=data.get("created_at", ""),
            subject=SubjectInfo(**data.get("subject", {"system_hash": ""})),
            scan=ScanInfo(**data.get("scan", {"scanner_version": "", "frameworks": []})),
            evidence=EvidenceInfo(**data.get("evidence", {})),
            crypto=CryptoInfo(**data.get("crypto", {})),
            verification=VerificationInfo(**data.get("verification", {})),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "AttestationRecord":
        """Parse an AttestationRecord from a JSON string."""
        return cls.from_dict(json.loads(json_str))

    def validate(self) -> List[str]:
        """Validate the record and return a list of issues (empty = valid)."""
        issues = []

        if not self.attestation_id.startswith(ATTESTATION_PREFIX):
            issues.append(f"Invalid attestation_id prefix: {self.attestation_id}")

        if not self.subject.system_hash:
            issues.append("Missing subject.system_hash")

        if not self.scan.scanner_version:
            issues.append("Missing scan.scanner_version")

        if not self.scan.frameworks:
            issues.append("Missing scan.frameworks (at least one required)")

        if self.scan.checks_total < 0:
            issues.append("scan.checks_total cannot be negative")

        if self.scan.checks_passed + self.scan.checks_warned + self.scan.checks_failed != self.scan.checks_total:
            issues.append(
                f"Check counts don't add up: "
                f"{self.scan.checks_passed}+{self.scan.checks_warned}+{self.scan.checks_failed} "
                f"!= {self.scan.checks_total}"
            )

        if self.crypto.signature and not self.crypto.public_key_fingerprint:
            issues.append("Has signature but missing public_key_fingerprint")

        return issues
