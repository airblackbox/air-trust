"""
Tests for the attestation module -- schema, registry, badge, and signing.

Covers record creation, validation, serialization, local storage,
badge generation, and cryptographic signing of attestations.
"""

import json
import pytest
from pathlib import Path

from air_blackbox.attestation.schema import (
    AttestationRecord, SubjectInfo, ScanInfo, EvidenceInfo, CryptoInfo,
    VerificationInfo, SCHEMA_VERSION, ATTESTATION_PREFIX,
    generate_attestation_id,
)
from air_blackbox.attestation.registry import LocalRegistry
from air_blackbox.attestation.badge import (
    generate_badge_svg, badge_for_attestation, badge_markdown,
    COLOR_GREEN, COLOR_YELLOW, COLOR_BLUE,
)
from air_blackbox.evidence.keys import KeyManager
from air_blackbox.evidence.signer import EvidenceSigner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_record():
    """A valid attestation record for testing."""
    return AttestationRecord(
        subject=SubjectInfo(
            system_hash="a" * 64,
            system_name="Test AI System",
            system_version="1.0.0",
            files_scanned=42,
        ),
        scan=ScanInfo(
            scanner_version="air-blackbox 1.9.0",
            frameworks=["eu", "iso42001", "nist", "colorado"],
            checks_passed=5,
            checks_warned=1,
            checks_failed=0,
            checks_total=6,
        ),
        evidence=EvidenceInfo(
            bundle_hash="b" * 64,
        ),
        crypto=CryptoInfo(
            algorithm="ML-DSA-65",
            public_key_fingerprint="c" * 64,
        ),
    )


@pytest.fixture
def registry(tmp_path):
    """Local registry in a temp directory."""
    return LocalRegistry(registry_dir=tmp_path / "attestations")


@pytest.fixture
def key_manager(tmp_path):
    """KeyManager with generated keys."""
    km = KeyManager(key_dir=tmp_path / "keys")
    km.generate()
    return km


# ---------------------------------------------------------------------------
# Schema Tests
# ---------------------------------------------------------------------------

class TestAttestationSchema:
    """Tests for the attestation record data model."""

    def test_generate_attestation_id_format(self):
        """Attestation IDs follow the expected format."""
        att_id = generate_attestation_id()
        assert att_id.startswith(ATTESTATION_PREFIX)
        parts = att_id.split("-")
        # air-att-YYYY-MM-DD-XXXXXXXX
        assert len(parts) == 6
        assert len(parts[5]) == 8  # 8 hex chars

    def test_unique_ids(self):
        """Each generated ID is unique."""
        ids = [generate_attestation_id() for _ in range(100)]
        assert len(set(ids)) == 100

    def test_default_record_has_required_fields(self):
        """A default record has schema version and attestation ID."""
        r = AttestationRecord(
            subject=SubjectInfo(system_hash="x" * 64),
            scan=ScanInfo(scanner_version="test", frameworks=["eu"]),
        )
        assert r.schema_version == SCHEMA_VERSION
        assert r.attestation_id.startswith(ATTESTATION_PREFIX)
        assert r.created_at  # auto-populated

    def test_to_dict_roundtrip(self, sample_record):
        """to_dict -> from_dict produces an equivalent record."""
        d = sample_record.to_dict()
        restored = AttestationRecord.from_dict(d)
        assert restored.attestation_id == sample_record.attestation_id
        assert restored.subject.system_hash == sample_record.subject.system_hash
        assert restored.scan.frameworks == sample_record.scan.frameworks
        assert restored.scan.checks_passed == sample_record.scan.checks_passed

    def test_to_json_roundtrip(self, sample_record):
        """to_json -> from_json produces an equivalent record."""
        j = sample_record.to_json()
        restored = AttestationRecord.from_json(j)
        assert restored.attestation_id == sample_record.attestation_id

    def test_canonical_bytes_deterministic(self, sample_record):
        """Same record always produces the same canonical bytes."""
        b1 = sample_record.to_canonical_bytes()
        b2 = sample_record.to_canonical_bytes()
        assert b1 == b2

    def test_canonical_bytes_excludes_signature(self, sample_record):
        """Canonical bytes have empty signature field (for signing)."""
        sample_record.crypto.signature = "deadbeef" * 100
        canonical = sample_record.to_canonical_bytes()
        parsed = json.loads(canonical)
        assert parsed["crypto"]["signature"] == ""

    def test_record_hash_changes_with_content(self, sample_record):
        """Record hash changes when content changes."""
        hash1 = sample_record.record_hash()
        sample_record.scan.checks_passed = 99
        hash2 = sample_record.record_hash()
        assert hash1 != hash2

    def test_validate_valid_record(self, sample_record):
        """A valid record passes validation."""
        issues = sample_record.validate()
        assert issues == []

    def test_validate_missing_system_hash(self):
        """Missing system hash fails validation."""
        r = AttestationRecord(
            subject=SubjectInfo(system_hash=""),
            scan=ScanInfo(scanner_version="test", frameworks=["eu"]),
        )
        issues = r.validate()
        assert any("system_hash" in i for i in issues)

    def test_validate_missing_frameworks(self):
        """Empty frameworks list fails validation."""
        r = AttestationRecord(
            subject=SubjectInfo(system_hash="x" * 64),
            scan=ScanInfo(scanner_version="test", frameworks=[]),
        )
        issues = r.validate()
        assert any("frameworks" in i for i in issues)

    def test_validate_check_count_mismatch(self):
        """Mismatched check counts fail validation."""
        r = AttestationRecord(
            subject=SubjectInfo(system_hash="x" * 64),
            scan=ScanInfo(
                scanner_version="test",
                frameworks=["eu"],
                checks_passed=3,
                checks_warned=0,
                checks_failed=0,
                checks_total=6,  # 3 != 6
            ),
        )
        issues = r.validate()
        assert any("don't add up" in i for i in issues)

    def test_validate_signature_without_key(self):
        """Having a signature but no key fingerprint fails validation."""
        r = AttestationRecord(
            subject=SubjectInfo(system_hash="x" * 64),
            scan=ScanInfo(
                scanner_version="test", frameworks=["eu"],
                checks_total=0,
            ),
            crypto=CryptoInfo(signature="abc123", public_key_fingerprint=""),
        )
        issues = r.validate()
        assert any("public_key_fingerprint" in i for i in issues)


# ---------------------------------------------------------------------------
# Registry Tests
# ---------------------------------------------------------------------------

class TestLocalRegistry:
    """Tests for the local attestation file store."""

    def test_save_and_load(self, registry, sample_record):
        """Save then load returns the same record."""
        registry.save(sample_record)
        loaded = registry.load(sample_record.attestation_id)
        assert loaded is not None
        assert loaded.attestation_id == sample_record.attestation_id
        assert loaded.subject.system_hash == sample_record.subject.system_hash

    def test_load_nonexistent_returns_none(self, registry):
        """Loading a missing attestation returns None."""
        result = registry.load("air-att-2026-01-01-nonexist")
        assert result is None

    def test_list_all_empty(self, registry):
        """Empty registry returns empty list."""
        assert registry.list_all() == []

    def test_list_all_returns_records(self, registry, sample_record):
        """Listing returns saved records."""
        registry.save(sample_record)
        records = registry.list_all()
        assert len(records) == 1
        assert records[0].attestation_id == sample_record.attestation_id

    def test_list_all_sorted_newest_first(self, registry):
        """Records are sorted newest first."""
        r1 = AttestationRecord(
            attestation_id="air-att-2026-01-01-aaaaaaaa",
            created_at="2026-01-01T00:00:00+00:00",
            subject=SubjectInfo(system_hash="x" * 64),
            scan=ScanInfo(scanner_version="test", frameworks=["eu"], checks_total=0),
        )
        r2 = AttestationRecord(
            attestation_id="air-att-2026-06-01-bbbbbbbb",
            created_at="2026-06-01T00:00:00+00:00",
            subject=SubjectInfo(system_hash="y" * 64),
            scan=ScanInfo(scanner_version="test", frameworks=["eu"], checks_total=0),
        )
        registry.save(r1)
        registry.save(r2)
        records = registry.list_all()
        assert records[0].attestation_id == r2.attestation_id  # newer first

    def test_count(self, registry, sample_record):
        """Count returns the number of stored attestations."""
        assert registry.count() == 0
        registry.save(sample_record)
        assert registry.count() == 1

    def test_delete(self, registry, sample_record):
        """Delete removes a record from the registry."""
        registry.save(sample_record)
        assert registry.count() == 1
        deleted = registry.delete(sample_record.attestation_id)
        assert deleted is True
        assert registry.count() == 0

    def test_delete_nonexistent(self, registry):
        """Deleting a missing record returns False."""
        assert registry.delete("air-att-2026-01-01-nonexist") is False

    def test_find_by_system(self, registry):
        """Find by system hash returns matching records."""
        hash_a = "a" * 64
        hash_b = "b" * 64
        r1 = AttestationRecord(
            subject=SubjectInfo(system_hash=hash_a),
            scan=ScanInfo(scanner_version="test", frameworks=["eu"], checks_total=0),
        )
        r2 = AttestationRecord(
            subject=SubjectInfo(system_hash=hash_b),
            scan=ScanInfo(scanner_version="test", frameworks=["eu"], checks_total=0),
        )
        registry.save(r1)
        registry.save(r2)
        results = registry.find_by_system(hash_a)
        assert len(results) == 1
        assert results[0].subject.system_hash == hash_a

    def test_save_invalid_record_raises(self, registry):
        """Saving an invalid record raises ValueError."""
        bad = AttestationRecord(
            subject=SubjectInfo(system_hash=""),  # invalid
            scan=ScanInfo(scanner_version="test", frameworks=["eu"], checks_total=0),
        )
        with pytest.raises(ValueError):
            registry.save(bad)


# ---------------------------------------------------------------------------
# Badge Tests
# ---------------------------------------------------------------------------

class TestBadge:
    """Tests for SVG badge generation."""

    def test_generate_badge_svg_is_valid_svg(self):
        """Generated badge is valid SVG."""
        svg = generate_badge_svg("AIR Attested", "EU | 6/6")
        assert svg.startswith("<svg")
        assert "</svg>" in svg
        assert "AIR Attested" in svg
        assert "EU | 6/6" in svg

    def test_badge_with_link(self):
        """Badge with link wraps in an anchor tag."""
        svg = generate_badge_svg("Test", "OK", link="https://example.com")
        assert 'href="https://example.com"' in svg

    def test_badge_for_all_passing(self, sample_record):
        """All-passing multi-framework record gets blue badge."""
        svg = badge_for_attestation(sample_record)
        assert "AIR Attested" in svg
        # 4 frameworks = blue badge
        assert COLOR_BLUE in svg

    def test_badge_for_failures(self):
        """Record with failures gets yellow AIR Scanned badge."""
        r = AttestationRecord(
            subject=SubjectInfo(system_hash="x" * 64),
            scan=ScanInfo(
                scanner_version="test",
                frameworks=["eu"],
                checks_passed=4, checks_warned=1, checks_failed=1,
                checks_total=6,
            ),
        )
        svg = badge_for_attestation(r)
        assert "AIR Scanned" in svg
        assert COLOR_YELLOW in svg

    def test_badge_for_single_framework_passing(self):
        """Single framework, all passing gets green badge."""
        r = AttestationRecord(
            subject=SubjectInfo(system_hash="x" * 64),
            scan=ScanInfo(
                scanner_version="test",
                frameworks=["eu"],
                checks_passed=6, checks_warned=0, checks_failed=0,
                checks_total=6,
            ),
        )
        svg = badge_for_attestation(r)
        assert "AIR Attested" in svg
        assert COLOR_GREEN in svg

    def test_badge_markdown_format(self, sample_record):
        """Badge markdown has correct format."""
        md = badge_markdown(sample_record)
        assert md.startswith("[![")
        assert sample_record.attestation_id in md
        assert "airblackbox.ai/badge/" in md
        assert "airblackbox.ai/verify/" in md

    def test_badge_escapes_special_chars(self):
        """Badge properly escapes XML special characters."""
        svg = generate_badge_svg("Test <>&", "OK \"quotes\"")
        assert "&lt;" in svg
        assert "&gt;" in svg
        assert "&amp;" in svg
        assert "&quot;" in svg


# ---------------------------------------------------------------------------
# Signed Attestation Tests
# ---------------------------------------------------------------------------

class TestSignedAttestation:
    """Tests for cryptographically signed attestations."""

    def test_sign_and_verify_attestation(self, sample_record, key_manager):
        """Sign an attestation, then verify the signature."""
        import hashlib
        pk = key_manager.load_public_key()
        pk_fingerprint = hashlib.sha256(pk).hexdigest()
        sample_record.crypto.public_key_fingerprint = pk_fingerprint

        signer = EvidenceSigner(key_manager=key_manager)
        canonical = sample_record.to_canonical_bytes()
        envelope = signer.sign_bytes(canonical)
        sample_record.crypto.signature = envelope["signature_hex"]

        # Verify
        # Re-compute canonical (signature excluded)
        verify_bytes = sample_record.to_canonical_bytes()
        assert signer.verify_bytes(verify_bytes, sample_record.crypto.signature) is True

    def test_tampered_attestation_fails(self, sample_record, key_manager):
        """Modifying a signed attestation fails verification."""
        import hashlib
        pk = key_manager.load_public_key()
        sample_record.crypto.public_key_fingerprint = hashlib.sha256(pk).hexdigest()

        signer = EvidenceSigner(key_manager=key_manager)
        canonical = sample_record.to_canonical_bytes()
        envelope = signer.sign_bytes(canonical)
        sample_record.crypto.signature = envelope["signature_hex"]

        # Tamper: change the check count
        sample_record.scan.checks_passed = 99
        tampered_bytes = sample_record.to_canonical_bytes()
        assert signer.verify_bytes(tampered_bytes, sample_record.crypto.signature) is False

    def test_signed_record_saves_and_loads(self, sample_record, key_manager, registry):
        """A signed record can be saved to registry and loaded back."""
        import hashlib
        pk = key_manager.load_public_key()
        sample_record.crypto.public_key_fingerprint = hashlib.sha256(pk).hexdigest()

        signer = EvidenceSigner(key_manager=key_manager)
        canonical = sample_record.to_canonical_bytes()
        envelope = signer.sign_bytes(canonical)
        sample_record.crypto.signature = envelope["signature_hex"]

        registry.save(sample_record)
        loaded = registry.load(sample_record.attestation_id)

        # Verify the loaded record's signature
        verify_bytes = loaded.to_canonical_bytes()
        assert signer.verify_bytes(verify_bytes, loaded.crypto.signature) is True
