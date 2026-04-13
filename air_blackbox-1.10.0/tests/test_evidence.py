"""
Tests for the ML-DSA-65 evidence signing module.

Covers key generation, signing, verification, tamper detection,
and edge cases.
"""

import json
import pytest
from pathlib import Path

from air_blackbox.evidence.keys import KeyManager, ALGORITHM
from air_blackbox.evidence.signer import EvidenceSigner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def key_dir(tmp_path):
    """Temporary key directory for each test."""
    return tmp_path / "keys"


@pytest.fixture
def key_manager(key_dir):
    """KeyManager pointed at a temporary directory."""
    return KeyManager(key_dir=key_dir)


@pytest.fixture
def generated_keys(key_manager):
    """Generate keys and return (key_manager, public_key, private_key)."""
    pk, sk = key_manager.generate()
    return key_manager, pk, sk


@pytest.fixture
def signer(generated_keys):
    """EvidenceSigner with generated keys ready to use."""
    km, _pk, _sk = generated_keys
    return EvidenceSigner(key_manager=km)


@pytest.fixture
def sample_file(tmp_path):
    """A sample file to sign."""
    f = tmp_path / "results.json"
    data = {"status": "pass", "articles": [9, 10, 11, 12, 14, 15]}
    f.write_text(json.dumps(data), encoding="utf-8")
    return f


# ---------------------------------------------------------------------------
# Key Management Tests
# ---------------------------------------------------------------------------

class TestKeyManager:
    """Tests for ML-DSA-65 key generation and storage."""

    def test_no_keys_initially(self, key_manager):
        """Fresh key directory has no keys."""
        assert key_manager.has_keys() is False

    def test_generate_creates_keys(self, key_manager):
        """Key generation creates public and private key files."""
        pk, sk = key_manager.generate()
        assert key_manager.has_keys() is True
        assert key_manager.private_key_path.exists()
        assert key_manager.public_key_path.exists()
        assert key_manager.metadata_path.exists()

    def test_key_sizes_are_correct(self, key_manager):
        """ML-DSA-65 keys have the expected sizes (pk=1952, sk=4000)."""
        pk, sk = key_manager.generate()
        assert len(pk) == 1952
        assert len(sk) == 4000

    def test_load_returns_same_keys(self, key_manager):
        """Loading keys returns the same bytes that were generated."""
        pk_gen, sk_gen = key_manager.generate()
        pk_load, sk_load = key_manager.load()
        assert pk_gen == pk_load
        assert sk_gen == sk_load

    def test_load_public_key_only(self, key_manager):
        """Can load just the public key for verification."""
        pk_gen, _sk = key_manager.generate()
        pk_loaded = key_manager.load_public_key()
        assert pk_gen == pk_loaded

    def test_generate_refuses_overwrite_without_force(self, key_manager):
        """Second keygen raises FileExistsError without force=True."""
        key_manager.generate()
        with pytest.raises(FileExistsError):
            key_manager.generate()

    def test_generate_force_overwrites(self, key_manager):
        """force=True generates new keys (different from old)."""
        pk1, _sk1 = key_manager.generate()
        pk2, _sk2 = key_manager.generate(force=True)
        # New keypair is different (extremely high probability)
        assert pk1 != pk2

    def test_load_without_keys_raises(self, key_manager):
        """Loading from empty directory raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            key_manager.load()

    def test_load_public_key_without_keys_raises(self, key_manager):
        """Loading public key from empty directory raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            key_manager.load_public_key()

    def test_metadata_has_expected_fields(self, key_manager):
        """Key metadata includes algorithm, key_id, and creation date."""
        key_manager.generate()
        meta = key_manager.get_metadata()
        assert meta["algorithm"] == ALGORITHM
        assert "key_id" in meta
        assert len(meta["key_id"]) == 16  # 16 hex chars
        assert "created_at" in meta
        assert meta["key_size_bytes"]["public"] == 1952
        assert meta["key_size_bytes"]["private"] == 4000

    def test_get_key_id(self, key_manager):
        """Key ID is a 16-char hex string derived from public key."""
        key_manager.generate()
        key_id = key_manager.get_key_id()
        assert len(key_id) == 16
        # All hex chars
        assert all(c in "0123456789abcdef" for c in key_id)

    def test_get_key_id_no_keys(self, key_manager):
        """Key ID returns 'no-key' when no keys exist."""
        assert key_manager.get_key_id() == "no-key"


# ---------------------------------------------------------------------------
# Signing Tests
# ---------------------------------------------------------------------------

class TestEvidenceSigner:
    """Tests for ML-DSA-65 signing and verification."""

    def test_sign_bytes_returns_envelope(self, signer):
        """Signing bytes returns a well-formed envelope dict."""
        data = b"hello world"
        envelope = signer.sign_bytes(data)
        assert envelope["algorithm"] == ALGORITHM
        assert "signature_hex" in envelope
        assert "data_sha256" in envelope
        assert "signed_at" in envelope
        assert "key_id" in envelope
        assert envelope["signature_size_bytes"] == 3293

    def test_sign_and_verify_bytes(self, signer):
        """Signed bytes verify successfully."""
        data = b"compliance scan results here"
        envelope = signer.sign_bytes(data)
        assert signer.verify_bytes(data, envelope["signature_hex"]) is True

    def test_tampered_data_fails_verification(self, signer):
        """Modified data fails signature verification."""
        data = b"original data"
        envelope = signer.sign_bytes(data)
        tampered = b"tampered data"
        assert signer.verify_bytes(tampered, envelope["signature_hex"]) is False

    def test_tampered_signature_fails(self, signer):
        """Modified signature fails verification."""
        data = b"original data"
        envelope = signer.sign_bytes(data)
        # Flip a byte in the signature
        sig_bytes = bytes.fromhex(envelope["signature_hex"])
        tampered_sig = bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]
        assert signer.verify_bytes(data, tampered_sig.hex()) is False

    def test_sign_json_deterministic(self, signer):
        """Same dict always produces the same canonical bytes for signing."""
        data = {"b": 2, "a": 1}
        env1 = signer.sign_json(data)
        env2 = signer.sign_json(data)
        assert env1["data_sha256"] == env2["data_sha256"]

    def test_sign_and_verify_json(self, signer):
        """Signed JSON dict verifies successfully."""
        data = {"status": "pass", "score": 95}
        envelope = signer.sign_json(data)
        assert signer.verify_json(data, envelope["signature_hex"]) is True

    def test_tampered_json_fails(self, signer):
        """Modified JSON dict fails verification."""
        data = {"status": "pass", "score": 95}
        envelope = signer.sign_json(data)
        tampered = {"status": "pass", "score": 100}
        assert signer.verify_json(tampered, envelope["signature_hex"]) is False

    def test_sign_file(self, signer, sample_file):
        """Signing a file includes the file path and size."""
        envelope = signer.sign_file(sample_file)
        assert "file" in envelope
        assert envelope["file_size_bytes"] > 0
        assert envelope["algorithm"] == ALGORITHM

    def test_sign_and_verify_file(self, signer, sample_file):
        """Signed file verifies successfully."""
        envelope = signer.sign_file(sample_file)
        assert signer.verify_file(
            sample_file, envelope["signature_hex"]
        ) is True

    def test_sign_nonexistent_file_raises(self, signer):
        """Signing a nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            signer.sign_file("/nonexistent/file.json")

    def test_verify_nonexistent_file_raises(self, signer):
        """Verifying a nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            signer.verify_file("/nonexistent/file.json", "aabbcc")

    def test_verify_with_explicit_public_key(self, generated_keys):
        """Verification works with an explicit public key argument."""
        km, pk, _sk = generated_keys
        signer = EvidenceSigner(key_manager=km)
        data = b"test data"
        envelope = signer.sign_bytes(data)
        assert signer.verify_bytes(data, envelope["signature_hex"], public_key=pk) is True

    def test_verify_with_wrong_public_key_fails(self, generated_keys, key_dir):
        """Verification with the wrong public key fails."""
        km, _pk, _sk = generated_keys
        signer = EvidenceSigner(key_manager=km)
        data = b"test data"
        envelope = signer.sign_bytes(data)

        # Generate a different key pair
        other_km = KeyManager(key_dir=key_dir.parent / "other_keys")
        other_pk, _other_sk = other_km.generate()

        assert signer.verify_bytes(data, envelope["signature_hex"], public_key=other_pk) is False


# ---------------------------------------------------------------------------
# Envelope Verification Tests
# ---------------------------------------------------------------------------

class TestVerifyEnvelope:
    """Tests for the full envelope verification workflow."""

    def test_valid_envelope_passes_all_checks(self, signer):
        """A valid envelope passes algorithm, hash, and signature checks."""
        data = b"compliance evidence"
        envelope = signer.sign_bytes(data)
        result = signer.verify_envelope(data, envelope)
        assert result["verified"] is True
        assert result["checks"]["algorithm"]["passed"] is True
        assert result["checks"]["data_integrity"]["passed"] is True
        assert result["checks"]["signature"]["passed"] is True

    def test_tampered_data_fails_hash_check(self, signer):
        """Tampered data fails the data_integrity check."""
        data = b"original"
        envelope = signer.sign_bytes(data)
        result = signer.verify_envelope(b"tampered", envelope)
        assert result["verified"] is False
        assert result["checks"]["data_integrity"]["passed"] is False

    def test_wrong_algorithm_fails(self, signer):
        """Wrong algorithm in envelope fails the algorithm check."""
        data = b"test"
        envelope = signer.sign_bytes(data)
        envelope["algorithm"] = "RSA-2048"
        result = signer.verify_envelope(data, envelope)
        assert result["verified"] is False
        assert result["checks"]["algorithm"]["passed"] is False

    def test_missing_signature_fails(self, signer):
        """Empty signature hex fails the signature check."""
        data = b"test"
        envelope = signer.sign_bytes(data)
        envelope["signature_hex"] = ""
        result = signer.verify_envelope(data, envelope)
        assert result["verified"] is False
        assert result["checks"]["signature"]["passed"] is False

    def test_envelope_includes_timestamp(self, signer):
        """Verification result includes a verified_at timestamp."""
        data = b"test"
        envelope = signer.sign_bytes(data)
        result = signer.verify_envelope(data, envelope)
        assert "verified_at" in result


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge case and boundary tests."""

    def test_sign_empty_bytes(self, signer):
        """Signing empty bytes works and verifies."""
        data = b""
        envelope = signer.sign_bytes(data)
        assert signer.verify_bytes(data, envelope["signature_hex"]) is True

    def test_sign_large_data(self, signer):
        """Signing 1MB of data works and verifies."""
        data = b"x" * (1024 * 1024)
        envelope = signer.sign_bytes(data)
        assert signer.verify_bytes(data, envelope["signature_hex"]) is True

    def test_sign_empty_json(self, signer):
        """Signing an empty dict works and verifies."""
        data = {}
        envelope = signer.sign_json(data)
        assert signer.verify_json(data, envelope["signature_hex"]) is True

    def test_sign_nested_json(self, signer):
        """Signing deeply nested JSON works and verifies."""
        data = {"a": {"b": {"c": [1, 2, {"d": True}]}}}
        envelope = signer.sign_json(data)
        assert signer.verify_json(data, envelope["signature_hex"]) is True

    def test_deterministic_signatures(self, signer):
        """Same data + same key produces the same signature (deterministic)."""
        data = b"same data"
        env1 = signer.sign_bytes(data)
        env2 = signer.sign_bytes(data)
        # dilithium-py uses deterministic signing
        assert env1["signature_hex"] == env2["signature_hex"]
        # Both verify
        assert signer.verify_bytes(data, env1["signature_hex"]) is True
        assert signer.verify_bytes(data, env2["signature_hex"]) is True

    def test_different_data_different_signatures(self, signer):
        """Different data produces different signatures."""
        env1 = signer.sign_bytes(b"data one")
        env2 = signer.sign_bytes(b"data two")
        assert env1["signature_hex"] != env2["signature_hex"]
