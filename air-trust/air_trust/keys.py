"""
Ed25519 key management for air-trust v1.2 signed handoffs.

Each AgentIdentity can have an Ed25519 keypair. Private keys are stored
with 0o600 permissions. Public keys are stored with 0o644 permissions.

Usage:
    from air_trust.keys import generate_keypair, load_private_key, load_public_key

    identity = AgentIdentity(agent_name="research-bot", owner="jason@airblackbox.ai")

    # Generate a new keypair for this identity
    pub_hex = generate_keypair(identity.fingerprint)

    # Sign some data
    from air_trust.keys import sign, verify_signature
    signature = sign(identity.fingerprint, b"data to sign")

    # Verify a signature
    is_valid = verify_signature(pub_hex, signature, b"data to sign")
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Optional, Tuple

# ── Ed25519 via cryptography library ──────────────────────────────

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature

    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


def _ensure_crypto():
    """Raise a clear error if the cryptography library is missing."""
    if not _HAS_CRYPTO:
        raise ImportError(
            "Ed25519 handoff signatures require the 'cryptography' package. "
            "Install it with: pip install cryptography"
        )


# ── Key storage paths ─────────────────────────────────────────────

def _keys_dir() -> Path:
    """Return the keys directory, creating it if needed."""
    d = Path.home() / ".air-trust" / "keys"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _private_key_path(fingerprint: str) -> Path:
    return _keys_dir() / f"{fingerprint}.key"


def _public_key_path(fingerprint: str) -> Path:
    return _keys_dir() / f"{fingerprint}.pub"


# ── Key generation ────────────────────────────────────────────────

def generate_keypair(fingerprint: str) -> str:
    """Generate an Ed25519 keypair and store it on disk.

    Args:
        fingerprint: The agent's fingerprint (from AgentIdentity).

    Returns:
        The public key as a hex string with 'ed25519:' prefix.

    Raises:
        FileExistsError: If a keypair already exists for this fingerprint.
        ImportError: If the cryptography library is not installed.
    """
    _ensure_crypto()

    priv_path = _private_key_path(fingerprint)
    pub_path = _public_key_path(fingerprint)

    if priv_path.exists():
        raise FileExistsError(
            f"Keypair already exists for fingerprint {fingerprint}. "
            f"Delete {priv_path} and {pub_path} to regenerate."
        )

    # Generate keypair
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Serialize to raw bytes
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Store private key (owner-only read/write)
    priv_path.write_text(priv_bytes.hex())
    os.chmod(priv_path, 0o600)

    # Store public key (world readable)
    pub_path.write_text(pub_bytes.hex())
    os.chmod(pub_path, 0o644)

    return f"ed25519:{pub_bytes.hex()}"


def has_keypair(fingerprint: str) -> bool:
    """Check if a keypair exists for this fingerprint."""
    return _private_key_path(fingerprint).exists()


# ── Key loading ───────────────────────────────────────────────────

def load_private_key(fingerprint: str) -> Ed25519PrivateKey:
    """Load the Ed25519 private key for the given fingerprint.

    Raises:
        FileNotFoundError: If no private key exists for this fingerprint.
        ImportError: If the cryptography library is not installed.
    """
    _ensure_crypto()

    priv_path = _private_key_path(fingerprint)
    if not priv_path.exists():
        raise FileNotFoundError(
            f"No private key for fingerprint {fingerprint}. "
            f"Generate one with: air_trust.keys.generate_keypair('{fingerprint}')"
        )

    priv_hex = priv_path.read_text().strip()
    priv_bytes = bytes.fromhex(priv_hex)
    return Ed25519PrivateKey.from_private_bytes(priv_bytes)


def load_public_key(fingerprint: str) -> Ed25519PublicKey:
    """Load the Ed25519 public key for the given fingerprint.

    Raises:
        FileNotFoundError: If no public key exists for this fingerprint.
        ImportError: If the cryptography library is not installed.
    """
    _ensure_crypto()

    pub_path = _public_key_path(fingerprint)
    if not pub_path.exists():
        raise FileNotFoundError(
            f"No public key for fingerprint {fingerprint}. "
            f"Generate one with: air_trust.keys.generate_keypair('{fingerprint}')"
        )

    pub_hex = pub_path.read_text().strip()
    pub_bytes = bytes.fromhex(pub_hex)
    return Ed25519PublicKey.from_public_bytes(pub_bytes)


def load_public_key_hex(fingerprint: str) -> str:
    """Load the public key as a prefixed hex string ('ed25519:...')."""
    pub_path = _public_key_path(fingerprint)
    if not pub_path.exists():
        raise FileNotFoundError(f"No public key for fingerprint {fingerprint}.")
    pub_hex = pub_path.read_text().strip()
    return f"ed25519:{pub_hex}"


def public_key_from_hex(pub_hex: str) -> Ed25519PublicKey:
    """Parse a public key from a prefixed hex string.

    Args:
        pub_hex: Either 'ed25519:abcdef...' or just 'abcdef...'

    Returns:
        Ed25519PublicKey object.
    """
    _ensure_crypto()

    if pub_hex.startswith("ed25519:"):
        pub_hex = pub_hex[8:]
    pub_bytes = bytes.fromhex(pub_hex)
    return Ed25519PublicKey.from_public_bytes(pub_bytes)


# ── Signing and verification ──────────────────────────────────────

def build_signing_payload(
    interaction_id: str,
    counterparty_id: str,
    payload_hash: str,
    nonce: str,
    event_type: str,
    timestamp: str,
) -> bytes:
    """Build the canonical signing payload for a handoff record.

    Format: interaction_id|counterparty_id|payload_hash|nonce|type|timestamp
    """
    parts = [interaction_id, counterparty_id, payload_hash, nonce, event_type, timestamp]
    return "|".join(parts).encode("utf-8")


def sign(fingerprint: str, data: bytes) -> str:
    """Sign data with the agent's Ed25519 private key.

    Args:
        fingerprint: The agent's fingerprint (to find the private key).
        data: The bytes to sign.

    Returns:
        Signature as a prefixed hex string: 'ed25519:abcdef...'
    """
    private_key = load_private_key(fingerprint)
    sig_bytes = private_key.sign(data)
    return f"ed25519:{sig_bytes.hex()}"


def verify_signature(public_key_hex: str, signature_hex: str, data: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        public_key_hex: Public key as 'ed25519:...' or raw hex.
        signature_hex: Signature as 'ed25519:...' or raw hex.
        data: The bytes that were signed.

    Returns:
        True if the signature is valid, False otherwise.
    """
    _ensure_crypto()

    pub_key = public_key_from_hex(public_key_hex)

    if signature_hex.startswith("ed25519:"):
        signature_hex = signature_hex[8:]
    sig_bytes = bytes.fromhex(signature_hex)

    try:
        pub_key.verify(sig_bytes, data)
        return True
    except InvalidSignature:
        return False


def compute_payload_hash(payload: str) -> str:
    """Compute SHA-256 hash of a payload string.

    Args:
        payload: The payload content (task description, result, etc.)

    Returns:
        Hash as 'sha256:abcdef...'
    """
    h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def generate_nonce() -> str:
    """Generate a random 16-byte nonce as a hex string."""
    return os.urandom(16).hex()
