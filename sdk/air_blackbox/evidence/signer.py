"""
ML-DSA-65 signing and verification for compliance evidence.

Signs scan results, audit chains, and evidence bundles with quantum-safe
digital signatures (FIPS 204 ML-DSA-65 / Dilithium3). Signatures prove
that evidence has not been tampered with since generation.
"""

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from rich.console import Console

from .keys import KeyManager, ALGORITHM

console = Console()


class EvidenceSigner:
    """Signs and verifies compliance evidence using ML-DSA-65.

    Uses the dilithium-py library (Dilithium3) for quantum-safe signatures.
    Designed so the signing backend can be swapped to liboqs-python for
    enterprise customers who need audited crypto libraries.

    Args:
        key_manager: KeyManager instance for key access. If None,
                     creates one with the default key directory.
    """

    def __init__(self, key_manager: Optional[KeyManager] = None) -> None:
        self.key_manager = key_manager or KeyManager()

    def sign_bytes(self, data: bytes) -> dict:
        """Sign raw bytes and return a signature envelope.

        Args:
            data: The bytes to sign.

        Returns:
            Dict containing the signature, algorithm, key_id, timestamp,
            and a SHA-256 hash of the signed data.

        Raises:
            FileNotFoundError: If no signing keys exist.
            ImportError: If dilithium-py is not installed.
        """
        from dilithium_py.dilithium import Dilithium3

        _public_key, private_key = self.key_manager.load()
        public_key = self.key_manager.load_public_key()

        signature = Dilithium3.sign(private_key, data)

        return {
            "algorithm": ALGORITHM,
            "key_id": self.key_manager.get_key_id(),
            "signature_hex": signature.hex(),
            "data_sha256": hashlib.sha256(data).hexdigest(),
            "signed_at": datetime.now(timezone.utc).isoformat(),
            "signature_size_bytes": len(signature),
            "public_key_hash": hashlib.sha256(public_key).hexdigest(),
        }

    def sign_json(self, data: dict) -> dict:
        """Sign a JSON-serializable dict and return a signature envelope.

        The dict is serialized with sorted keys and no extra whitespace
        to ensure deterministic output. The same dict will always produce
        the same bytes for signing.

        Args:
            data: Dict to sign.

        Returns:
            Signature envelope dict (see sign_bytes).
        """
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self.sign_bytes(canonical)

    def sign_file(self, file_path: Union[str, Path]) -> dict:
        """Sign a file and return a signature envelope.

        Args:
            file_path: Path to the file to sign.

        Returns:
            Signature envelope dict with an additional 'file' field.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        data = path.read_bytes()
        envelope = self.sign_bytes(data)
        envelope["file"] = str(path.resolve())
        envelope["file_size_bytes"] = len(data)
        return envelope

    def verify_bytes(self, data: bytes, signature_hex: str,
                     public_key: Optional[bytes] = None) -> bool:
        """Verify a signature over raw bytes.

        Args:
            data: The original signed bytes.
            signature_hex: Hex-encoded ML-DSA-65 signature.
            public_key: Public key bytes. If None, loads from key_manager.

        Returns:
            True if the signature is valid, False otherwise.
        """
        from dilithium_py.dilithium import Dilithium3

        if public_key is None:
            public_key = self.key_manager.load_public_key()

        signature = bytes.fromhex(signature_hex)

        try:
            return Dilithium3.verify(public_key, data, signature)
        except Exception:
            return False

    def verify_json(self, data: dict, signature_hex: str,
                    public_key: Optional[bytes] = None) -> bool:
        """Verify a signature over a JSON dict.

        The dict is re-serialized with sorted keys to match the signing
        canonical form.

        Args:
            data: The original dict that was signed.
            signature_hex: Hex-encoded ML-DSA-65 signature.
            public_key: Public key bytes. If None, loads from key_manager.

        Returns:
            True if the signature is valid, False otherwise.
        """
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self.verify_bytes(canonical, signature_hex, public_key)

    def verify_file(self, file_path: Union[str, Path], signature_hex: str,
                    public_key: Optional[bytes] = None) -> bool:
        """Verify a signature over a file.

        Args:
            file_path: Path to the file to verify.
            signature_hex: Hex-encoded ML-DSA-65 signature.
            public_key: Public key bytes. If None, loads from key_manager.

        Returns:
            True if the signature is valid, False otherwise.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        data = path.read_bytes()
        return self.verify_bytes(data, signature_hex, public_key)

    def verify_envelope(self, data: bytes, envelope: dict,
                        public_key: Optional[bytes] = None) -> dict:
        """Verify a signature envelope and return a detailed result.

        Checks:
        1. Signature is cryptographically valid
        2. Data SHA-256 matches the envelope hash
        3. Algorithm matches expected ML-DSA-65

        Args:
            data: The original signed bytes.
            envelope: The signature envelope dict from sign_bytes/sign_json.
            public_key: Public key bytes. If None, loads from key_manager.

        Returns:
            Dict with verification result details.
        """
        result = {
            "verified": False,
            "checks": {},
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

        # Check 1: Algorithm matches
        algo_ok = envelope.get("algorithm") == ALGORITHM
        result["checks"]["algorithm"] = {
            "passed": algo_ok,
            "expected": ALGORITHM,
            "actual": envelope.get("algorithm"),
        }

        # Check 2: Data hash matches
        data_hash = hashlib.sha256(data).hexdigest()
        hash_ok = data_hash == envelope.get("data_sha256")
        result["checks"]["data_integrity"] = {
            "passed": hash_ok,
            "expected": envelope.get("data_sha256"),
            "actual": data_hash,
        }

        # Check 3: Cryptographic signature is valid
        sig_hex = envelope.get("signature_hex", "")
        sig_ok = False
        if sig_hex:
            sig_ok = self.verify_bytes(data, sig_hex, public_key)
        result["checks"]["signature"] = {
            "passed": sig_ok,
            "algorithm": ALGORITHM,
            "key_id": envelope.get("key_id"),
        }

        # Overall verdict
        result["verified"] = algo_ok and hash_ok and sig_ok
        return result
