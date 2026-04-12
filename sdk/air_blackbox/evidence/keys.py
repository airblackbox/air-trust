"""
Key management for ML-DSA-65 quantum-safe signing.

Generates, stores, and loads ML-DSA-65 (Dilithium3 / FIPS 204) key pairs.
Keys are stored locally in ~/.air-blackbox/keys/ and never leave the machine.
"""

import json
import hashlib
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

from rich.console import Console

console = Console()

# Default key storage location
DEFAULT_KEY_DIR = Path.home() / ".air-blackbox" / "keys"

# Algorithm identifier used in metadata and bundles
ALGORITHM = "ML-DSA-65"
ALGORITHM_IMPL = "dilithium-py (Dilithium3)"


def _check_dilithium_available() -> bool:
    """Check if dilithium-py is installed."""
    try:
        from dilithium_py.dilithium import Dilithium3  # noqa: F401
        return True
    except ImportError:
        return False


class KeyManager:
    """Manages ML-DSA-65 key pairs for signing compliance evidence.

    Keys are stored in a local directory (default: ~/.air-blackbox/keys/).
    Private keys are restricted to owner-only read/write (chmod 600).
    Keys never leave the local machine.

    Args:
        key_dir: Directory to store keys. Defaults to ~/.air-blackbox/keys/.
    """

    def __init__(self, key_dir: Optional[Path] = None) -> None:
        self.key_dir = Path(key_dir) if key_dir else DEFAULT_KEY_DIR

    def _ensure_dir(self) -> None:
        """Create the key directory if it does not exist."""
        self.key_dir.mkdir(parents=True, exist_ok=True)

    @property
    def private_key_path(self) -> Path:
        return self.key_dir / "signing_key.bin"

    @property
    def public_key_path(self) -> Path:
        return self.key_dir / "public_key.bin"

    @property
    def metadata_path(self) -> Path:
        return self.key_dir / "key_metadata.json"

    def has_keys(self) -> bool:
        """Check if a key pair already exists."""
        return self.private_key_path.exists() and self.public_key_path.exists()

    def generate(self, force: bool = False) -> Tuple[bytes, bytes]:
        """Generate a new ML-DSA-65 key pair and save to disk.

        Args:
            force: If True, overwrite existing keys. Defaults to False.

        Returns:
            Tuple of (public_key_bytes, private_key_bytes).

        Raises:
            FileExistsError: If keys already exist and force is False.
            ImportError: If dilithium-py is not installed.
        """
        if not _check_dilithium_available():
            raise ImportError(
                "dilithium-py is required for ML-DSA-65 signing.\n"
                "Install it with: pip install dilithium-py"
            )

        if self.has_keys() and not force:
            raise FileExistsError(
                f"Keys already exist in {self.key_dir}. "
                "Use force=True to overwrite, or load existing keys."
            )

        from dilithium_py.dilithium import Dilithium3

        # Generate the key pair
        public_key, private_key = Dilithium3.keygen()

        # Save keys to disk
        self._ensure_dir()
        self._write_key_file(self.private_key_path, private_key, restricted=True)
        self._write_key_file(self.public_key_path, public_key, restricted=False)

        # Save metadata
        key_id = hashlib.sha256(public_key).hexdigest()[:16]
        metadata = {
            "algorithm": ALGORITHM,
            "implementation": ALGORITHM_IMPL,
            "key_id": key_id,
            "public_key_hash": hashlib.sha256(public_key).hexdigest(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "key_size_bytes": {
                "public": len(public_key),
                "private": len(private_key),
            },
        }
        self.metadata_path.write_text(
            json.dumps(metadata, indent=2), encoding="utf-8"
        )

        console.print(f"[green]Generated ML-DSA-65 key pair[/green]")
        console.print(f"  Key ID:      {key_id}")
        console.print(f"  Public key:  {self.public_key_path}")
        console.print(f"  Private key: {self.private_key_path}")

        return public_key, private_key

    def load(self) -> Tuple[bytes, bytes]:
        """Load an existing key pair from disk.

        Returns:
            Tuple of (public_key_bytes, private_key_bytes).

        Raises:
            FileNotFoundError: If keys do not exist.
        """
        if not self.has_keys():
            raise FileNotFoundError(
                f"No keys found in {self.key_dir}. "
                "Run 'air-blackbox sign --keygen' to generate a key pair."
            )

        public_key = self.public_key_path.read_bytes()
        private_key = self.private_key_path.read_bytes()
        return public_key, private_key

    def load_public_key(self) -> bytes:
        """Load only the public key (for verification).

        Returns:
            Public key bytes.

        Raises:
            FileNotFoundError: If public key does not exist.
        """
        if not self.public_key_path.exists():
            raise FileNotFoundError(
                f"No public key found at {self.public_key_path}."
            )
        return self.public_key_path.read_bytes()

    def get_metadata(self) -> dict:
        """Load key metadata.

        Returns:
            Dict with algorithm, key_id, creation date, etc.
        """
        if not self.metadata_path.exists():
            return {}
        return json.loads(self.metadata_path.read_text(encoding="utf-8"))

    def get_key_id(self) -> str:
        """Get the short key ID (first 16 hex chars of public key SHA-256).

        Returns:
            Key ID string, or 'no-key' if no keys exist.
        """
        metadata = self.get_metadata()
        return metadata.get("key_id", "no-key")

    def _write_key_file(self, path: Path, data: bytes, restricted: bool) -> None:
        """Write key bytes to a file, optionally restricting permissions.

        Args:
            path: File path to write.
            data: Key bytes.
            restricted: If True, set file to owner-only read/write (chmod 600).
        """
        # Write to temp file first, then rename (atomic write)
        tmp_path = path.with_suffix(".tmp")
        try:
            tmp_path.write_bytes(data)
            if restricted:
                # Owner read/write only -- protects the private key
                try:
                    os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)
                except OSError:
                    # Some filesystems (Docker, mounted volumes) may not support chmod
                    pass
            tmp_path.rename(path)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise
