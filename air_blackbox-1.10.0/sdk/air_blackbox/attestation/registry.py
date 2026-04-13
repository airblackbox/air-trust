"""
Local attestation registry -- stores and queries attestation records.

This is the local storage layer. Attestations are saved as JSON files
in ~/.air-blackbox/attestations/. When the public registry API ships
(Phase 2D+), the CLI will push attestations from here to the cloud.

The local registry is the source of truth. The cloud registry is a mirror.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console

from .schema import AttestationRecord

console = Console()

# Default storage location
DEFAULT_ATTESTATION_DIR = Path.home() / ".air-blackbox" / "attestations"


class LocalRegistry:
    """Local file-based attestation registry.

    Stores attestation records as individual JSON files, indexed by
    attestation_id. Supports listing, filtering, and lookup.

    Args:
        registry_dir: Directory to store attestation files.
                      Defaults to ~/.air-blackbox/attestations/.
    """

    def __init__(self, registry_dir: Optional[Path] = None) -> None:
        self.registry_dir = Path(registry_dir) if registry_dir else DEFAULT_ATTESTATION_DIR

    def _ensure_dir(self) -> None:
        """Create the registry directory if it does not exist."""
        self.registry_dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, attestation_id: str) -> Path:
        """Get the file path for a given attestation ID."""
        safe_name = attestation_id.replace("/", "_").replace("\\", "_")
        return self.registry_dir / f"{safe_name}.json"

    def save(self, record: AttestationRecord) -> Path:
        """Save an attestation record to the local registry.

        Args:
            record: The attestation record to save.

        Returns:
            Path to the saved file.

        Raises:
            ValueError: If the record fails validation.
        """
        issues = record.validate()
        if issues:
            raise ValueError(
                f"Invalid attestation record: {'; '.join(issues)}"
            )

        self._ensure_dir()
        path = self._path_for(record.attestation_id)

        # Atomic write
        tmp_path = path.with_suffix(".tmp")
        try:
            tmp_path.write_text(record.to_json(), encoding="utf-8")
            tmp_path.rename(path)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise

        return path

    def load(self, attestation_id: str) -> Optional[AttestationRecord]:
        """Load an attestation record by ID.

        Args:
            attestation_id: The attestation ID to look up.

        Returns:
            AttestationRecord if found, None otherwise.
        """
        path = self._path_for(attestation_id)
        if not path.exists():
            return None

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return AttestationRecord.from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            console.print(f"[yellow]Warning:[/yellow] Corrupt attestation file {path}: {e}")
            return None

    def list_all(self) -> List[AttestationRecord]:
        """List all attestation records, newest first.

        Returns:
            List of AttestationRecord objects sorted by created_at descending.
        """
        if not self.registry_dir.exists():
            return []

        records = []
        for path in self.registry_dir.glob("air-att-*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                records.append(AttestationRecord.from_dict(data))
            except (json.JSONDecodeError, KeyError, TypeError):
                continue

        # Sort by created_at descending (newest first)
        records.sort(key=lambda r: r.created_at, reverse=True)
        return records

    def find_by_system(self, system_hash: str) -> List[AttestationRecord]:
        """Find all attestations for a given system hash.

        Args:
            system_hash: SHA-256 hash of the system to look up.

        Returns:
            List of matching AttestationRecords, newest first.
        """
        return [
            r for r in self.list_all()
            if r.subject.system_hash == system_hash
        ]

    def count(self) -> int:
        """Count total attestations in the registry."""
        if not self.registry_dir.exists():
            return 0
        return len(list(self.registry_dir.glob("air-att-*.json")))

    def delete(self, attestation_id: str) -> bool:
        """Delete an attestation record.

        Args:
            attestation_id: The attestation ID to delete.

        Returns:
            True if deleted, False if not found.
        """
        path = self._path_for(attestation_id)
        if path.exists():
            path.unlink()
            return True
        return False
