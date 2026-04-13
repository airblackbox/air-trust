"""
Attestation module -- compliance oracle and public trust layer.

Creates, stores, and verifies attestation records that prove an AI system
was scanned for compliance. Attestations are signed with ML-DSA-65 and
designed for future publication to a public registry.
"""

from .schema import AttestationRecord
from .registry import LocalRegistry

__all__ = ["AttestationRecord", "LocalRegistry"]
