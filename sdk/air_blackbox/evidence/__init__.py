"""
Evidence module -- cryptographic signing and verification for AIR Blackbox.

Provides ML-DSA-65 (FIPS 204) quantum-safe digital signatures for
compliance scan results, audit chains, and evidence bundles.
"""

from .keys import KeyManager
from .signer import EvidenceSigner

__all__ = ["KeyManager", "EvidenceSigner"]
