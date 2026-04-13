"""
A2A Transaction Layer -- signed, chained records for every agent-to-agent message.

Every message between agents gets intercepted, signed with ML-DSA-65,
chained with HMAC-SHA256, and stored in a local tamper-evident ledger.
The content itself is never stored -- only its hash. This gives regulators
a verifiable audit trail without exposing the actual data.

Usage:
    from air_blackbox.a2a.transaction import TransactionRecord, TransactionLedger

    ledger = TransactionLedger(ledger_dir="./ledger", signing_key="my-key")
    record = TransactionRecord.create(
        sender_id="agent-a",
        sender_name="LangChain RAG",
        sender_framework="langchain",
        receiver_id="agent-b",
        receiver_name="CrewAI Research",
        receiver_framework="crewai",
        message_type="request",
        content=b"the actual message bytes",
    )
    ledger.write(record)
"""

import hashlib
import hmac
import json
import os
import re
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4


# ---------------------------------------------------------------------------
# PII detection patterns (shared with trust layers)
# ---------------------------------------------------------------------------

_PII_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "phone": re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "credit_card": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
}

_INJECTION_PATTERNS = [
    re.compile(r"ignore (?:all )?previous instructions", re.IGNORECASE),
    re.compile(r"you are now (?:a |an )?(?:new |different )", re.IGNORECASE),
    re.compile(r"ignore (?:all )?above instructions", re.IGNORECASE),
    re.compile(r"disregard (?:all )?(?:previous|prior|above)", re.IGNORECASE),
    re.compile(r"system prompt:", re.IGNORECASE),
    re.compile(r"new instructions:", re.IGNORECASE),
    re.compile(r"override:", re.IGNORECASE),
]


def _scan_text(text: str) -> Dict[str, Any]:
    """Scan text for PII and injection attempts.

    Returns a dict with pii_detected, pii_types, injection_score,
    and a redacted_preview (first 100 chars with PII replaced).
    """
    pii_types = []
    redacted = text
    for name, pattern in _PII_PATTERNS.items():
        if pattern.search(text):
            pii_types.append(name)
            redacted = pattern.sub(f"[{name.upper()}_REDACTED]", redacted)

    injection_score = 0.0
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            injection_score = max(injection_score, 0.9)

    # Truncate preview to 100 chars
    preview = redacted[:100]
    if len(redacted) > 100:
        preview += "..."

    return {
        "pii_detected": len(pii_types) > 0,
        "pii_types": pii_types,
        "injection_score": injection_score,
        "redacted_preview": preview,
    }


# ---------------------------------------------------------------------------
# TransactionRecord -- the core data structure
# ---------------------------------------------------------------------------

@dataclass
class TransactionRecord:
    """A single signed record of an agent-to-agent message.

    The actual message content is NEVER stored. Only its SHA-256 hash
    and byte size are recorded. This gives auditors proof of what was
    exchanged without exposing the data itself.
    """

    # Identity
    transaction_id: str
    timestamp: str
    sequence: int

    # Sender
    sender_id: str
    sender_name: str
    sender_framework: str
    sender_key_fingerprint: str

    # Receiver
    receiver_id: str
    receiver_name: str
    receiver_framework: str
    receiver_key_fingerprint: str

    # Payload (hashed, never raw)
    message_type: str  # request / response / tool_call / tool_result / handoff
    content_hash: str  # SHA-256 of the actual content
    content_size: int  # byte size of the content
    redacted_preview: str  # first 100 chars with PII stripped

    # Compliance scan results
    pii_detected: bool
    pii_types: List[str]
    pii_action: str  # redacted / blocked / none
    injection_score: float
    injection_action: str  # allowed / blocked

    # Chain fields (set by the ledger, not the caller)
    chain_hash: str = ""
    prev_chain_hash: str = ""
    sender_signature: str = ""

    @classmethod
    def create(
        cls,
        sender_id: str,
        sender_name: str,
        sender_framework: str,
        receiver_id: str,
        receiver_name: str,
        receiver_framework: str,
        message_type: str,
        content: bytes,
        sender_key_fingerprint: str = "",
        receiver_key_fingerprint: str = "",
        sequence: int = 0,
        injection_block_threshold: float = 0.8,
    ) -> "TransactionRecord":
        """Create a new transaction record from raw message content.

        This is the main constructor. It hashes the content, scans for
        PII and injection attempts, and builds the record. The raw
        content is NOT stored anywhere.

        Args:
            sender_id: Unique ID of the sending agent.
            sender_name: Human-readable name of the sender.
            sender_framework: Framework the sender runs on.
            receiver_id: Unique ID of the receiving agent.
            receiver_name: Human-readable name of the receiver.
            receiver_framework: Framework the receiver runs on.
            message_type: One of request, response, tool_call, tool_result, handoff.
            content: The raw message bytes to hash and scan.
            sender_key_fingerprint: ML-DSA-65 public key fingerprint of sender.
            receiver_key_fingerprint: ML-DSA-65 public key fingerprint of receiver.
            sequence: Monotonic sequence number (set by ledger if 0).
            injection_block_threshold: Score above which injection is blocked.

        Returns:
            A new TransactionRecord ready to be written to a ledger.
        """
        valid_types = ("request", "response", "tool_call", "tool_result", "handoff")
        if message_type not in valid_types:
            raise ValueError(
                f"Invalid message_type '{message_type}'. "
                f"Must be one of: {', '.join(valid_types)}"
            )

        # Hash the content (never store the raw bytes)
        content_hash = hashlib.sha256(content).hexdigest()
        content_size = len(content)

        # Scan the text for PII and injection
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            text = ""

        scan = _scan_text(text)

        # Determine actions
        pii_action = "none"
        if scan["pii_detected"]:
            pii_action = "redacted"

        injection_action = "allowed"
        if scan["injection_score"] >= injection_block_threshold:
            injection_action = "blocked"

        return cls(
            transaction_id=f"txn-{uuid4().hex[:16]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            sequence=sequence,
            sender_id=sender_id,
            sender_name=sender_name,
            sender_framework=sender_framework,
            sender_key_fingerprint=sender_key_fingerprint,
            receiver_id=receiver_id,
            receiver_name=receiver_name,
            receiver_framework=receiver_framework,
            receiver_key_fingerprint=receiver_key_fingerprint,
            message_type=message_type,
            content_hash=content_hash,
            content_size=content_size,
            redacted_preview=scan["redacted_preview"],
            pii_detected=scan["pii_detected"],
            pii_types=scan["pii_types"],
            pii_action=pii_action,
            injection_score=scan["injection_score"],
            injection_action=injection_action,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for JSON serialization."""
        return asdict(self)

    def to_signable_bytes(self) -> bytes:
        """Return canonical bytes for signing.

        Excludes chain_hash, prev_chain_hash, and sender_signature
        since those are set AFTER signing.
        """
        d = self.to_dict()
        d.pop("chain_hash", None)
        d.pop("prev_chain_hash", None)
        d.pop("sender_signature", None)
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# TransactionLedger -- tamper-evident storage for transaction records
# ---------------------------------------------------------------------------

class TransactionLedger:
    """Tamper-evident ledger that stores signed transaction records.

    Each record is chained to the previous one via HMAC-SHA256. Modifying
    any record breaks all subsequent chain hashes. Records are written as
    individual JSON files to a local directory.

    Optionally signs each record with ML-DSA-65 if an EvidenceSigner
    is provided.

    Args:
        ledger_dir: Directory to store transaction files.
        signing_key: HMAC key for the chain. Uses TRUST_SIGNING_KEY env
                     var if not provided. Generates ephemeral key as fallback.
        signer: Optional EvidenceSigner for ML-DSA-65 signatures.
    """

    GENESIS = b"genesis"

    def __init__(
        self,
        ledger_dir: str = "./a2a-ledger",
        signing_key: Optional[str] = None,
        signer: Optional[Any] = None,
    ) -> None:
        self.ledger_dir = Path(ledger_dir)
        self.ledger_dir.mkdir(parents=True, exist_ok=True)

        resolved_key = signing_key or os.environ.get("TRUST_SIGNING_KEY", "")
        if not resolved_key:
            import secrets as _secrets
            import warnings
            resolved_key = _secrets.token_hex(32)
            warnings.warn(
                "TRUST_SIGNING_KEY not set. Using a random ephemeral key. "
                "Set TRUST_SIGNING_KEY env var for persistent chains.",
                stacklevel=2,
            )
        self._key = resolved_key.encode("utf-8")
        self._prev_hash = self.GENESIS
        self._sequence = 0
        self._lock = threading.Lock()
        self._signer = signer

    @property
    def record_count(self) -> int:
        """Number of records written to this ledger."""
        return self._sequence

    @property
    def current_hash(self) -> str:
        """Current chain head hash."""
        if self._prev_hash == self.GENESIS:
            return "genesis"
        return self._prev_hash.hex()

    def write(self, record: TransactionRecord) -> TransactionRecord:
        """Write a transaction record to the ledger.

        Sets the sequence number, computes the HMAC chain hash,
        optionally signs with ML-DSA-65, and writes to disk.

        Args:
            record: The TransactionRecord to store.

        Returns:
            The record with chain_hash, prev_chain_hash, sequence,
            and sender_signature fields populated.
        """
        with self._lock:
            # Set sequence
            self._sequence += 1
            record.sequence = self._sequence

            # Set prev chain hash
            if self._prev_hash == self.GENESIS:
                record.prev_chain_hash = "genesis"
            else:
                record.prev_chain_hash = self._prev_hash.hex()

            # Sign with ML-DSA-65 if signer is available
            if self._signer is not None:
                try:
                    envelope = self._signer.sign_bytes(record.to_signable_bytes())
                    record.sender_signature = envelope.get("signature_hex", "")
                except Exception:
                    # Non-blocking: signing failure does not break the ledger
                    record.sender_signature = ""

            # Compute HMAC chain hash
            record_bytes = json.dumps(
                record.to_dict(), sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            h = hmac.new(
                self._key, self._prev_hash + record_bytes, hashlib.sha256
            )
            chain_hash = h.hexdigest()
            record.chain_hash = chain_hash

            # Write to disk
            fname = f"{record.transaction_id}.txn.json"
            fpath = self.ledger_dir / fname
            tmp_path = fpath.with_suffix(".tmp")
            try:
                tmp_path.write_text(
                    json.dumps(record.to_dict(), indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
                tmp_path.rename(fpath)
            except Exception:
                tmp_path.unlink(missing_ok=True)
                raise

            # Advance chain
            self._prev_hash = h.digest()

            return record

    def read_all(self) -> List[TransactionRecord]:
        """Read all transaction records from disk, sorted by sequence.

        Returns:
            List of TransactionRecord objects, oldest first.
        """
        records = []
        for fpath in self.ledger_dir.glob("*.txn.json"):
            try:
                data = json.loads(fpath.read_text(encoding="utf-8"))
                records.append(TransactionRecord(**data))
            except Exception:
                continue

        records.sort(key=lambda r: r.sequence)
        return records

    def verify_chain(self) -> Dict[str, Any]:
        """Verify the integrity of the entire ledger chain.

        Re-computes every HMAC chain hash from scratch and compares
        against the stored hashes. Returns a detailed report.

        Returns:
            Dict with 'valid' (bool), 'records_checked' (int),
            'first_broken_at' (int or None), and 'details' (list).
        """
        records = self.read_all()
        if not records:
            return {
                "valid": True,
                "records_checked": 0,
                "first_broken_at": None,
                "details": [],
            }

        prev_hash = self.GENESIS
        first_broken = None
        details = []

        for record in records:
            stored_hash = record.chain_hash

            # To recompute, we must match what write() saw:
            # chain_hash was "" when the HMAC was computed.
            d = record.to_dict()
            d["chain_hash"] = ""  # match the state during write()
            record_bytes = json.dumps(
                d, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")

            expected = hmac.new(
                self._key, prev_hash + record_bytes, hashlib.sha256
            ).hexdigest()

            valid = stored_hash == expected
            details.append({
                "sequence": record.sequence,
                "transaction_id": record.transaction_id,
                "valid": valid,
            })

            if not valid and first_broken is None:
                first_broken = record.sequence

            # Advance chain using the same bytes (match write() behavior)
            prev_hash = hmac.new(
                self._key, prev_hash + record_bytes, hashlib.sha256
            ).digest()

        return {
            "valid": first_broken is None,
            "records_checked": len(records),
            "first_broken_at": first_broken,
            "details": details,
        }
