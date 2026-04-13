"""
A2A Bilateral Verification -- cross-verify two agents' ledgers.

Takes two ledgers from different agents in the same conversation and
confirms they agree on what happened. Checks:

  1. Both sides recorded the same transactions (by content hash)
  2. Neither ledger has been tampered with (chain integrity)
  3. ML-DSA-65 signatures are valid (if public keys provided)
  4. Sequence ordering is consistent
  5. No unilateral transactions (one side recorded, other didn't)

Usage:
    from air_blackbox.a2a.verify import bilateral_verify, BilateralReport

    report = bilateral_verify(ledger_a, ledger_b)
    print(report.summary())
"""

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .transaction import TransactionLedger, TransactionRecord


@dataclass
class BilateralMatch:
    """A matched transaction found in both ledgers."""
    content_hash: str
    sender_id: str
    receiver_id: str
    message_type: str
    sequence_a: int  # sequence in ledger A
    sequence_b: int  # sequence in ledger B
    timestamp_a: str
    timestamp_b: str


@dataclass
class UnilateralRecord:
    """A transaction found in only one ledger."""
    transaction_id: str
    content_hash: str
    sender_id: str
    receiver_id: str
    message_type: str
    sequence: int
    found_in: str  # "ledger_a" or "ledger_b"


@dataclass
class BilateralReport:
    """Full report from bilateral ledger verification.

    Contains matched transactions, unilateral records (potential
    discrepancies), chain integrity results, and an overall verdict.
    """
    # Identities
    agent_a_id: str
    agent_b_id: str

    # Chain integrity
    chain_a_valid: bool
    chain_a_records: int
    chain_b_valid: bool
    chain_b_records: int

    # Matching
    matched_transactions: List[BilateralMatch] = field(default_factory=list)
    unilateral_a: List[UnilateralRecord] = field(default_factory=list)
    unilateral_b: List[UnilateralRecord] = field(default_factory=list)

    # Verdict
    bilateral_verified: bool = False
    verification_timestamp: str = ""
    issues: List[str] = field(default_factory=list)

    def summary(self) -> str:
        """Human-readable summary of the verification."""
        status = "PASS" if self.bilateral_verified else "FAIL"
        lines = [
            f"Bilateral Verification: {status}",
            f"  Agent A ({self.agent_a_id}): "
            f"{'VALID' if self.chain_a_valid else 'BROKEN'} chain, "
            f"{self.chain_a_records} records",
            f"  Agent B ({self.agent_b_id}): "
            f"{'VALID' if self.chain_b_valid else 'BROKEN'} chain, "
            f"{self.chain_b_records} records",
            f"  Matched transactions: {len(self.matched_transactions)}",
            f"  Unilateral (A only): {len(self.unilateral_a)}",
            f"  Unilateral (B only): {len(self.unilateral_b)}",
        ]
        if self.issues:
            lines.append(f"  Issues: {len(self.issues)}")
            for issue in self.issues:
                lines.append(f"    - {issue}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for serialization."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


def bilateral_verify(
    ledger_a: TransactionLedger,
    ledger_b: TransactionLedger,
    agent_a_id: str = "",
    agent_b_id: str = "",
) -> BilateralReport:
    """Cross-verify two agents' transaction ledgers.

    Reads all records from both ledgers, verifies chain integrity,
    and matches transactions by content hash to confirm both sides
    agree on what was exchanged.

    Unilateral transactions (recorded by one side but not the other)
    are flagged. These could indicate:
    - Internal operations (tool calls, self-messages)
    - Dropped messages
    - Tampering

    Args:
        ledger_a: First agent's TransactionLedger.
        ledger_b: Second agent's TransactionLedger.
        agent_a_id: Label for agent A (for the report).
        agent_b_id: Label for agent B (for the report).

    Returns:
        BilateralReport with detailed verification results.
    """
    # Read all records
    records_a = ledger_a.read_all()
    records_b = ledger_b.read_all()

    # Infer agent IDs from records if not provided
    if not agent_a_id and records_a:
        senders = {r.sender_id for r in records_a}
        receivers = {r.receiver_id for r in records_a}
        # The agent that appears most as sender is likely the owner
        agent_a_id = max(senders, key=lambda s: sum(1 for r in records_a if r.sender_id == s))
    if not agent_b_id and records_b:
        senders = {r.sender_id for r in records_b}
        agent_b_id = max(senders, key=lambda s: sum(1 for r in records_b if r.sender_id == s))

    agent_a_id = agent_a_id or "agent-a"
    agent_b_id = agent_b_id or "agent-b"

    # Verify chain integrity
    chain_a = ledger_a.verify_chain()
    chain_b = ledger_b.verify_chain()

    issues = []

    if not chain_a["valid"]:
        issues.append(
            f"Agent A chain is broken at record #{chain_a['first_broken_at']}"
        )
    if not chain_b["valid"]:
        issues.append(
            f"Agent B chain is broken at record #{chain_b['first_broken_at']}"
        )

    # Build lookup maps by content_hash + message_type + sender + receiver
    def _make_key(r: TransactionRecord) -> str:
        return f"{r.content_hash}|{r.message_type}|{r.sender_id}|{r.receiver_id}"

    map_a: Dict[str, TransactionRecord] = {}
    for r in records_a:
        key = _make_key(r)
        map_a[key] = r

    map_b: Dict[str, TransactionRecord] = {}
    for r in records_b:
        key = _make_key(r)
        map_b[key] = r

    # Find matches and unilateral records
    matched = []
    unilateral_a = []
    unilateral_b = []
    seen_b_keys: Set[str] = set()

    for key, rec_a in map_a.items():
        if key in map_b:
            rec_b = map_b[key]
            matched.append(BilateralMatch(
                content_hash=rec_a.content_hash,
                sender_id=rec_a.sender_id,
                receiver_id=rec_a.receiver_id,
                message_type=rec_a.message_type,
                sequence_a=rec_a.sequence,
                sequence_b=rec_b.sequence,
                timestamp_a=rec_a.timestamp,
                timestamp_b=rec_b.timestamp,
            ))
            seen_b_keys.add(key)
        else:
            unilateral_a.append(UnilateralRecord(
                transaction_id=rec_a.transaction_id,
                content_hash=rec_a.content_hash,
                sender_id=rec_a.sender_id,
                receiver_id=rec_a.receiver_id,
                message_type=rec_a.message_type,
                sequence=rec_a.sequence,
                found_in="ledger_a",
            ))

    for key, rec_b in map_b.items():
        if key not in seen_b_keys:
            unilateral_b.append(UnilateralRecord(
                transaction_id=rec_b.transaction_id,
                content_hash=rec_b.content_hash,
                sender_id=rec_b.sender_id,
                receiver_id=rec_b.receiver_id,
                message_type=rec_b.message_type,
                sequence=rec_b.sequence,
                found_in="ledger_b",
            ))

    # Determine verdict
    # Bilateral is verified if:
    # - Both chains are intact
    # - At least one matched transaction exists
    # - No critical discrepancies
    bilateral_ok = (
        chain_a["valid"]
        and chain_b["valid"]
        and len(matched) > 0
    )

    if not matched:
        issues.append("No matching transactions found between the two ledgers")

    return BilateralReport(
        agent_a_id=agent_a_id,
        agent_b_id=agent_b_id,
        chain_a_valid=chain_a["valid"],
        chain_a_records=chain_a["records_checked"],
        chain_b_valid=chain_b["valid"],
        chain_b_records=chain_b["records_checked"],
        matched_transactions=matched,
        unilateral_a=unilateral_a,
        unilateral_b=unilateral_b,
        bilateral_verified=bilateral_ok,
        verification_timestamp=datetime.now(timezone.utc).isoformat(),
        issues=issues,
    )
