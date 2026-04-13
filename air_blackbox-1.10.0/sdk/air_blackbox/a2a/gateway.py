"""
A2A Gateway -- middleware that wraps agent-to-agent communication.

The gateway sits between two agents and intercepts every message.
Each message gets hashed, scanned for PII/injection, signed, chained,
and stored in a tamper-evident ledger. The actual message content
passes through untouched (unless injection is blocked).

Usage:
    from air_blackbox.a2a.gateway import A2AGateway

    gw = A2AGateway(
        agent_id="agent-alpha",
        agent_name="LangChain RAG",
        framework="langchain",
    )

    # Send a message through the gateway
    result = gw.send(
        content=b"What are the Article 12 requirements?",
        receiver_id="agent-beta",
        receiver_name="CrewAI Research",
        receiver_framework="crewai",
        message_type="request",
    )

    if result.blocked:
        print(f"Message blocked: {result.reason}")
    else:
        # Forward result.content to the receiver
        pass
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from .transaction import TransactionRecord, TransactionLedger


@dataclass
class GatewayResult:
    """Result of sending a message through the A2A Gateway.

    Attributes:
        content: The original message bytes (unchanged unless blocked).
        record: The TransactionRecord written to the ledger.
        blocked: True if the message was blocked (injection detected).
        reason: Why the message was blocked (empty if not blocked).
    """
    content: bytes
    record: TransactionRecord
    blocked: bool = False
    reason: str = ""


class A2AGateway:
    """Middleware that wraps agent-to-agent communication.

    Create one gateway per agent. Every message sent or received
    goes through the gateway, which signs it, chains it, and stores
    the proof in a local ledger.

    Args:
        agent_id: Unique identifier for this agent.
        agent_name: Human-readable name for this agent.
        framework: AI framework this agent runs on.
        ledger_dir: Directory for the transaction ledger.
        signing_key: HMAC key for the chain (uses env var if not set).
        key_fingerprint: ML-DSA-65 public key fingerprint for this agent.
        signer: Optional EvidenceSigner for ML-DSA-65 signatures.
        block_injections: Whether to block messages with injection attempts.
        injection_threshold: Score above which messages are blocked.
    """

    def __init__(
        self,
        agent_id: str,
        agent_name: str,
        framework: str,
        ledger_dir: Optional[str] = None,
        signing_key: Optional[str] = None,
        key_fingerprint: str = "",
        signer: Optional[Any] = None,
        block_injections: bool = True,
        injection_threshold: float = 0.8,
    ) -> None:
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.framework = framework
        self.key_fingerprint = key_fingerprint
        self.block_injections = block_injections
        self.injection_threshold = injection_threshold

        # Default ledger directory: ~/.air-blackbox/a2a-ledger/{agent_id}/
        if ledger_dir is None:
            ledger_dir = str(
                Path.home() / ".air-blackbox" / "a2a-ledger" / agent_id
            )

        self.ledger = TransactionLedger(
            ledger_dir=ledger_dir,
            signing_key=signing_key,
            signer=signer,
        )

        # Stats
        self._messages_sent = 0
        self._messages_received = 0
        self._messages_blocked = 0

    @property
    def stats(self) -> Dict[str, int]:
        """Return gateway statistics."""
        return {
            "messages_sent": self._messages_sent,
            "messages_received": self._messages_received,
            "messages_blocked": self._messages_blocked,
            "ledger_records": self.ledger.record_count,
        }

    def send(
        self,
        content: bytes,
        receiver_id: str,
        receiver_name: str,
        receiver_framework: str,
        message_type: str = "request",
        receiver_key_fingerprint: str = "",
    ) -> GatewayResult:
        """Send a message through the gateway.

        The message is hashed, scanned, signed, chained, and stored.
        If injection is detected and blocking is enabled, the message
        is blocked and not forwarded.

        Args:
            content: Raw message bytes.
            receiver_id: Unique ID of the receiving agent.
            receiver_name: Human-readable name of the receiver.
            receiver_framework: Framework the receiver runs on.
            message_type: Type of message (request, response, etc.).
            receiver_key_fingerprint: Receiver's ML-DSA-65 key fingerprint.

        Returns:
            GatewayResult with the transaction record and block status.
        """
        # Create the transaction record
        record = TransactionRecord.create(
            sender_id=self.agent_id,
            sender_name=self.agent_name,
            sender_framework=self.framework,
            receiver_id=receiver_id,
            receiver_name=receiver_name,
            receiver_framework=receiver_framework,
            message_type=message_type,
            content=content,
            sender_key_fingerprint=self.key_fingerprint,
            receiver_key_fingerprint=receiver_key_fingerprint,
            injection_block_threshold=self.injection_threshold,
        )

        # Check if message should be blocked
        blocked = False
        reason = ""
        if self.block_injections and record.injection_action == "blocked":
            blocked = True
            reason = (
                f"Injection attempt detected (score: {record.injection_score:.2f}). "
                f"Message from {self.agent_name} to {receiver_name} was blocked."
            )
            self._messages_blocked += 1

        # Write to ledger regardless (blocked messages are still recorded)
        written_record = self.ledger.write(record)
        self._messages_sent += 1

        return GatewayResult(
            content=content if not blocked else b"",
            record=written_record,
            blocked=blocked,
            reason=reason,
        )

    def receive(
        self,
        content: bytes,
        sender_id: str,
        sender_name: str,
        sender_framework: str,
        message_type: str = "response",
        sender_key_fingerprint: str = "",
    ) -> GatewayResult:
        """Receive a message through the gateway.

        Same as send(), but records this agent as the receiver.
        Both sides should record the transaction for bilateral proof.

        Args:
            content: Raw message bytes.
            sender_id: Unique ID of the sending agent.
            sender_name: Human-readable name of the sender.
            sender_framework: Framework the sender runs on.
            message_type: Type of message (request, response, etc.).
            sender_key_fingerprint: Sender's ML-DSA-65 key fingerprint.

        Returns:
            GatewayResult with the transaction record and block status.
        """
        record = TransactionRecord.create(
            sender_id=sender_id,
            sender_name=sender_name,
            sender_framework=sender_framework,
            receiver_id=self.agent_id,
            receiver_name=self.agent_name,
            receiver_framework=self.framework,
            message_type=message_type,
            content=content,
            sender_key_fingerprint=sender_key_fingerprint,
            receiver_key_fingerprint=self.key_fingerprint,
            injection_block_threshold=self.injection_threshold,
        )

        blocked = False
        reason = ""
        if self.block_injections and record.injection_action == "blocked":
            blocked = True
            reason = (
                f"Injection attempt detected (score: {record.injection_score:.2f}). "
                f"Incoming message from {sender_name} was blocked."
            )
            self._messages_blocked += 1

        written_record = self.ledger.write(record)
        self._messages_received += 1

        return GatewayResult(
            content=content if not blocked else b"",
            record=written_record,
            blocked=blocked,
            reason=reason,
        )

    def verify_ledger(self) -> Dict[str, Any]:
        """Verify the integrity of this gateway's ledger.

        Returns:
            Dict with 'valid', 'records_checked', 'first_broken_at', 'details'.
        """
        return self.ledger.verify_chain()


def create_bilateral_channel(
    agent_a_id: str,
    agent_a_name: str,
    agent_a_framework: str,
    agent_b_id: str,
    agent_b_name: str,
    agent_b_framework: str,
    ledger_base_dir: Optional[str] = None,
    signing_key: Optional[str] = None,
    signer_a: Optional[Any] = None,
    signer_b: Optional[Any] = None,
) -> tuple:
    """Create a pair of A2A Gateways for bilateral communication.

    Returns two gateways, one for each agent. Both use the same
    HMAC signing key so their chains can be cross-verified.

    Args:
        agent_a_id: Unique ID for agent A.
        agent_a_name: Name for agent A.
        agent_a_framework: Framework for agent A.
        agent_b_id: Unique ID for agent B.
        agent_b_name: Name for agent B.
        agent_b_framework: Framework for agent B.
        ledger_base_dir: Base directory for ledgers (each agent gets a subdirectory).
        signing_key: Shared HMAC key for chain verification.
        signer_a: Optional ML-DSA-65 signer for agent A.
        signer_b: Optional ML-DSA-65 signer for agent B.

    Returns:
        Tuple of (gateway_a, gateway_b).
    """
    if ledger_base_dir is None:
        ledger_base_dir = str(Path.home() / ".air-blackbox" / "a2a-ledger")

    gateway_a = A2AGateway(
        agent_id=agent_a_id,
        agent_name=agent_a_name,
        framework=agent_a_framework,
        ledger_dir=os.path.join(ledger_base_dir, agent_a_id),
        signing_key=signing_key,
        signer=signer_a,
    )

    gateway_b = A2AGateway(
        agent_id=agent_b_id,
        agent_name=agent_b_name,
        framework=agent_b_framework,
        ledger_dir=os.path.join(ledger_base_dir, agent_b_id),
        signing_key=signing_key,
        signer=signer_b,
    )

    return gateway_a, gateway_b
