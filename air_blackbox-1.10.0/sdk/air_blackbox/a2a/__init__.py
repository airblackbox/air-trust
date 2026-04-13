"""Agent-to-Agent (A2A) compliance framework.

Provides signed, tamper-evident transaction records for every
message exchanged between AI agents. Includes compliance verification,
bilateral handshakes, and a gateway middleware for runtime interception.
"""

from .protocol import (
    AgentComplianceCard,
    A2AComplianceGate,
    A2AVerificationResult,
    generate_compliance_card,
    verify_a2a_communication,
)
from .transaction import TransactionRecord, TransactionLedger
from .gateway import A2AGateway, GatewayResult, create_bilateral_channel
from .verify import bilateral_verify, BilateralReport
from .export import build_transaction_trace, export_evidence_bundle

__all__ = [
    "AgentComplianceCard",
    "A2AComplianceGate",
    "A2AVerificationResult",
    "generate_compliance_card",
    "verify_a2a_communication",
    "TransactionRecord",
    "TransactionLedger",
    "A2AGateway",
    "GatewayResult",
    "create_bilateral_channel",
    "bilateral_verify",
    "BilateralReport",
    "build_transaction_trace",
    "export_evidence_bundle",
]
