"""Agent-to-Agent (A2A) compliance framework.

Provides signed, tamper-evident transaction records for every
message exchanged between AI agents. Includes compliance verification,
bilateral handshakes, and a gateway middleware for runtime interception.
"""

from .export import build_transaction_trace, export_evidence_bundle
from .gateway import A2AGateway, GatewayResult, create_bilateral_channel
from .protocol import (
    A2AComplianceGate,
    A2AVerificationResult,
    AgentComplianceCard,
    generate_compliance_card,
    verify_a2a_communication,
)
from .transaction import TransactionLedger, TransactionRecord
from .verify import BilateralReport, bilateral_verify

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
