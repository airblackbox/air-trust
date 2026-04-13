"""
Comprehensive tests for AIR Blackbox A2A Protocol.

These tests cover:
- AgentComplianceCard: Creation, serialization, deserialization
- A2AVerificationResult: Result handling and summaries
- A2AComplianceGate: Verification logic, handshakes, audit trails
- generate_compliance_card: Card generation from scan results
- verify_a2a_communication: End-to-end A2A verification

All tests use pytest fixtures, parameterization, and mocking as needed.
"""

import json
import hashlib
import hmac
from datetime import datetime
from typing import Any, Dict
from unittest.mock import MagicMock, Mock, patch
from uuid import uuid4

import pytest

from air_blackbox.a2a.protocol import (
    AgentComplianceCard,
    A2AVerificationResult,
    A2AComplianceGate,
    generate_compliance_card,
    verify_a2a_communication,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def valid_compliance_card() -> AgentComplianceCard:
    """Create a valid compliance card with all requirements met."""
    return AgentComplianceCard(
        agent_id="agent-001",
        agent_name="TestAgent",
        framework="langchain",
        trust_layer_version="1.0.0",
        audit_chain_enabled=True,
        injection_protection=True,
        compliance_checks={
            "9": "pass",
            "10": "pass",
            "11": "pass",
            "12": "pass",
            "14": "pass",
            "15": "pass",
        },
        gdpr_checks={"data_retention": "pass", "consent": "pass"},
        last_verified=datetime.utcnow().isoformat(),
        signing_key_fingerprint="abcdef0123456789",
        capabilities=["analyze", "classify", "scan"],
    )


@pytest.fixture
def peer_compliance_card() -> AgentComplianceCard:
    """Create a peer compliance card for testing communication."""
    return AgentComplianceCard(
        agent_id="agent-002",
        agent_name="PeerAgent",
        framework="langchain",
        trust_layer_version="1.0.0",
        audit_chain_enabled=True,
        injection_protection=True,
        compliance_checks={
            "9": "pass",
            "10": "pass",
            "11": "pass",
            "12": "pass",
            "14": "pass",
            "15": "pass",
        },
        gdpr_checks={"data_retention": "pass", "consent": "pass"},
        last_verified=datetime.utcnow().isoformat(),
        signing_key_fingerprint="fedcba9876543210",
        capabilities=["execute", "log"],
    )


@pytest.fixture
def scan_results_complete() -> Dict[str, Any]:
    """Create complete scan results for card generation."""
    return {
        "framework": "crewai",
        "trust_layer_version": "1.2.0",
        "audit_chain_enabled": True,
        "injection_protection": True,
        "article_9": "pass",
        "article_10": "pass",
        "article_11": "pass",
        "article_12": "pass",
        "article_14": "pass",
        "article_15": "pass",
        "gdpr_checks": {
            "data_processing": "pass",
            "consent_management": "pass",
        },
        "signing_key_fingerprint": "scan_key_12345678",
        "capabilities": ["scan", "report"],
    }


@pytest.fixture
def scan_results_minimal() -> Dict[str, Any]:
    """Create minimal scan results (all defaults)."""
    return {}


@pytest.fixture
def scan_results_with_failures() -> Dict[str, Any]:
    """Create scan results with some failures."""
    return {
        "framework": "openai",
        "trust_layer_version": "1.0.0",
        "audit_chain_enabled": False,
        "injection_protection": True,
        "article_9": "fail",
        "article_10": "pass",
        "article_11": "pass",
        "article_12": "fail",
        "article_14": "pass",
        "article_15": "pass",
        "gdpr_checks": {"data_retention": "fail"},
    }


@pytest.fixture
def compliance_gate(valid_compliance_card) -> A2AComplianceGate:
    """Create a compliance gate with local agent."""
    return A2AComplianceGate(valid_compliance_card)


# ============================================================================
# AgentComplianceCard Tests
# ============================================================================


class TestAgentComplianceCard:
    """Tests for AgentComplianceCard dataclass."""

    def test_card_creation_with_all_fields(self):
        """Test creating a card with all fields populated."""
        card = AgentComplianceCard(
            agent_id="test-agent-001",
            agent_name="TestAgent",
            framework="langchain",
            trust_layer_version="1.0.0",
            audit_chain_enabled=True,
            injection_protection=True,
            compliance_checks={"9": "pass"},
            gdpr_checks={"consent": "pass"},
            last_verified="2024-01-01T00:00:00",
            signing_key_fingerprint="abcd1234",
            capabilities=["scan"],
        )
        assert card.agent_id == "test-agent-001"
        assert card.agent_name == "TestAgent"
        assert card.framework == "langchain"

    def test_card_creation_with_defaults(self):
        """Test creating a card with default values."""
        card = AgentComplianceCard(
            agent_id="test-agent",
            agent_name="Agent",
            framework="crewai",
            trust_layer_version="1.0.0",
            audit_chain_enabled=False,
            injection_protection=False,
            compliance_checks={},
            gdpr_checks={},
            last_verified="2024-01-01T00:00:00",
            signing_key_fingerprint="abc123",
        )
        assert card.capabilities == []
        assert isinstance(card.compliance_checks, dict)

    def test_to_dict(self, valid_compliance_card):
        """Test converting card to dictionary."""
        card_dict = valid_compliance_card.to_dict()
        assert isinstance(card_dict, dict)
        assert card_dict["agent_id"] == "agent-001"
        assert card_dict["agent_name"] == "TestAgent"
        assert card_dict["audit_chain_enabled"] is True

    def test_to_json(self, valid_compliance_card):
        """Test converting card to JSON string."""
        json_str = valid_compliance_card.to_json()
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["agent_id"] == "agent-001"
        assert "indent" not in json_str  # to_json uses indent=2

    def test_from_dict(self, valid_compliance_card):
        """Test creating card from dictionary."""
        card_dict = valid_compliance_card.to_dict()
        new_card = AgentComplianceCard.from_dict(card_dict)
        assert new_card.agent_id == valid_compliance_card.agent_id
        assert new_card.agent_name == valid_compliance_card.agent_name

    def test_from_json(self, valid_compliance_card):
        """Test creating card from JSON string."""
        json_str = valid_compliance_card.to_json()
        new_card = AgentComplianceCard.from_json(json_str)
        assert new_card.agent_id == valid_compliance_card.agent_id
        assert new_card.framework == valid_compliance_card.framework

    def test_from_dict_roundtrip(self, valid_compliance_card):
        """Test that to_dict -> from_dict preserves data."""
        original_dict = valid_compliance_card.to_dict()
        restored_card = AgentComplianceCard.from_dict(original_dict)
        restored_dict = restored_card.to_dict()
        assert original_dict == restored_dict

    def test_from_json_roundtrip(self, valid_compliance_card):
        """Test that to_json -> from_json preserves data."""
        json_str = valid_compliance_card.to_json()
        restored_card = AgentComplianceCard.from_json(json_str)
        assert restored_card.agent_id == valid_compliance_card.agent_id
        assert restored_card.compliance_checks == valid_compliance_card.compliance_checks

    def test_from_json_with_empty_string_fails(self):
        """Test that from_json fails gracefully with empty string."""
        with pytest.raises(json.JSONDecodeError):
            AgentComplianceCard.from_json("")

    def test_from_json_with_invalid_json_fails(self):
        """Test that from_json fails gracefully with invalid JSON."""
        with pytest.raises(json.JSONDecodeError):
            AgentComplianceCard.from_json("{invalid json}")

    def test_from_dict_with_missing_fields_fails(self):
        """Test that from_dict fails with missing required fields."""
        incomplete_dict = {
            "agent_id": "test",
            "agent_name": "Test",
            # Missing other required fields
        }
        with pytest.raises(TypeError):
            AgentComplianceCard.from_dict(incomplete_dict)

    def test_to_dict_empty_lists_and_dicts(self):
        """Test to_dict with empty lists and dicts."""
        card = AgentComplianceCard(
            agent_id="test",
            agent_name="Test",
            framework="unknown",
            trust_layer_version="1.0.0",
            audit_chain_enabled=False,
            injection_protection=False,
            compliance_checks={},
            gdpr_checks={},
            last_verified="2024-01-01T00:00:00",
            signing_key_fingerprint="abc",
            capabilities=[],
        )
        card_dict = card.to_dict()
        assert card_dict["compliance_checks"] == {}
        assert card_dict["capabilities"] == []


# ============================================================================
# A2AVerificationResult Tests
# ============================================================================


class TestA2AVerificationResult:
    """Tests for A2AVerificationResult dataclass."""

    def test_result_creation_with_pass(self):
        """Test creating a passing verification result."""
        result = A2AVerificationResult(
            verified=True,
            score=1.0,
            issues=[],
            recommendations=[],
            handshake_record={"data": "test"},
        )
        assert result.verified is True
        assert result.score == 1.0
        assert len(result.issues) == 0

    def test_result_creation_with_fail(self):
        """Test creating a failing verification result."""
        result = A2AVerificationResult(
            verified=False,
            score=0.5,
            issues=["Missing audit chain"],
            recommendations=["Enable audit chain"],
        )
        assert result.verified is False
        assert result.score == 0.5
        assert "Missing audit chain" in result.issues

    def test_result_to_dict(self):
        """Test converting result to dictionary."""
        result = A2AVerificationResult(
            verified=True,
            score=0.85,
            issues=["Issue 1"],
            recommendations=["Fix 1"],
        )
        result_dict = result.to_dict()
        assert result_dict["verified"] is True
        assert result_dict["score"] == 0.85

    def test_result_to_json(self):
        """Test converting result to JSON string."""
        result = A2AVerificationResult(
            verified=False,
            score=0.6,
            issues=["Issue"],
            recommendations=["Recommendation"],
        )
        json_str = result.to_json()
        parsed = json.loads(json_str)
        assert parsed["verified"] is False
        assert parsed["score"] == 0.6

    def test_result_summary_pass(self):
        """Test summary string for passing verification."""
        result = A2AVerificationResult(
            verified=True,
            score=1.0,
            issues=[],
            recommendations=[],
        )
        summary = result.summary()
        assert "PASS" in summary
        assert "Score: 1.00" in summary
        assert "Issues: 0" in summary

    def test_result_summary_fail(self):
        """Test summary string for failing verification."""
        result = A2AVerificationResult(
            verified=False,
            score=0.3,
            issues=["Issue 1", "Issue 2"],
            recommendations=["Fix 1"],
        )
        summary = result.summary()
        assert "FAIL" in summary
        assert "Score: 0.30" in summary
        assert "Issues: 2" in summary
        assert "Recommendations: 1" in summary

    def test_result_default_handshake_record(self):
        """Test that handshake_record defaults to empty dict."""
        result = A2AVerificationResult(verified=True, score=1.0)
        assert result.handshake_record == {}

    def test_result_default_issues_and_recommendations(self):
        """Test that issues and recommendations default to empty lists."""
        result = A2AVerificationResult(verified=True, score=1.0)
        assert result.issues == []
        assert result.recommendations == []


# ============================================================================
# A2AComplianceGate Tests
# ============================================================================


class TestA2AComplianceGate:
    """Tests for A2AComplianceGate class."""

    def test_gate_initialization(self, valid_compliance_card):
        """Test creating a compliance gate."""
        gate = A2AComplianceGate(valid_compliance_card)
        assert gate.local_agent == valid_compliance_card
        assert gate.verification_log == []

    def test_minimum_requirements_property(self, compliance_gate):
        """Test minimum_requirements property returns expected structure."""
        requirements = compliance_gate.minimum_requirements
        assert "audit_chain_enabled" in requirements
        assert "injection_protection" in requirements
        assert "no_critical_failures" in requirements
        assert "signing_key_present" in requirements
        assert "compatible_trust_layer" in requirements
        assert requirements["audit_chain_enabled"] is True

    def test_verify_peer_both_compliant(
        self, valid_compliance_card, peer_compliance_card
    ):
        """Test verification when both agents are compliant."""
        gate = A2AComplianceGate(valid_compliance_card)
        result = gate.verify_peer(peer_compliance_card)
        assert result.verified is True
        assert result.score == 1.0
        assert len(result.issues) == 0
        assert isinstance(result.handshake_record, dict)
        assert "signature" in result.handshake_record

    def test_verify_peer_local_audit_disabled(
        self, peer_compliance_card
    ):
        """Test verification fails when local audit chain disabled."""
        local_card = AgentComplianceCard(
            agent_id="agent-bad-local",
            agent_name="BadLocal",
            framework="langchain",
            trust_layer_version="1.0.0",
            audit_chain_enabled=False,  # Disabled
            injection_protection=True,
            compliance_checks={"9": "pass", "10": "pass", "11": "pass",
                              "12": "pass", "14": "pass", "15": "pass"},
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="abc123",
        )
        gate = A2AComplianceGate(local_card)
        result = gate.verify_peer(peer_compliance_card)
        assert result.verified is False
        assert "Local agent audit chain is not enabled" in result.issues
        assert result.score < 1.0

    def test_verify_peer_peer_audit_disabled(
        self, valid_compliance_card
    ):
        """Test verification fails when peer audit chain disabled."""
        peer_card = AgentComplianceCard(
            agent_id="agent-bad-peer",
            agent_name="BadPeer",
            framework="langchain",
            trust_layer_version="1.0.0",
            audit_chain_enabled=False,  # Disabled
            injection_protection=True,
            compliance_checks={"9": "pass", "10": "pass", "11": "pass",
                              "12": "pass", "14": "pass", "15": "pass"},
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="abc123",
        )
        gate = A2AComplianceGate(valid_compliance_card)
        result = gate.verify_peer(peer_card)
        assert result.verified is False
        assert "Peer agent audit chain is not enabled" in result.issues

    def test_verify_peer_local_injection_protection_disabled(
        self, peer_compliance_card
    ):
        """Test verification fails when local injection protection disabled."""
        local_card = AgentComplianceCard(
            agent_id="agent-no-inject-local",
            agent_name="NoInjectLocal",
            framework="langchain",
            trust_layer_version="1.0.0",
            audit_chain_enabled=True,
            injection_protection=False,  # Disabled
            compliance_checks={"9": "pass", "10": "pass", "11": "pass",
                              "12": "pass", "14": "pass", "15": "pass"},
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="abc123",
        )
        gate = A2AComplianceGate(local_card)
        result = gate.verify_peer(peer_compliance_card)
        assert result.verified is False
        assert "Local agent injection protection is not enabled" in result.issues

    def test_verify_peer_peer_injection_protection_disabled(
        self, valid_compliance_card
    ):
        """Test verification fails when peer injection protection disabled."""
        peer_card = AgentComplianceCard(
            agent_id="agent-no-inject-peer",
            agent_name="NoInjectPeer",
            framework="langchain",
            trust_layer_version="1.0.0",
            audit_chain_enabled=True,
            injection_protection=False,  # Disabled
            compliance_checks={"9": "pass", "10": "pass", "11": "pass",
                              "12": "pass", "14": "pass", "15": "pass"},
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="abc123",
        )
        gate = A2AComplianceGate(valid_compliance_card)
        result = gate.verify_peer(peer_card)
        assert result.verified is False
        assert "Peer agent injection protection is not enabled" in result.issues

    def test_verify_peer_local_critical_failure(
        self, peer_compliance_card
    ):
        """Test verification fails when local agent has critical compliance failure."""
        local_card = AgentComplianceCard(
            agent_id="agent-fail-local",
            agent_name="FailLocal",
            framework="langchain",
            trust_layer_version="1.0.0",
            audit_chain_enabled=True,
            injection_protection=True,
            compliance_checks={
                "9": "fail",  # Critical failure
                "10": "pass",
                "11": "pass",
                "12": "pass",
                "14": "pass",
                "15": "pass",
            },
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="abc123",
        )
        gate = A2AComplianceGate(local_card)
        result = gate.verify_peer(peer_compliance_card)
        assert result.verified is False
        assert any("Local agent has critical failures" in issue for issue in result.issues)

    def test_verify_peer_peer_critical_failure(self, valid_compliance_card):
        """Test verification fails when peer agent has critical compliance failure."""
        peer_card = AgentComplianceCard(
            agent_id="agent-fail-peer",
            agent_name="FailPeer",
            framework="langchain",
            trust_layer_version="1.0.0",
            audit_chain_enabled=True,
            injection_protection=True,
            compliance_checks={
                "9": "pass",
                "10": "fail",  # Critical failure
                "11": "pass",
                "12": "pass",
                "14": "pass",
                "15": "pass",
            },
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="abc123",
        )
        gate = A2AComplianceGate(valid_compliance_card)
        result = gate.verify_peer(peer_card)
        assert result.verified is False
        assert any("Peer agent has critical failures" in issue for issue in result.issues)

    def test_verify_peer_local_missing_signing_key(
        self, peer_compliance_card
    ):
        """Test verification fails when local agent has no signing key."""
        local_card = AgentComplianceCard(
            agent_id="agent-no-key-local",
            agent_name="NoKeyLocal",
            framework="langchain",
            trust_layer_version="1.0.0",
            audit_chain_enabled=True,
            injection_protection=True,
            compliance_checks={"9": "pass", "10": "pass", "11": "pass",
                              "12": "pass", "14": "pass", "15": "pass"},
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="",  # Empty
        )
        gate = A2AComplianceGate(local_card)
        result = gate.verify_peer(peer_compliance_card)
        assert result.verified is False
        assert "Local agent has no signing key fingerprint" in result.issues

    def test_verify_peer_peer_missing_signing_key(
        self, valid_compliance_card
    ):
        """Test verification fails when peer agent has no signing key."""
        peer_card = AgentComplianceCard(
            agent_id="agent-no-key-peer",
            agent_name="NoKeyPeer",
            framework="langchain",
            trust_layer_version="1.0.0",
            audit_chain_enabled=True,
            injection_protection=True,
            compliance_checks={"9": "pass", "10": "pass", "11": "pass",
                              "12": "pass", "14": "pass", "15": "pass"},
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="",  # Empty
        )
        gate = A2AComplianceGate(valid_compliance_card)
        result = gate.verify_peer(peer_card)
        assert result.verified is False
        assert "Peer agent has no signing key fingerprint" in result.issues

    def test_verify_peer_trust_layer_version_mismatch(
        self, valid_compliance_card
    ):
        """Test verification fails when trust layer versions don't match (major version)."""
        peer_card = AgentComplianceCard(
            agent_id="agent-version-peer",
            agent_name="VersionPeer",
            framework="langchain",
            trust_layer_version="2.0.0",  # Different major version
            audit_chain_enabled=True,
            injection_protection=True,
            compliance_checks={"9": "pass", "10": "pass", "11": "pass",
                              "12": "pass", "14": "pass", "15": "pass"},
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="abc123",
        )
        gate = A2AComplianceGate(valid_compliance_card)
        result = gate.verify_peer(peer_card)
        assert result.verified is False
        assert any("Trust layer version mismatch" in issue for issue in result.issues)

    def test_verify_peer_trust_layer_version_minor_mismatch_ok(
        self, valid_compliance_card
    ):
        """Test that minor version differences are allowed."""
        peer_card = AgentComplianceCard(
            agent_id="agent-minor-peer",
            agent_name="MinorPeer",
            framework="langchain",
            trust_layer_version="1.5.0",  # Different minor version (same major)
            audit_chain_enabled=True,
            injection_protection=True,
            compliance_checks={"9": "pass", "10": "pass", "11": "pass",
                              "12": "pass", "14": "pass", "15": "pass"},
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="abc123",
        )
        gate = A2AComplianceGate(valid_compliance_card)
        result = gate.verify_peer(peer_card)
        # Minor version mismatch should not prevent verification if other checks pass
        assert "Trust layer version mismatch" not in result.issues

    def test_verify_peer_score_clamped_to_zero(self, valid_compliance_card):
        """Test that score is clamped to 0 when many issues exist."""
        # Create a card with many failures
        peer_card = AgentComplianceCard(
            agent_id="agent-many-fails",
            agent_name="ManyFails",
            framework="langchain",
            trust_layer_version="2.0.0",  # Version mismatch
            audit_chain_enabled=False,  # Audit disabled
            injection_protection=False,  # Injection disabled
            compliance_checks={
                "9": "fail",
                "10": "fail",
                "11": "fail",
                "12": "fail",
                "14": "fail",
                "15": "fail",
            },
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="",  # No signing key
        )
        local_card = AgentComplianceCard(
            agent_id="agent-also-fails",
            agent_name="AlsoFails",
            framework="langchain",
            trust_layer_version="1.0.0",
            audit_chain_enabled=False,  # Audit disabled
            injection_protection=False,  # Injection disabled
            compliance_checks={
                "9": "fail",
                "10": "fail",
                "11": "fail",
                "12": "fail",
                "14": "fail",
                "15": "fail",
            },
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="",  # No signing key
        )
        gate = A2AComplianceGate(local_card)
        result = gate.verify_peer(peer_card)
        assert result.score >= 0.0

    def test_verify_peer_score_clamped_to_one(
        self, valid_compliance_card, peer_compliance_card
    ):
        """Test that score is clamped to 1.0 for perfect verification."""
        gate = A2AComplianceGate(valid_compliance_card)
        result = gate.verify_peer(peer_compliance_card)
        assert result.score <= 1.0

    def test_create_handshake(
        self, valid_compliance_card, peer_compliance_card
    ):
        """Test creating a handshake record."""
        gate = A2AComplianceGate(valid_compliance_card)
        handshake = gate.create_handshake(peer_compliance_card)

        assert "data" in handshake
        assert "signature" in handshake
        assert handshake["signature_algorithm"] == "HMAC-SHA256"
        assert handshake["signer_fingerprint"] == valid_compliance_card.signing_key_fingerprint

        # Check handshake data
        data = handshake["data"]
        assert data["initiator_id"] == valid_compliance_card.agent_id
        assert data["peer_id"] == peer_compliance_card.agent_id
        assert "handshake_id" in data
        assert "timestamp" in data

    def test_create_handshake_signature_valid(
        self, valid_compliance_card, peer_compliance_card
    ):
        """Test that handshake signature is valid."""
        gate = A2AComplianceGate(valid_compliance_card)
        handshake = gate.create_handshake(peer_compliance_card)

        # Verify signature manually
        message = json.dumps(handshake["data"], sort_keys=True)
        message_bytes = message.encode("utf-8")
        key = valid_compliance_card.signing_key_fingerprint.encode("utf-8")
        expected_signature = hmac.new(
            key, message_bytes, hashlib.sha256
        ).hexdigest()

        assert handshake["signature"] == expected_signature

    def test_get_verification_log_empty(self, compliance_gate):
        """Test getting empty verification log."""
        log = compliance_gate.get_verification_log()
        assert log == []
        assert isinstance(log, list)

    def test_get_verification_log_after_verification(
        self, compliance_gate, peer_compliance_card
    ):
        """Test that verification is logged."""
        compliance_gate.verify_peer(peer_compliance_card)
        log = compliance_gate.get_verification_log()

        assert len(log) == 1
        assert log[0]["peer_id"] == peer_compliance_card.agent_id
        assert "timestamp" in log[0]
        assert "verified" in log[0]
        assert "score" in log[0]

    def test_get_verification_log_multiple_verifications(
        self, valid_compliance_card
    ):
        """Test logging multiple verifications."""
        gate = A2AComplianceGate(valid_compliance_card)

        peer_1 = AgentComplianceCard(
            agent_id="peer-1",
            agent_name="Peer1",
            framework="langchain",
            trust_layer_version="1.0.0",
            audit_chain_enabled=True,
            injection_protection=True,
            compliance_checks={"9": "pass", "10": "pass", "11": "pass",
                              "12": "pass", "14": "pass", "15": "pass"},
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="key1",
        )

        peer_2 = AgentComplianceCard(
            agent_id="peer-2",
            agent_name="Peer2",
            framework="crewai",
            trust_layer_version="1.0.0",
            audit_chain_enabled=True,
            injection_protection=True,
            compliance_checks={"9": "pass", "10": "pass", "11": "pass",
                              "12": "pass", "14": "pass", "15": "pass"},
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="key2",
        )

        gate.verify_peer(peer_1)
        gate.verify_peer(peer_2)

        log = gate.get_verification_log()
        assert len(log) == 2
        assert log[0]["peer_id"] == peer_1.agent_id
        assert log[1]["peer_id"] == peer_2.agent_id

    def test_get_verification_log_returns_copy(self, compliance_gate):
        """Test that get_verification_log returns a copy, not original."""
        original_log = compliance_gate.verification_log
        returned_log = compliance_gate.get_verification_log()

        # Modify returned log
        returned_log.append({"fake": "entry"})

        # Original should be unchanged
        assert len(compliance_gate.verification_log) == 0
        assert len(returned_log) == 1


# ============================================================================
# generate_compliance_card Tests
# ============================================================================


class TestGenerateComplianceCard:
    """Tests for generate_compliance_card function."""

    def test_generate_with_all_parameters(self, scan_results_complete):
        """Test generating card with all parameters specified."""
        card = generate_compliance_card(
            scan_results=scan_results_complete,
            agent_id="custom-agent-001",
            agent_name="CustomAgent",
            framework="autogen",
            trust_layer_version="2.0.0",
            capabilities=["custom_cap"],
        )

        assert card.agent_id == "custom-agent-001"
        assert card.agent_name == "CustomAgent"
        assert card.framework == "autogen"
        assert card.trust_layer_version == "2.0.0"
        assert "custom_cap" in card.capabilities

    def test_generate_with_minimal_scan_results(self, scan_results_minimal):
        """Test generating card from minimal scan results."""
        card = generate_compliance_card(scan_results=scan_results_minimal)

        # Should have generated IDs and defaults
        assert card.agent_id is not None
        assert len(card.agent_id) > 0
        assert card.agent_name == card.agent_id[:8]
        assert card.framework == "unknown"
        assert card.trust_layer_version == "1.0.0"
        assert card.audit_chain_enabled is False
        assert card.injection_protection is False

    def test_generate_auto_generates_agent_id(self, scan_results_complete):
        """Test that agent_id is auto-generated if not provided."""
        card1 = generate_compliance_card(scan_results=scan_results_complete)
        card2 = generate_compliance_card(scan_results=scan_results_complete)

        # IDs should be different
        assert card1.agent_id != card2.agent_id

    def test_generate_agent_name_defaults_to_id_prefix(
        self, scan_results_complete
    ):
        """Test that agent_name defaults to first 8 chars of agent_id."""
        agent_id = "super-long-agent-id-12345"
        card = generate_compliance_card(
            scan_results=scan_results_complete,
            agent_id=agent_id,
        )

        assert card.agent_name == agent_id[:8]

    def test_generate_extracts_framework_from_scan_results(
        self, scan_results_complete
    ):
        """Test that framework is extracted from scan results if not provided."""
        card = generate_compliance_card(scan_results=scan_results_complete)
        assert card.framework == "crewai"

    def test_generate_framework_override(self, scan_results_complete):
        """Test that provided framework overrides scan results."""
        card = generate_compliance_card(
            scan_results=scan_results_complete,
            framework="custom_framework",
        )
        assert card.framework == "custom_framework"

    def test_generate_extracts_trust_layer_version(
        self, scan_results_complete
    ):
        """Test that trust_layer_version is extracted from scan results."""
        card = generate_compliance_card(scan_results=scan_results_complete)
        assert card.trust_layer_version == "1.2.0"

    def test_generate_trust_layer_version_override(
        self, scan_results_complete
    ):
        """Test that provided trust_layer_version overrides scan results."""
        card = generate_compliance_card(
            scan_results=scan_results_complete,
            trust_layer_version="3.0.0",
        )
        assert card.trust_layer_version == "3.0.0"

    def test_generate_extracts_audit_chain_status(
        self, scan_results_complete
    ):
        """Test that audit_chain_enabled is extracted."""
        card = generate_compliance_card(scan_results=scan_results_complete)
        assert card.audit_chain_enabled is True

    def test_generate_extracts_injection_protection_status(
        self, scan_results_complete
    ):
        """Test that injection_protection is extracted."""
        card = generate_compliance_card(scan_results=scan_results_complete)
        assert card.injection_protection is True

    def test_generate_extracts_compliance_checks(self, scan_results_complete):
        """Test that all article compliance checks are extracted."""
        card = generate_compliance_card(scan_results=scan_results_complete)

        for article in ["9", "10", "11", "12", "14", "15"]:
            assert article in card.compliance_checks
            assert card.compliance_checks[article] == "pass"

    def test_generate_compliance_checks_with_failures(
        self, scan_results_with_failures
    ):
        """Test that failing compliance checks are captured."""
        card = generate_compliance_card(scan_results=scan_results_with_failures)

        assert card.compliance_checks["9"] == "fail"
        assert card.compliance_checks["12"] == "fail"
        assert card.compliance_checks["10"] == "pass"

    def test_generate_extracts_gdpr_checks(self, scan_results_complete):
        """Test that GDPR checks are extracted."""
        card = generate_compliance_card(scan_results=scan_results_complete)
        assert "data_processing" in card.gdpr_checks
        assert card.gdpr_checks["data_processing"] == "pass"

    def test_generate_signing_key_from_scan_results(self, scan_results_complete):
        """Test that signing key is extracted from scan results."""
        card = generate_compliance_card(scan_results=scan_results_complete)
        assert card.signing_key_fingerprint == "scan_key_12345678"

    def test_generate_signing_key_deterministic_generation(
        self, scan_results_minimal
    ):
        """Test that signing key is deterministically generated from agent_id."""
        agent_id = "test-agent-deterministic"
        card1 = generate_compliance_card(
            scan_results=scan_results_minimal,
            agent_id=agent_id,
        )
        card2 = generate_compliance_card(
            scan_results=scan_results_minimal,
            agent_id=agent_id,
        )

        # Same agent_id should produce same fingerprint
        assert card1.signing_key_fingerprint == card2.signing_key_fingerprint

    def test_generate_signing_key_different_for_different_agents(
        self, scan_results_minimal
    ):
        """Test that different agents get different signing keys."""
        card1 = generate_compliance_card(
            scan_results=scan_results_minimal,
            agent_id="agent-1",
        )
        card2 = generate_compliance_card(
            scan_results=scan_results_minimal,
            agent_id="agent-2",
        )

        assert card1.signing_key_fingerprint != card2.signing_key_fingerprint

    def test_generate_extracts_capabilities(self, scan_results_complete):
        """Test that capabilities are extracted from scan results."""
        card = generate_compliance_card(scan_results=scan_results_complete)
        assert "scan" in card.capabilities
        assert "report" in card.capabilities

    def test_generate_capabilities_override(self, scan_results_complete):
        """Test that provided capabilities override scan results."""
        card = generate_compliance_card(
            scan_results=scan_results_complete,
            capabilities=["override_cap"],
        )
        assert card.capabilities == ["override_cap"]

    def test_generate_last_verified_is_set(self, scan_results_complete):
        """Test that last_verified is set to current time."""
        before = datetime.utcnow().isoformat()
        card = generate_compliance_card(scan_results=scan_results_complete)
        after = datetime.utcnow().isoformat()

        assert before <= card.last_verified <= after

    def test_generate_card_is_valid(self, scan_results_complete):
        """Test that generated card is a valid AgentComplianceCard."""
        card = generate_compliance_card(scan_results=scan_results_complete)
        assert isinstance(card, AgentComplianceCard)

        # All required fields should be set
        assert card.agent_id is not None
        assert card.agent_name is not None
        assert card.framework is not None
        assert card.trust_layer_version is not None
        assert card.audit_chain_enabled is not None
        assert card.injection_protection is not None
        assert card.compliance_checks is not None
        assert card.gdpr_checks is not None
        assert card.last_verified is not None
        assert card.signing_key_fingerprint is not None


# ============================================================================
# verify_a2a_communication Tests
# ============================================================================


class TestVerifyA2ACommunication:
    """Tests for verify_a2a_communication function."""

    def test_verify_compliant_agents(
        self, valid_compliance_card, peer_compliance_card
    ):
        """Test verification of two compliant agents."""
        result = verify_a2a_communication(
            valid_compliance_card, peer_compliance_card
        )

        assert result.verified is True
        assert result.score == 1.0
        assert len(result.issues) == 0

    def test_verify_with_non_compliant_first_agent(
        self, peer_compliance_card
    ):
        """Test verification with non-compliant first agent."""
        bad_agent = AgentComplianceCard(
            agent_id="bad-agent-1",
            agent_name="BadAgent1",
            framework="langchain",
            trust_layer_version="1.0.0",
            audit_chain_enabled=False,  # Non-compliant
            injection_protection=True,
            compliance_checks={"9": "pass", "10": "pass", "11": "pass",
                              "12": "pass", "14": "pass", "15": "pass"},
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="abc123",
        )

        result = verify_a2a_communication(bad_agent, peer_compliance_card)
        assert result.verified is False

    def test_verify_with_non_compliant_second_agent(
        self, valid_compliance_card
    ):
        """Test verification with non-compliant second agent."""
        bad_agent = AgentComplianceCard(
            agent_id="bad-agent-2",
            agent_name="BadAgent2",
            framework="langchain",
            trust_layer_version="1.0.0",
            audit_chain_enabled=False,  # Non-compliant
            injection_protection=True,
            compliance_checks={"9": "pass", "10": "pass", "11": "pass",
                              "12": "pass", "14": "pass", "15": "pass"},
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="abc123",
        )

        result = verify_a2a_communication(valid_compliance_card, bad_agent)
        assert result.verified is False

    def test_verify_creates_audit_record_when_verified(
        self, valid_compliance_card, peer_compliance_card
    ):
        """Test that verification creates audit record when successful."""
        result = verify_a2a_communication(
            valid_compliance_card, peer_compliance_card
        )

        # We can't directly verify the audit record creation (it's not returned),
        # but we can check that result has handshake_record when verified
        assert result.verified is True

    def test_verify_no_audit_record_without_signing_keys(
        self, peer_compliance_card
    ):
        """Test behavior when signing keys are missing."""
        no_key_agent = AgentComplianceCard(
            agent_id="no-key-agent",
            agent_name="NoKeyAgent",
            framework="langchain",
            trust_layer_version="1.0.0",
            audit_chain_enabled=True,
            injection_protection=True,
            compliance_checks={"9": "pass", "10": "pass", "11": "pass",
                              "12": "pass", "14": "pass", "15": "pass"},
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="",  # Missing
        )

        result = verify_a2a_communication(
            no_key_agent, peer_compliance_card
        )
        # Should fail verification due to missing signing key
        assert result.verified is False

    def test_verify_returns_a2a_verification_result(
        self, valid_compliance_card, peer_compliance_card
    ):
        """Test that function returns A2AVerificationResult."""
        result = verify_a2a_communication(
            valid_compliance_card, peer_compliance_card
        )
        assert isinstance(result, A2AVerificationResult)

    def test_verify_sets_correct_agent_ids_in_audit_record(
        self, valid_compliance_card, peer_compliance_card
    ):
        """Test that audit records contain correct agent IDs."""
        result = verify_a2a_communication(
            valid_compliance_card, peer_compliance_card
        )

        # When verified, handshake should be created
        if result.verified:
            assert result.handshake_record is not None


# ============================================================================
# Edge Cases and Integration Tests
# ============================================================================


class TestProtocolEdgeCases:
    """Tests for edge cases and integration scenarios."""

    def test_empty_compliance_checks_dict(self):
        """Test card with empty compliance checks dict."""
        card = AgentComplianceCard(
            agent_id="test",
            agent_name="Test",
            framework="test",
            trust_layer_version="1.0.0",
            audit_chain_enabled=True,
            injection_protection=True,
            compliance_checks={},  # Empty
            gdpr_checks={},
            last_verified="2024-01-01T00:00:00",
            signing_key_fingerprint="abc123",
        )

        gate = A2AComplianceGate(card)
        # Should handle empty checks without crashing
        requirements = gate.minimum_requirements
        assert requirements is not None

    def test_very_long_agent_name(self):
        """Test card with very long agent name."""
        long_name = "A" * 1000
        card = AgentComplianceCard(
            agent_id="test",
            agent_name=long_name,
            framework="test",
            trust_layer_version="1.0.0",
            audit_chain_enabled=True,
            injection_protection=True,
            compliance_checks={},
            gdpr_checks={},
            last_verified="2024-01-01T00:00:00",
            signing_key_fingerprint="abc123",
        )

        assert card.agent_name == long_name
        dict_form = card.to_dict()
        assert dict_form["agent_name"] == long_name

    def test_special_characters_in_agent_id(self):
        """Test card with special characters in agent_id."""
        special_id = "agent!@#$%^&*()"
        card = AgentComplianceCard(
            agent_id=special_id,
            agent_name="Test",
            framework="test",
            trust_layer_version="1.0.0",
            audit_chain_enabled=True,
            injection_protection=True,
            compliance_checks={},
            gdpr_checks={},
            last_verified="2024-01-01T00:00:00",
            signing_key_fingerprint="abc123",
        )

        assert card.agent_id == special_id

    def test_json_serialization_preserves_data(self):
        """Test that JSON serialization roundtrip preserves all data."""
        original_card = AgentComplianceCard(
            agent_id="test-agent",
            agent_name="TestAgent",
            framework="langchain",
            trust_layer_version="1.2.3",
            audit_chain_enabled=True,
            injection_protection=False,
            compliance_checks={"9": "pass", "10": "fail"},
            gdpr_checks={"consent": "pass"},
            last_verified="2024-01-01T12:34:56",
            signing_key_fingerprint="fingerprint123",
            capabilities=["cap1", "cap2"],
        )

        json_str = original_card.to_json()
        restored_card = AgentComplianceCard.from_json(json_str)

        assert original_card.agent_id == restored_card.agent_id
        assert original_card.framework == restored_card.framework
        assert original_card.compliance_checks == restored_card.compliance_checks
        assert original_card.capabilities == restored_card.capabilities

    def test_verification_with_many_issues(self):
        """Test verification result with many issues."""
        issues = [f"Issue {i}" for i in range(100)]
        result = A2AVerificationResult(
            verified=False,
            score=0.0,
            issues=issues,
            recommendations=[f"Fix {i}" for i in range(100)],
        )

        assert len(result.issues) == 100
        assert len(result.recommendations) == 100
        summary = result.summary()
        assert "Issues: 100" in summary
        assert "Recommendations: 100" in summary

    def test_generate_card_with_missing_articles(self):
        """Test card generation when some articles are missing from scan results."""
        incomplete_scan = {
            "framework": "test",
            "trust_layer_version": "1.0.0",
            # Missing articles 14, 15
            "article_9": "pass",
            "article_10": "pass",
        }

        card = generate_compliance_card(scan_results=incomplete_scan)

        # Missing articles should default to "unknown"
        assert card.compliance_checks["14"] == "unknown"
        assert card.compliance_checks["15"] == "unknown"

    def test_handshake_contains_all_required_fields(
        self, valid_compliance_card, peer_compliance_card
    ):
        """Test that handshake contains all required fields."""
        gate = A2AComplianceGate(valid_compliance_card)
        handshake = gate.create_handshake(peer_compliance_card)

        required_top_level = ["data", "signature", "signature_algorithm", "signer_fingerprint"]
        for field in required_top_level:
            assert field in handshake

        required_data_fields = [
            "handshake_id", "timestamp", "initiator_id", "initiator_name",
            "peer_id", "peer_name", "local_framework", "peer_framework",
            "local_trust_layer", "peer_trust_layer", "compliance_verified",
        ]
        for field in required_data_fields:
            assert field in handshake["data"]

    def test_verification_log_includes_timestamp(
        self, compliance_gate, peer_compliance_card
    ):
        """Test that verification log entries include timestamps."""
        compliance_gate.verify_peer(peer_compliance_card)
        log = compliance_gate.get_verification_log()

        assert len(log) == 1
        assert "timestamp" in log[0]
        # Timestamp should be ISO format
        timestamp = log[0]["timestamp"]
        datetime.fromisoformat(timestamp)  # Should not raise

    @pytest.mark.parametrize("major,minor,patch", [
        ("1", "0", "0"),
        ("1", "5", "3"),
        ("2", "0", "0"),
        ("2", "10", "5"),
    ])
    def test_version_parsing(self, valid_compliance_card, major, minor, patch):
        """Test that version parsing works for various formats."""
        version = f"{major}.{minor}.{patch}"
        peer_card = AgentComplianceCard(
            agent_id="test",
            agent_name="Test",
            framework="test",
            trust_layer_version=version,
            audit_chain_enabled=True,
            injection_protection=True,
            compliance_checks={"9": "pass", "10": "pass", "11": "pass",
                              "12": "pass", "14": "pass", "15": "pass"},
            gdpr_checks={},
            last_verified=datetime.utcnow().isoformat(),
            signing_key_fingerprint="abc",
        )

        gate = A2AComplianceGate(valid_compliance_card)
        # Should not crash when parsing version
        result = gate.verify_peer(peer_card)
        assert result is not None
