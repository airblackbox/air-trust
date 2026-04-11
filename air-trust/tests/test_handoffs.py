"""Tests for v1.2 signed handoffs — Ed25519 key management and handoff protocol."""

import os
import json
import tempfile
import uuid
import pytest

from air_trust.events import Event, AgentIdentity
from air_trust.chain import AuditChain


# ── Helpers ───────────────────────────────────────────────────────

def _make_identity(name: str, owner: str = "jason@airblackbox.ai") -> AgentIdentity:
    return AgentIdentity(agent_name=name, owner=owner)


def _fresh_chain(tmp_path) -> AuditChain:
    db = str(tmp_path / f"test_{uuid.uuid4().hex[:8]}.db")
    return AuditChain(db_path=db, signing_key="test-key-handoffs")


# ── Key Management Tests ─────────────────────────────────────────

class TestKeyManagement:
    """Test Ed25519 keypair generation, storage, and loading."""

    def test_generate_keypair(self, tmp_path, monkeypatch):
        """generate_keypair creates .key and .pub files."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        identity = _make_identity("test-agent")
        pub_hex = keys.generate_keypair(identity.fingerprint)

        assert pub_hex.startswith("ed25519:")
        assert (tmp_path / f"{identity.fingerprint}.key").exists()
        assert (tmp_path / f"{identity.fingerprint}.pub").exists()

    def test_private_key_permissions(self, tmp_path, monkeypatch):
        """Private key file should have 0o600 permissions."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        identity = _make_identity("perm-agent")
        keys.generate_keypair(identity.fingerprint)

        priv_path = tmp_path / f"{identity.fingerprint}.key"
        mode = oct(os.stat(priv_path).st_mode)[-3:]
        assert mode == "600"

    def test_duplicate_keypair_raises(self, tmp_path, monkeypatch):
        """generate_keypair raises FileExistsError if keys already exist."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        identity = _make_identity("dup-agent")
        keys.generate_keypair(identity.fingerprint)

        with pytest.raises(FileExistsError):
            keys.generate_keypair(identity.fingerprint)

    def test_has_keypair(self, tmp_path, monkeypatch):
        """has_keypair returns True after generation, False before."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        identity = _make_identity("has-agent")
        assert not keys.has_keypair(identity.fingerprint)
        keys.generate_keypair(identity.fingerprint)
        assert keys.has_keypair(identity.fingerprint)

    def test_load_private_key(self, tmp_path, monkeypatch):
        """load_private_key returns a usable Ed25519PrivateKey."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        identity = _make_identity("load-agent")
        keys.generate_keypair(identity.fingerprint)

        priv_key = keys.load_private_key(identity.fingerprint)
        # Should be able to sign without error
        sig = priv_key.sign(b"test data")
        assert len(sig) == 64  # Ed25519 signatures are 64 bytes

    def test_load_public_key(self, tmp_path, monkeypatch):
        """load_public_key returns a usable Ed25519PublicKey."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        identity = _make_identity("pub-agent")
        keys.generate_keypair(identity.fingerprint)

        pub_key = keys.load_public_key(identity.fingerprint)
        priv_key = keys.load_private_key(identity.fingerprint)

        # Sign and verify roundtrip
        sig = priv_key.sign(b"roundtrip test")
        pub_key.verify(sig, b"roundtrip test")  # Should not raise

    def test_load_missing_key_raises(self, tmp_path, monkeypatch):
        """Loading a key that doesn't exist raises FileNotFoundError."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        with pytest.raises(FileNotFoundError):
            keys.load_private_key("nonexistent")

    def test_public_key_from_hex_roundtrip(self, tmp_path, monkeypatch):
        """public_key_from_hex parses the output of generate_keypair."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        identity = _make_identity("hex-agent")
        pub_hex = keys.generate_keypair(identity.fingerprint)

        pub_key = keys.public_key_from_hex(pub_hex)
        assert pub_key is not None


# ── Signing and Verification Tests ────────────────────────────────

class TestSigningPrimitives:
    """Test the low-level sign/verify functions."""

    def test_sign_and_verify(self, tmp_path, monkeypatch):
        """sign() produces a signature that verify_signature() accepts."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        identity = _make_identity("sig-agent")
        pub_hex = keys.generate_keypair(identity.fingerprint)

        sig = keys.sign(identity.fingerprint, b"hello world")
        assert sig.startswith("ed25519:")

        assert keys.verify_signature(pub_hex, sig, b"hello world") is True

    def test_wrong_data_fails_verification(self, tmp_path, monkeypatch):
        """verify_signature returns False for wrong data."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        identity = _make_identity("wrong-data-agent")
        pub_hex = keys.generate_keypair(identity.fingerprint)

        sig = keys.sign(identity.fingerprint, b"original data")
        assert keys.verify_signature(pub_hex, sig, b"tampered data") is False

    def test_wrong_key_fails_verification(self, tmp_path, monkeypatch):
        """verify_signature returns False for wrong public key."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        agent_a = _make_identity("agent-a")
        agent_b = _make_identity("agent-b")
        pub_a = keys.generate_keypair(agent_a.fingerprint)
        pub_b = keys.generate_keypair(agent_b.fingerprint)

        sig = keys.sign(agent_a.fingerprint, b"signed by A")
        assert keys.verify_signature(pub_a, sig, b"signed by A") is True
        assert keys.verify_signature(pub_b, sig, b"signed by A") is False

    def test_build_signing_payload(self):
        """build_signing_payload produces the canonical pipe-delimited format."""
        from air_trust.keys import build_signing_payload

        payload = build_signing_payload(
            interaction_id="abc123",
            counterparty_id="fp-b",
            payload_hash="sha256:deadbeef",
            nonce="random16",
            event_type="handoff_request",
            timestamp="2026-04-10T14:30:00Z",
        )
        assert payload == b"abc123|fp-b|sha256:deadbeef|random16|handoff_request|2026-04-10T14:30:00Z"

    def test_compute_payload_hash(self):
        """compute_payload_hash produces sha256-prefixed hash."""
        from air_trust.keys import compute_payload_hash

        h = compute_payload_hash("test payload")
        assert h.startswith("sha256:")
        assert len(h) == 7 + 64  # "sha256:" + 64 hex chars

    def test_generate_nonce(self):
        """generate_nonce produces unique 32-char hex strings."""
        from air_trust.keys import generate_nonce

        n1 = generate_nonce()
        n2 = generate_nonce()
        assert len(n1) == 32  # 16 bytes = 32 hex chars
        assert n1 != n2


# ── Handoff Chain Integration Tests ───────────────────────────────

class TestHandoffChainWrite:
    """Test that handoff records are auto-signed when written to the chain."""

    def test_handoff_request_auto_signed(self, tmp_path, monkeypatch):
        """Writing a handoff_request with identity auto-signs with Ed25519."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        agent_a = _make_identity("researcher")
        keys.generate_keypair(agent_a.fingerprint)

        chain = _fresh_chain(tmp_path)
        iid = uuid.uuid4().hex

        event = Event(
            type="handoff_request",
            framework="raw_python",
            identity=agent_a,
            interaction_id=iid,
            counterparty_id="target-fingerprint",
            payload_hash="sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            nonce=os.urandom(16).hex(),
        )
        chain.write(event)

        assert event.signature is not None
        assert event.signature.startswith("ed25519:")
        assert event.signature_alg == "ed25519"
        assert event.public_key is not None

    def test_non_handoff_not_signed(self, tmp_path):
        """Regular events do NOT get Ed25519 signatures."""
        chain = _fresh_chain(tmp_path)

        event = Event(type="llm_call", framework="openai")
        chain.write(event)

        assert event.signature is None
        assert event.signature_alg is None

    def test_handoff_without_key_skips_signing(self, tmp_path, monkeypatch):
        """If no keypair exists, handoff is written without signature."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)
        # Don't generate any keys

        agent_a = _make_identity("no-key-agent")
        chain = _fresh_chain(tmp_path)

        event = Event(
            type="handoff_request",
            framework="raw_python",
            identity=agent_a,
            interaction_id=uuid.uuid4().hex,
            counterparty_id="target-fp",
            payload_hash="sha256:0" * 32,
            nonce=os.urandom(16).hex(),
        )
        chain.write(event)

        # Should write without error, but no signature
        assert event.signature is None


# ── Handoff Verification Tests ────────────────────────────────────

def _write_complete_handoff(chain, agent_a, agent_b, tmp_path, monkeypatch):
    """Helper: write a complete request → ack → result handoff."""
    from air_trust import keys
    monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

    if not keys.has_keypair(agent_a.fingerprint):
        keys.generate_keypair(agent_a.fingerprint)
    if not keys.has_keypair(agent_b.fingerprint):
        keys.generate_keypair(agent_b.fingerprint)

    iid = uuid.uuid4().hex
    task_hash = keys.compute_payload_hash("research AI governance trends")
    result_hash = keys.compute_payload_hash("here are the results")

    # Agent A sends request
    chain.write(Event(
        type="handoff_request",
        framework="raw_python",
        identity=agent_a,
        interaction_id=iid,
        counterparty_id=agent_b.fingerprint,
        payload_hash=task_hash,
        nonce=keys.generate_nonce(),
    ))

    # Agent B acknowledges
    chain.write(Event(
        type="handoff_ack",
        framework="raw_python",
        identity=agent_b,
        interaction_id=iid,
        counterparty_id=agent_a.fingerprint,
        payload_hash=task_hash,
        nonce=keys.generate_nonce(),
    ))

    # Agent B delivers result
    chain.write(Event(
        type="handoff_result",
        framework="raw_python",
        identity=agent_b,
        interaction_id=iid,
        counterparty_id=agent_a.fingerprint,
        payload_hash=result_hash,
        nonce=keys.generate_nonce(),
    ))

    return iid


class TestHandoffVerification:
    """Test the handoff verification section of verify()."""

    def test_clean_handoff_passes(self, tmp_path, monkeypatch):
        """A complete handoff (request + ack + result) passes verification."""
        agent_a = _make_identity("agent-a")
        agent_b = _make_identity("agent-b")
        chain = _fresh_chain(tmp_path)

        _write_complete_handoff(chain, agent_a, agent_b, tmp_path, monkeypatch)

        result = chain.verify()
        handoffs = result["handoffs"]
        assert handoffs["interactions_checked"] == 1
        assert handoffs["interactions_complete"] == 1
        assert handoffs["interactions_incomplete"] == 0
        assert len(handoffs["issues"]) == 0

    def test_missing_ack_detected(self, tmp_path, monkeypatch):
        """A handoff_request without ack is flagged as missing_ack."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        agent_a = _make_identity("lone-sender")
        keys.generate_keypair(agent_a.fingerprint)

        chain = _fresh_chain(tmp_path)
        chain.write(Event(
            type="handoff_request",
            framework="raw_python",
            identity=agent_a,
            interaction_id=uuid.uuid4().hex,
            counterparty_id="missing-agent-fp",
            payload_hash="sha256:" + "0" * 64,
            nonce=keys.generate_nonce(),
        ))

        result = chain.verify()
        handoffs = result["handoffs"]
        assert handoffs["interactions_checked"] == 1
        assert handoffs["interactions_incomplete"] == 1
        issues = [i for i in handoffs["issues"] if i["issue"] == "missing_ack"]
        assert len(issues) == 1

    def test_missing_result_detected(self, tmp_path, monkeypatch):
        """Request + ack without result is flagged as missing_result (info)."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        agent_a = _make_identity("sender-2")
        agent_b = _make_identity("receiver-2")
        keys.generate_keypair(agent_a.fingerprint)
        keys.generate_keypair(agent_b.fingerprint)

        chain = _fresh_chain(tmp_path)
        iid = uuid.uuid4().hex
        task_hash = "sha256:" + "a" * 64

        chain.write(Event(
            type="handoff_request", framework="raw_python",
            identity=agent_a, interaction_id=iid,
            counterparty_id=agent_b.fingerprint,
            payload_hash=task_hash, nonce=keys.generate_nonce(),
        ))
        chain.write(Event(
            type="handoff_ack", framework="raw_python",
            identity=agent_b, interaction_id=iid,
            counterparty_id=agent_a.fingerprint,
            payload_hash=task_hash, nonce=keys.generate_nonce(),
        ))

        result = chain.verify()
        issues = [i for i in result["handoffs"]["issues"] if i["issue"] == "missing_result"]
        assert len(issues) == 1
        assert issues[0]["severity"] == "info"

    def test_payload_mismatch_detected(self, tmp_path, monkeypatch):
        """Mismatched payload_hash between request and ack is flagged."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        agent_a = _make_identity("mismatch-a")
        agent_b = _make_identity("mismatch-b")
        keys.generate_keypair(agent_a.fingerprint)
        keys.generate_keypair(agent_b.fingerprint)

        chain = _fresh_chain(tmp_path)
        iid = uuid.uuid4().hex

        chain.write(Event(
            type="handoff_request", framework="raw_python",
            identity=agent_a, interaction_id=iid,
            counterparty_id=agent_b.fingerprint,
            payload_hash="sha256:" + "a" * 64,
            nonce=keys.generate_nonce(),
        ))
        chain.write(Event(
            type="handoff_ack", framework="raw_python",
            identity=agent_b, interaction_id=iid,
            counterparty_id=agent_a.fingerprint,
            payload_hash="sha256:" + "b" * 64,  # Different hash!
            nonce=keys.generate_nonce(),
        ))

        result = chain.verify()
        issues = [i for i in result["handoffs"]["issues"] if i["issue"] == "payload_mismatch"]
        assert len(issues) == 1

    def test_invalid_signature_detected(self, tmp_path, monkeypatch):
        """A record with a tampered signature is flagged as signature_invalid."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        agent_a = _make_identity("tamper-agent")
        pub_hex = keys.generate_keypair(agent_a.fingerprint)

        chain = _fresh_chain(tmp_path)
        event = Event(
            type="handoff_request", framework="raw_python",
            identity=agent_a, interaction_id=uuid.uuid4().hex,
            counterparty_id="some-fp",
            payload_hash="sha256:" + "c" * 64,
            nonce=keys.generate_nonce(),
        )
        chain.write(event)

        # Tamper with the signature in the database
        import sqlite3
        conn = sqlite3.connect(chain._db_path)
        # Get the stored data and modify the signature
        row = conn.execute("SELECT id, data FROM events WHERE type='handoff_request'").fetchone()
        record = json.loads(row[1])
        record["signature"] = "ed25519:" + "ff" * 64  # Fake signature
        conn.execute("UPDATE events SET data=?, signature=? WHERE id=?",
                     (json.dumps(record), "ed25519:" + "ff" * 64, row[0]))
        conn.commit()
        conn.close()

        result = chain.verify()
        # Integrity will fail because we modified data, but let's check handoff issues too
        sig_issues = [i for i in result["handoffs"]["issues"] if i["issue"] == "signature_invalid"]
        assert len(sig_issues) == 1

    def test_orphaned_ack_detected(self, tmp_path, monkeypatch):
        """An ack without a matching request is flagged as orphaned."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        agent_b = _make_identity("orphan-acker")
        keys.generate_keypair(agent_b.fingerprint)

        chain = _fresh_chain(tmp_path)
        chain.write(Event(
            type="handoff_ack", framework="raw_python",
            identity=agent_b, interaction_id=uuid.uuid4().hex,
            counterparty_id="nonexistent-requester",
            payload_hash="sha256:" + "d" * 64,
            nonce=keys.generate_nonce(),
        ))

        result = chain.verify()
        issues = [i for i in result["handoffs"]["issues"] if i["issue"] == "orphaned_response"]
        assert len(issues) == 1

    def test_no_handoffs_returns_empty(self, tmp_path):
        """A chain with no handoff records returns zeroed handoff section."""
        chain = _fresh_chain(tmp_path)
        chain.write(Event(type="llm_call", framework="openai"))
        chain.write(Event(type="tool_call", framework="langchain"))

        result = chain.verify()
        handoffs = result["handoffs"]
        assert handoffs["interactions_checked"] == 0
        assert handoffs["interactions_complete"] == 0
        assert len(handoffs["issues"]) == 0

    def test_multiple_handoffs(self, tmp_path, monkeypatch):
        """Multiple independent handoffs are each verified separately."""
        agent_a = _make_identity("multi-a")
        agent_b = _make_identity("multi-b")
        chain = _fresh_chain(tmp_path)

        _write_complete_handoff(chain, agent_a, agent_b, tmp_path, monkeypatch)
        _write_complete_handoff(chain, agent_a, agent_b, tmp_path, monkeypatch)

        result = chain.verify()
        handoffs = result["handoffs"]
        assert handoffs["interactions_checked"] == 2
        assert handoffs["interactions_complete"] == 2

    def test_duplicate_nonce_detected(self, tmp_path, monkeypatch):
        """Duplicate nonces across handoff records are flagged."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        agent_a = _make_identity("nonce-a")
        agent_b = _make_identity("nonce-b")
        keys.generate_keypair(agent_a.fingerprint)
        keys.generate_keypair(agent_b.fingerprint)

        chain = _fresh_chain(tmp_path)
        iid = uuid.uuid4().hex
        task_hash = "sha256:" + "e" * 64
        shared_nonce = "deadbeef" * 4  # Same nonce used twice

        chain.write(Event(
            type="handoff_request", framework="raw_python",
            identity=agent_a, interaction_id=iid,
            counterparty_id=agent_b.fingerprint,
            payload_hash=task_hash, nonce=shared_nonce,
        ))
        chain.write(Event(
            type="handoff_ack", framework="raw_python",
            identity=agent_b, interaction_id=iid,
            counterparty_id=agent_a.fingerprint,
            payload_hash=task_hash, nonce=shared_nonce,  # Duplicate!
        ))

        result = chain.verify()
        nonce_issues = [i for i in result["handoffs"]["issues"] if i["issue"] == "duplicate_nonce"]
        assert len(nonce_issues) == 1


# ── Backward Compatibility Tests ──────────────────────────────────

class TestHandoffBackwardCompat:
    """Ensure v1.0 and v1.1 chains still verify with v1.2 verifier."""

    def test_v10_records_still_verify(self, tmp_path):
        """Records without any handoff or session fields still pass."""
        chain = _fresh_chain(tmp_path)
        for i in range(5):
            chain.write(Event(type="llm_call", framework="openai"))

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["handoffs"]["interactions_checked"] == 0

    def test_v11_session_records_still_verify(self, tmp_path):
        """v1.1 session records with completeness still pass alongside handoffs."""
        chain = _fresh_chain(tmp_path)

        # Write some session records (v1.1 style)
        sid = uuid.uuid4().hex
        chain.write(Event(type="session_start", framework="raw_python", session_id=sid, status="running"))
        chain.write(Event(type="llm_call", framework="openai", session_id=sid))
        chain.write(Event(type="session_end", framework="raw_python", session_id=sid, status="success"))

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["completeness"]["sessions_checked"] == 1
        assert result["completeness"]["sessions_complete"] == 1
        assert result["handoffs"]["interactions_checked"] == 0

    def test_mixed_v11_and_v12(self, tmp_path, monkeypatch):
        """Session completeness records and handoff records coexist."""
        from air_trust import keys
        monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)

        agent_a = _make_identity("mixed-a")
        agent_b = _make_identity("mixed-b")
        keys.generate_keypair(agent_a.fingerprint)
        keys.generate_keypair(agent_b.fingerprint)

        chain = _fresh_chain(tmp_path)
        sid = uuid.uuid4().hex
        iid = uuid.uuid4().hex
        task_hash = keys.compute_payload_hash("mixed test")

        # Session records
        chain.write(Event(type="session_start", framework="raw_python", session_id=sid, status="running"))
        chain.write(Event(type="llm_call", framework="openai", session_id=sid))

        # Handoff records within the same session
        chain.write(Event(
            type="handoff_request", framework="raw_python",
            identity=agent_a, interaction_id=iid, session_id=sid,
            counterparty_id=agent_b.fingerprint,
            payload_hash=task_hash, nonce=keys.generate_nonce(),
        ))
        chain.write(Event(
            type="handoff_ack", framework="raw_python",
            identity=agent_b, interaction_id=iid, session_id=sid,
            counterparty_id=agent_a.fingerprint,
            payload_hash=task_hash, nonce=keys.generate_nonce(),
        ))
        chain.write(Event(
            type="handoff_result", framework="raw_python",
            identity=agent_b, interaction_id=iid, session_id=sid,
            counterparty_id=agent_a.fingerprint,
            payload_hash=keys.compute_payload_hash("result"),
            nonce=keys.generate_nonce(),
        ))

        chain.write(Event(type="session_end", framework="raw_python", session_id=sid, status="success"))

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["completeness"]["sessions_complete"] == 1
        assert result["handoffs"]["interactions_complete"] == 1


# ── Verify Output Format Tests ────────────────────────────────────

class TestVerifyOutputFormat:
    """Test that verify() output has the expected v1.2 shape."""

    def test_has_all_three_sections(self, tmp_path):
        """verify() returns integrity, completeness, AND handoffs."""
        chain = _fresh_chain(tmp_path)
        chain.write(Event(type="llm_call", framework="openai"))

        result = chain.verify()
        assert "integrity" in result
        assert "completeness" in result
        assert "handoffs" in result

    def test_handoffs_section_shape(self, tmp_path):
        """Handoffs section has the expected keys."""
        chain = _fresh_chain(tmp_path)
        chain.write(Event(type="llm_call", framework="openai"))

        handoffs = chain.verify()["handoffs"]
        assert "interactions_checked" in handoffs
        assert "interactions_complete" in handoffs
        assert "interactions_incomplete" in handoffs
        assert "issues" in handoffs

    def test_backward_compat_top_level(self, tmp_path):
        """Top-level valid/records/broken_at still exist for backward compat."""
        chain = _fresh_chain(tmp_path)
        chain.write(Event(type="llm_call", framework="openai"))

        result = chain.verify()
        assert "valid" in result
        assert "records" in result
        assert "broken_at" in result
