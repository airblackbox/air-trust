"""
Stress tests and edge-case tests for v1.2 signed handoffs.

These go beyond the unit tests in test_handoffs.py to catch:
- False positives (clean chains incorrectly flagged)
- False negatives (broken chains not caught)
- Edge cases around mixed versions, large chains, concurrent sessions
- Database tampering scenarios
"""

import json
import os
import sqlite3
import uuid
import pytest

from air_trust.events import Event, AgentIdentity
from air_trust.chain import AuditChain


def _identity(name):
    return AgentIdentity(agent_name=name, owner="test@test.com")


def _chain(tmp_path, name="stress"):
    db = str(tmp_path / f"{name}_{uuid.uuid4().hex[:8]}.db")
    return AuditChain(db_path=db, signing_key="stress-test-key")


def _setup_keys(tmp_path, monkeypatch, *identities):
    """Generate keys for all given identities, return them."""
    from air_trust import keys
    monkeypatch.setattr(keys, "_keys_dir", lambda: tmp_path)
    for ident in identities:
        if not keys.has_keypair(ident.fingerprint):
            keys.generate_keypair(ident.fingerprint)
    return keys


def _write_handoff(chain, keys_mod, agent_a, agent_b, interaction_id=None):
    """Write a complete request/ack/result handoff."""
    iid = interaction_id or uuid.uuid4().hex
    task_hash = keys_mod.compute_payload_hash(f"task-{iid}")
    result_hash = keys_mod.compute_payload_hash(f"result-{iid}")

    chain.write(Event(
        type="handoff_request", framework="raw_python",
        identity=agent_a, interaction_id=iid,
        counterparty_id=agent_b.fingerprint,
        payload_hash=task_hash, nonce=keys_mod.generate_nonce(),
    ))
    chain.write(Event(
        type="handoff_ack", framework="raw_python",
        identity=agent_b, interaction_id=iid,
        counterparty_id=agent_a.fingerprint,
        payload_hash=task_hash, nonce=keys_mod.generate_nonce(),
    ))
    chain.write(Event(
        type="handoff_result", framework="raw_python",
        identity=agent_b, interaction_id=iid,
        counterparty_id=agent_a.fingerprint,
        payload_hash=result_hash, nonce=keys_mod.generate_nonce(),
    ))
    return iid


# ═══════════════════════════════════════════════════════════════════
# FALSE POSITIVE TESTS - clean chains should NOT be flagged
# ═══════════════════════════════════════════════════════════════════

class TestFalsePositives:
    """Ensure clean chains produce zero issues."""

    def test_single_handoff_no_false_positives(self, tmp_path, monkeypatch):
        """A single clean handoff should have zero issues."""
        a, b = _identity("fp-a"), _identity("fp-b")
        keys = _setup_keys(tmp_path, monkeypatch, a, b)
        chain = _chain(tmp_path)

        _write_handoff(chain, keys, a, b)

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["handoffs"]["issues"] == []
        assert result["handoffs"]["interactions_complete"] == 1

    def test_ten_handoffs_no_false_positives(self, tmp_path, monkeypatch):
        """10 sequential handoffs should all pass clean."""
        a, b = _identity("multi-fp-a"), _identity("multi-fp-b")
        keys = _setup_keys(tmp_path, monkeypatch, a, b)
        chain = _chain(tmp_path)

        for _ in range(10):
            _write_handoff(chain, keys, a, b)

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["handoffs"]["interactions_checked"] == 10
        assert result["handoffs"]["interactions_complete"] == 10
        assert result["handoffs"]["issues"] == []

    def test_handoff_mixed_with_regular_events(self, tmp_path, monkeypatch):
        """Handoffs interleaved with regular events should not cause false positives."""
        a, b = _identity("mix-a"), _identity("mix-b")
        keys = _setup_keys(tmp_path, monkeypatch, a, b)
        chain = _chain(tmp_path)

        # Regular events
        chain.write(Event(type="llm_call", framework="openai"))
        chain.write(Event(type="tool_call", framework="langchain"))

        # Handoff
        _write_handoff(chain, keys, a, b)

        # More regular events
        chain.write(Event(type="llm_call", framework="anthropic"))

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["handoffs"]["interactions_complete"] == 1
        assert result["handoffs"]["issues"] == []

    def test_handoff_inside_session_no_false_positives(self, tmp_path, monkeypatch):
        """Handoffs within a session context should pass both completeness and handoff checks."""
        a, b = _identity("sess-a"), _identity("sess-b")
        keys = _setup_keys(tmp_path, monkeypatch, a, b)
        chain = _chain(tmp_path)
        sid = uuid.uuid4().hex
        iid = uuid.uuid4().hex
        task_hash = keys.compute_payload_hash("session-task")

        chain.write(Event(type="session_start", framework="raw_python", session_id=sid, status="running"))
        chain.write(Event(type="llm_call", framework="openai", session_id=sid))

        chain.write(Event(
            type="handoff_request", framework="raw_python", session_id=sid,
            identity=a, interaction_id=iid,
            counterparty_id=b.fingerprint,
            payload_hash=task_hash, nonce=keys.generate_nonce(),
        ))
        chain.write(Event(
            type="handoff_ack", framework="raw_python", session_id=sid,
            identity=b, interaction_id=iid,
            counterparty_id=a.fingerprint,
            payload_hash=task_hash, nonce=keys.generate_nonce(),
        ))
        chain.write(Event(
            type="handoff_result", framework="raw_python", session_id=sid,
            identity=b, interaction_id=iid,
            counterparty_id=a.fingerprint,
            payload_hash=keys.compute_payload_hash("result"), nonce=keys.generate_nonce(),
        ))

        chain.write(Event(type="session_end", framework="raw_python", session_id=sid, status="success"))

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["completeness"]["sessions_complete"] == 1
        assert result["completeness"]["issues"] == []
        assert result["handoffs"]["interactions_complete"] == 1
        assert result["handoffs"]["issues"] == []

    def test_multiple_agent_pairs(self, tmp_path, monkeypatch):
        """Different agent pairs doing handoffs should all verify independently."""
        agents = [_identity(f"agent-{i}") for i in range(4)]
        keys = _setup_keys(tmp_path, monkeypatch, *agents)
        chain = _chain(tmp_path)

        # A→B, C→D - two independent handoffs with different agent pairs
        _write_handoff(chain, keys, agents[0], agents[1])
        _write_handoff(chain, keys, agents[2], agents[3])

        result = chain.verify()
        assert result["handoffs"]["interactions_checked"] == 2
        assert result["handoffs"]["interactions_complete"] == 2
        assert result["handoffs"]["issues"] == []

    def test_chain_with_only_regular_events(self, tmp_path):
        """A chain with zero handoffs should report clean with 0 interactions checked."""
        chain = _chain(tmp_path)
        for i in range(20):
            chain.write(Event(type="llm_call", framework="openai", model="gpt-4o"))

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["handoffs"]["interactions_checked"] == 0
        assert result["handoffs"]["interactions_complete"] == 0
        assert result["handoffs"]["issues"] == []


# ═══════════════════════════════════════════════════════════════════
# FALSE NEGATIVE TESTS - broken chains MUST be caught
# ═══════════════════════════════════════════════════════════════════

class TestFalseNegatives:
    """Ensure broken chains are always detected."""

    def test_tampered_payload_hash_in_db(self, tmp_path, monkeypatch):
        """Modifying payload_hash in the database should break integrity."""
        a, b = _identity("tamper-a"), _identity("tamper-b")
        keys = _setup_keys(tmp_path, monkeypatch, a, b)
        chain = _chain(tmp_path)
        _write_handoff(chain, keys, a, b)

        # Tamper with the payload_hash in the stored JSON
        conn = sqlite3.connect(chain._db_path)
        row = conn.execute("SELECT id, data FROM events WHERE type='handoff_request'").fetchone()
        record = json.loads(row[1])
        record["payload_hash"] = "sha256:" + "0" * 64  # Changed!
        conn.execute("UPDATE events SET data=? WHERE id=?", (json.dumps(record), row[0]))
        conn.commit()
        conn.close()

        result = chain.verify()
        # HMAC chain should break because we modified the stored JSON
        assert result["integrity"]["valid"] is False

    def test_swapped_signatures_detected(self, tmp_path, monkeypatch):
        """Swapping signatures between two records should be caught."""
        a, b = _identity("swap-a"), _identity("swap-b")
        keys = _setup_keys(tmp_path, monkeypatch, a, b)
        chain = _chain(tmp_path)
        _write_handoff(chain, keys, a, b)

        # Swap signatures between request and ack in the data JSON
        conn = sqlite3.connect(chain._db_path)
        req = conn.execute("SELECT id, data FROM events WHERE type='handoff_request'").fetchone()
        ack = conn.execute("SELECT id, data FROM events WHERE type='handoff_ack'").fetchone()

        req_data = json.loads(req[1])
        ack_data = json.loads(ack[1])

        # Swap signatures
        req_sig = req_data.get("signature")
        ack_sig = ack_data.get("signature")
        req_data["signature"] = ack_sig
        ack_data["signature"] = req_sig

        conn.execute("UPDATE events SET data=? WHERE id=?", (json.dumps(req_data), req[0]))
        conn.execute("UPDATE events SET data=? WHERE id=?", (json.dumps(ack_data), ack[0]))
        conn.commit()
        conn.close()

        result = chain.verify()
        # HMAC chain should break from the data modification
        assert result["integrity"]["valid"] is False

    def test_deleted_ack_detected(self, tmp_path, monkeypatch):
        """Deleting the ack record should flag missing_ack."""
        a, b = _identity("del-a"), _identity("del-b")
        keys = _setup_keys(tmp_path, monkeypatch, a, b)
        chain = _chain(tmp_path)
        _write_handoff(chain, keys, a, b)

        # Delete the ack from the database
        conn = sqlite3.connect(chain._db_path)
        conn.execute("DELETE FROM events WHERE type='handoff_ack'")
        conn.commit()
        conn.close()

        result = chain.verify()
        # Integrity breaks because we deleted a record from the middle
        assert result["integrity"]["valid"] is False
        # Handoff should also flag the missing ack
        handoff_issues = [i for i in result["handoffs"]["issues"]
                          if i["issue"] in ("missing_ack", "missing_result")]
        assert len(handoff_issues) > 0


# ═══════════════════════════════════════════════════════════════════
# MIXED VERSION CHAIN TESTS
# ═══════════════════════════════════════════════════════════════════

class TestMixedVersionChains:
    """Test chains with v1.0, v1.1, and v1.2 records mixed together."""

    def test_v10_then_v12_handoff(self, tmp_path, monkeypatch):
        """Old v1.0 events followed by v1.2 handoff records."""
        a, b = _identity("mixed-a"), _identity("mixed-b")
        keys = _setup_keys(tmp_path, monkeypatch, a, b)
        chain = _chain(tmp_path)

        # v1.0 style events (no session_id, no handoff fields)
        for _ in range(5):
            chain.write(Event(type="llm_call", framework="openai"))

        # v1.2 handoff
        _write_handoff(chain, keys, a, b)

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["handoffs"]["interactions_complete"] == 1

    def test_v11_session_then_v12_handoff(self, tmp_path, monkeypatch):
        """v1.1 session records followed by v1.2 handoff records in another session."""
        a, b = _identity("v11v12-a"), _identity("v11v12-b")
        keys = _setup_keys(tmp_path, monkeypatch, a, b)
        chain = _chain(tmp_path)

        # v1.1 session
        sid1 = uuid.uuid4().hex
        chain.write(Event(type="session_start", framework="raw_python", session_id=sid1, status="running"))
        chain.write(Event(type="llm_call", framework="openai", session_id=sid1))
        chain.write(Event(type="session_end", framework="raw_python", session_id=sid1, status="success"))

        # v1.2 session with handoff
        sid2 = uuid.uuid4().hex
        iid = uuid.uuid4().hex
        task_hash = keys.compute_payload_hash("cross-version-task")

        chain.write(Event(type="session_start", framework="raw_python", session_id=sid2, status="running"))
        chain.write(Event(
            type="handoff_request", framework="raw_python", session_id=sid2,
            identity=a, interaction_id=iid,
            counterparty_id=b.fingerprint,
            payload_hash=task_hash, nonce=keys.generate_nonce(),
        ))
        chain.write(Event(
            type="handoff_ack", framework="raw_python", session_id=sid2,
            identity=b, interaction_id=iid,
            counterparty_id=a.fingerprint,
            payload_hash=task_hash, nonce=keys.generate_nonce(),
        ))
        chain.write(Event(
            type="handoff_result", framework="raw_python", session_id=sid2,
            identity=b, interaction_id=iid,
            counterparty_id=a.fingerprint,
            payload_hash=keys.compute_payload_hash("result"), nonce=keys.generate_nonce(),
        ))
        chain.write(Event(type="session_end", framework="raw_python", session_id=sid2, status="success"))

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["completeness"]["sessions_checked"] == 2
        assert result["completeness"]["sessions_complete"] == 2
        assert result["handoffs"]["interactions_complete"] == 1
        assert result["handoffs"]["issues"] == []

    def test_all_three_versions_in_one_chain(self, tmp_path, monkeypatch):
        """v1.0 + v1.1 + v1.2 records all in one chain."""
        a, b = _identity("allver-a"), _identity("allver-b")
        keys = _setup_keys(tmp_path, monkeypatch, a, b)
        chain = _chain(tmp_path)

        # v1.0: bare events
        chain.write(Event(type="llm_call", framework="openai"))

        # v1.1: session events
        sid = uuid.uuid4().hex
        chain.write(Event(type="session_start", framework="raw_python", session_id=sid, status="running"))
        chain.write(Event(type="llm_call", framework="openai", session_id=sid))
        chain.write(Event(type="session_end", framework="raw_python", session_id=sid, status="success"))

        # v1.2: handoff
        _write_handoff(chain, keys, a, b)

        # More v1.0
        chain.write(Event(type="tool_call", framework="langchain"))

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["completeness"]["sessions_complete"] == 1
        assert result["handoffs"]["interactions_complete"] == 1
        # No issues at all
        all_issues = (result["completeness"]["issues"] + result["handoffs"]["issues"])
        assert all_issues == []


# ═══════════════════════════════════════════════════════════════════
# STRESS TESTS - large chains, many handoffs
# ═══════════════════════════════════════════════════════════════════

class TestStress:
    """Performance and scale tests."""

    def test_fifty_handoffs(self, tmp_path, monkeypatch):
        """50 handoffs should all verify correctly."""
        a, b = _identity("stress-a"), _identity("stress-b")
        keys = _setup_keys(tmp_path, monkeypatch, a, b)
        chain = _chain(tmp_path)

        for _ in range(50):
            _write_handoff(chain, keys, a, b)

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["handoffs"]["interactions_checked"] == 50
        assert result["handoffs"]["interactions_complete"] == 50
        assert result["handoffs"]["issues"] == []

    def test_large_chain_with_mixed_content(self, tmp_path, monkeypatch):
        """200 events: 150 regular + 5 complete handoffs (15 handoff records)."""
        a, b = _identity("big-a"), _identity("big-b")
        keys = _setup_keys(tmp_path, monkeypatch, a, b)
        chain = _chain(tmp_path)

        for i in range(200):
            if i % 40 == 0 and i > 0:
                _write_handoff(chain, keys, a, b)
            else:
                chain.write(Event(type="llm_call", framework="openai"))

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["handoffs"]["interactions_complete"] == result["handoffs"]["interactions_checked"]
        assert result["handoffs"]["issues"] == []


# ═══════════════════════════════════════════════════════════════════
# EDGE CASE TESTS - weird but valid scenarios
# ═══════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Unusual but valid configurations."""

    def test_handoff_to_self(self, tmp_path, monkeypatch):
        """An agent handing off to itself (same fingerprint) should still verify."""
        a = _identity("self-agent")
        keys = _setup_keys(tmp_path, monkeypatch, a)
        chain = _chain(tmp_path)
        iid = uuid.uuid4().hex
        task_hash = keys.compute_payload_hash("self-task")

        chain.write(Event(
            type="handoff_request", framework="raw_python",
            identity=a, interaction_id=iid,
            counterparty_id=a.fingerprint,  # handoff to self
            payload_hash=task_hash, nonce=keys.generate_nonce(),
        ))
        chain.write(Event(
            type="handoff_ack", framework="raw_python",
            identity=a, interaction_id=iid,
            counterparty_id=a.fingerprint,
            payload_hash=task_hash, nonce=keys.generate_nonce(),
        ))
        chain.write(Event(
            type="handoff_result", framework="raw_python",
            identity=a, interaction_id=iid,
            counterparty_id=a.fingerprint,
            payload_hash=keys.compute_payload_hash("self-result"),
            nonce=keys.generate_nonce(),
        ))

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        # Self-handoff is structurally complete
        assert result["handoffs"]["interactions_checked"] == 1

    def test_empty_chain(self, tmp_path):
        """An empty chain should verify cleanly with zero everything."""
        chain = _chain(tmp_path)
        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["integrity"]["records"] == 0
        assert result["handoffs"]["interactions_checked"] == 0
        assert result["handoffs"]["issues"] == []

    def test_handoff_with_very_long_payload(self, tmp_path, monkeypatch):
        """Handoff with a very large payload hash (1MB payload) should work."""
        a, b = _identity("long-a"), _identity("long-b")
        keys = _setup_keys(tmp_path, monkeypatch, a, b)
        chain = _chain(tmp_path)

        # Simulate hashing a 1MB payload
        big_payload = "x" * (1024 * 1024)
        task_hash = keys.compute_payload_hash(big_payload)

        iid = uuid.uuid4().hex
        chain.write(Event(
            type="handoff_request", framework="raw_python",
            identity=a, interaction_id=iid,
            counterparty_id=b.fingerprint,
            payload_hash=task_hash, nonce=keys.generate_nonce(),
        ))
        chain.write(Event(
            type="handoff_ack", framework="raw_python",
            identity=b, interaction_id=iid,
            counterparty_id=a.fingerprint,
            payload_hash=task_hash, nonce=keys.generate_nonce(),
        ))
        chain.write(Event(
            type="handoff_result", framework="raw_python",
            identity=b, interaction_id=iid,
            counterparty_id=a.fingerprint,
            payload_hash=keys.compute_payload_hash("result"), nonce=keys.generate_nonce(),
        ))

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["handoffs"]["interactions_complete"] == 1

    def test_handoff_without_identity_no_auto_sign(self, tmp_path):
        """Handoff records without identity should NOT be auto-signed but still write."""
        chain = _chain(tmp_path)
        event = Event(
            type="handoff_request", framework="raw_python",
            interaction_id=uuid.uuid4().hex,
            counterparty_id="some-fp",
            payload_hash="sha256:" + "a" * 64,
            nonce=os.urandom(16).hex(),
            # No identity = no auto-signing
        )
        chain.write(event)
        assert event.signature is None  # Not signed
        assert chain.record_count == 1  # But still written

    def test_result_payload_hash_differs_from_request(self, tmp_path, monkeypatch):
        """result.payload_hash SHOULD differ from request.payload_hash (it's the result, not the task)."""
        a, b = _identity("diff-hash-a"), _identity("diff-hash-b")
        keys = _setup_keys(tmp_path, monkeypatch, a, b)
        chain = _chain(tmp_path)
        iid = uuid.uuid4().hex
        task_hash = keys.compute_payload_hash("the task")
        result_hash = keys.compute_payload_hash("the result")  # Different!

        chain.write(Event(
            type="handoff_request", framework="raw_python",
            identity=a, interaction_id=iid,
            counterparty_id=b.fingerprint,
            payload_hash=task_hash, nonce=keys.generate_nonce(),
        ))
        chain.write(Event(
            type="handoff_ack", framework="raw_python",
            identity=b, interaction_id=iid,
            counterparty_id=a.fingerprint,
            payload_hash=task_hash, nonce=keys.generate_nonce(),
        ))
        chain.write(Event(
            type="handoff_result", framework="raw_python",
            identity=b, interaction_id=iid,
            counterparty_id=a.fingerprint,
            payload_hash=result_hash, nonce=keys.generate_nonce(),
        ))

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        # Should NOT flag payload_mismatch - result hash is allowed to differ
        payload_issues = [i for i in result["handoffs"]["issues"] if i["issue"] == "payload_mismatch"]
        assert len(payload_issues) == 0
        assert result["handoffs"]["interactions_complete"] == 1
