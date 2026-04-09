"""Tests for the HMAC-SHA256 audit chain."""

import os
import shutil
import sqlite3
import pytest
from air_trust.chain import AuditChain
from air_trust.events import Event


@pytest.fixture
def temp_dir(tmp_path):
    """Use pytest's built-in tmp_path which handles cleanup."""
    return str(tmp_path)


@pytest.fixture
def chain(temp_dir):
    """Create a fresh AuditChain in a temp directory."""
    db_path = os.path.join(temp_dir, "events.db")
    return AuditChain(db_path=db_path, signing_key="test-key-for-unit-tests")


class TestAuditChain:
    """Test HMAC-SHA256 audit chain integrity."""

    def test_create_chain(self, chain):
        """Chain should initialize with zero records."""
        result = chain.verify()
        assert result["valid"] is True
        assert result["records"] == 0

    def test_write_single_event(self, chain):
        """Writing one event should produce a valid chain."""
        event = Event(type="llm_call", framework="openai", model="gpt-4o")
        chain.write(event)

        result = chain.verify()
        assert result["valid"] is True
        assert result["records"] == 1

    def test_write_multiple_events(self, chain):
        """Multiple events should produce a valid chain."""
        for i in range(10):
            event = Event(
                type="llm_call",
                framework="openai",
                model="gpt-4o",
                description=f"Event {i}",
            )
            chain.write(event)

        result = chain.verify()
        assert result["valid"] is True
        assert result["records"] == 10

    def test_chain_hashes_are_linked(self, chain):
        """Each record's hash depends on the previous record."""
        e1 = Event(type="llm_call", framework="openai", description="first")
        e2 = Event(type="llm_call", framework="openai", description="second")
        chain.write(e1)
        chain.write(e2)

        result = chain.verify()
        assert result["valid"] is True

    def test_tamper_detection(self, temp_dir):
        """Modifying a record should break verification."""
        db_path = os.path.join(temp_dir, "tamper_test.db")
        chain = AuditChain(db_path=db_path, signing_key="tamper-test-key")

        for i in range(5):
            chain.write(Event(type="llm_call", framework="openai", description=f"Event {i}"))

        # Verify it's valid first
        assert chain.verify()["valid"] is True

        # Tamper: modify a record directly in SQLite
        conn = sqlite3.connect(db_path)
        conn.execute(
            "UPDATE events SET data = REPLACE(data, 'Event 2', 'TAMPERED') WHERE rowid = 3"
        )
        conn.commit()
        conn.close()

        # Create a new chain instance that re-reads from DB
        chain2 = AuditChain(db_path=db_path, signing_key="tamper-test-key")
        result = chain2.verify()
        assert result["valid"] is False
        assert result["broken_at"] is not None

    def test_key_consistency(self, temp_dir):
        """Same key should verify the same chain."""
        db_path = os.path.join(temp_dir, "key_test.db")
        key = "persistent-key"

        chain1 = AuditChain(db_path=db_path, signing_key=key)
        chain1.write(Event(type="llm_call", framework="openai", description="test"))

        # New instance with same key should verify
        chain2 = AuditChain(db_path=db_path, signing_key=key)
        result = chain2.verify()
        assert result["valid"] is True
        assert result["records"] == 1

    def test_wrong_key_fails(self, temp_dir):
        """Different key should fail to verify."""
        db_path = os.path.join(temp_dir, "wrong_key.db")

        chain1 = AuditChain(db_path=db_path, signing_key="key-one")
        chain1.write(Event(type="llm_call", framework="openai", description="test"))

        chain2 = AuditChain(db_path=db_path, signing_key="key-two")
        result = chain2.verify()
        assert result["valid"] is False

    def test_event_gets_chain_hash(self, chain):
        """Written event should have chain_hash set."""
        event = Event(type="llm_call", framework="openai")
        chain.write(event)
        assert event.chain_hash is not None
        assert len(event.chain_hash) == 64  # SHA-256 hex digest

    def test_concurrent_writes(self, temp_dir):
        """Thread safety: concurrent writes should not corrupt the chain."""
        import threading

        db_path = os.path.join(temp_dir, "concurrent.db")
        chain = AuditChain(db_path=db_path, signing_key="concurrent-key")
        errors = []

        def write_events(start):
            try:
                for i in range(20):
                    chain.write(Event(type="llm_call", framework="openai", description=f"Thread {start} Event {i}"))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=write_events, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        result = chain.verify()
        assert result["valid"] is True
        assert result["records"] == 100  # 5 threads x 20 events

    def test_empty_chain_verify(self, chain):
        """Empty chain should verify as valid."""
        result = chain.verify()
        assert result["valid"] is True
        assert result["records"] == 0
        assert result["broken_at"] is None

    def test_count_increments(self, chain):
        """Internal count should track events written."""
        assert chain._count == 0
        chain.write(Event(type="llm_call", framework="openai"))
        assert chain._count == 1
        chain.write(Event(type="tool_call", framework="openai"))
        assert chain._count == 2
