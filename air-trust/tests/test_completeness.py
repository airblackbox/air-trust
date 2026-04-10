"""Tests for v1.1 session completeness: sequence numbers, gap detection, lifecycle validation."""

import json
import os
import sqlite3
import pytest
from air_trust.chain import AuditChain, _active_session_id
from air_trust.events import Event
from air_trust.core import AirTrustSession


@pytest.fixture
def chain(tmp_path):
    """Create a fresh AuditChain in a temp directory."""
    db_path = os.path.join(str(tmp_path), "events.db")
    return AuditChain(db_path=db_path, signing_key="test-key-completeness")


# ── Session Sequence Assignment ─────────────────────────────────


class TestSessionSequenceAssignment:
    """Events within a session get auto-assigned session_seq and prev_session_seq."""

    def test_session_start_gets_seq_zero(self, chain):
        """The first event in a session should get session_seq=0, prev_session_seq=-1."""
        event = Event(
            type="session_start",
            framework="air_trust",
            session_id="test-session-001",
        )
        chain.write(event)
        assert event.session_seq == 0
        assert event.prev_session_seq == -1

    def test_second_event_gets_seq_one(self, chain):
        """The second event in a session should get session_seq=1, prev_session_seq=0."""
        e1 = Event(type="session_start", framework="air_trust", session_id="sess-a")
        e2 = Event(type="llm_call", framework="openai", session_id="sess-a")
        chain.write(e1)
        chain.write(e2)
        assert e2.session_seq == 1
        assert e2.prev_session_seq == 0

    def test_monotonic_sequence(self, chain):
        """All events in a session should have strictly monotonic sequences."""
        sid = "sess-monotonic"
        events = []
        for i in range(10):
            e = Event(
                type="llm_call" if i > 0 else "session_start",
                framework="air_trust",
                session_id=sid,
            )
            chain.write(e)
            events.append(e)

        for i, e in enumerate(events):
            assert e.session_seq == i
            assert e.prev_session_seq == (i - 1)

    def test_no_session_id_means_no_seq(self, chain):
        """Events without session_id should NOT get sequence numbers."""
        event = Event(type="llm_call", framework="openai")
        chain.write(event)
        assert event.session_seq is None
        assert event.prev_session_seq is None

    def test_different_sessions_have_independent_counters(self, chain):
        """Two sessions should have independent sequence counters."""
        e1 = Event(type="session_start", framework="air_trust", session_id="sess-a")
        e2 = Event(type="session_start", framework="air_trust", session_id="sess-b")
        e3 = Event(type="llm_call", framework="openai", session_id="sess-a")
        e4 = Event(type="llm_call", framework="openai", session_id="sess-b")

        chain.write(e1)
        chain.write(e2)
        chain.write(e3)
        chain.write(e4)

        # sess-a: 0, 1
        assert e1.session_seq == 0
        assert e3.session_seq == 1

        # sess-b: 0, 1 (independent)
        assert e2.session_seq == 0
        assert e4.session_seq == 1

    def test_sequence_included_in_hmac(self, chain):
        """Sequence numbers should be tamper-evident (included in HMAC payload)."""
        e1 = Event(type="session_start", framework="air_trust", session_id="sess-hmac")
        e2 = Event(type="llm_call", framework="openai", session_id="sess-hmac")
        chain.write(e1)
        chain.write(e2)

        # Verify chain is valid
        result = chain.verify()
        assert result["integrity"]["valid"] is True

        # Tamper: change session_seq in the DB
        import json
        conn = sqlite3.connect(chain._db_path)
        row = conn.execute("SELECT data FROM events WHERE id = 2").fetchone()
        record = json.loads(row[0])
        record["session_seq"] = 999
        conn.execute(
            "UPDATE events SET data = ? WHERE id = 2",
            (json.dumps(record),),
        )
        conn.commit()
        conn.close()

        # Re-verify: should fail integrity
        chain2 = AuditChain(db_path=chain._db_path, signing_key="test-key-completeness")
        result2 = chain2.verify()
        assert result2["integrity"]["valid"] is False


# ── Completeness Verification ─────────────────────────────────


class TestCompletenessVerification:
    """The verifier should detect gaps, duplicates, rewinds, and lifecycle issues."""

    def _write_session(self, chain, session_id, count=5, include_start=True, include_end=True):
        """Helper: write a complete session with N events."""
        events = []
        for i in range(count):
            if i == 0 and include_start:
                etype = "session_start"
            elif i == count - 1 and include_end:
                etype = "session_end"
            else:
                etype = "llm_call"
            e = Event(type=etype, framework="air_trust", session_id=session_id)
            chain.write(e)
            events.append(e)
        return events

    def test_clean_session_passes(self, chain):
        """A complete session with no gaps should pass completeness."""
        self._write_session(chain, "clean-session")
        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["completeness"]["sessions_checked"] == 1
        assert result["completeness"]["sessions_complete"] == 1
        assert len(result["completeness"]["issues"]) == 0

    def test_multiple_clean_sessions(self, chain):
        """Multiple complete sessions should all pass."""
        self._write_session(chain, "sess-1", count=3)
        self._write_session(chain, "sess-2", count=5)
        self._write_session(chain, "sess-3", count=2)
        result = chain.verify()
        assert result["completeness"]["sessions_checked"] == 3
        assert result["completeness"]["sessions_complete"] == 3
        assert len(result["completeness"]["issues"]) == 0

    def test_gap_detection(self, tmp_path):
        """Deleting a record should produce a detectable gap."""
        db_path = os.path.join(str(tmp_path), "gap.db")
        chain = AuditChain(db_path=db_path, signing_key="test-key-completeness")

        # Write 5 events
        for i in range(5):
            chain.write(Event(
                type="session_start" if i == 0 else "llm_call",
                framework="air_trust",
                session_id="gap-session",
            ))

        # Delete the middle record (id=3, session_seq=2)
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM events WHERE id = 3")
        conn.commit()
        conn.close()

        # Re-verify
        chain2 = AuditChain(db_path=db_path, signing_key="test-key-completeness")
        result = chain2.verify()

        # Integrity will also fail because the chain is broken, but check completeness too
        completeness = result["completeness"]
        gap_issues = [i for i in completeness["issues"] if i["issue"] == "gap"]
        assert len(gap_issues) > 0

    def test_missing_session_end(self, chain):
        """A session without session_end should be flagged as incomplete."""
        self._write_session(chain, "no-end", count=5, include_end=False)
        result = chain.verify()
        assert result["integrity"]["valid"] is True  # HMAC chain is fine
        completeness = result["completeness"]
        incomplete_issues = [i for i in completeness["issues"] if i["issue"] == "missing_session_end"]
        assert len(incomplete_issues) == 1
        assert incomplete_issues[0]["session_id"] == "no-end"

    def test_missing_session_start(self, chain):
        """A session without session_start should be flagged."""
        self._write_session(chain, "no-start", count=5, include_start=False)
        result = chain.verify()
        completeness = result["completeness"]
        start_issues = [i for i in completeness["issues"] if i["issue"] == "missing_session_start"]
        assert len(start_issues) == 1
        assert start_issues[0]["session_id"] == "no-start"

    def test_unscoped_events_ignored(self, chain):
        """Events without session_id should be ignored by completeness checker."""
        chain.write(Event(type="llm_call", framework="openai"))
        chain.write(Event(type="tool_call", framework="openai"))
        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["completeness"]["sessions_checked"] == 0
        assert len(result["completeness"]["issues"]) == 0

    def test_mixed_scoped_and_unscoped(self, chain):
        """Unscoped events interleaved with session events should not affect completeness."""
        chain.write(Event(type="llm_call", framework="openai"))  # unscoped
        self._write_session(chain, "mixed-session", count=3)
        chain.write(Event(type="llm_call", framework="openai"))  # unscoped

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["completeness"]["sessions_checked"] == 1
        assert result["completeness"]["sessions_complete"] == 1


# ── AirTrustSession Integration ─────────────────────────────────


class TestSessionContextManager:
    """AirTrustSession should auto-assign session_id and sequence numbers."""

    def test_session_assigns_session_id(self, chain):
        """All events in a session block should share the same session_id."""
        sess = AirTrustSession("test-session", chain)
        with sess:
            pass

        # Read back from DB
        conn = sqlite3.connect(chain._db_path)
        rows = conn.execute("SELECT data FROM events ORDER BY id ASC").fetchall()
        conn.close()

        import json
        records = [json.loads(r[0]) for r in rows]
        assert len(records) == 2  # start + end

        # Both should have the same session_id
        sid = records[0]["session_id"]
        assert sid is not None
        assert records[1]["session_id"] == sid

    def test_session_events_have_sequences(self, chain):
        """Events in a session should have session_seq assigned."""
        sess = AirTrustSession("seq-test", chain)
        with sess:
            sess.log("Checkpoint A")
            sess.log("Checkpoint B")

        # 4 events: start, checkpoint, checkpoint, end
        conn = sqlite3.connect(chain._db_path)
        rows = conn.execute("SELECT data FROM events ORDER BY id ASC").fetchall()
        conn.close()

        import json
        records = [json.loads(r[0]) for r in rows]
        assert len(records) == 4

        for i, rec in enumerate(records):
            assert rec["session_seq"] == i
            assert rec["prev_session_seq"] == i - 1

    def test_session_start_and_end_types(self, chain):
        """Session should emit session_start as first and session_end as last."""
        sess = AirTrustSession("lifecycle-test", chain)
        with sess:
            sess.log("middle")

        conn = sqlite3.connect(chain._db_path)
        rows = conn.execute("SELECT data FROM events ORDER BY id ASC").fetchall()
        conn.close()

        import json
        records = [json.loads(r[0]) for r in rows]
        assert records[0]["type"] == "session_start"
        assert records[0]["session_seq"] == 0
        assert records[-1]["type"] == "session_end"

    def test_full_session_passes_completeness(self, chain):
        """A full session with context manager should pass completeness verification."""
        sess = AirTrustSession("complete-test", chain)
        with sess:
            sess.log("Step 1")
            sess.log("Step 2")

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["completeness"]["sessions_checked"] == 1
        assert result["completeness"]["sessions_complete"] == 1
        assert len(result["completeness"]["issues"]) == 0


# ── Backward Compatibility ─────────────────────────────────


class TestBackwardCompatibility:
    """v1.0 records (without session_seq) should still verify correctly."""

    def test_v10_records_verify_integrity(self, chain):
        """Records without session_seq should pass integrity verification."""
        # Write events without session_id (v1.0 style)
        for i in range(5):
            chain.write(Event(type="llm_call", framework="openai", description=f"v1.0 event {i}"))

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["completeness"]["sessions_checked"] == 0

    def test_mixed_v10_and_v11(self, chain):
        """Chain with both v1.0 and v1.1 records should verify correctly."""
        # v1.0 style (no session)
        chain.write(Event(type="llm_call", framework="openai"))

        # v1.1 style (with session)
        sess = AirTrustSession("v11-session", chain)
        with sess:
            sess.log("v1.1 checkpoint")

        # More v1.0 style
        chain.write(Event(type="llm_call", framework="openai"))

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["completeness"]["sessions_checked"] == 1
        assert result["completeness"]["sessions_complete"] == 1


# ── Verify Output Format ─────────────────────────────────


class TestVerifyOutputFormat:
    """The verify() output should match the SPEC.md v1.1 format."""

    def test_verify_returns_integrity_and_completeness(self, chain):
        """verify() should return both integrity and completeness sections."""
        result = chain.verify()
        assert "integrity" in result
        assert "completeness" in result

    def test_integrity_section_shape(self, chain):
        """Integrity section should have valid, records, broken_at."""
        chain.write(Event(type="llm_call", framework="openai"))
        result = chain.verify()
        integrity = result["integrity"]
        assert "valid" in integrity
        assert "records" in integrity
        assert "broken_at" in integrity
        assert isinstance(integrity["valid"], bool)
        assert isinstance(integrity["records"], int)

    def test_completeness_section_shape(self, chain):
        """Completeness section should have sessions_checked, sessions_complete, issues."""
        sess = AirTrustSession("shape-test", chain)
        with sess:
            pass

        result = chain.verify()
        completeness = result["completeness"]
        assert "sessions_checked" in completeness
        assert "sessions_complete" in completeness
        assert "sessions_incomplete" in completeness
        assert "issues" in completeness
        assert isinstance(completeness["issues"], list)

    def test_backward_compat_top_level_keys(self, chain):
        """verify() should still have top-level 'valid', 'records', 'broken_at' for v1.0 compat."""
        chain.write(Event(type="llm_call", framework="openai"))
        result = chain.verify()
        assert "valid" in result
        assert "records" in result
        assert "broken_at" in result
        assert result["valid"] == result["integrity"]["valid"]


# ── Session ID Propagation (ContextVar) ─────────────────────


class TestSessionIdPropagation:
    """Adapter events written inside a session block should inherit the session_id."""

    def test_direct_chain_write_inherits_session_id(self, chain):
        """Events written directly to chain inside a session should get session_id."""
        sess = AirTrustSession("propagation-test", chain)
        with sess:
            # Simulate what an adapter does: write an Event without session_id
            adapter_event = Event(type="llm_call", framework="openai", model="gpt-4o")
            chain.write(adapter_event)

        # The adapter event should have inherited the session_id
        assert adapter_event.session_id == sess.session_id
        assert adapter_event.session_seq is not None

        # Verify: 3 events (start, llm_call, end), all with same session_id
        conn = sqlite3.connect(chain._db_path)
        rows = conn.execute("SELECT data FROM events ORDER BY id ASC").fetchall()
        conn.close()
        records = [json.loads(r[0]) for r in rows]
        assert len(records) == 3
        for rec in records:
            assert rec["session_id"] == sess.session_id

    def test_events_outside_session_have_no_session_id(self, chain):
        """Events written outside a session block should NOT get a session_id."""
        sess = AirTrustSession("outside-test", chain)
        with sess:
            pass

        # Write an event after the session exits
        outside_event = Event(type="llm_call", framework="openai")
        chain.write(outside_event)
        assert outside_event.session_id is None
        assert outside_event.session_seq is None

    def test_propagated_events_have_correct_sequences(self, chain):
        """Propagated adapter events should get correct sequence numbers."""
        sess = AirTrustSession("seq-propagation", chain)
        with sess:
            # 3 adapter events inside the session
            for i in range(3):
                chain.write(Event(type="llm_call", framework="openai"))

        # Should be: session_start(0), llm(1), llm(2), llm(3), session_end(4)
        conn = sqlite3.connect(chain._db_path)
        rows = conn.execute("SELECT data FROM events ORDER BY id ASC").fetchall()
        conn.close()
        records = [json.loads(r[0]) for r in rows]
        assert len(records) == 5
        for i, rec in enumerate(records):
            assert rec["session_seq"] == i
            assert rec["prev_session_seq"] == i - 1

    def test_nested_sessions_use_outer_session_id(self, chain):
        """If session_id is already set on an event, it should NOT be overridden."""
        sess = AirTrustSession("outer", chain)
        with sess:
            # Event with explicit session_id should keep its own
            explicit_event = Event(
                type="llm_call", framework="openai", session_id="my-custom-sid"
            )
            chain.write(explicit_event)
            assert explicit_event.session_id == "my-custom-sid"

    def test_contextvar_cleared_after_exit(self, chain):
        """_active_session_id should be None after session exits."""
        sess = AirTrustSession("clear-test", chain)
        with sess:
            assert _active_session_id.get() == sess.session_id
        assert _active_session_id.get() is None

    def test_completeness_passes_with_propagated_events(self, chain):
        """Completeness check should pass when adapter events are propagated."""
        sess = AirTrustSession("completeness-propagated", chain)
        with sess:
            chain.write(Event(type="llm_call", framework="openai"))
            sess.log("Manual checkpoint")
            chain.write(Event(type="tool_call", framework="openai", tool_name="search"))

        result = chain.verify()
        assert result["integrity"]["valid"] is True
        assert result["completeness"]["sessions_checked"] == 1
        assert result["completeness"]["sessions_complete"] == 1
        assert len(result["completeness"]["issues"]) == 0


# ── CLI Verify Output ─────────────────────────────────


class TestCLIVerify:
    """Test the CLI verify command output."""

    def test_cli_verify_json_clean_chain(self, chain, capsys):
        """CLI verify --json should output valid JSON for clean chain."""
        from air_trust.__main__ import cmd_verify

        sess = AirTrustSession("cli-test", chain)
        with sess:
            sess.log("test")

        # Simulate CLI args (must pass same signing key)
        class Args:
            db = chain._db_path
            json_output = True
            key = "test-key-completeness"

        exit_code = cmd_verify(Args())
        assert exit_code == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["integrity"]["valid"] is True
        assert data["completeness"]["sessions_checked"] == 1

    def test_cli_verify_human_clean_chain(self, chain, capsys):
        """CLI verify (human mode) should show PASS for clean chain."""
        from air_trust.__main__ import cmd_verify

        sess = AirTrustSession("cli-human", chain)
        with sess:
            pass

        class Args:
            db = chain._db_path
            json_output = False
            key = "test-key-completeness"

        exit_code = cmd_verify(Args())
        assert exit_code == 0

        captured = capsys.readouterr()
        assert "PASS" in captured.out
        assert "Integrity" in captured.out
