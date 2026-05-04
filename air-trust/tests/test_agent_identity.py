"""Tests for air_trust.agent_identity - continuity + ghost detection."""

import json
import os
import sqlite3
import pytest

from air_trust.agent_identity import verify_identity, format_report
from air_trust.chain import AuditChain
from air_trust.events import AgentIdentity, Event


@pytest.fixture
def signing_env(monkeypatch):
    monkeypatch.setenv("AIR_TRUST_KEY", "test-identity-key")


def _make_chain(tmp_path, identity: AgentIdentity, n_events: int = 3):
    db_path = str(tmp_path / "events.db")
    chain = AuditChain(db_path=db_path, signing_key="test-identity-key")
    for i in range(n_events):
        event = Event(
            type="llm_call",
            framework="openai",
            model="gpt-4o",
            identity=identity,
            description=f"event-{i}",
        )
        chain.write(event)
    return db_path


class TestVerifyIdentity:
    def test_missing_db_returns_warn(self, tmp_path, signing_env):
        report = verify_identity(db_path=str(tmp_path / "nope.db"))
        assert report.verdict == "warn"
        assert report.total_records == 0

    def test_stable_single_agent_passes(self, tmp_path, signing_env):
        identity = AgentIdentity(
            agent_name="botbotfromuk",
            owner="jason@airblackbox.ai",
            agent_version="1.0.0",
        )
        db_path = _make_chain(tmp_path, identity, n_events=5)
        report = verify_identity(db_path=db_path, agent_name="botbotfromuk")
        assert report.verdict == "pass"
        assert report.agent_records == 5
        assert report.distinct_fingerprints == 1

    def test_ghost_agent_detected(self, tmp_path, signing_env):
        # Two identities with same name but different versions -> different fingerprints
        id1 = AgentIdentity(
            agent_name="ghost", owner="a@b.co", agent_version="1.0.0"
        )
        id2 = AgentIdentity(
            agent_name="ghost", owner="a@b.co", agent_version="2.0.0"
        )
        db_path = str(tmp_path / "events.db")
        chain = AuditChain(db_path=db_path, signing_key="test-identity-key")
        for i in range(3):
            chain.write(Event(type="llm_call", framework="openai", model="gpt-4o",
                              identity=id1, description=f"e{i}"))
        for i in range(3):
            chain.write(Event(type="llm_call", framework="openai", model="gpt-4o",
                              identity=id2, description=f"e{i + 3}"))

        report = verify_identity(db_path=db_path, agent_name="ghost")
        assert report.ghost_risk is True
        assert report.verdict == "fail"
        assert report.distinct_fingerprints == 2

    def test_no_matching_agent_warns(self, tmp_path, signing_env):
        identity = AgentIdentity(
            agent_name="alpha", owner="a@b.co", agent_version="1.0.0"
        )
        db_path = _make_chain(tmp_path, identity, n_events=2)
        report = verify_identity(db_path=db_path, agent_name="does-not-exist")
        assert report.verdict == "warn"
        assert report.agent_records == 0

    def test_report_json_serializable(self, tmp_path, signing_env):
        identity = AgentIdentity(
            agent_name="alpha", owner="a@b.co", agent_version="1.0.0"
        )
        db_path = _make_chain(tmp_path, identity, n_events=2)
        report = verify_identity(db_path=db_path, agent_name="alpha")
        # to_dict() must be serializable (default=str handles any stragglers)
        blob = json.dumps(report.to_dict(), default=str)
        assert "alpha" in blob

    def test_format_report_is_string(self, tmp_path, signing_env):
        identity = AgentIdentity(
            agent_name="alpha", owner="a@b.co", agent_version="1.0.0"
        )
        db_path = _make_chain(tmp_path, identity, n_events=2)
        report = verify_identity(db_path=db_path, agent_name="alpha")
        rendered = format_report(report)
        assert isinstance(rendered, str)
        assert "Agent Identity Continuity Report" in rendered
