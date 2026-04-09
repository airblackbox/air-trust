"""Tests for the canonical Event dataclass."""

import pytest
from air_trust.events import Event, PIIAlert, InjectionAlert


class TestEvent:
    """Test Event creation and serialization."""

    def test_minimal_event(self):
        """Event with type and framework should work."""
        e = Event(type="llm_call", framework="openai")
        assert e.type == "llm_call"
        assert e.framework == "openai"
        assert e.status == "success"
        assert e.version == "1.0.0"
        assert e.timestamp is not None

    def test_full_event(self):
        """Event with all fields populated."""
        e = Event(
            type="llm_call",
            framework="openai",
            model="gpt-4o",
            provider="openai",
            tokens={"prompt": 100, "completion": 50, "total": 150},
            cost=0.0023,
            duration_ms=1200,
            tool_name="chat.completions.create",
            risk_level="low",
            input_preview="Hello world",
            output_preview="Hi there",
            description="Test call",
            status="success",
        )
        assert e.model == "gpt-4o"
        assert e.tokens["total"] == 150
        assert e.cost == 0.0023
        assert e.duration_ms == 1200

    def test_to_dict_drops_none(self):
        """to_dict() should exclude None values for clean chain signing."""
        e = Event(type="llm_call", framework="openai")
        d = e.to_dict()
        assert "model" not in d  # None values dropped
        assert "type" in d
        assert "timestamp" in d
        assert d["type"] == "llm_call"

    def test_to_dict_includes_set_values(self):
        """to_dict() should include all explicitly set values."""
        e = Event(type="tool_call", framework="langchain", model="gpt-4o")
        d = e.to_dict()
        assert d["type"] == "tool_call"
        assert d["framework"] == "langchain"
        assert d["model"] == "gpt-4o"

    def test_unique_run_ids(self):
        """Each event should get a unique run_id."""
        e1 = Event(type="llm_call", framework="openai")
        e2 = Event(type="llm_call", framework="openai")
        assert e1.run_id != e2.run_id

    def test_pii_alert_dataclass(self):
        """PIIAlert should hold type and count."""
        alert = PIIAlert(type="email", count=2)
        assert alert.type == "email"
        assert alert.count == 2

    def test_injection_alert_dataclass(self):
        """InjectionAlert should hold pattern and weight."""
        alert = InjectionAlert(
            pattern="ignore previous", weight=0.95
        )
        assert alert.weight == 0.95

    def test_event_with_alerts(self):
        """Event should accept PII and injection alerts."""
        pii = [PIIAlert(type="email", count=1)]
        inj = [InjectionAlert(pattern="ignore", weight=0.9)]
        e = Event(
            type="llm_call",
            framework="openai",
            pii_alerts=pii,
            injection_alerts=inj,
            injection_score=0.9,
        )
        assert len(e.pii_alerts) == 1
        assert e.injection_score == 0.9

    def test_event_error_state(self):
        """Event should store error information."""
        e = Event(type="llm_call", framework="openai", status="error", error="Rate limit exceeded")
        assert e.status == "error"
        assert e.error == "Rate limit exceeded"

    def test_event_meta_dict(self):
        """Event should accept arbitrary metadata."""
        e = Event(type="llm_call", framework="openai", meta={"custom_key": "custom_value", "count": 42})
        assert e.meta["custom_key"] == "custom_value"
        assert e.meta["count"] == 42
