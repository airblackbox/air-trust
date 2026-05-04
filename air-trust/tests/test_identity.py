"""Tests for AgentIdentity - Article 14 agent-to-user identity binding."""
import pytest
import hashlib
from air_trust.events import AgentIdentity, Event


class TestAgentIdentityCreation:
    """Test creating and configuring agent identities."""

    def test_basic_creation(self):
        identity = AgentIdentity(
            agent_name="search-agent",
            owner="jason@airblackbox.ai",
        )
        assert identity.agent_name == "search-agent"
        assert identity.owner == "jason@airblackbox.ai"
        assert identity.agent_version == "0.0.0"
        assert identity.permissions == []
        assert identity.denied == []
        assert len(identity.agent_id) == 12
        assert len(identity.fingerprint) == 16

    def test_full_creation(self):
        identity = AgentIdentity(
            agent_name="customer-search",
            owner="jason@airblackbox.ai",
            agent_version="1.2.0",
            permissions=["database:read", "email:send"],
            denied=["database:delete", "admin:access"],
            description="Handles customer search queries",
            org="AIR Blackbox",
        )
        assert identity.agent_version == "1.2.0"
        assert len(identity.permissions) == 2
        assert len(identity.denied) == 2
        assert identity.description == "Handles customer search queries"
        assert identity.org == "AIR Blackbox"

    def test_fingerprint_deterministic(self):
        """Same name+owner+version always produces the same fingerprint."""
        id1 = AgentIdentity(agent_name="agent-a", owner="user@test.com", agent_version="1.0.0")
        id2 = AgentIdentity(agent_name="agent-a", owner="user@test.com", agent_version="1.0.0")
        assert id1.fingerprint == id2.fingerprint

    def test_fingerprint_changes_with_version(self):
        """Different version = different fingerprint."""
        id1 = AgentIdentity(agent_name="agent-a", owner="user@test.com", agent_version="1.0.0")
        id2 = AgentIdentity(agent_name="agent-a", owner="user@test.com", agent_version="2.0.0")
        assert id1.fingerprint != id2.fingerprint

    def test_fingerprint_changes_with_owner(self):
        """Different owner = different fingerprint."""
        id1 = AgentIdentity(agent_name="agent-a", owner="alice@test.com")
        id2 = AgentIdentity(agent_name="agent-a", owner="bob@test.com")
        assert id1.fingerprint != id2.fingerprint

    def test_fingerprint_is_sha256_prefix(self):
        """Fingerprint is first 16 chars of sha256(name:owner:version)."""
        identity = AgentIdentity(agent_name="test", owner="owner@test.com", agent_version="1.0.0")
        raw = "test:owner@test.com:1.0.0"
        expected = hashlib.sha256(raw.encode()).hexdigest()[:16]
        assert identity.fingerprint == expected

    def test_unique_agent_ids(self):
        """Each identity gets a unique agent_id."""
        id1 = AgentIdentity(agent_name="agent-a", owner="user@test.com")
        id2 = AgentIdentity(agent_name="agent-a", owner="user@test.com")
        assert id1.agent_id != id2.agent_id


class TestAgentIdentityPermissions:
    """Test the permission checking system."""

    def test_allows_when_no_restrictions(self):
        """Empty permissions list = allow everything."""
        identity = AgentIdentity(agent_name="agent", owner="owner")
        assert identity.allows("database:read") is True
        assert identity.allows("anything") is True

    def test_allows_permitted_action(self):
        identity = AgentIdentity(
            agent_name="agent", owner="owner",
            permissions=["database:read", "email:send"],
        )
        assert identity.allows("database:read") is True
        assert identity.allows("email:send") is True

    def test_denies_unpermitted_action(self):
        identity = AgentIdentity(
            agent_name="agent", owner="owner",
            permissions=["database:read"],
        )
        assert identity.allows("database:write") is False
        assert identity.allows("admin:access") is False

    def test_denied_overrides_permissions(self):
        """Denied list takes priority over permissions."""
        identity = AgentIdentity(
            agent_name="agent", owner="owner",
            permissions=["database:read", "database:write"],
            denied=["database:write"],
        )
        assert identity.allows("database:read") is True
        assert identity.allows("database:write") is False

    def test_denied_with_no_permissions(self):
        """Denied list works even without explicit permissions."""
        identity = AgentIdentity(
            agent_name="agent", owner="owner",
            denied=["admin:access"],
        )
        assert identity.allows("database:read") is True
        assert identity.allows("admin:access") is False


class TestAgentIdentitySerialization:
    """Test to_dict serialization."""

    def test_to_dict_minimal(self):
        identity = AgentIdentity(agent_name="agent-a", owner="owner@test.com")
        d = identity.to_dict()
        assert d["agent_name"] == "agent-a"
        assert d["owner"] == "owner@test.com"
        assert d["fingerprint"] == identity.fingerprint
        assert d["agent_id"] == identity.agent_id
        assert "permissions" not in d  # empty list excluded
        assert "denied" not in d

    def test_to_dict_full(self):
        identity = AgentIdentity(
            agent_name="agent-a", owner="owner@test.com",
            permissions=["read"], denied=["delete"],
            description="Test agent", org="TestCo",
        )
        d = identity.to_dict()
        assert d["permissions"] == ["read"]
        assert d["denied"] == ["delete"]
        assert d["description"] == "Test agent"
        assert d["org"] == "TestCo"


class TestEventWithIdentity:
    """Test Event integration with AgentIdentity."""

    def test_event_without_identity(self):
        event = Event(type="llm_call", framework="openai")
        assert event.identity is None
        d = event.to_dict()
        assert "identity" not in d

    def test_event_with_identity(self):
        identity = AgentIdentity(agent_name="search-agent", owner="jason@test.com")
        event = Event(type="llm_call", framework="openai", identity=identity)
        assert event.identity is not None
        assert event.identity.agent_name == "search-agent"

    def test_event_to_dict_includes_identity(self):
        identity = AgentIdentity(agent_name="search-agent", owner="jason@test.com")
        event = Event(type="llm_call", framework="openai", identity=identity)
        d = event.to_dict()
        assert "identity" in d
        assert d["identity"]["agent_name"] == "search-agent"
        assert d["identity"]["owner"] == "jason@test.com"
        assert d["identity"]["fingerprint"] == identity.fingerprint

    def test_event_identity_in_chain(self, tmp_path):
        """Identity data flows through the HMAC chain correctly."""
        from air_trust.chain import AuditChain
        chain = AuditChain(
            db_path=str(tmp_path / "test.db"),
            signing_key="test-key-123",
        )
        identity = AgentIdentity(
            agent_name="search-agent",
            owner="jason@test.com",
            agent_version="1.0.0",
            permissions=["database:read"],
        )
        event = Event(
            type="llm_call", framework="openai",
            identity=identity,
        )
        chain_hash = chain.write(event)
        assert chain_hash is not None

        # Verify chain is valid
        result = chain.verify()
        assert result["valid"] is True
        assert result["records"] == 1


class TestSessionWithIdentity:
    """Test session() with identity parameter."""

    def test_session_with_identity(self, tmp_path):
        from air_trust.chain import AuditChain
        from air_trust.core import session

        chain = AuditChain(
            db_path=str(tmp_path / "test.db"),
            signing_key="test-key-123",
        )
        identity = AgentIdentity(
            agent_name="pipeline-agent",
            owner="jason@airblackbox.ai",
        )
        with session("test-pipeline", chain=chain, identity=identity) as s:
            s.log("Step 1 complete")

        # Should have 3 events: session_start, checkpoint, session_end
        assert chain._count == 3
        result = chain.verify()
        assert result["valid"] is True

    def test_session_without_identity(self, tmp_path):
        """Sessions still work without identity (backward compatible)."""
        from air_trust.chain import AuditChain
        from air_trust.core import session

        chain = AuditChain(
            db_path=str(tmp_path / "test.db"),
            signing_key="test-key-123",
        )
        with session("test-pipeline", chain=chain) as s:
            s.log("Step 1 complete")

        assert chain._count == 3
        result = chain.verify()
        assert result["valid"] is True


class TestImports:
    """Test that AgentIdentity is properly exported."""

    def test_import_from_package(self):
        from air_trust import AgentIdentity
        identity = AgentIdentity(agent_name="test", owner="test@test.com")
        assert identity.agent_name == "test"

    def test_import_get_identity(self):
        from air_trust import get_identity
        # Should return None when no identity set
        # (global state may be set from other tests, so just check callable)
        assert callable(get_identity)
