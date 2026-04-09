"""Tests for CSA Agentic Trust Framework (ATF) conformance module."""
import json
import pytest

from air_trust.events import AgentIdentity
from air_trust import atf


# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture
def minimal_identity():
    """An identity with only agent_name + owner — bare minimum."""
    return AgentIdentity(
        agent_name="minimal-agent",
        owner="jason@airblackbox.ai",
    )


@pytest.fixture
def full_identity():
    """An identity with all ATF fields populated."""
    return AgentIdentity(
        agent_name="customer-search",
        owner="jason@airblackbox.ai",
        agent_version="1.2.0",
        org="AIR Blackbox",
        purpose="Answer customer questions from product docs",
        capabilities=["search:docs", "llm:respond"],
        permissions=["database:read"],
        external_id="search-bot@agentlair.dev",
        atf_level="junior",
    )


# ── URN Auto-Generation ───────────────────────────────────────


class TestUrnGeneration:
    def test_urn_auto_generated_from_name(self, minimal_identity):
        assert minimal_identity.urn.startswith("urn:agent:")
        assert "minimal-agent" in minimal_identity.urn

    def test_urn_uses_org_when_present(self, full_identity):
        assert "air-blackbox" in full_identity.urn
        assert "customer-search" in full_identity.urn
        assert "1.2.0" in full_identity.urn

    def test_urn_sanitizes_spaces_and_colons(self):
        identity = AgentIdentity(
            agent_name="My Agent: v2",
            owner="test@example.com",
            org="Acme Corp",
        )
        assert " " not in identity.urn
        # The name itself contained colons so urn should have them sanitized
        # beyond the leading "urn:agent:" prefix.
        # Strip the standard prefix and check the remainder.
        remainder = identity.urn[len("urn:agent:"):]
        assert ":" not in remainder or remainder.count(":") <= 2  # 2 separators

    def test_custom_urn_is_preserved(self):
        identity = AgentIdentity(
            agent_name="agent",
            owner="test@example.com",
            urn="urn:agent:custom:identifier:v1",
        )
        assert identity.urn == "urn:agent:custom:identifier:v1"


# ── atf_level Validation ──────────────────────────────────────


class TestAtfLevel:
    def test_default_level_is_intern(self, minimal_identity):
        assert minimal_identity.atf_level == "intern"

    def test_valid_levels_are_preserved(self):
        for level in ("intern", "junior", "senior", "principal"):
            identity = AgentIdentity(
                agent_name="a", owner="b", atf_level=level
            )
            assert identity.atf_level == level

    def test_invalid_level_falls_back_to_intern(self):
        identity = AgentIdentity(
            agent_name="a", owner="b", atf_level="nonsense"
        )
        assert identity.atf_level == "intern"


# ── Individual Requirement Checks ─────────────────────────────


class TestRequirementChecks:
    def test_i1_passes_with_urn(self, minimal_identity):
        assert atf.check_i1_unique_identifier(minimal_identity) is True

    def test_i2_passes_with_fingerprint(self, minimal_identity):
        assert atf.check_i2_credential_binding(minimal_identity) is True

    def test_i3_passes_with_owner(self, minimal_identity):
        assert atf.check_i3_ownership_chain(minimal_identity) is True

    def test_i4_fails_without_purpose_or_description(self, minimal_identity):
        assert atf.check_i4_purpose_declaration(minimal_identity) is False

    def test_i4_passes_with_purpose(self, full_identity):
        assert atf.check_i4_purpose_declaration(full_identity) is True

    def test_i4_passes_with_legacy_description(self):
        identity = AgentIdentity(
            agent_name="a",
            owner="b",
            description="Legacy description",
        )
        assert atf.check_i4_purpose_declaration(identity) is True

    def test_i5_fails_without_capabilities_or_permissions(self, minimal_identity):
        assert atf.check_i5_capability_manifest(minimal_identity) is False

    def test_i5_passes_with_capabilities(self, full_identity):
        assert atf.check_i5_capability_manifest(full_identity) is True

    def test_i5_passes_with_legacy_permissions(self):
        identity = AgentIdentity(
            agent_name="a",
            owner="b",
            permissions=["read:x"],
        )
        assert atf.check_i5_capability_manifest(identity) is True


# ── conformance() dict ────────────────────────────────────────


class TestConformanceDict:
    def test_conformance_keys(self, minimal_identity):
        result = atf.conformance(minimal_identity)
        assert set(result.keys()) == {"I-1", "I-2", "I-3", "I-4", "I-5"}

    def test_minimal_identity_fails_i4_and_i5(self, minimal_identity):
        result = atf.conformance(minimal_identity)
        assert result["I-1"] is True
        assert result["I-2"] is True
        assert result["I-3"] is True
        assert result["I-4"] is False
        assert result["I-5"] is False

    def test_full_identity_passes_all(self, full_identity):
        result = atf.conformance(full_identity)
        assert all(result.values())


# ── level_compliant() ─────────────────────────────────────────


class TestLevelCompliant:
    def test_minimal_not_intern_compliant(self, minimal_identity):
        # I-4 is MUST at intern, and minimal has no purpose
        assert atf.level_compliant(minimal_identity, "intern") is False

    def test_full_identity_is_intern_compliant(self, full_identity):
        assert atf.level_compliant(full_identity, "intern") is True

    def test_full_identity_is_principal_compliant(self, full_identity):
        assert atf.level_compliant(full_identity, "principal") is True

    def test_invalid_level_raises(self, full_identity):
        with pytest.raises(ValueError):
            atf.level_compliant(full_identity, "overlord")


# ── highest_compliant_level() ─────────────────────────────────


class TestHighestLevel:
    def test_minimal_identity_is_none(self, minimal_identity):
        assert atf.highest_compliant_level(minimal_identity) == "none"

    def test_full_identity_is_principal(self, full_identity):
        assert atf.highest_compliant_level(full_identity) == "principal"


# ── gaps() ────────────────────────────────────────────────────


class TestGaps:
    def test_minimal_identity_has_gaps(self, minimal_identity):
        result = atf.gaps(minimal_identity, "intern")
        ids = [r[0] for r in result]
        assert "I-4" in ids  # purpose missing

    def test_full_identity_has_no_gaps(self, full_identity):
        result = atf.gaps(full_identity, "intern")
        assert result == []

    def test_invalid_level_raises(self, full_identity):
        with pytest.raises(ValueError):
            atf.gaps(full_identity, "overlord")


# ── Export Functions ──────────────────────────────────────────


class TestExports:
    def test_conformance_statement_returns_string(self, full_identity):
        statement = atf.conformance_statement(full_identity)
        assert isinstance(statement, str)
        assert "CSA Agentic Trust Framework" in statement
        assert "customer-search" in statement
        assert "PASS" in statement

    def test_conformance_statement_shows_gaps(self, minimal_identity):
        statement = atf.conformance_statement(minimal_identity)
        assert "Gaps to reach" in statement
        assert "Purpose Declaration" in statement

    def test_conformance_dict_is_json_serializable(self, full_identity):
        result = atf.conformance_dict(full_identity)
        # Must be serializable without error
        dumped = json.dumps(result)
        assert "customer-search" in dumped

    def test_conformance_dict_structure(self, full_identity):
        result = atf.conformance_dict(full_identity)
        assert result["framework"] == "CSA Agentic Trust Framework"
        assert result["core_element"] == "Identity (Element 1)"
        assert result["agent"]["name"] == "customer-search"
        assert result["target_level"] == "junior"
        assert "I-1" in result["requirements"]
        assert result["requirements"]["I-4"]["satisfied"] is True
        assert result["gaps"] == []


# ── Serialization Round-Trip ──────────────────────────────────


class TestSerialization:
    def test_to_dict_includes_atf_fields(self, full_identity):
        d = full_identity.to_dict()
        assert "urn" in d
        assert "atf_level" in d
        assert d["atf_level"] == "junior"
        assert "purpose" in d
        assert "capabilities" in d
        assert "external_id" in d

    def test_to_dict_omits_empty_atf_fields(self, minimal_identity):
        d = minimal_identity.to_dict()
        # Core fields always present
        assert "urn" in d
        assert "atf_level" in d
        # Empty optional fields should be omitted
        assert "purpose" not in d
        assert "capabilities" not in d
        assert "external_id" not in d
