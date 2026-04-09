"""Tests for policy enforcement."""

import os
import pytest
from air_trust.chain import AuditChain
from air_trust.events import Event, PIIAlert, InjectionAlert, AgentIdentity
from air_trust.policy import Policy, PolicyResult, PolicyEnforcer, PolicyViolation


@pytest.fixture
def temp_dir(tmp_path):
    """Use pytest's built-in tmp_path which handles cleanup."""
    return str(tmp_path)


@pytest.fixture
def chain(temp_dir):
    """Create a fresh AuditChain in a temp directory."""
    db_path = os.path.join(temp_dir, "events.db")
    return AuditChain(db_path=db_path, signing_key="test-policy-key")


class TestPolicyBasic:
    """Test basic policy checks."""

    def test_empty_policy_allows_everything(self, chain):
        """Empty policy should allow any event."""
        policy = Policy(name="empty")
        event = Event(type="llm_call", framework="openai", model="gpt-4o")
        result = policy.check(event)
        assert result.allowed is True
        assert result.violations == []

    def test_blocked_models(self, chain):
        """Policy should block specific models."""
        policy = Policy(
            name="block-old",
            blocked_models=["gpt-3.5-turbo", "davinci"],
        )
        # Allowed model
        event1 = Event(type="llm_call", framework="openai", model="gpt-4o")
        result1 = policy.check(event1)
        assert result1.allowed is True

        # Blocked model
        event2 = Event(type="llm_call", framework="openai", model="gpt-3.5-turbo")
        result2 = policy.check(event2)
        assert result2.allowed is False
        assert any("gpt-3.5-turbo" in v for v in result2.violations)

    def test_required_identity(self, chain):
        """Policy should require identity if specified."""
        policy = Policy(name="require-id", required_identity=True)

        # Without identity
        event1 = Event(type="llm_call", framework="openai")
        result1 = policy.check(event1)
        assert result1.allowed is False
        assert any("identity" in v.lower() for v in result1.violations)

        # With identity
        identity = AgentIdentity(
            agent_name="test-agent",
            owner="test@example.com",
        )
        event2 = Event(type="llm_call", framework="openai", identity=identity)
        result2 = policy.check(event2)
        assert result2.allowed is True

    def test_max_tokens(self, chain):
        """Policy should enforce token limits."""
        policy = Policy(name="token-limit", max_tokens=1000)

        # Within limit
        event1 = Event(
            type="llm_call",
            framework="openai",
            tokens={"prompt": 100, "completion": 200, "total": 300},
        )
        result1 = policy.check(event1)
        assert result1.allowed is True

        # Exceeds limit
        event2 = Event(
            type="llm_call",
            framework="openai",
            tokens={"prompt": 600, "completion": 500, "total": 1100},
        )
        result2 = policy.check(event2)
        assert result2.allowed is False
        assert any("token" in v.lower() for v in result2.violations)

    def test_blocked_tools(self, chain):
        """Policy should block specific tools."""
        policy = Policy(
            name="safe-tools",
            blocked_tools=["shell", "file_write"],
        )

        # Allowed tool
        event1 = Event(
            type="tool_call",
            framework="custom",
            tool_name="search",
        )
        result1 = policy.check(event1)
        assert result1.allowed is True

        # Blocked tool
        event2 = Event(
            type="tool_call",
            framework="custom",
            tool_name="shell",
        )
        result2 = policy.check(event2)
        assert result2.allowed is False
        assert any("shell" in v for v in result2.violations)

    def test_allowed_tools_allowlist(self, chain):
        """Policy should enforce tool allowlist."""
        policy = Policy(
            name="limited-tools",
            allowed_tools=["search", "calc"],
        )

        # Allowed
        event1 = Event(
            type="tool_call",
            framework="custom",
            tool_name="search",
        )
        result1 = policy.check(event1)
        assert result1.allowed is True

        # Not in allowlist
        event2 = Event(
            type="tool_call",
            framework="custom",
            tool_name="file_write",
        )
        result2 = policy.check(event2)
        assert result2.allowed is False
        assert any("not in the allowed" in v for v in result2.violations)


class TestPolicyInjection:
    """Test injection score checking."""

    def test_max_injection_score_blocks(self, chain):
        """Policy should block high injection scores."""
        policy = Policy(
            name="injection-guard",
            max_injection_score=0.5,
        )

        # Low score (allowed)
        event1 = Event(
            type="llm_call",
            framework="openai",
            injection_score=0.3,
        )
        result1 = policy.check(event1)
        assert result1.allowed is True

        # High score (blocked)
        event2 = Event(
            type="llm_call",
            framework="openai",
            injection_score=0.75,
        )
        result2 = policy.check(event2)
        assert result2.allowed is False
        assert any("injection" in v.lower() for v in result2.violations)

    def test_injection_score_zero_allowed(self, chain):
        """Zero injection score should always be allowed."""
        policy = Policy(
            name="strict-injection",
            max_injection_score=0.01,
        )
        event = Event(
            type="llm_call",
            framework="openai",
            injection_score=0.0,
        )
        result = policy.check(event)
        assert result.allowed is True


class TestPolicyPII:
    """Test PII blocking."""

    def test_blocked_pii_types(self, chain):
        """Policy should block specified PII types."""
        policy = Policy(
            name="pii-filter",
            blocked_pii_types=["ssn", "credit_card"],
        )

        # Allowed PII type
        event1 = Event(
            type="llm_call",
            framework="openai",
            pii_alerts=[PIIAlert(type="email", count=1)],
        )
        result1 = policy.check(event1)
        assert result1.allowed is True

        # Blocked PII type
        event2 = Event(
            type="llm_call",
            framework="openai",
            pii_alerts=[PIIAlert(type="ssn", count=2)],
        )
        result2 = policy.check(event2)
        assert result2.allowed is False
        assert any("ssn" in v for v in result2.violations)

    def test_multiple_pii_alerts(self, chain):
        """Policy should detect all blocked PII types."""
        policy = Policy(
            name="multi-pii",
            blocked_pii_types=["ssn", "credit_card"],
        )
        event = Event(
            type="llm_call",
            framework="openai",
            pii_alerts=[
                PIIAlert(type="ssn", count=1),
                PIIAlert(type="credit_card", count=1),
            ],
        )
        result = policy.check(event)
        assert result.allowed is False
        assert len(result.violations) >= 2


class TestPolicyCustomRules:
    """Test custom rule functions."""

    def test_custom_rule_blocking(self, chain):
        """Custom rules can block events."""
        def rule_no_openai(event: Event):
            if event.framework == "openai":
                return "OpenAI framework is not allowed"
            return None

        policy = Policy(
            name="custom-block",
            rules=[rule_no_openai],
        )

        # Allowed framework
        event1 = Event(type="llm_call", framework="anthropic")
        result1 = policy.check(event1)
        assert result1.allowed is True

        # Blocked by custom rule
        event2 = Event(type="llm_call", framework="openai")
        result2 = policy.check(event2)
        assert result2.allowed is False
        assert any("OpenAI" in v for v in result2.violations)

    def test_custom_rule_passes(self, chain):
        """Custom rules that return None should pass."""
        def rule_always_pass(event: Event):
            return None

        policy = Policy(
            name="pass-rule",
            rules=[rule_always_pass],
        )
        event = Event(type="llm_call", framework="openai")
        result = policy.check(event)
        assert result.allowed is True

    def test_custom_rule_exception_handling(self, chain):
        """Exceptions in custom rules should be caught."""
        def rule_bad(event: Event):
            raise ValueError("Rule error")

        policy = Policy(
            name="bad-rule",
            rules=[rule_bad],
        )
        event = Event(type="llm_call", framework="openai")
        result = policy.check(event)
        assert result.allowed is False
        assert any("error" in v.lower() for v in result.violations)


class TestPolicyMultipleViolations:
    """Test that multiple violations are collected."""

    def test_multiple_violations_collected(self, chain):
        """All violations should be collected in one result."""
        policy = Policy(
            name="strict",
            blocked_models=["gpt-3.5-turbo"],
            required_identity=True,
            max_tokens=100,
            max_injection_score=0.3,
        )
        event = Event(
            type="llm_call",
            framework="openai",
            model="gpt-3.5-turbo",
            tokens={"total": 500},
            injection_score=0.8,
        )
        result = policy.check(event)
        assert result.allowed is False
        # Should have violations for: model, identity, tokens, injection
        assert len(result.violations) >= 3

    def test_violation_messages_distinct(self, chain):
        """Each violation should have a distinct message."""
        policy = Policy(
            name="multi",
            blocked_models=["gpt-3.5"],
            max_tokens=100,
        )
        event = Event(
            type="llm_call",
            framework="openai",
            model="gpt-3.5",
            tokens={"total": 500},
        )
        result = policy.check(event)
        assert len(result.violations) == 2
        assert result.violations[0] != result.violations[1]


class TestPolicyResult:
    """Test PolicyResult dataclass."""

    def test_policy_result_fields(self, chain):
        """PolicyResult should have all required fields."""
        result = PolicyResult(
            allowed=True,
            violations=[],
            policy_name="test",
        )
        assert result.allowed is True
        assert result.violations == []
        assert result.policy_name == "test"
        assert result.checked_at is not None

    def test_policy_result_str_allowed(self, chain):
        """String representation for allowed result."""
        result = PolicyResult(
            allowed=True,
            violations=[],
            policy_name="test",
        )
        s = str(result)
        assert "ALLOWED" in s
        assert "test" in s

    def test_policy_result_str_blocked(self, chain):
        """String representation for blocked result."""
        result = PolicyResult(
            allowed=False,
            violations=["violation 1", "violation 2"],
            policy_name="test",
        )
        s = str(result)
        assert "BLOCKED" in s
        assert "2 violation" in s


class TestPolicyViolation:
    """Test PolicyViolation exception."""

    def test_policy_violation_exception(self, chain):
        """PolicyViolation should be an exception."""
        result = PolicyResult(
            allowed=False,
            violations=["Test violation"],
            policy_name="test",
        )
        exc = PolicyViolation(result)
        assert isinstance(exc, Exception)
        assert "test" in str(exc)
        assert "Test violation" in str(exc)

    def test_policy_violation_carries_result(self, chain):
        """PolicyViolation should carry the result."""
        result = PolicyResult(
            allowed=False,
            violations=["violation"],
            policy_name="test",
        )
        exc = PolicyViolation(result)
        assert exc.result == result


class TestPolicyEnforcer:
    """Test PolicyEnforcer integration."""

    def test_enforcer_creation(self, chain):
        """PolicyEnforcer should initialize correctly."""
        policy = Policy(name="test")
        enforcer = PolicyEnforcer(policy, chain)
        assert enforcer.policy == policy
        assert enforcer.chain == chain
        assert enforcer.on_violation == "block"

    def test_enforcer_check_event_allowed(self, chain):
        """Enforcer should return allowed results without exception."""
        policy = Policy(name="test")
        enforcer = PolicyEnforcer(policy, chain, on_violation="block")
        event = Event(type="llm_call", framework="openai")
        result = enforcer.check_event(event)
        assert result.allowed is True

    def test_enforcer_check_event_blocked_raises(self, chain):
        """Enforcer should raise PolicyViolation in block mode."""
        policy = Policy(name="test", blocked_models=["gpt-3.5"])
        enforcer = PolicyEnforcer(policy, chain, on_violation="block")
        event = Event(type="llm_call", framework="openai", model="gpt-3.5")
        with pytest.raises(PolicyViolation):
            enforcer.check_event(event)

    def test_enforcer_check_event_warn_mode(self, chain):
        """Enforcer should warn in warn mode without raising."""
        policy = Policy(name="test", blocked_models=["gpt-3.5"])
        enforcer = PolicyEnforcer(policy, chain, on_violation="warn")
        event = Event(type="llm_call", framework="openai", model="gpt-3.5")
        # Should not raise, but should warn
        result = enforcer.check_event(event)
        assert result.allowed is False

    def test_enforcer_check_event_log_mode(self, chain):
        """Enforcer should silently log in log mode."""
        policy = Policy(name="test", blocked_models=["gpt-3.5"])
        enforcer = PolicyEnforcer(policy, chain, on_violation="log")
        event = Event(type="llm_call", framework="openai", model="gpt-3.5")
        result = enforcer.check_event(event)
        assert result.allowed is False

    def test_enforcer_invalid_on_violation(self, chain):
        """Enforcer should validate on_violation parameter."""
        policy = Policy(name="test")
        with pytest.raises(ValueError):
            PolicyEnforcer(policy, chain, on_violation="invalid")

    def test_enforcer_logs_violation_to_chain(self, chain):
        """Enforcer should write violation event to chain."""
        policy = Policy(name="test", blocked_models=["gpt-3.5"])
        enforcer = PolicyEnforcer(policy, chain, on_violation="log")
        event = Event(type="llm_call", framework="openai", model="gpt-3.5")
        enforcer.check_event(event)

        # Check that violation was logged
        result = chain.verify()
        assert result["records"] == 1  # The violation event

    def test_enforcer_wrap_chain_write(self, chain):
        """Enforcer should be able to wrap chain.write()."""
        policy = Policy(name="test", blocked_models=["gpt-3.5"])
        enforcer = PolicyEnforcer(policy, chain, on_violation="block")
        enforcer.wrap_chain_write()

        # Normal event should work
        event1 = Event(type="llm_call", framework="openai", model="gpt-4o")
        chain.write(event1)

        # Blocked event should raise
        event2 = Event(type="llm_call", framework="openai", model="gpt-3.5")
        with pytest.raises(PolicyViolation):
            chain.write(event2)
