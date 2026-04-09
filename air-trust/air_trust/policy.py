"""
Policy enforcement for the AIR Trust layer.

Define runtime policies that check every event and block/warn/log violations.
Policies check models, tools, injection scores, PII types, and custom rules.

Usage:
    policy = Policy(
        name="production",
        blocked_models=["gpt-3.5-turbo"],
        required_identity=True,
        max_injection_score=0.5,
        blocked_pii_types=["ssn", "credit_card"],
    )

    enforcer = air_trust.enforce(policy)
    # Now every event is checked against the policy
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Callable
import time

from air_trust.events import Event


@dataclass
class PolicyResult:
    """Result of a policy check."""

    allowed: bool
    violations: List[str]  # List of violation reasons
    policy_name: str
    checked_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def __str__(self) -> str:
        """Human-readable representation."""
        status = "ALLOWED" if self.allowed else "BLOCKED"
        msg = f"Policy '{self.policy_name}': {status}"
        if self.violations:
            msg += f" ({len(self.violations)} violation{'s' if len(self.violations) != 1 else ''})"
        return msg


@dataclass
class Policy:
    """Runtime policy for event enforcement.

    Pre-execution checks:
    - blocked_models: List of models to reject (e.g., ["gpt-3.5-turbo"])
    - required_identity: Must event have an identity?
    - max_tokens: Token limit per call (None = no limit)
    - blocked_tools: Tools to reject (e.g., ["shell", "file_write"])
    - allowed_tools: Allowlist of tools (empty = all allowed)
    - max_injection_score: Block if injection score exceeds this
    - require_pii_scan: Always scan for PII?
    - blocked_pii_types: PII types to reject (e.g., ["ssn", "credit_card"])

    Custom rules:
    - rules: List of Callable[[Event], Optional[str]]
      Each rule returns None (pass) or a string (violation reason)
    """

    name: str
    description: str = ""

    # Pre-execution checks
    blocked_models: List[str] = field(default_factory=list)
    required_identity: bool = False
    max_tokens: Optional[int] = None
    blocked_tools: List[str] = field(default_factory=list)
    allowed_tools: List[str] = field(default_factory=list)
    max_injection_score: float = 0.7
    require_pii_scan: bool = True
    blocked_pii_types: List[str] = field(default_factory=list)

    # Custom rules
    rules: List[Callable[[Event], Optional[str]]] = field(default_factory=list)

    def check(self, event: Event) -> PolicyResult:
        """Run all policy checks against an event.

        Returns PolicyResult with allowed=True/False and list of violations.
        """
        violations = []

        # Check blocked models
        if self.blocked_models and event.model:
            if event.model in self.blocked_models:
                violations.append(f"Model '{event.model}' is blocked")

        # Check required identity
        if self.required_identity and event.identity is None:
            violations.append("Identity is required but not provided")

        # Check max tokens
        if self.max_tokens is not None and event.tokens:
            total_tokens = event.tokens.get("total", 0)
            if total_tokens > self.max_tokens:
                violations.append(
                    f"Token count {total_tokens} exceeds limit {self.max_tokens}"
                )

        # Check blocked tools
        if self.blocked_tools and event.tool_name:
            if event.tool_name in self.blocked_tools:
                violations.append(f"Tool '{event.tool_name}' is blocked")

        # Check allowed tools (allowlist)
        if self.allowed_tools and event.tool_name:
            if event.tool_name not in self.allowed_tools:
                violations.append(
                    f"Tool '{event.tool_name}' is not in the allowed list"
                )

        # Check injection score
        if event.injection_score > self.max_injection_score:
            violations.append(
                f"Injection score {event.injection_score:.2f} exceeds threshold "
                f"{self.max_injection_score:.2f}"
            )

        # Check blocked PII types
        if self.blocked_pii_types and event.pii_alerts:
            for pii_alert in event.pii_alerts:
                if pii_alert.type in self.blocked_pii_types:
                    violations.append(
                        f"PII type '{pii_alert.type}' is blocked ({pii_alert.count} found)"
                    )

        # Run custom rules
        for rule in self.rules:
            try:
                result = rule(event)
                if result is not None:
                    violations.append(result)
            except Exception as e:
                violations.append(f"Custom rule error: {e}")

        return PolicyResult(
            allowed=len(violations) == 0,
            violations=violations,
            policy_name=self.name,
        )


class PolicyViolation(Exception):
    """Raised when a policy check fails in 'block' mode."""

    def __init__(self, result: PolicyResult):
        self.result = result
        msg = f"Policy '{result.policy_name}' violated: {', '.join(result.violations)}"
        super().__init__(msg)


class PolicyEnforcer:
    """Attaches policies to the trust layer.

    Checks every event against the policy and either blocks, warns, or silently logs.

    Usage:
        policy = Policy(
            name="production",
            blocked_models=["gpt-3.5-turbo"],
            required_identity=True,
            max_injection_score=0.5,
        )

        enforcer = air_trust.enforce(policy)
        # Now every event through the chain is checked
        # Violations are logged AND raise PolicyViolation (in 'block' mode)
    """

    def __init__(
        self,
        policy: Policy,
        chain,
        on_violation: str = "block",
    ):
        """Initialize the policy enforcer.

        Args:
            policy: A Policy object defining rules
            chain: AuditChain instance to log violations to
            on_violation: "block" (raise), "warn" (log warning), "log" (silent)
        """
        if on_violation not in ("block", "warn", "log"):
            raise ValueError(
                f"on_violation must be 'block', 'warn', or 'log', got {on_violation}"
            )

        self.policy = policy
        self.chain = chain
        self.on_violation = on_violation

    def check_event(self, event: Event) -> PolicyResult:
        """Check an event against the policy.

        Returns PolicyResult. If on_violation is "block" and check fails,
        raises PolicyViolation.
        """
        result = self.policy.check(event)

        if not result.allowed:
            # Log the violation to the chain
            violation_event = Event(
                type="policy_violation",
                framework="air_trust",
                description=f"Policy '{self.policy.name}' violation",
                status="blocked",
                error="; ".join(result.violations),
                meta={
                    "policy_name": self.policy.name,
                    "violations": result.violations,
                    "blocked_event_type": event.type,
                    "blocked_event_framework": event.framework,
                },
            )
            self.chain.write(violation_event)

            # Take action based on on_violation mode
            if self.on_violation == "block":
                raise PolicyViolation(result)
            elif self.on_violation == "warn":
                import warnings
                warnings.warn(f"Policy violation: {'; '.join(result.violations)}")

        return result

    def wrap_chain_write(self):
        """Decorator to wrap AuditChain.write to enforce policy on all events.

        Call this to automatically check every event written to the chain.

        Usage:
            enforcer.wrap_chain_write()
        """
        original_write = self.chain.write

        def wrapped_write(event: Event) -> str:
            self.check_event(event)
            return original_write(event)

        self.chain.write = wrapped_write
