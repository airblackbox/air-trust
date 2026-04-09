"""
Canonical event format for air-trust.

Every adapter — regardless of framework — produces Event objects.
Events are the universal currency of the trust layer.
"""

from __future__ import annotations
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any


@dataclass
class AgentIdentity:
    """EU AI Act Article 14 + CSA Agentic Trust Framework (ATF) identity.

    Every agent action must be attributable to:
    - A specific agent (name, version, persistent URN)
    - An authorizing human (owner, ownership chain)
    - A defined permission scope (capabilities)
    - A declared purpose (what this agent is for)

    Satisfies ATF Level 1 (Intern) Identity requirements:
      I-1 Unique Identifier   (MUST)   -> urn
      I-2 Credential Binding  (SHOULD) -> fingerprint + signing key
      I-3 Ownership Chain     (MUST)   -> owner + org
      I-4 Purpose Declaration (MUST)   -> purpose
      I-5 Capability Manifest (SHOULD) -> capabilities + permissions

    Usage:
        identity = AgentIdentity(
            agent_name="customer-search-agent",
            agent_version="1.2.0",
            owner="jason@airblackbox.ai",
            purpose="Answer customer questions from product docs",
            capabilities=["search:docs", "llm:respond"],
            permissions=["database:read", "email:send"],
            external_id="search-bot@airblackbox.ai",  # AgentLair/DID/etc.
        )

        # Attach to a session
        with air_trust.session("search", identity=identity) as s:
            ...

        # Or attach to trust()
        client = air_trust.trust(OpenAI(), identity=identity)

        # Check ATF conformance
        from air_trust.atf import conformance
        print(conformance(identity))  # {"I-1": True, "I-2": True, ...}
    """

    # Required: who is this agent?
    agent_name: str

    # Required: who authorized this agent to act? (I-3 Ownership Chain)
    owner: str

    # Optional: version tracking for reproducibility
    agent_version: str = "0.0.0"

    # Optional: what is this agent allowed to do? (I-5 Capability Manifest)
    permissions: List[str] = field(default_factory=list)

    # Optional: what tools/actions are blocked?
    denied: List[str] = field(default_factory=list)

    # Optional: human-readable description
    description: str = ""

    # Optional: organization / team (strengthens I-3)
    org: str = ""

    # ── ATF (CSA Agentic Trust Framework) Fields ────────────────

    # I-4 Purpose Declaration (MUST for Intern level)
    # Structured statement of intended use and scope.
    purpose: str = ""

    # I-5 Capability Manifest (SHOULD for Intern level)
    # Machine-readable list of claimed capabilities.
    # Different from permissions: capabilities are WHAT the agent CAN do,
    # permissions are WHAT the agent IS ALLOWED to do.
    capabilities: List[str] = field(default_factory=list)

    # I-1 Unique Identifier (MUST for Intern level)
    # Globally unique persistent URN for this agent.
    # Auto-derived from name:owner:version if not provided.
    # Format: urn:agent:{org-or-owner}:{agent-name}:{version}
    urn: str = ""

    # Optional: external identity provider binding
    # e.g. "pico@agentlair.dev", "did:web:example.com:agent:foo"
    # Maps the local URN to an external registry (AgentLair, DID, etc.)
    external_id: str = ""

    # ATF Maturity Level — one of: "intern", "junior", "senior", "principal"
    # Defaults to "intern" (lowest trust, most oversight).
    atf_level: str = "intern"

    # ── Legacy / Internal Fields ────────────────────────────────

    # Optional: unique short identifier (auto-generated if empty)
    # Kept for backward compatibility. Use `urn` for ATF compliance.
    agent_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    # Fingerprint: computed from name + owner + version for audit matching
    fingerprint: str = field(init=False)

    def __post_init__(self):
        """Compute deterministic fingerprint + URN for this identity."""
        import hashlib
        raw = f"{self.agent_name}:{self.owner}:{self.agent_version}"
        self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]

        # Auto-derive URN if not provided (I-1 Unique Identifier)
        if not self.urn:
            org_part = self.org or self.owner
            # Sanitize for URN format (lowercase, replace spaces and colons)
            org_clean = org_part.lower().replace(" ", "-").replace(":", "-")
            name_clean = self.agent_name.lower().replace(" ", "-").replace(":", "-")
            ver_clean = self.agent_version.lower().replace(" ", "-").replace(":", "-")
            self.urn = f"urn:agent:{org_clean}:{name_clean}:{ver_clean}"

        # Validate atf_level
        valid_levels = {"intern", "junior", "senior", "principal"}
        if self.atf_level not in valid_levels:
            self.atf_level = "intern"

    def to_dict(self) -> dict:
        """Serialize for inclusion in Event and chain records."""
        d = {
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "agent_version": self.agent_version,
            "owner": self.owner,
            "fingerprint": self.fingerprint,
            "urn": self.urn,
            "atf_level": self.atf_level,
        }
        if self.permissions:
            d["permissions"] = self.permissions
        if self.denied:
            d["denied"] = self.denied
        if self.description:
            d["description"] = self.description
        if self.org:
            d["org"] = self.org
        if self.purpose:
            d["purpose"] = self.purpose
        if self.capabilities:
            d["capabilities"] = self.capabilities
        if self.external_id:
            d["external_id"] = self.external_id
        return d

    def allows(self, action: str) -> bool:
        """Check if this identity permits a given action.

        Returns True if:
        - permissions list is empty (no restrictions), OR
        - action is in the permissions list
        AND action is NOT in the denied list.
        """
        if action in self.denied:
            return False
        if not self.permissions:
            return True
        return action in self.permissions


@dataclass
class PIIAlert:
    type: str          # email | ssn | phone | credit_card | iban
    count: int = 1
    timestamp: str = ""


@dataclass
class InjectionAlert:
    pattern: str
    weight: float      # 0.0 - 1.0 confidence
    timestamp: str = ""


@dataclass
class Event:
    """Universal event produced by every adapter.

    This is the single format that flows into the HMAC chain.
    Framework adapters map their native events into this shape.
    """

    # Required
    type: str                           # llm_call | tool_call | agent_step | retrieval |
                                        # function_call | delegation | session_start |
                                        # session_end | injection_blocked | error
    framework: str                      # langchain | crewai | openai | anthropic | google_adk |
                                        # llamaindex | smolagents | pydantic_ai | dspy |
                                        # autogen | semantic_kernel | haystack | browser_use |
                                        # n8n | nvidia_agent | mcp | otel | raw_python | unknown

    # Identity
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    session_id: Optional[str] = None
    agent: Optional[str] = None         # agent name if multi-agent

    # Timing
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    duration_ms: int = 0

    # LLM-specific
    model: Optional[str] = None         # gpt-4o | claude-sonnet-4-20250514 | llama-3.1 | ...
    provider: Optional[str] = None      # openai | anthropic | google | local | ...
    tokens: Optional[Dict[str, int]] = None  # {"prompt": X, "completion": Y, "total": Z}
    cost: Optional[float] = None        # estimated cost in USD

    # Tool-specific
    tool_name: Optional[str] = None
    tool_args: Optional[Dict[str, Any]] = None
    risk_level: Optional[str] = None    # critical | high | medium | low

    # Content (previews only — never log full prompts/responses)
    input_preview: Optional[str] = None   # max 500 chars
    output_preview: Optional[str] = None  # max 500 chars
    description: Optional[str] = None     # human-readable summary

    # Safety
    pii_alerts: List[PIIAlert] = field(default_factory=list)
    injection_alerts: List[InjectionAlert] = field(default_factory=list)
    injection_score: float = 0.0

    # Status
    status: str = "success"             # success | error | blocked | skipped
    error: Optional[str] = None

    # Identity (Article 14 — agent-to-user binding)
    identity: Optional[AgentIdentity] = None

    # Metadata (adapter can attach anything)
    meta: Dict[str, Any] = field(default_factory=dict)

    # Set by AuditChain after signing — never set manually
    chain_hash: Optional[str] = None
    version: str = "1.0.0"

    def to_dict(self) -> dict:
        """Serialize to dict for the HMAC chain, dropping None values."""
        d = asdict(self)
        # AgentIdentity serializes via its own to_dict for cleanliness
        if self.identity is not None:
            d["identity"] = self.identity.to_dict()
        return {k: v for k, v in d.items() if v is not None}

    def preview(self, text: str, max_len: int = 500) -> str:
        """Truncate text for safe logging."""
        if not text:
            return ""
        return text[:max_len] + ("..." if len(text) > max_len else "")
