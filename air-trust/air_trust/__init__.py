"""
air-trust - Universal compliance trust layer for any AI system.

One package. Any framework. Any LLM. Any agent.

    from air_trust import trust

    # Auto-detects your framework and starts recording
    trust(my_agent)

    # Or wrap any function manually
    @trust.monitor
    def my_agent_step(prompt):
        return openai.chat.completions.create(...)

    # Or use as context manager
    with trust.session("my-agent") as t:
        t.record("llm_call", model="gpt-4o", tokens=1500, cost=0.023)

That's it. HMAC-SHA256 signed audit chain, PII detection,
prompt injection scanning, evidence export - all local, no API key.
"""

__version__ = "0.6.1"

from air_trust.core import trust, monitor, session, get_chain, get_identity, verify, stats, scan_text, enforce
from air_trust.chain import AuditChain
from air_trust.events import Event, AgentIdentity
from air_trust.policy import Policy, PolicyResult, PolicyViolation, PolicyEnforcer
from air_trust import atf

__all__ = [
    "trust", "monitor", "session",
    "get_chain", "get_identity", "verify", "stats", "scan_text", "enforce",
    "AuditChain", "Event", "AgentIdentity",
    "Policy", "PolicyResult", "PolicyViolation", "PolicyEnforcer",
    "atf",
]
