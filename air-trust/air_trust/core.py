"""
AIR Trust — Public API.

Three ways to use it:

    # 1. One-liner: wrap any client/agent/pipeline
    import air_trust
    client = air_trust.trust(client)

    # 2. Decorator: wrap any function
    @air_trust.monitor
    def my_tool(query: str) -> str:
        ...

    # 3. Context manager: audit a block of code
    with air_trust.session("my-pipeline") as s:
        result = client.chat.completions.create(...)
        s.log("Custom checkpoint", risk_level="low")

Everything is local-first. No API keys, no network calls.
Audit chain is HMAC-SHA256 signed and stored in SQLite.
"""

from __future__ import annotations
import functools
import atexit
from typing import Any, Optional, Callable
from contextlib import contextmanager

from air_trust.chain import AuditChain, _active_session_id
from air_trust.events import Event, AgentIdentity
from air_trust.detection import detect_installed, detect_object
from air_trust.scan import scan_pii, scan_injection


# ── Global State ────────────────────────────────────────────────
#
# Thread safety: _global_chain and _global_identity are protected by
# _global_lock. In multi-threaded applications, concurrent calls to
# trust() with different identities are serialized. For per-thread
# identity isolation, use session() with explicit identity instead.

import threading as _threading

_global_lock = _threading.Lock()
_global_chain: Optional[AuditChain] = None
_global_identity: Optional[AgentIdentity] = None
_adapters: dict = {}  # framework_id -> adapter instance


def _get_chain() -> AuditChain:
    """Get or create the global audit chain (thread-safe)."""
    global _global_chain
    with _global_lock:
        if _global_chain is None:
            _global_chain = AuditChain()
        return _global_chain


# ── trust() — The One-Liner ────────────────────────────────────

def trust(obj: Any, *, chain: Optional[AuditChain] = None,
          framework: Optional[str] = None,
          identity: Optional[AgentIdentity] = None) -> Any:
    """Wrap any AI client, agent, pipeline, or module with audit logging.

    Auto-detects the framework and applies the right adapter.
    Returns the same object (mutated in place with wrapped methods).

    Args:
        obj: Any AI client, agent, pipeline, or module.
             Examples: OpenAI(), Anthropic(), CrewAI Crew,
             LangChain chain, LlamaIndex engine, DSPy module, etc.
        chain: Optional custom AuditChain. Uses global chain if None.
        framework: Optional framework override (skip auto-detection).
        identity: Optional AgentIdentity for Article 14 compliance.
                  Binds every event to a named agent + authorizing owner.

    Returns:
        The same object, now audited. Use it exactly as before.

    Examples:
        # OpenAI with identity
        from air_trust import trust, AgentIdentity
        identity = AgentIdentity(
            agent_name="search-agent",
            owner="jason@airblackbox.ai",
            permissions=["database:read"],
        )
        client = trust(OpenAI(), identity=identity)
        client.chat.completions.create(model="gpt-4o", messages=[...])

        # Without identity (still works, just no binding)
        client = trust(OpenAI())
    """
    global _global_identity
    c = chain or _get_chain()

    # Store identity globally so adapters can attach it to events.
    # Protected by lock to prevent cross-thread identity clobbering.
    if identity is not None:
        with _global_lock:
            _global_identity = identity
    detection = None

    if framework:
        # Manual override
        adapter_map = {
            "openai": "proxy", "anthropic": "proxy", "google": "proxy",
            "ollama": "proxy", "litellm": "proxy", "vllm": "proxy",
            "together": "proxy", "groq": "proxy", "mistral": "proxy",
            "cohere": "proxy",
            "langchain": "callback", "llamaindex": "callback",
            "haystack": "callback",
            "crewai": "decorator", "smolagents": "decorator",
            "pydantic_ai": "decorator", "dspy": "decorator",
            "autogen": "decorator", "browser_use": "decorator",
            "semantic_kernel": "otel", "otel": "otel",
            "mcp": "mcp",
        }
        adapter_type = adapter_map.get(framework, "proxy")
        detection = (framework, adapter_type)
    else:
        # Auto-detect from the object
        detection = detect_object(obj)

    if not detection:
        # Fallback: try proxy adapter (works for any SDK with .create/.generate)
        detection = ("unknown", "proxy")

    framework_id, adapter_type = detection
    return _apply_adapter(obj, c, framework_id, adapter_type)


def _apply_adapter(obj: Any, chain: AuditChain,
                   framework_id: str, adapter_type: str) -> Any:
    """Apply the correct adapter based on detection results."""

    if adapter_type == "proxy":
        from air_trust.adapters.proxy import ProxyAdapter
        adapter = ProxyAdapter(chain, framework_id)
        _adapters[framework_id] = adapter
        return adapter.wrap_client(obj)

    elif adapter_type == "callback":
        from air_trust.adapters.callback import (
            LangChainCallback, LlamaIndexCallback, HaystackCallback
        )

        if framework_id == "langchain":
            adapter = LangChainCallback(chain)
            _adapters[framework_id] = adapter
            return adapter.as_handler()

        elif framework_id == "llamaindex":
            adapter = LlamaIndexCallback(chain)
            _adapters[framework_id] = adapter
            handler = adapter.as_handler()
            return handler if handler else obj

        elif framework_id == "haystack":
            adapter = HaystackCallback(chain)
            _adapters[framework_id] = adapter
            tracer = adapter.as_tracer()
            return tracer if tracer else obj

    elif adapter_type == "decorator":
        from air_trust.adapters.decorator import DecoratorAdapter
        adapter = DecoratorAdapter(chain, framework_id)
        _adapters[framework_id] = adapter

        wrapper_map = {
            "crewai": adapter.wrap_crewai,
            "smolagents": adapter.wrap_smolagents,
            "pydantic_ai": adapter.wrap_pydantic_ai,
            "dspy": adapter.wrap_dspy,
            "autogen": adapter.wrap_autogen,
            "browser_use": adapter.wrap_browser_use,
        }

        wrapper = wrapper_map.get(framework_id)
        if wrapper:
            return wrapper(obj)

        # Generic: try to find something wrappable
        for method_name in ("run", "invoke", "execute", "forward", "call"):
            if hasattr(obj, method_name):
                wrapped_fn = adapter.trace()(getattr(obj, method_name))
                setattr(obj, method_name, wrapped_fn)
                return obj
        return obj

    elif adapter_type == "otel":
        from air_trust.adapters.otel import OTelAdapter
        adapter = OTelAdapter(chain, framework_id)
        _adapters[framework_id] = adapter

        if framework_id == "semantic_kernel":
            return adapter.wrap_semantic_kernel(obj)

        # Generic OTel: register span processor
        processor = adapter.as_span_processor()
        if processor:
            try:
                from opentelemetry import trace
                from opentelemetry.sdk.trace import TracerProvider
                current = trace.get_tracer_provider()
                if isinstance(current, TracerProvider):
                    current.add_span_processor(processor)
            except ImportError:
                pass
        return obj

    elif adapter_type == "mcp":
        from air_trust.adapters.mcp import MCPAdapter
        adapter = MCPAdapter(chain)
        _adapters[framework_id] = adapter
        return adapter.wrap_server(obj)

    return obj


# ── monitor — The Decorator ────────────────────────────────────

def monitor(fn: Optional[Callable] = None, *,
            event_type: str = "function_call",
            scan: bool = True,
            framework: str = "custom"):
    """Decorator that wraps any function with audit logging.

    Can be used with or without arguments:

        @air_trust.monitor
        def my_function():
            ...

        @air_trust.monitor(event_type="llm_call", scan=True)
        def call_model(prompt):
            ...
    """
    from air_trust.adapters.decorator import DecoratorAdapter

    def decorator(f: Callable) -> Callable:
        chain = _get_chain()
        adapter = DecoratorAdapter(chain, framework)
        return adapter.trace(event_type=event_type, scan=scan)(f)

    if fn is not None:
        # Called without arguments: @air_trust.monitor
        return decorator(fn)
    else:
        # Called with arguments: @air_trust.monitor(event_type="llm_call")
        return decorator


# ── session — The Context Manager ───────────────────────────────

class AirTrustSession:
    """Context manager for auditing a block of code.

    Provides .log() for custom checkpoints and auto-detects
    any AI clients used inside the block.

    v1.1: Generates a unique session_id and attaches it to every
    event written within the session block. This enables the
    completeness verifier to detect dropped records.
    """

    def __init__(self, name: str, chain: Optional[AuditChain] = None,
                 identity: Optional[AgentIdentity] = None):
        import uuid
        self.name = name
        self._chain = chain or _get_chain()
        self._identity = identity
        self._start_time = None
        self._event_count_start = 0
        # v1.1: unique session ID for completeness tracking
        self._session_id = uuid.uuid4().hex

    def __enter__(self):
        import time
        self._start_time = time.time()
        self._event_count_start = self._chain._count
        # Store identity globally so adapters can access it
        if self._identity is not None:
            global _global_identity
            _global_identity = self._identity
        # v1.1: Set the active session_id so ALL adapter events
        # written inside this block inherit it automatically.
        self._session_token = _active_session_id.set(self._session_id)
        self._chain.write(Event(
            type="session_start",
            framework="air_trust",
            session_id=self._session_id,
            description=f"Session: {self.name}",
            status="running",
            identity=self._identity,
        ))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            import time
            duration = int((time.time() - self._start_time) * 1000)
            events_in_session = self._chain._count - self._event_count_start
            self._chain.write(Event(
                type="session_end",
                framework="air_trust",
                session_id=self._session_id,
                description=f"Session: {self.name}",
                duration_ms=duration,
                status="error" if exc_type else "success",
                error=str(exc_val) if exc_val else None,
                identity=self._identity,
                meta={"events_recorded": events_in_session},
            ))
        finally:
            # v1.1: Always clear the active session_id, even if
            # session_end write fails. Prevents session_id leaking
            # into subsequent events in the same thread/context.
            _active_session_id.reset(self._session_token)
        return False  # Don't suppress exceptions

    @property
    def session_id(self) -> str:
        """The unique session ID for this session (v1.1)."""
        return self._session_id

    def log(self, message: str, *,
            risk_level: Optional[str] = None,
            meta: Optional[dict] = None):
        """Log a custom checkpoint event.

        Usage:
            with air_trust.session("pipeline") as s:
                s.log("User input received", risk_level="low")
                result = chain.invoke(...)
                s.log("Output generated", meta={"tokens": 150})
        """
        self._chain.write(Event(
            type="checkpoint",
            framework="air_trust",
            session_id=self._session_id,
            description=message,
            risk_level=risk_level,
            status="logged",
            identity=self._identity,
            meta=meta,
        ))

    def scan(self, text: str) -> dict:
        """Run PII + injection scan on arbitrary text.

        Returns dict with 'pii' and 'injection' results.

        Usage:
            with air_trust.session("pipeline") as s:
                results = s.scan(user_input)
                if results["injection"]["score"] > 0.7:
                    raise ValueError("Injection detected")
        """
        pii = scan_pii(text)
        inj, score = scan_injection(text)
        return {
            "pii": [{"type": a.type, "count": a.count} for a in pii],
            "injection": {
                "alerts": [{"pattern": a.pattern, "weight": a.weight} for a in inj],
                "score": score,
            },
        }

    def trust(self, obj: Any, **kwargs) -> Any:
        """Wrap an AI client within this session's chain.

        Usage:
            with air_trust.session("pipeline") as s:
                client = s.trust(OpenAI())
                client.chat.completions.create(...)
        """
        return trust(obj, chain=self._chain, **kwargs)


def session(name: str, chain: Optional[AuditChain] = None,
            identity: Optional[AgentIdentity] = None) -> AirTrustSession:
    """Create an audit session context manager.

    Usage:
        # Without identity
        with air_trust.session("my-pipeline") as s:
            client = s.trust(OpenAI())
            result = client.chat.completions.create(...)

        # With identity (Article 14 compliance)
        identity = AgentIdentity(
            agent_name="search-agent",
            owner="jason@airblackbox.ai",
        )
        with air_trust.session("search", identity=identity) as s:
            s.log("Search started")
    """
    return AirTrustSession(name, chain, identity)


# ── Utility Functions ───────────────────────────────────────────

def get_chain() -> AuditChain:
    """Get the global audit chain. Creates one if needed."""
    return _get_chain()


def get_identity() -> Optional[AgentIdentity]:
    """Get the current global agent identity, if one has been set."""
    return _global_identity


def verify() -> dict:
    """Verify the integrity and completeness of the global audit chain.

    Returns a dict with both integrity and completeness results.
    See AuditChain.verify() for the full output format.
    """
    return _get_chain().verify()


def stats() -> dict:
    """Get audit statistics.

    Returns:
        {
            "total_events": int,
            "chain_length": int,
            "chain_valid": bool,
            "frameworks_detected": [...],
            "adapters_active": [...],
        }
    """
    chain = _get_chain()
    installed = detect_installed()
    return {
        "total_events": chain._count,
        "chain_length": chain._count,
        "chain_valid": chain.verify()["integrity"]["valid"],
        "frameworks_detected": [f"{fid} ({atype})" for fid, atype in installed],
        "adapters_active": list(_adapters.keys()),
    }


def scan_text(text: str) -> dict:
    """Standalone PII + injection scan (no session needed).

    Usage:
        result = air_trust.scan_text(user_input)
        if result["injection"]["score"] > 0.7:
            print("Warning: possible injection")
    """
    pii = scan_pii(text)
    inj, score = scan_injection(text)
    return {
        "pii": [{"type": a.type, "count": a.count} for a in pii],
        "injection": {
            "alerts": [{"pattern": a.pattern, "weight": a.weight} for a in inj],
            "score": score,
        },
    }


def enforce(policy, *, chain: Optional[AuditChain] = None, on_violation: str = "block"):
    """Attach a policy to the trust layer.

    Policies enforce runtime rules on every event — block certain models,
    require identities, reject high injection scores, etc.

    Args:
        policy: A Policy object defining enforcement rules
        chain: Optional AuditChain (uses global if None)
        on_violation: "block" (raise exception), "warn" (log warning), or "log" (silent)

    Returns:
        PolicyEnforcer instance

    Usage:
        from air_trust import Policy, enforce

        policy = Policy(
            name="production",
            blocked_models=["gpt-3.5-turbo"],
            required_identity=True,
            max_injection_score=0.5,
        )

        enforcer = enforce(policy)
        enforcer.wrap_chain_write()
        # Now every event is checked against the policy
    """
    from air_trust.policy import PolicyEnforcer

    c = chain or _get_chain()
    return PolicyEnforcer(policy, c, on_violation=on_violation)
