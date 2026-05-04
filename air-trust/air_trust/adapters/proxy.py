"""
Proxy Adapter - intercepts LLM API calls at the HTTP/SDK level.

Covers: OpenAI, Anthropic, Google, Ollama, vLLM, LiteLLM, Together,
        Groq, Mistral, Cohere, and any SDK that calls an LLM endpoint.

Strategy: monkey-patch the client's create/generate method to wrap it
with timing, token counting, and audit logging.
"""

from __future__ import annotations
import time
import functools
from typing import Any, Optional, Callable

from air_trust.events import Event
from air_trust.scan import scan_pii, scan_injection
from air_trust.chain import AuditChain


class ProxyAdapter:
    """Wraps any LLM client to intercept API calls."""

    def __init__(self, chain: AuditChain, framework: str = "unknown"):
        self._chain = chain
        self._framework = framework
        self._event_count = 0

    def wrap_client(self, client: Any) -> Any:
        """Auto-detect client type and wrap the appropriate method."""
        module = type(client).__module__ or ""

        # OpenAI-style: client.chat.completions.create()
        if hasattr(client, "chat") and hasattr(client.chat, "completions"):
            self._wrap_openai(client)
            return client

        # Anthropic-style: client.messages.create()
        if hasattr(client, "messages") and hasattr(client.messages, "create"):
            self._wrap_anthropic(client)
            return client

        # Google-style: model.generate_content()
        if hasattr(client, "generate_content"):
            self._wrap_google(client)
            return client

        # Ollama-style: client.chat() or client.generate()
        if hasattr(client, "chat") and callable(client.chat):
            self._wrap_ollama(client)
            return client

        # LiteLLM-style: module-level completion()
        if "litellm" in module:
            self._wrap_litellm(client)
            return client

        # Generic: wrap any .create() or .generate() method
        for method_name in ("create", "generate", "invoke", "call", "run"):
            if hasattr(client, method_name) and callable(getattr(client, method_name)):
                self._wrap_method(client, method_name)
                return client

        return client

    def _make_wrapper(self, original: Callable, extract_fn: Callable) -> Callable:
        """Create a wrapper that logs to the audit chain."""
        adapter = self

        @functools.wraps(original)
        def wrapper(*args, **kwargs):
            start = time.time()
            error_msg = None
            result = None
            try:
                result = original(*args, **kwargs)
                return result
            except Exception as e:
                error_msg = str(e)
                raise
            finally:
                duration = int((time.time() - start) * 1000)
                event = extract_fn(args, kwargs, result, error_msg, duration)
                adapter._chain.write(event)
                adapter._event_count += 1

        return wrapper

    def _wrap_openai(self, client):
        original = client.chat.completions.create

        def extract(args, kwargs, result, error, duration):
            model = kwargs.get("model", "unknown")
            tokens = None
            cost = None
            if result and hasattr(result, "usage") and result.usage:
                tokens = {
                    "prompt": result.usage.prompt_tokens,
                    "completion": result.usage.completion_tokens,
                    "total": result.usage.total_tokens,
                }
                cost = _estimate_cost(model, tokens)

            # Scan the messages for PII/injection
            messages = kwargs.get("messages", [])
            text = " ".join(m.get("content", "") for m in messages if isinstance(m, dict))
            pii = scan_pii(text)
            inj, inj_score = scan_injection(text)

            return Event(
                type="llm_call",
                framework=self._framework or "openai",
                model=model,
                provider="openai",
                tokens=tokens,
                cost=cost,
                duration_ms=duration,
                status="error" if error else "success",
                error=error,
                pii_alerts=pii,
                injection_alerts=inj,
                injection_score=inj_score,
                input_preview=text[:500] if text else None,
            )

        client.chat.completions.create = self._make_wrapper(original, extract)

    def _wrap_anthropic(self, client):
        original = client.messages.create

        def extract(args, kwargs, result, error, duration):
            model = kwargs.get("model", "unknown")
            tokens = None
            cost = None
            if result and hasattr(result, "usage"):
                tokens = {
                    "prompt": result.usage.input_tokens,
                    "completion": result.usage.output_tokens,
                    "total": result.usage.input_tokens + result.usage.output_tokens,
                }
                cost = _estimate_cost(model, tokens)

            messages = kwargs.get("messages", [])
            text = " ".join(
                m.get("content", "") for m in messages
                if isinstance(m, dict) and isinstance(m.get("content"), str)
            )
            pii = scan_pii(text)
            inj, inj_score = scan_injection(text)

            return Event(
                type="llm_call",
                framework=self._framework or "anthropic",
                model=model,
                provider="anthropic",
                tokens=tokens,
                cost=cost,
                duration_ms=duration,
                status="error" if error else "success",
                error=error,
                pii_alerts=pii,
                injection_alerts=inj,
                injection_score=inj_score,
            )

        client.messages.create = self._make_wrapper(original, extract)

    def _wrap_google(self, client):
        original = client.generate_content

        def extract(args, kwargs, result, error, duration):
            model = getattr(client, "model_name", "unknown")
            tokens = None
            if result and hasattr(result, "usage_metadata"):
                u = result.usage_metadata
                tokens = {
                    "prompt": getattr(u, "prompt_token_count", 0),
                    "completion": getattr(u, "candidates_token_count", 0),
                    "total": getattr(u, "total_token_count", 0),
                }
            return Event(
                type="llm_call",
                framework=self._framework or "google",
                model=model,
                provider="google",
                tokens=tokens,
                duration_ms=duration,
                status="error" if error else "success",
                error=error,
            )

        client.generate_content = self._make_wrapper(original, extract)

    def _wrap_ollama(self, client):
        original = client.chat

        def extract(args, kwargs, result, error, duration):
            model = kwargs.get("model", "unknown")
            tokens = None
            if isinstance(result, dict):
                tokens = {
                    "prompt": result.get("prompt_eval_count", 0),
                    "completion": result.get("eval_count", 0),
                    "total": result.get("prompt_eval_count", 0) + result.get("eval_count", 0),
                }
            return Event(
                type="llm_call",
                framework=self._framework or "ollama",
                model=model,
                provider="local",
                tokens=tokens,
                duration_ms=duration,
                status="error" if error else "success",
                error=error,
            )

        client.chat = self._make_wrapper(original, extract)

    def _wrap_litellm(self, module):
        # LiteLLM uses module-level completion()
        if hasattr(module, "completion"):
            original = module.completion

            def extract(args, kwargs, result, error, duration):
                model = kwargs.get("model", args[0] if args else "unknown")
                tokens = None
                if result and hasattr(result, "usage"):
                    tokens = {
                        "prompt": result.usage.prompt_tokens,
                        "completion": result.usage.completion_tokens,
                        "total": result.usage.total_tokens,
                    }
                return Event(
                    type="llm_call",
                    framework="litellm",
                    model=model,
                    provider="litellm",
                    tokens=tokens,
                    duration_ms=duration,
                    status="error" if error else "success",
                    error=error,
                )

            module.completion = self._make_wrapper(original, extract)

    def _wrap_method(self, obj, method_name: str):
        """Generic wrapper for any .create()/.generate()/.run() method."""
        original = getattr(obj, method_name)

        def extract(args, kwargs, result, error, duration):
            return Event(
                type="llm_call",
                framework=self._framework,
                model=kwargs.get("model", "unknown"),
                provider="unknown",
                duration_ms=duration,
                status="error" if error else "success",
                error=error,
            )

        setattr(obj, method_name, self._make_wrapper(original, extract))

    @property
    def event_count(self) -> int:
        return self._event_count


# ── Cost Estimation ──────────────────────────────────────────
# Rough per-1K-token costs (input). Good enough for estimates.
_COST_MAP = {
    "gpt-4o": 0.0025, "gpt-4o-mini": 0.00015, "gpt-4-turbo": 0.01,
    "gpt-4": 0.03, "gpt-3.5-turbo": 0.0005,
    "claude-sonnet-4": 0.003, "claude-opus-4": 0.015, "claude-haiku-3.5": 0.0008,
    "gemini-1.5-pro": 0.00125, "gemini-1.5-flash": 0.000075,
    "command-r-plus": 0.003, "mistral-large": 0.004,
}


def _estimate_cost(model: str, tokens: dict) -> Optional[float]:
    """Estimate cost in USD from model name and token counts."""
    if not tokens:
        return None
    for key, rate in _COST_MAP.items():
        if key in model.lower():
            return round(tokens.get("total", 0) / 1000 * rate, 6)
    return None
