"""
Callback Adapter — hooks into framework event systems.

Covers: LangChain, LangGraph, LlamaIndex, Haystack.

These frameworks fire events (on_llm_start, on_tool_end, etc.)
that we listen to and convert into audit records.
"""

from __future__ import annotations
import time
from typing import Any, Optional

from air_trust.events import Event
from air_trust.scan import scan_pii, scan_injection
from air_trust.chain import AuditChain


class CallbackAdapter:
    """Base callback adapter. Framework shims inherit from this."""

    def __init__(self, chain: AuditChain, framework: str = "unknown"):
        self._chain = chain
        self._framework = framework
        self._event_count = 0
        self._active_spans = {}  # trace_id -> start_time

    def _record(self, event: Event):
        """Write event to chain."""
        self._chain.write(event)
        self._event_count += 1

    @property
    def event_count(self) -> int:
        return self._event_count


class LangChainCallback(CallbackAdapter):
    """LangChain/LangGraph callback handler.

    Usage:
        from air_trust.adapters.callback import LangChainCallback
        cb = LangChainCallback(chain)
        handler = cb.as_handler()
        chain.invoke(input, config={"callbacks": [handler]})
    """

    def __init__(self, chain: AuditChain):
        super().__init__(chain, "langchain")

    def as_handler(self):
        """Return a LangChain-compatible BaseCallbackHandler."""
        try:
            from langchain_core.callbacks import BaseCallbackHandler
        except ImportError:
            from langchain.callbacks.base import BaseCallbackHandler

        adapter = self

        class _Handler(BaseCallbackHandler):
            name = "air_trust"

            def on_llm_start(self, serialized, prompts, **kwargs):
                run_id = str(kwargs.get("run_id", ""))
                adapter._active_spans[run_id] = time.time()

            def on_llm_end(self, response, **kwargs):
                run_id = str(kwargs.get("run_id", ""))
                start = adapter._active_spans.pop(run_id, time.time())
                duration = int((time.time() - start) * 1000)

                tokens = None
                model = "unknown"
                if hasattr(response, "llm_output") and response.llm_output:
                    usage = response.llm_output.get("token_usage", {})
                    if usage:
                        tokens = {
                            "prompt": usage.get("prompt_tokens", 0),
                            "completion": usage.get("completion_tokens", 0),
                            "total": usage.get("total_tokens", 0),
                        }
                    model = response.llm_output.get("model_name", "unknown")

                adapter._record(Event(
                    type="llm_call",
                    framework="langchain",
                    model=model,
                    tokens=tokens,
                    duration_ms=duration,
                    status="success",
                ))

            def on_llm_error(self, error, **kwargs):
                run_id = str(kwargs.get("run_id", ""))
                start = adapter._active_spans.pop(run_id, time.time())
                adapter._record(Event(
                    type="llm_call",
                    framework="langchain",
                    duration_ms=int((time.time() - start) * 1000),
                    status="error",
                    error=str(error),
                ))

            def on_tool_start(self, serialized, input_str, **kwargs):
                run_id = str(kwargs.get("run_id", ""))
                adapter._active_spans[run_id] = time.time()
                # Scan tool input
                pii = scan_pii(input_str)
                inj, score = scan_injection(input_str)
                if pii or inj:
                    adapter._record(Event(
                        type="tool_call",
                        framework="langchain",
                        tool_name=serialized.get("name", "unknown"),
                        status="scanned",
                        pii_alerts=pii,
                        injection_alerts=inj,
                        injection_score=score,
                        input_preview=input_str[:500],
                    ))

            def on_tool_end(self, output, **kwargs):
                run_id = str(kwargs.get("run_id", ""))
                start = adapter._active_spans.pop(run_id, time.time())
                adapter._record(Event(
                    type="tool_call",
                    framework="langchain",
                    duration_ms=int((time.time() - start) * 1000),
                    status="success",
                    output_preview=str(output)[:500],
                ))

            def on_tool_error(self, error, **kwargs):
                run_id = str(kwargs.get("run_id", ""))
                adapter._active_spans.pop(run_id, None)
                adapter._record(Event(
                    type="tool_call",
                    framework="langchain",
                    status="error",
                    error=str(error),
                ))

        return _Handler()


class LlamaIndexCallback(CallbackAdapter):
    """LlamaIndex callback handler.

    Usage:
        from air_trust.adapters.callback import LlamaIndexCallback
        cb = LlamaIndexCallback(chain)
        handler = cb.as_handler()
        # Set globally or pass per-query
    """

    def __init__(self, chain: AuditChain):
        super().__init__(chain, "llamaindex")

    def as_handler(self):
        """Return a LlamaIndex-compatible callback handler."""
        try:
            from llama_index.core.callbacks import CBEventType, CallbackManager
            from llama_index.core.callbacks.base_handler import BaseCallbackHandler
        except ImportError:
            return None  # LlamaIndex not installed

        adapter = self

        class _Handler(BaseCallbackHandler):
            def on_event_start(self, event_type, payload=None, event_id="", **kwargs):
                adapter._active_spans[event_id] = time.time()

            def on_event_end(self, event_type, payload=None, event_id="", **kwargs):
                start = adapter._active_spans.pop(event_id, time.time())
                duration = int((time.time() - start) * 1000)
                etype = str(event_type)

                if "LLM" in etype:
                    adapter._record(Event(
                        type="llm_call", framework="llamaindex",
                        duration_ms=duration, status="success",
                    ))
                elif "RETRIEV" in etype:
                    adapter._record(Event(
                        type="retrieval", framework="llamaindex",
                        duration_ms=duration, status="success",
                    ))
                else:
                    adapter._record(Event(
                        type="function_call", framework="llamaindex",
                        description=etype, duration_ms=duration, status="success",
                    ))

            def start_trace(self, trace_id=None):
                pass

            def end_trace(self, trace_id=None, trace_map=None):
                pass

        return _Handler()


class HaystackCallback(CallbackAdapter):
    """Haystack pipeline tracer.

    Usage:
        from air_trust.adapters.callback import HaystackCallback
        cb = HaystackCallback(chain)
        tracer = cb.as_tracer()
    """

    def __init__(self, chain: AuditChain):
        super().__init__(chain, "haystack")

    def as_tracer(self):
        """Return a Haystack-compatible Tracer."""
        try:
            from haystack.tracing import Tracer
        except ImportError:
            return None

        adapter = self

        class _Tracer(Tracer):
            def trace(self, operation_name, tags=None):
                return _Span(adapter, operation_name, tags)

        class _Span:
            def __init__(self, adapter, op, tags):
                self._adapter = adapter
                self._op = op
                self._tags = tags or {}
                self._start = time.time()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                duration = int((time.time() - self._start) * 1000)
                adapter._record(Event(
                    type="function_call", framework="haystack",
                    description=self._op, duration_ms=duration,
                    status="success", meta=self._tags,
                ))

            def set_tag(self, key, value):
                self._tags[key] = value

        return _Tracer()
