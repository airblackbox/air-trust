"""
OpenTelemetry Adapter — reads gen_ai spans from OTel-instrumented systems.

Covers: Semantic Kernel, any system already emitting OTel traces,
        enterprise observability stacks.

Strategy: register a SpanProcessor that converts gen_ai.* spans
into AIR Trust audit events as they complete.
"""

from __future__ import annotations
import time
from typing import Any, Optional

from air_trust.events import Event
from air_trust.chain import AuditChain


class OTelAdapter:
    """Reads OpenTelemetry spans and converts them to audit events."""

    def __init__(self, chain: AuditChain, framework: str = "otel"):
        self._chain = chain
        self._framework = framework
        self._event_count = 0

    def _record(self, event: Event):
        self._chain.write(event)
        self._event_count += 1

    @property
    def event_count(self) -> int:
        return self._event_count

    def as_span_processor(self):
        """Return an OTel SpanProcessor that writes to the audit chain.

        Usage:
            from opentelemetry import trace
            from opentelemetry.sdk.trace import TracerProvider
            from air_trust.adapters.otel import OTelAdapter

            adapter = OTelAdapter(chain)
            provider = TracerProvider()
            provider.add_span_processor(adapter.as_span_processor())
            trace.set_tracer_provider(provider)
        """
        try:
            from opentelemetry.sdk.trace import SpanProcessor
        except ImportError:
            return None

        adapter = self

        class AirTrustSpanProcessor(SpanProcessor):
            """Processes completed spans and writes audit events."""

            def on_start(self, span, parent_context=None):
                pass  # We only care about completed spans

            def on_end(self, span):
                attrs = dict(span.attributes or {})
                span_name = span.name or ""

                # Only process AI-related spans
                if not _is_ai_span(span_name, attrs):
                    return

                # Extract common attributes
                model = (
                    attrs.get("gen_ai.request.model")
                    or attrs.get("gen_ai.response.model")
                    or attrs.get("llm.model")
                    or "unknown"
                )

                # Calculate duration
                duration_ms = 0
                if span.start_time and span.end_time:
                    duration_ms = int((span.end_time - span.start_time) / 1_000_000)

                # Extract tokens
                tokens = _extract_tokens(attrs)

                # Determine event type
                event_type = _classify_span(span_name, attrs)

                # Check for errors
                status = "success"
                error = None
                if span.status and span.status.status_code:
                    try:
                        from opentelemetry.trace import StatusCode
                        if span.status.status_code == StatusCode.ERROR:
                            status = "error"
                            error = span.status.description
                    except ImportError:
                        if str(span.status.status_code) == "ERROR":
                            status = "error"
                            error = span.status.description

                # Build provider from attributes
                provider = attrs.get("gen_ai.system", adapter._framework)

                adapter._record(Event(
                    type=event_type,
                    framework=adapter._framework,
                    model=str(model),
                    provider=str(provider),
                    tokens=tokens,
                    duration_ms=duration_ms,
                    status=status,
                    error=error,
                    description=span_name,
                    trace_id=f"{span.context.trace_id:032x}" if span.context else None,
                    meta={k: str(v) for k, v in attrs.items() if k.startswith("gen_ai.")},
                ))

            def shutdown(self):
                pass

            def force_flush(self, timeout_millis=None):
                pass

        return AirTrustSpanProcessor()

    def wrap_semantic_kernel(self, kernel: Any) -> Any:
        """Set up OTel tracing for a Semantic Kernel instance.

        Semantic Kernel natively emits OTel spans. This method
        ensures our SpanProcessor is registered to capture them.

        Usage:
            from air_trust.adapters.otel import OTelAdapter
            adapter = OTelAdapter(chain, "semantic_kernel")
            kernel = adapter.wrap_semantic_kernel(kernel)
        """
        try:
            from opentelemetry import trace
            from opentelemetry.sdk.trace import TracerProvider

            # Get or create provider
            current = trace.get_tracer_provider()
            if isinstance(current, TracerProvider):
                provider = current
            else:
                provider = TracerProvider()
                trace.set_tracer_provider(provider)

            # Add our processor
            processor = self.as_span_processor()
            if processor:
                provider.add_span_processor(processor)

        except ImportError:
            pass  # OTel SDK not installed

        return kernel

    def process_span_data(self, span_data: dict) -> None:
        """Manually process span data from any source.

        For systems that export span data as dicts (e.g., from
        OTel collectors, log files, or custom exporters).

        Args:
            span_data: dict with keys like 'name', 'attributes',
                      'start_time', 'end_time', 'status'
        """
        attrs = span_data.get("attributes", {})
        span_name = span_data.get("name", "")

        if not _is_ai_span(span_name, attrs):
            return

        model = (
            attrs.get("gen_ai.request.model")
            or attrs.get("gen_ai.response.model")
            or "unknown"
        )

        duration_ms = 0
        start = span_data.get("start_time")
        end = span_data.get("end_time")
        if start and end:
            duration_ms = int((end - start) / 1_000_000)

        tokens = _extract_tokens(attrs)
        event_type = _classify_span(span_name, attrs)

        status_info = span_data.get("status", {})
        status = "error" if status_info.get("status_code") == "ERROR" else "success"
        error = status_info.get("description") if status == "error" else None

        self._record(Event(
            type=event_type,
            framework=self._framework,
            model=str(model),
            provider=str(attrs.get("gen_ai.system", "unknown")),
            tokens=tokens,
            duration_ms=duration_ms,
            status=status,
            error=error,
            description=span_name,
            trace_id=span_data.get("trace_id"),
        ))


# ── Helper functions ────────────────────────────────────────────

def _is_ai_span(name: str, attrs: dict) -> bool:
    """Check if a span is AI-related (worth auditing)."""
    name_lower = name.lower()
    ai_keywords = ("gen_ai", "llm", "chat", "completion", "embedding",
                   "retrieval", "tool", "agent", "invoke", "predict")

    if any(kw in name_lower for kw in ai_keywords):
        return True

    # Check attributes for gen_ai.* keys
    if any(k.startswith("gen_ai.") for k in attrs):
        return True

    return False


def _classify_span(name: str, attrs: dict) -> str:
    """Classify span into event type."""
    name_lower = name.lower()

    if any(kw in name_lower for kw in ("chat", "completion", "llm", "generate")):
        return "llm_call"
    if any(kw in name_lower for kw in ("embed",)):
        return "embedding"
    if any(kw in name_lower for kw in ("retriev",)):
        return "retrieval"
    if any(kw in name_lower for kw in ("tool",)):
        return "tool_call"
    if any(kw in name_lower for kw in ("agent",)):
        return "agent_end"

    # Check operation name attribute
    op = attrs.get("gen_ai.operation.name", "")
    if "chat" in op:
        return "llm_call"
    if "embed" in op:
        return "embedding"

    return "function_call"


def _extract_tokens(attrs: dict) -> Optional[dict]:
    """Extract token counts from span attributes."""
    prompt = (
        attrs.get("gen_ai.usage.prompt_tokens")
        or attrs.get("gen_ai.usage.input_tokens")
        or attrs.get("llm.token_count.prompt")
    )
    completion = (
        attrs.get("gen_ai.usage.completion_tokens")
        or attrs.get("gen_ai.usage.output_tokens")
        or attrs.get("llm.token_count.completion")
    )

    if prompt is not None or completion is not None:
        p = int(prompt or 0)
        c = int(completion or 0)
        return {"prompt": p, "completion": c, "total": p + c}

    return None
