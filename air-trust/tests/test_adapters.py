"""Tests for all 5 adapter types."""

import os
import pytest
from air_trust.chain import AuditChain
from air_trust.events import Event


@pytest.fixture
def chain(tmp_path):
    return AuditChain(
        db_path=os.path.join(str(tmp_path), "events.db"),
        signing_key="test-key",
    )


# ── Proxy Adapter Tests ────────────────────────────────────────

class TestProxyAdapter:
    """Test the proxy adapter (OpenAI, Anthropic, etc.)."""

    def test_import(self):
        from air_trust.adapters.proxy import ProxyAdapter
        assert ProxyAdapter is not None

    def test_create_adapter(self, chain):
        from air_trust.adapters.proxy import ProxyAdapter
        adapter = ProxyAdapter(chain, "openai")
        assert adapter.event_count == 0

    def test_wrap_unknown_client(self, chain):
        """Wrapping an unknown object should not crash."""
        from air_trust.adapters.proxy import ProxyAdapter
        adapter = ProxyAdapter(chain, "unknown")

        class FakeClient:
            pass

        result = adapter.wrap_client(FakeClient())
        assert result is not None

    def test_wrap_generic_client(self, chain):
        """Should wrap objects that have create/generate methods."""
        from air_trust.adapters.proxy import ProxyAdapter
        adapter = ProxyAdapter(chain, "generic")

        class FakeClient:
            def create(self, **kwargs):
                return {"result": "ok"}

        client = FakeClient()
        wrapped = adapter.wrap_client(client)
        assert wrapped is not None


# ── Callback Adapter Tests ──────────────────────────────────────

class TestCallbackAdapter:
    """Test the callback adapter (LangChain, LlamaIndex, Haystack)."""

    def test_import(self):
        from air_trust.adapters.callback import (
            LangChainCallback, LlamaIndexCallback, HaystackCallback
        )
        assert LangChainCallback is not None

    def test_langchain_callback_creation(self, chain):
        from air_trust.adapters.callback import LangChainCallback
        cb = LangChainCallback(chain)
        assert cb.event_count == 0

    def test_langchain_as_handler(self, chain):
        """as_handler() should return handler or raise ImportError if langchain not installed."""
        from air_trust.adapters.callback import LangChainCallback
        cb = LangChainCallback(chain)
        try:
            handler = cb.as_handler()
            # If langchain is installed, handler should be truthy
            assert handler is not None
        except (ImportError, ModuleNotFoundError):
            # Expected if langchain not installed
            pass

    def test_llamaindex_callback_creation(self, chain):
        from air_trust.adapters.callback import LlamaIndexCallback
        cb = LlamaIndexCallback(chain)
        assert cb.event_count == 0

    def test_haystack_callback_creation(self, chain):
        from air_trust.adapters.callback import HaystackCallback
        cb = HaystackCallback(chain)
        assert cb.event_count == 0


# ── Decorator Adapter Tests ─────────────────────────────────────

class TestDecoratorAdapter:
    """Test the decorator adapter (CrewAI, Smolagents, DSPy, etc.)."""

    def test_import(self):
        from air_trust.adapters.decorator import DecoratorAdapter
        assert DecoratorAdapter is not None

    def test_trace_sync_function(self, chain):
        """@trace should wrap sync functions."""
        from air_trust.adapters.decorator import DecoratorAdapter
        adapter = DecoratorAdapter(chain, "test")

        @adapter.trace()
        def multiply(a, b):
            return a * b

        result = multiply(3, 5)
        assert result == 15
        assert adapter.event_count == 1

    def test_trace_with_custom_event_type(self, chain):
        from air_trust.adapters.decorator import DecoratorAdapter
        adapter = DecoratorAdapter(chain, "test")

        @adapter.trace(event_type="llm_call")
        def call_model(prompt):
            return "response"

        call_model("hello")
        assert adapter.event_count == 1

    def test_trace_captures_exception(self, chain):
        from air_trust.adapters.decorator import DecoratorAdapter
        adapter = DecoratorAdapter(chain, "test")

        @adapter.trace()
        def bad_function():
            raise TypeError("oops")

        with pytest.raises(TypeError):
            bad_function()

        assert adapter.event_count == 1

    def test_trace_no_scan(self, chain):
        from air_trust.adapters.decorator import DecoratorAdapter
        adapter = DecoratorAdapter(chain, "test")

        @adapter.trace(scan=False)
        def process(text):
            return text

        process("my SSN is 123-45-6789")
        assert adapter.event_count == 1

    def test_wrap_crewai_no_crash(self, chain):
        from air_trust.adapters.decorator import DecoratorAdapter
        adapter = DecoratorAdapter(chain, "crewai")

        class FakeNonCrew:
            pass

        result = adapter.wrap_crewai(FakeNonCrew())
        assert result is not None

    def test_wrap_crewai_with_kickoff(self, chain):
        from air_trust.adapters.decorator import DecoratorAdapter
        adapter = DecoratorAdapter(chain, "crewai")

        class FakeCrew:
            tasks = []
            def kickoff(self):
                return "crew result"

        crew = FakeCrew()
        wrapped = adapter.wrap_crewai(crew)
        result = wrapped.kickoff()
        assert result == "crew result"
        assert adapter.event_count == 2  # start + end

    def test_wrap_smolagents(self, chain):
        from air_trust.adapters.decorator import DecoratorAdapter
        adapter = DecoratorAdapter(chain, "smolagents")

        class FakeAgent:
            def run(self, task):
                return f"did: {task}"

        agent = FakeAgent()
        wrapped = adapter.wrap_smolagents(agent)
        result = wrapped.run("test task")
        assert result == "did: test task"
        assert adapter.event_count == 2  # start + end

    def test_wrap_dspy(self, chain):
        from air_trust.adapters.decorator import DecoratorAdapter
        adapter = DecoratorAdapter(chain, "dspy")

        class FakeModule:
            def forward(self, question):
                return f"answer to {question}"

        module = FakeModule()
        wrapped = adapter.wrap_dspy(module)
        result = wrapped.forward("what is AI?")
        assert result == "answer to what is AI?"
        assert adapter.event_count == 1

    def test_wrap_autogen(self, chain):
        from air_trust.adapters.decorator import DecoratorAdapter
        adapter = DecoratorAdapter(chain, "autogen")

        class FakeAgent:
            name = "test_agent"
            def generate_reply(self, messages=None, sender=None):
                return "reply"

        agent = FakeAgent()
        wrapped = adapter.wrap_autogen(agent)
        result = wrapped.generate_reply(messages=[])
        assert result == "reply"
        assert adapter.event_count == 1


# ── OTel Adapter Tests ──────────────────────────────────────────

class TestOTelAdapter:
    """Test the OpenTelemetry adapter."""

    def test_import(self):
        from air_trust.adapters.otel import OTelAdapter
        assert OTelAdapter is not None

    def test_create_adapter(self, chain):
        from air_trust.adapters.otel import OTelAdapter
        adapter = OTelAdapter(chain, "semantic_kernel")
        assert adapter.event_count == 0

    def test_process_span_data(self, chain):
        from air_trust.adapters.otel import OTelAdapter
        adapter = OTelAdapter(chain, "otel")

        span_data = {
            "name": "gen_ai.chat.completion",
            "attributes": {
                "gen_ai.request.model": "gpt-4o",
                "gen_ai.system": "openai",
                "gen_ai.usage.prompt_tokens": 100,
                "gen_ai.usage.completion_tokens": 50,
            },
            "start_time": 1000000000,
            "end_time": 1500000000,
            "status": {"status_code": "OK"},
        }

        adapter.process_span_data(span_data)
        assert adapter.event_count == 1

    def test_non_ai_span_ignored(self, chain):
        from air_trust.adapters.otel import OTelAdapter
        adapter = OTelAdapter(chain, "otel")

        span_data = {
            "name": "http.request",
            "attributes": {"http.method": "GET"},
        }

        adapter.process_span_data(span_data)
        assert adapter.event_count == 0


# ── MCP Adapter Tests ───────────────────────────────────────────

class TestMCPAdapter:
    """Test the MCP protocol adapter."""

    def test_import(self):
        from air_trust.adapters.mcp import MCPAdapter
        assert MCPAdapter is not None

    def test_create_adapter(self, chain):
        from air_trust.adapters.mcp import MCPAdapter
        adapter = MCPAdapter(chain, "mcp")
        assert adapter.event_count == 0

    def test_log_request(self, chain):
        from air_trust.adapters.mcp import MCPAdapter
        adapter = MCPAdapter(chain, "mcp")

        adapter.log_request("tools/call", {"name": "search", "arguments": {"query": "test"}})
        assert adapter.event_count == 1

    def test_log_response(self, chain):
        from air_trust.adapters.mcp import MCPAdapter
        adapter = MCPAdapter(chain, "mcp")

        adapter.log_response("tools/call", result="found 5 items", duration_ms=150)
        assert adapter.event_count == 1

    def test_log_request_with_pii(self, chain):
        from air_trust.adapters.mcp import MCPAdapter
        adapter = MCPAdapter(chain, "mcp")

        adapter.log_request("tools/call", {
            "name": "send_email",
            "arguments": {"to": "test@example.com", "body": "SSN: 123-45-6789"},
        })
        assert adapter.event_count == 1

    def test_wrap_tool_handler_sync(self, chain):
        from air_trust.adapters.mcp import MCPAdapter
        adapter = MCPAdapter(chain, "mcp")

        @adapter.wrap_tool_handler("search")
        def handle_search(arguments):
            return f"found: {arguments.get('query', '')}"

        result = handle_search({"query": "test"})
        assert result == "found: test"
        assert adapter.event_count == 1

    def test_wrap_tool_handler_error(self, chain):
        from air_trust.adapters.mcp import MCPAdapter
        adapter = MCPAdapter(chain, "mcp")

        @adapter.wrap_tool_handler("failing_tool")
        def handle_fail(arguments):
            raise RuntimeError("tool broke")

        with pytest.raises(RuntimeError, match="tool broke"):
            handle_fail({})

        assert adapter.event_count == 1
