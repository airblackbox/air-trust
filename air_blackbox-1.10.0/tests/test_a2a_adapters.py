"""
Tests for AIR Blackbox A2A Framework Adapters.

These tests cover:
- A2ALangChainHandler: LangChain callback handler for transaction recording
- A2AOpenAIWrapper: OpenAI client wrapper for transaction recording
- A2ACrewAIAdapter: CrewAI crew execution wrapper
- A2AAutoGenAdapter: AutoGen agent wrapper (legacy and modern versions)

All tests use mock objects for external frameworks to avoid dependencies.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, Mock, patch

import pytest

# Import the adapters under test
from air_blackbox.a2a.adapters.langchain_adapter import A2ALangChainHandler
from air_blackbox.a2a.adapters.openai_adapter import A2AOpenAIWrapper
from air_blackbox.a2a.adapters.crewai_adapter import A2ACrewAIAdapter
from air_blackbox.a2a.adapters.autogen_adapter import A2AAutoGenAdapter
from air_blackbox.a2a.gateway import A2AGateway


# ============================================================================
# Mock Classes
# ============================================================================


class MockLLMResponse:
    """Fake LangChain LLM response object."""

    def __init__(self, text: str):
        self.generations = [[type("Gen", (), {"text": text})()]]


class MockToolOutput:
    """Fake tool output object."""

    def __init__(self, text: str):
        self.output = text


class MockOpenAIMessage:
    """Fake OpenAI message object."""

    def __init__(self, content: str):
        self.content = content


class MockOpenAIChoice:
    """Fake OpenAI choice object."""

    def __init__(self, content: str):
        self.message = MockOpenAIMessage(content)


class MockOpenAIResponse:
    """Fake OpenAI API response."""

    def __init__(self, content: str = "test response"):
        self.choices = [MockOpenAIChoice(content)]


class MockOpenAIClient:
    """Fake OpenAI client that doesn't require the actual library."""

    class chat:
        class completions:
            @staticmethod
            def create(**kwargs) -> MockOpenAIResponse:
                return MockOpenAIResponse("mocked response")


class MockCrewAITask:
    """Mock CrewAI task object."""

    def __init__(self, description: str):
        self.description = description


class MockCrewAICrew:
    """Mock CrewAI crew object."""

    def __init__(self, tasks: Optional[List[MockCrewAITask]] = None):
        self.tasks = tasks or []
        self._original_kickoff_called = False

    def kickoff(self):
        """Mock kickoff method that returns a result."""
        self._original_kickoff_called = True
        return {"output": "crew execution result"}


class MockAutoGenAgent:
    """Mock legacy AutoGen agent (v0.2.x with generate_reply)."""

    def __init__(self, name: str = "agent"):
        self.name = name
        self.generate_reply = MagicMock(return_value={"content": "agent response"})


class MockAutoGenModernAgent:
    """Mock modern AutoGen agent (v0.4+ with on_messages)."""

    def __init__(self, name: str = "agent"):
        self.name = name
        self.on_messages = MagicMock(return_value="agent response")


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_ledger_dir():
    """Create a temporary ledger directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def gateway(temp_ledger_dir):
    """Create an A2AGateway for testing."""
    return A2AGateway(
        agent_id="test-agent",
        agent_name="Test Agent",
        framework="test",
        ledger_dir=temp_ledger_dir,
        signing_key="test-key-adapters",
    )


# ============================================================================
# A2ALangChainHandler Tests
# ============================================================================


class TestA2ALangChainHandler:
    """Tests for the LangChain callback handler."""

    def test_handler_creation_with_gateway(self, gateway):
        """Test creating a handler with an explicit gateway."""
        handler = A2ALangChainHandler(
            agent_id="test-agent",
            agent_name="Test Agent",
            gateway=gateway,
        )
        assert handler.agent_id == "test-agent"
        assert handler.agent_name == "Test Agent"
        assert handler.gateway == gateway

    def test_handler_creation_without_gateway(self, temp_ledger_dir):
        """Test creating a handler without an explicit gateway."""
        handler = A2ALangChainHandler(
            agent_id="test-agent",
            agent_name="Test Agent",
            ledger_dir=temp_ledger_dir,
            signing_key="test-key",
        )
        assert handler.gateway is not None
        assert handler.gateway.agent_id == "test-agent"

    def test_on_llm_start_records_request(self, gateway):
        """Test that on_llm_start records a request transaction."""
        handler = A2ALangChainHandler(gateway=gateway)

        prompts = ["What is AI?", "Explain machine learning"]
        serialized = {"id": ["gpt-4"]}

        handler.on_llm_start(
            serialized=serialized,
            prompts=prompts,
            run_id="run-1",
        )

        # Check that the gateway recorded a message
        stats = gateway.stats
        assert stats["messages_sent"] == 1

    def test_on_llm_end_records_response(self, gateway):
        """Test that on_llm_end records a response transaction."""
        handler = A2ALangChainHandler(gateway=gateway)

        # First send a request
        handler.on_llm_start(
            serialized={"id": ["gpt-4"]},
            prompts=["Hello"],
            run_id="run-1",
        )

        # Then end with a response
        response = MockLLMResponse("Hello, I am an AI assistant!")
        handler.on_llm_end(response, run_id="run-1")

        stats = gateway.stats
        assert stats["messages_sent"] == 1
        assert stats["messages_received"] == 1

    def test_on_llm_error_records_error(self, gateway):
        """Test that on_llm_error records an error transaction."""
        handler = A2ALangChainHandler(gateway=gateway)

        error = ValueError("API rate limit exceeded")
        handler.on_llm_error(error, run_id="run-1")

        stats = gateway.stats
        assert stats["messages_received"] == 1

    def test_on_tool_start_records_tool_call(self, gateway):
        """Test that on_tool_start records a tool call transaction."""
        handler = A2ALangChainHandler(gateway=gateway)

        serialized = {"name": "search_tool"}
        handler.on_tool_start(
            serialized=serialized,
            input_str='{"query": "climate change"}',
            run_id="run-2",
        )

        stats = gateway.stats
        assert stats["messages_sent"] == 1

    def test_on_tool_end_records_tool_result(self, gateway):
        """Test that on_tool_end records a tool result transaction."""
        handler = A2ALangChainHandler(gateway=gateway)

        # Record tool start
        handler.on_tool_start(
            serialized={"name": "search_tool"},
            input_str="climate",
            run_id="run-2",
        )

        # Record tool end
        handler.on_tool_end("Found 42 results about climate", run_id="run-2")

        stats = gateway.stats
        assert stats["messages_sent"] == 1
        assert stats["messages_received"] == 1

    def test_on_tool_error_records_error(self, gateway):
        """Test that on_tool_error records an error transaction."""
        handler = A2ALangChainHandler(gateway=gateway)

        error = RuntimeError("Tool execution failed")
        handler.on_tool_error(error, run_id="run-2")

        stats = gateway.stats
        assert stats["messages_received"] == 1

    def test_multiple_callbacks_tracked_independently(self, gateway):
        """Test that multiple callback sequences are tracked."""
        handler = A2ALangChainHandler(gateway=gateway)

        # First LLM call
        handler.on_llm_start(
            serialized={"id": ["gpt-4"]},
            prompts=["First prompt"],
            run_id="run-1",
        )
        handler.on_llm_end(MockLLMResponse("First response"), run_id="run-1")

        # Second LLM call
        handler.on_llm_start(
            serialized={"id": ["gpt-4"]},
            prompts=["Second prompt"],
            run_id="run-2",
        )
        handler.on_llm_end(MockLLMResponse("Second response"), run_id="run-2")

        stats = gateway.stats
        assert stats["messages_sent"] == 2
        assert stats["messages_received"] == 2

    def test_llm_end_with_malformed_response(self, gateway):
        """Test that on_llm_end handles malformed responses gracefully."""
        handler = A2ALangChainHandler(gateway=gateway)

        # Send with a response that doesn't have the expected structure
        malformed_response = Mock()
        handler.on_llm_end(malformed_response, run_id="run-1")

        stats = gateway.stats
        assert stats["messages_received"] == 1


# ============================================================================
# A2AOpenAIWrapper Tests
# ============================================================================


class TestA2AOpenAIWrapper:
    """Tests for the OpenAI client wrapper."""

    def test_wrapper_creation_with_gateway(self, gateway):
        """Test creating a wrapper with an explicit gateway."""
        client = MockOpenAIClient()
        wrapper = A2AOpenAIWrapper(
            client=client,
            agent_id="openai-agent",
            agent_name="OpenAI Agent",
            gateway=gateway,
        )
        assert wrapper.agent_id == "openai-agent"
        assert wrapper.gateway == gateway

    def test_wrapper_creation_without_gateway(self, temp_ledger_dir):
        """Test creating a wrapper without an explicit gateway."""
        client = MockOpenAIClient()
        wrapper = A2AOpenAIWrapper(
            client=client,
            agent_id="openai-agent",
            agent_name="OpenAI Agent",
            ledger_dir=temp_ledger_dir,
            signing_key="test-key",
        )
        assert wrapper.gateway is not None
        assert wrapper.gateway.agent_id == "openai-agent"

    def test_create_proxies_to_client(self, gateway):
        """Test that create() calls the underlying client."""
        client = MockOpenAIClient()
        wrapper = A2AOpenAIWrapper(client=client, gateway=gateway)

        response = wrapper.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Hello"}],
        )

        # Verify response is returned unchanged
        assert response.choices[0].message.content == "mocked response"

    def test_create_records_request_and_response(self, gateway):
        """Test that create() records both request and response."""
        client = MockOpenAIClient()
        wrapper = A2AOpenAIWrapper(client=client, gateway=gateway)

        wrapper.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Hello"}],
        )

        stats = gateway.stats
        assert stats["messages_sent"] == 1
        assert stats["messages_received"] == 1

    def test_create_with_multiple_messages(self, gateway):
        """Test create() with a conversation."""
        client = MockOpenAIClient()
        wrapper = A2AOpenAIWrapper(client=client, gateway=gateway)

        messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"},
            {"role": "user", "content": "How are you?"},
        ]

        wrapper.create(model="gpt-4", messages=messages)

        stats = gateway.stats
        assert stats["messages_sent"] == 1
        assert stats["messages_received"] == 1

    def test_create_handles_empty_response(self, gateway):
        """Test create() with an empty response."""
        client = MagicMock()
        client.chat.completions.create = MagicMock(
            return_value=type("Response", (), {"choices": []})()
        )

        wrapper = A2AOpenAIWrapper(client=client, gateway=gateway)
        response = wrapper.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "test"}],
        )

        # Should not crash
        stats = gateway.stats
        assert stats["messages_sent"] == 1
        assert stats["messages_received"] == 1

    def test_send_to_agent(self, gateway):
        """Test send_to_agent for inter-agent communication."""
        client = MockOpenAIClient()
        wrapper = A2AOpenAIWrapper(client=client, gateway=gateway)

        result = wrapper.send_to_agent(
            content=b"Handoff to CrewAI",
            receiver_id="crewai-agent",
            receiver_name="CrewAI Research",
            receiver_framework="crewai",
            message_type="handoff",
        )

        assert result.record is not None
        stats = gateway.stats
        assert stats["messages_sent"] == 1

    def test_receive_from_agent(self, gateway):
        """Test receive_from_agent for inter-agent communication."""
        client = MockOpenAIClient()
        wrapper = A2AOpenAIWrapper(client=client, gateway=gateway)

        result = wrapper.receive_from_agent(
            content=b"Result from research",
            sender_id="crewai-agent",
            sender_name="CrewAI Research",
            sender_framework="crewai",
            message_type="handoff",
        )

        assert result.record is not None
        stats = gateway.stats
        assert stats["messages_received"] == 1


# ============================================================================
# A2ACrewAIAdapter Tests
# ============================================================================


class TestA2ACrewAIAdapter:
    """Tests for the CrewAI crew wrapper."""

    def test_adapter_creation_with_gateway(self, gateway):
        """Test creating an adapter with an explicit gateway."""
        adapter = A2ACrewAIAdapter(
            agent_id="crewai-crew",
            agent_name="Research Crew",
            gateway=gateway,
        )
        assert adapter.agent_id == "crewai-crew"
        assert adapter.agent_name == "Research Crew"
        assert adapter.gateway == gateway

    def test_adapter_creation_without_gateway(self, temp_ledger_dir):
        """Test creating an adapter without an explicit gateway."""
        adapter = A2ACrewAIAdapter(
            agent_id="crewai-crew",
            agent_name="Research Crew",
            ledger_dir=temp_ledger_dir,
            signing_key="test-key",
        )
        assert adapter.gateway is not None
        assert adapter.gateway.agent_id == "crewai-crew"

    def test_wrap_modifies_crew_object(self, gateway):
        """Test that wrap() modifies the crew's kickoff method."""
        adapter = A2ACrewAIAdapter(gateway=gateway)
        crew = MockCrewAICrew()

        original_kickoff = crew.kickoff
        wrapped_crew = adapter.wrap(crew)

        # Verify that the kickoff method was replaced
        assert crew.kickoff != original_kickoff
        assert wrapped_crew == crew

    def test_wrapped_kickoff_returns_result(self, gateway):
        """Test that wrapped kickoff still returns the result."""
        adapter = A2ACrewAIAdapter(gateway=gateway)
        crew = MockCrewAICrew()
        adapter.wrap(crew)

        result = crew.kickoff()

        assert result == {"output": "crew execution result"}
        assert crew._original_kickoff_called

    def test_wrapped_kickoff_records_transaction(self, gateway):
        """Test that wrapped kickoff records a transaction."""
        adapter = A2ACrewAIAdapter(gateway=gateway)
        crew = MockCrewAICrew(tasks=[MockCrewAITask("Research task")])
        adapter.wrap(crew)

        crew.kickoff()

        stats = gateway.stats
        assert stats["messages_sent"] == 1

    def test_adapter_tracks_task_count(self, gateway):
        """Test that the adapter tracks task count in stats."""
        adapter = A2ACrewAIAdapter(gateway=gateway)
        crew = MockCrewAICrew()
        adapter.wrap(crew)

        crew.kickoff()

        stats = adapter.stats
        assert stats["tasks_recorded"] == 1

    def test_stats_include_gateway_stats(self, gateway):
        """Test that adapter stats include gateway stats."""
        adapter = A2ACrewAIAdapter(gateway=gateway)
        crew = MockCrewAICrew()
        adapter.wrap(crew)

        crew.kickoff()

        stats = adapter.stats
        assert "tasks_recorded" in stats
        assert "messages_sent" in stats
        assert "messages_received" in stats

    def test_send_to_agent(self, gateway):
        """Test send_to_agent for delegation."""
        adapter = A2ACrewAIAdapter(gateway=gateway)

        result = adapter.send_to_agent(
            content=b"Delegate to external agent",
            receiver_id="external-agent",
            receiver_name="External Agent",
            receiver_framework="langchain",
            message_type="handoff",
        )

        assert result.record is not None
        stats = gateway.stats
        assert stats["messages_sent"] == 1

    def test_receive_from_agent(self, gateway):
        """Test receive_from_agent for delegation results."""
        adapter = A2ACrewAIAdapter(gateway=gateway)

        result = adapter.receive_from_agent(
            content=b"Result from delegation",
            sender_id="external-agent",
            sender_name="External Agent",
            sender_framework="langchain",
            message_type="handoff",
        )

        assert result.record is not None
        stats = gateway.stats
        assert stats["messages_received"] == 1


# ============================================================================
# A2AAutoGenAdapter Tests
# ============================================================================


class TestA2AAutoGenAdapter:
    """Tests for the AutoGen agent wrapper."""

    def test_adapter_creation_with_gateway(self, gateway):
        """Test creating an adapter with an explicit gateway."""
        adapter = A2AAutoGenAdapter(
            agent_id="autogen-agent",
            agent_name="AutoGen Agent",
            gateway=gateway,
        )
        assert adapter.agent_id == "autogen-agent"
        assert adapter.gateway == gateway

    def test_adapter_creation_without_gateway(self, temp_ledger_dir):
        """Test creating an adapter without an explicit gateway."""
        adapter = A2AAutoGenAdapter(
            agent_id="autogen-agent",
            agent_name="AutoGen Agent",
            ledger_dir=temp_ledger_dir,
            signing_key="test-key",
        )
        assert adapter.gateway is not None

    def test_wrap_detects_legacy_autogen(self, gateway):
        """Test that wrap() detects legacy pyautogen agents."""
        adapter = A2AAutoGenAdapter(gateway=gateway)
        agent = MockAutoGenAgent(name="assistant")

        # Should wrap without error
        wrapped = adapter.wrap(agent)
        assert wrapped == agent

    def test_wrap_detects_modern_autogen(self, gateway):
        """Test that wrap() detects modern autogen-agentchat agents."""
        adapter = A2AAutoGenAdapter(gateway=gateway)
        agent = MockAutoGenModernAgent(name="assistant")

        # Should wrap without error
        wrapped = adapter.wrap(agent)
        assert wrapped == agent

    def test_wrap_raises_on_unsupported_agent(self, gateway):
        """Test that wrap() raises on unsupported agent types."""
        adapter = A2AAutoGenAdapter(gateway=gateway)

        # Create an agent with neither generate_reply nor on_messages
        bad_agent = Mock()
        del bad_agent.generate_reply  # Ensure it doesn't have the method
        del bad_agent.on_messages

        with pytest.raises(ValueError):
            adapter.wrap(bad_agent)

    def test_legacy_generate_reply_instrumented(self, gateway):
        """Test that legacy generate_reply is instrumented."""
        adapter = A2AAutoGenAdapter(gateway=gateway)
        agent = MockAutoGenAgent()

        original_generate_reply = agent.generate_reply
        adapter.wrap(agent)

        # Calling the instrumented method should still work
        messages = [{"content": "Hello"}]
        result = agent.generate_reply(messages=messages, sender=None)

        assert result == {"content": "agent response"}
        original_generate_reply.assert_called()

    def test_legacy_agent_records_messages(self, gateway):
        """Test that legacy agents record incoming and outgoing messages."""
        adapter = A2AAutoGenAdapter(gateway=gateway)
        agent = MockAutoGenAgent()
        adapter.wrap(agent)

        messages = [{"content": "Hello"}]
        # Create a proper sender mock with name attribute
        sender = Mock()
        sender.name = "user"
        agent.generate_reply(messages=messages, sender=sender)

        stats = gateway.stats
        assert stats["messages_received"] == 1  # Incoming message
        assert stats["messages_sent"] == 1  # Agent response

    def test_modern_agent_instrumented(self, gateway):
        """Test that modern on_messages is instrumented."""
        adapter = A2AAutoGenAdapter(gateway=gateway)
        agent = MockAutoGenModernAgent()

        original_on_messages = agent.on_messages
        adapter.wrap(agent)

        # Calling the instrumented method should still work
        messages = [{"content": "Hello"}]
        result = agent.on_messages(messages=messages)

        assert result == "agent response"
        original_on_messages.assert_called()

    def test_modern_agent_records_messages(self, gateway):
        """Test that modern agents record incoming and outgoing messages."""
        adapter = A2AAutoGenAdapter(gateway=gateway)
        agent = MockAutoGenModernAgent(name="assistant")
        adapter.wrap(agent)

        messages = [{"content": "Hello"}]
        agent.on_messages(messages=messages)

        stats = gateway.stats
        assert stats["messages_received"] == 1  # Incoming message
        assert stats["messages_sent"] == 1  # Agent response

    def test_wrap_multiple_agents(self, gateway):
        """Test wrap_agents() for wrapping multiple agents."""
        adapter = A2AAutoGenAdapter(gateway=gateway)

        agent1 = MockAutoGenAgent(name="assistant")
        agent2 = MockAutoGenAgent(name="user_proxy")

        agents = adapter.wrap_agents([agent1, agent2])

        assert len(agents) == 2
        assert agents[0] == agent1
        assert agents[1] == agent2

    def test_adapter_tracks_message_count(self, gateway):
        """Test that the adapter tracks message count."""
        adapter = A2AAutoGenAdapter(gateway=gateway)
        agent = MockAutoGenAgent()
        adapter.wrap(agent)

        messages = [{"content": "Hello"}]
        agent.generate_reply(messages=messages, sender=None)

        stats = adapter.stats
        assert stats["messages_recorded"] == 2  # incoming + outgoing

    def test_adapter_tracks_tool_count(self, gateway):
        """Test that the adapter tracks tool calls."""
        adapter = A2AAutoGenAdapter(gateway=gateway)
        agent = MockAutoGenAgent()

        # Mock _function_map with a function
        def mock_tool(arg1):
            return f"result of {arg1}"

        agent._function_map = {"search": mock_tool}
        adapter.wrap(agent)

        # The tool should be wrapped
        wrapped_tool = agent._function_map["search"]
        result = wrapped_tool("test")

        assert result == "result of test"
        stats = adapter.stats
        assert stats["tools_recorded"] >= 1

    def test_adapter_stats_include_gateway_stats(self, gateway):
        """Test that adapter stats include gateway stats."""
        adapter = A2AAutoGenAdapter(gateway=gateway)
        agent = MockAutoGenAgent()
        adapter.wrap(agent)

        messages = [{"content": "Hello"}]
        agent.generate_reply(messages=messages, sender=None)

        stats = adapter.stats
        assert "messages_recorded" in stats
        assert "tools_recorded" in stats
        assert "messages_sent" in stats
        assert "messages_received" in stats

    def test_send_to_agent(self, gateway):
        """Test send_to_agent for handoffs."""
        adapter = A2AAutoGenAdapter(gateway=gateway)

        result = adapter.send_to_agent(
            content=b"Handoff message",
            receiver_id="external-agent",
            receiver_name="External Agent",
            receiver_framework="crewai",
            message_type="handoff",
        )

        assert result.record is not None
        stats = gateway.stats
        assert stats["messages_sent"] == 1

    def test_receive_from_agent(self, gateway):
        """Test receive_from_agent for handoff results."""
        adapter = A2AAutoGenAdapter(gateway=gateway)

        result = adapter.receive_from_agent(
            content=b"Result from handoff",
            sender_id="external-agent",
            sender_name="External Agent",
            sender_framework="crewai",
            message_type="handoff",
        )

        assert result.record is not None
        stats = gateway.stats
        assert stats["messages_received"] == 1


# ============================================================================
# Integration Tests
# ============================================================================


class TestAdapterIntegration:
    """Integration tests combining multiple adapters."""

    def test_langchain_to_openai_handoff(self, gateway):
        """Test LangChain agent handing off to OpenAI."""
        lc_handler = A2ALangChainHandler(gateway=gateway)
        openai_client = MockOpenAIClient()
        openai_wrapper = A2AOpenAIWrapper(client=openai_client, gateway=gateway)

        # LangChain sends a message
        lc_handler.on_llm_start(
            serialized={"id": ["gpt-4"]},
            prompts=["Complex question"],
            run_id="run-1",
        )

        # OpenAI receives and responds
        response = openai_wrapper.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Complex question"}],
        )

        stats = gateway.stats
        assert stats["messages_sent"] >= 1
        assert stats["messages_received"] >= 1

    def test_all_adapters_share_same_ledger(self):
        """Test that all adapters can share the same gateway."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gateway = A2AGateway(
                agent_id="shared-gateway",
                agent_name="Shared Gateway",
                framework="test",
                ledger_dir=tmpdir,
                signing_key="test-key",
            )

            lc_handler = A2ALangChainHandler(gateway=gateway)
            openai_wrapper = A2AOpenAIWrapper(
                client=MockOpenAIClient(), gateway=gateway
            )
            crew_adapter = A2ACrewAIAdapter(gateway=gateway)
            autogen_adapter = A2AAutoGenAdapter(gateway=gateway)

            # Each adapter uses the same gateway
            assert lc_handler.gateway == gateway
            assert openai_wrapper.gateway == gateway
            assert crew_adapter.gateway == gateway
            assert autogen_adapter.gateway == gateway


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
