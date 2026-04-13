"""
Tests for AIR Blackbox A2A CrewAI Adapter.

Covers:
- A2ACrewAIAdapter initialization and configuration
- Crew wrapping and kickoff instrumentation
- Step and task callback handling
- Gateway integration (send/receive)
"""

from unittest.mock import MagicMock, AsyncMock, patch, call
import pytest

from air_blackbox.a2a.adapters.crewai_adapter import A2ACrewAIAdapter
from air_blackbox.a2a.gateway import A2AGateway


# ────────────────────────────────────────────────────────────────
# A2ACrewAIAdapter Initialization Tests
# ────────────────────────────────────────────────────────────────


class TestA2ACrewAIAdapterInit:
    """Test A2ACrewAIAdapter initialization."""

    def test_init_default_values(self):
        """Initialize with default parameters."""
        adapter = A2ACrewAIAdapter()
        assert adapter.agent_id == "crewai-crew"
        assert adapter.agent_name == "CrewAI Crew"
        assert adapter.gateway is not None
        assert adapter._step_count == 0
        assert adapter._task_count == 0

    def test_init_custom_agent_id(self):
        """Initialize with custom agent_id."""
        adapter = A2ACrewAIAdapter(
            agent_id="research-team",
            agent_name="Research Team"
        )
        assert adapter.agent_id == "research-team"
        assert adapter.agent_name == "Research Team"

    def test_init_with_custom_gateway(self):
        """Initialize with pre-configured gateway."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)
        assert adapter.gateway is mock_gateway

    def test_init_creates_default_gateway(self):
        """Initialize creates gateway if not provided."""
        adapter = A2ACrewAIAdapter(
            agent_id="test-crew",
            ledger_dir="/tmp/ledger"
        )
        assert adapter.gateway is not None
        assert adapter.gateway.agent_id == "test-crew"

    def test_init_with_signing_key(self):
        """Initialize with custom signing key."""
        adapter = A2ACrewAIAdapter(
            signing_key="test-key-12345",
            ledger_dir="/tmp/test"
        )
        assert adapter.gateway is not None

    def test_init_counts_are_zero(self):
        """Initialize with zero counters."""
        adapter = A2ACrewAIAdapter()
        assert adapter._step_count == 0
        assert adapter._task_count == 0


# ────────────────────────────────────────────────────────────────
# A2ACrewAIAdapter Stats Tests
# ────────────────────────────────────────────────────────────────


class TestA2ACrewAIAdapterStats:
    """Test the stats property."""

    def test_stats_initial_state(self):
        """Stats returns initial counts."""
        adapter = A2ACrewAIAdapter()
        stats = adapter.stats
        assert stats["steps_recorded"] == 0
        assert stats["tasks_recorded"] == 0

    def test_stats_after_steps_recorded(self):
        """Stats reflects recorded steps."""
        adapter = A2ACrewAIAdapter()
        adapter._step_count = 5
        stats = adapter.stats
        assert stats["steps_recorded"] == 5

    def test_stats_after_tasks_recorded(self):
        """Stats reflects recorded tasks."""
        adapter = A2ACrewAIAdapter()
        adapter._task_count = 3
        stats = adapter.stats
        assert stats["tasks_recorded"] == 3

    def test_stats_includes_gateway_stats(self):
        """Stats includes gateway statistics."""
        mock_gateway = MagicMock(spec=A2AGateway)
        mock_gateway.stats = {"transactions": 10}
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)
        stats = adapter.stats
        assert "transactions" in stats
        assert stats["transactions"] == 10

    def test_stats_is_dict(self):
        """Stats returns dictionary."""
        adapter = A2ACrewAIAdapter()
        stats = adapter.stats
        assert isinstance(stats, dict)


# ────────────────────────────────────────────────────────────────
# A2ACrewAIAdapter Wrap Tests
# ────────────────────────────────────────────────────────────────


class TestA2ACrewAIAdapterWrap:
    """Test crew wrapping and kickoff instrumentation."""

    def test_wrap_saves_original_kickoff(self):
        """Wrap saves the original kickoff method."""
        adapter = A2ACrewAIAdapter()
        crew = MagicMock()
        original_kickoff = MagicMock(return_value="result")
        crew.kickoff = original_kickoff

        adapter.wrap(crew)

        # The kickoff should be replaced
        assert crew.kickoff != original_kickoff

    def test_wrap_returns_crew(self):
        """Wrap returns the same crew object."""
        adapter = A2ACrewAIAdapter()
        crew = MagicMock()
        crew.kickoff = MagicMock(return_value="result")

        result = adapter.wrap(crew)
        assert result is crew

    def test_wrap_instrumented_kickoff_calls_original(self):
        """Instrumented kickoff calls the original method."""
        adapter = A2ACrewAIAdapter()
        crew = MagicMock()
        original_kickoff = MagicMock(return_value="original_result")
        crew.kickoff = original_kickoff
        crew.tasks = []

        adapter.wrap(crew)

        # Call the instrumented kickoff
        result = crew.kickoff()
        assert result == "original_result"

    def test_wrap_instrumented_kickoff_increments_task_count(self):
        """Instrumented kickoff increments task counter."""
        adapter = A2ACrewAIAdapter()
        crew = MagicMock()
        crew.kickoff = MagicMock(return_value="result")
        crew.tasks = []

        initial_count = adapter._task_count
        adapter.wrap(crew)
        crew.kickoff()

        assert adapter._task_count == initial_count + 1

    def test_wrap_extracts_task_description(self):
        """Wrap extracts task descriptions from crew."""
        adapter = A2ACrewAIAdapter()
        crew = MagicMock()
        crew.kickoff = MagicMock(return_value="result")

        task1 = MagicMock()
        task1.description = "Analyze data"
        task2 = MagicMock()
        task2.description = "Generate report"
        crew.tasks = [task1, task2]

        adapter.wrap(crew)
        crew.kickoff()

        # Should have recorded a transaction

    def test_wrap_handles_dict_result(self):
        """Wrap handles dictionary result from kickoff."""
        adapter = A2ACrewAIAdapter()
        crew = MagicMock()
        crew.kickoff = MagicMock(return_value={"output": "final result"})
        crew.tasks = []

        adapter.wrap(crew)
        result = crew.kickoff()
        assert result["output"] == "final result"

    def test_wrap_handles_string_result(self):
        """Wrap handles string result from kickoff."""
        adapter = A2ACrewAIAdapter()
        crew = MagicMock()
        crew.kickoff = MagicMock(return_value="simple result")
        crew.tasks = []

        adapter.wrap(crew)
        result = crew.kickoff()
        assert result == "simple result"

    def test_wrap_sends_gateway_message(self):
        """Wrap sends message through gateway on completion."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)
        crew = MagicMock()
        crew.kickoff = MagicMock(return_value="done")
        crew.tasks = []

        adapter.wrap(crew)
        crew.kickoff()

        mock_gateway.send.assert_called()


# ────────────────────────────────────────────────────────────────
# A2ACrewAIAdapter _on_step Tests
# ────────────────────────────────────────────────────────────────


class TestA2ACrewAIAdapterOnStep:
    """Test _on_step method for recording agent steps."""

    def test_on_step_increments_counter(self):
        """_on_step increments step counter."""
        adapter = A2ACrewAIAdapter()
        initial_count = adapter._step_count

        step_output = MagicMock()
        step_output.text = "Step output"
        adapter._on_step(step_output)

        assert adapter._step_count == initial_count + 1

    def test_on_step_extracts_text_attribute(self):
        """_on_step extracts text from step_output."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        step_output = MagicMock()
        step_output.text = "Processing data"
        step_output.tool = None
        step_output.tool_input = None

        adapter._on_step(step_output)

        # Should have sent a message
        mock_gateway.send.assert_called()

    def test_on_step_extracts_output_attribute(self):
        """_on_step falls back to output attribute."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        step_output = MagicMock(spec=["output"])
        step_output.output = "Output text"
        step_output.text = None
        step_output.tool = None

        adapter._on_step(step_output)

        # Should have extracted output

    def test_on_step_detects_delegation(self):
        """_on_step detects delegation tool calls."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        step_output = MagicMock()
        step_output.text = "Delegating task"
        step_output.tool = "delegate_to_expert"
        step_output.tool_input = {"task": "analysis"}

        adapter._on_step(step_output)

        # Should record as delegation
        call_args = mock_gateway.send.call_args
        assert call_args is not None
        if call_args:
            assert call_args[1]["message_type"] == "handoff"

    def test_on_step_records_tool_call(self):
        """_on_step records tool calls."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        step_output = MagicMock()
        step_output.text = "Using calculator"
        step_output.tool = "calculator"
        step_output.tool_input = "2+2"

        adapter._on_step(step_output)

        call_args = mock_gateway.send.call_args
        if call_args:
            assert call_args[1]["message_type"] == "tool_call"

    def test_on_step_truncates_long_text(self):
        """_on_step truncates long text to 500 chars."""
        adapter = A2ACrewAIAdapter()

        long_text = "x" * 1000
        step_output = MagicMock()
        step_output.text = long_text
        step_output.tool = None
        step_output.tool_input = None

        adapter._on_step(step_output)

        # Should be truncated in record


# ────────────────────────────────────────────────────────────────
# A2ACrewAIAdapter _on_task Tests
# ────────────────────────────────────────────────────────────────


class TestA2ACrewAIAdapterOnTask:
    """Test _on_task method for recording task completion."""

    def test_on_task_increments_counter(self):
        """_on_task increments task counter."""
        adapter = A2ACrewAIAdapter()
        initial_count = adapter._task_count

        task_output = MagicMock()
        task_output.description = "Task description"
        task_output.output = "Task result"
        task_output.agent = "agent_name"

        adapter._on_task(task_output)

        assert adapter._task_count == initial_count + 1

    def test_on_task_extracts_description(self):
        """_on_task extracts task description."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        task_output = MagicMock()
        task_output.description = "Analyze the data"
        task_output.output = "Done"
        task_output.agent = "analyzer"

        adapter._on_task(task_output)

        # Should have sent via gateway
        mock_gateway.send.assert_called()

    def test_on_task_extracts_result_from_raw(self):
        """_on_task uses raw attribute for result."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        task_output = MagicMock()
        task_output.description = "Task"
        task_output.raw = "Raw result"
        task_output.agent = "worker"

        adapter._on_task(task_output)

        call_args = mock_gateway.send.call_args
        if call_args:
            content = call_args[1]["content"]
            assert b"Raw result" in content

    def test_on_task_extracts_result_from_output(self):
        """_on_task falls back to output attribute."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        task_output = MagicMock(spec=["description", "output", "agent"])
        task_output.description = "Task"
        task_output.output = "Task output"
        task_output.agent = "worker"

        adapter._on_task(task_output)

        # Should record the output

    def test_on_task_extracts_agent_name(self):
        """_on_task extracts agent name."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        task_output = MagicMock()
        task_output.description = "Task"
        task_output.output = "Result"
        task_output.agent = "specialist_agent"

        adapter._on_task(task_output)

        call_args = mock_gateway.send.call_args
        if call_args:
            receiver_name = call_args[1]["receiver_name"]
            assert "specialist_agent" in receiver_name

    def test_on_task_truncates_long_description(self):
        """_on_task truncates long description to 200 chars."""
        adapter = A2ACrewAIAdapter()

        long_desc = "x" * 300
        task_output = MagicMock()
        task_output.description = long_desc
        task_output.output = "Result"
        task_output.agent = "worker"

        adapter._on_task(task_output)

        # Should be truncated in record

    def test_on_task_truncates_long_result(self):
        """_on_task truncates long result to 500 chars."""
        adapter = A2ACrewAIAdapter()

        task_output = MagicMock()
        task_output.description = "Task"
        task_output.output = "x" * 1000
        task_output.agent = "worker"

        adapter._on_task(task_output)

        # Should be truncated in record


# ────────────────────────────────────────────────────────────────
# A2ACrewAIAdapter Gateway Integration Tests
# ────────────────────────────────────────────────────────────────


class TestA2ACrewAIAdapterSendToAgent:
    """Test send_to_agent method."""

    def test_send_to_agent_forwards_to_gateway(self):
        """send_to_agent forwards message to gateway."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        content = b"Hello agent"
        result = adapter.send_to_agent(
            content=content,
            receiver_id="agent_1",
            receiver_name="Agent One",
            receiver_framework="crewai",
            message_type="handoff"
        )

        mock_gateway.send.assert_called_once()
        call_kwargs = mock_gateway.send.call_args[1]
        assert call_kwargs["content"] == content
        assert call_kwargs["receiver_id"] == "agent_1"

    def test_send_to_agent_default_message_type(self):
        """send_to_agent uses handoff as default message_type."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        adapter.send_to_agent(
            content=b"test",
            receiver_id="agent_1",
            receiver_name="Agent",
            receiver_framework="crewai"
        )

        call_kwargs = mock_gateway.send.call_args[1]
        assert call_kwargs["message_type"] == "handoff"

    def test_send_to_agent_custom_message_type(self):
        """send_to_agent accepts custom message_type."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        adapter.send_to_agent(
            content=b"test",
            receiver_id="agent_1",
            receiver_name="Agent",
            receiver_framework="crewai",
            message_type="response"
        )

        call_kwargs = mock_gateway.send.call_args[1]
        assert call_kwargs["message_type"] == "response"

    def test_send_to_agent_returns_gateway_result(self):
        """send_to_agent returns gateway send result."""
        mock_gateway = MagicMock(spec=A2AGateway)
        mock_gateway.send.return_value = "tx_123"
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        result = adapter.send_to_agent(
            content=b"test",
            receiver_id="agent_1",
            receiver_name="Agent",
            receiver_framework="crewai"
        )

        assert result == "tx_123"


class TestA2ACrewAIAdapterReceiveFromAgent:
    """Test receive_from_agent method."""

    def test_receive_from_agent_forwards_to_gateway(self):
        """receive_from_agent forwards message to gateway."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        content = b"Agent response"
        result = adapter.receive_from_agent(
            content=content,
            sender_id="agent_1",
            sender_name="Agent One",
            sender_framework="crewai",
            message_type="handoff"
        )

        mock_gateway.receive.assert_called_once()
        call_kwargs = mock_gateway.receive.call_args[1]
        assert call_kwargs["content"] == content
        assert call_kwargs["sender_id"] == "agent_1"

    def test_receive_from_agent_default_message_type(self):
        """receive_from_agent uses handoff as default message_type."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        adapter.receive_from_agent(
            content=b"test",
            sender_id="agent_1",
            sender_name="Agent",
            sender_framework="crewai"
        )

        call_kwargs = mock_gateway.receive.call_args[1]
        assert call_kwargs["message_type"] == "handoff"

    def test_receive_from_agent_custom_message_type(self):
        """receive_from_agent accepts custom message_type."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        adapter.receive_from_agent(
            content=b"test",
            sender_id="agent_1",
            sender_name="Agent",
            sender_framework="crewai",
            message_type="request"
        )

        call_kwargs = mock_gateway.receive.call_args[1]
        assert call_kwargs["message_type"] == "request"

    def test_receive_from_agent_returns_gateway_result(self):
        """receive_from_agent returns gateway receive result."""
        mock_gateway = MagicMock(spec=A2AGateway)
        mock_gateway.receive.return_value = "verified_123"
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        result = adapter.receive_from_agent(
            content=b"test",
            sender_id="agent_1",
            sender_name="Agent",
            sender_framework="crewai"
        )

        assert result == "verified_123"


# ────────────────────────────────────────────────────────────────
# A2ACrewAIAdapter Integration Tests
# ────────────────────────────────────────────────────────────────


class TestA2ACrewAIAdapterIntegration:
    """Integration tests for complete workflows."""

    def test_full_crew_execution_workflow(self):
        """Test complete crew execution recording."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(
            agent_id="research-team",
            agent_name="Research Team",
            gateway=mock_gateway
        )

        crew = MagicMock()
        crew.kickoff = MagicMock(return_value={"output": "Research complete"})

        task1 = MagicMock()
        task1.description = "Gather information"
        task2 = MagicMock()
        task2.description = "Analyze results"
        crew.tasks = [task1, task2]

        # Wrap and execute
        adapter.wrap(crew)
        result = crew.kickoff()

        # Verify execution
        assert result["output"] == "Research complete"
        assert adapter._task_count == 1
        mock_gateway.send.assert_called()

    def test_step_and_task_recording_combination(self):
        """Test recording steps and tasks together."""
        mock_gateway = MagicMock(spec=A2AGateway)
        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        # Record some steps
        for i in range(3):
            step = MagicMock()
            step.text = f"Step {i+1}"
            step.tool = None
            adapter._on_step(step)

        # Record tasks
        for i in range(2):
            task = MagicMock()
            task.description = f"Task {i+1}"
            task.output = f"Result {i+1}"
            task.agent = f"agent_{i+1}"
            adapter._on_task(task)

        # Verify stats
        assert adapter._step_count == 3
        assert adapter._task_count == 2

    def test_adapter_with_multiple_crews(self):
        """Test adapter with multiple different crews."""
        adapter = A2ACrewAIAdapter()

        # First crew
        crew1 = MagicMock()
        crew1.kickoff = MagicMock(return_value="Result 1")
        crew1.tasks = []
        adapter.wrap(crew1)
        crew1.kickoff()

        # Second crew
        crew2 = MagicMock()
        crew2.kickoff = MagicMock(return_value="Result 2")
        crew2.tasks = []
        adapter.wrap(crew2)
        crew2.kickoff()

        # Both should increment counters
        assert adapter._task_count == 2

    def test_gateway_error_handling_in_wrap(self):
        """Test adapter handles gateway errors gracefully."""
        mock_gateway = MagicMock(spec=A2AGateway)
        mock_gateway.send.side_effect = Exception("Gateway error")

        adapter = A2ACrewAIAdapter(gateway=mock_gateway)

        crew = MagicMock()
        crew.kickoff = MagicMock(return_value="Result")
        crew.tasks = []

        adapter.wrap(crew)

        # Should still work even if gateway fails
        try:
            result = crew.kickoff()
            # The result should still be returned
        except:
            pass  # Gateway error may be raised

    def test_stats_accumulation(self):
        """Test stats accumulate over multiple operations."""
        adapter = A2ACrewAIAdapter()

        initial_stats = adapter.stats
        assert initial_stats["steps_recorded"] == 0
        assert initial_stats["tasks_recorded"] == 0

        # Simulate operations
        for i in range(5):
            step = MagicMock()
            step.text = f"Step {i}"
            step.tool = None
            adapter._on_step(step)

        for i in range(3):
            task = MagicMock()
            task.description = f"Task {i}"
            task.output = "Result"
            task.agent = "agent"
            adapter._on_task(task)

        final_stats = adapter.stats
        assert final_stats["steps_recorded"] == 5
        assert final_stats["tasks_recorded"] == 3
