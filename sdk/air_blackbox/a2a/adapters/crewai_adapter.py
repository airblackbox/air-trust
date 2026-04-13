"""
CrewAI A2A Transaction Adapter.

Wraps a CrewAI Crew's step and task callbacks to record every
agent step, task completion, and delegation as signed A2A transactions.

Usage:
    from crewai import Agent, Task, Crew
    from air_blackbox.a2a.adapters.crewai_adapter import A2ACrewAIAdapter

    adapter = A2ACrewAIAdapter(
        agent_id="crewai-research-team",
        agent_name="Research Team",
    )

    crew = Crew(agents=[...], tasks=[...])
    wrapped_crew = adapter.wrap(crew)
    result = wrapped_crew.kickoff()
"""

from typing import Any, Dict, Optional

from ..gateway import A2AGateway


class A2ACrewAIAdapter:
    """Wraps CrewAI step and task callbacks for A2A transaction recording.

    Injects callbacks into the Crew's step_callback and task_callback
    hooks. Every agent step, tool call, delegation, and task completion
    is recorded as a signed transaction.

    Args:
        agent_id: Unique identifier for this crew.
        agent_name: Human-readable name for this crew.
        gateway: Optional pre-configured A2AGateway.
        ledger_dir: Directory for the transaction ledger.
        signing_key: HMAC key for the chain.
        signer: Optional EvidenceSigner for ML-DSA-65 signatures.
    """

    def __init__(
        self,
        agent_id: str = "crewai-crew",
        agent_name: str = "CrewAI Crew",
        gateway: Optional[A2AGateway] = None,
        ledger_dir: Optional[str] = None,
        signing_key: Optional[str] = None,
        signer: Optional[Any] = None,
    ) -> None:
        self.agent_id = agent_id
        self.agent_name = agent_name

        if gateway is not None:
            self.gateway = gateway
        else:
            self.gateway = A2AGateway(
                agent_id=agent_id,
                agent_name=agent_name,
                framework="crewai",
                ledger_dir=ledger_dir,
                signing_key=signing_key,
                signer=signer,
            )

        self._step_count = 0
        self._task_count = 0

    @property
    def stats(self) -> Dict[str, Any]:
        """Return adapter statistics."""
        return {
            "steps_recorded": self._step_count,
            "tasks_recorded": self._task_count,
            **self.gateway.stats,
        }

    def wrap(self, crew: Any) -> Any:
        """Wrap a CrewAI Crew with A2A transaction recording.

        Injects step_callback and task_callback that record transactions.
        Preserves any existing callbacks on the crew.

        Args:
            crew: A CrewAI Crew instance.

        Returns:
            The same crew with callbacks injected.
        """
        # Preserve existing callbacks
        existing_step_cb = getattr(crew, "step_callback", None)
        existing_task_cb = getattr(crew, "task_callback", None)

        def air_step_callback(step_output: Any) -> None:
            self._on_step(step_output)
            if existing_step_cb:
                existing_step_cb(step_output)

        def air_task_callback(task_output: Any) -> None:
            self._on_task(task_output)
            if existing_task_cb:
                existing_task_cb(task_output)

        crew.step_callback = air_step_callback
        crew.task_callback = air_task_callback

        return crew

    def _on_step(self, step_output: Any) -> None:
        """Record an agent step as a transaction."""
        self._step_count += 1

        # Extract what we can from the step output
        text = ""
        tool_name = ""
        tool_input = ""
        is_delegation = False

        if hasattr(step_output, "text"):
            text = str(step_output.text)[:500]
        elif hasattr(step_output, "output"):
            text = str(step_output.output)[:500]
        else:
            text = str(step_output)[:500]

        if hasattr(step_output, "tool"):
            tool_name = str(step_output.tool)
            if "delegate" in tool_name.lower():
                is_delegation = True

        if hasattr(step_output, "tool_input"):
            tool_input = str(step_output.tool_input)[:500]

        # Determine message type
        if is_delegation:
            msg_type = "handoff"
            content = f"DELEGATION:{tool_name}:{tool_input}".encode("utf-8")
        elif tool_name:
            msg_type = "tool_call"
            content = f"TOOL:{tool_name}:{tool_input}:{text}".encode("utf-8")
        else:
            msg_type = "request"
            content = text.encode("utf-8")

        # Record as an internal step (agent talking to itself/tools)
        self.gateway.send(
            content=content,
            receiver_id=f"crewai-step-{self._step_count}",
            receiver_name=tool_name or "CrewAI Step",
            receiver_framework="crewai",
            message_type=msg_type,
        )

    def _on_task(self, task_output: Any) -> None:
        """Record a task completion as a transaction."""
        self._task_count += 1

        description = ""
        result = ""
        agent_name = ""

        if hasattr(task_output, "description"):
            description = str(task_output.description)[:200]
        if hasattr(task_output, "raw"):
            result = str(task_output.raw)[:500]
        elif hasattr(task_output, "output"):
            result = str(task_output.output)[:500]
        if hasattr(task_output, "agent"):
            agent_name = str(task_output.agent)

        content = f"TASK_COMPLETE:{description}:{result}".encode("utf-8")

        self.gateway.send(
            content=content,
            receiver_id=f"crewai-task-{self._task_count}",
            receiver_name=agent_name or f"Task {self._task_count}",
            receiver_framework="crewai",
            message_type="response",
        )

    def send_to_agent(
        self,
        content: bytes,
        receiver_id: str,
        receiver_name: str,
        receiver_framework: str,
        message_type: str = "handoff",
    ) -> Any:
        """Send a message to an external agent through the gateway."""
        return self.gateway.send(
            content=content,
            receiver_id=receiver_id,
            receiver_name=receiver_name,
            receiver_framework=receiver_framework,
            message_type=message_type,
        )

    def receive_from_agent(
        self,
        content: bytes,
        sender_id: str,
        sender_name: str,
        sender_framework: str,
        message_type: str = "handoff",
    ) -> Any:
        """Receive a message from an external agent through the gateway."""
        return self.gateway.receive(
            content=content,
            sender_id=sender_id,
            sender_name=sender_name,
            sender_framework=sender_framework,
            message_type=message_type,
        )
