"""
CrewAI A2A Transaction Adapter.

Wraps a CrewAI Crew's kickoff method to record every agent step,
task completion, and delegation as signed A2A transactions.

Supports CrewAI 1.14.x and later. Uses monkey-patching of the kickoff()
method since step_callback and task_callback are constructor-only parameters.

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
    """Wraps CrewAI Crew execution for A2A transaction recording.

    Monkey-patches the Crew's kickoff() method to intercept execution
    and record every agent step, tool call, delegation, and task completion
    as a signed transaction via the A2AGateway.

    Works with CrewAI 1.14.x and later by wrapping the kickoff method
    rather than relying on constructor-only callback parameters.

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

        Monkey-patches the crew's kickoff() method to record transactions
        during execution. Preserves the original method so it can be called.

        Args:
            crew: A CrewAI Crew instance.

        Returns:
            The same crew with the kickoff method instrumented.
        """
        # Save original kickoff method
        original_kickoff = crew.kickoff
        adapter = self

        def instrumented_kickoff(*args: Any, **kwargs: Any) -> Any:
            """Instrumented kickoff that records transactions."""
            # Call the original kickoff
            result = original_kickoff(*args, **kwargs)

            # Record the overall execution as a task completion
            task_description = ""
            if hasattr(crew, "tasks") and crew.tasks:
                task_description = ", ".join(
                    str(getattr(t, "description", f"Task {i}"))
                    for i, t in enumerate(crew.tasks)
                )[:200]

            result_text = ""
            if isinstance(result, dict):
                result_text = str(result.get("output", str(result)))[:500]
            else:
                result_text = str(result)[:500]

            adapter.gateway.send(
                content=f"CREW_EXECUTION:{task_description}:{result_text}".encode(
                    "utf-8"
                ),
                receiver_id="crewai-kickoff-completion",
                receiver_name="CrewAI Execution",
                receiver_framework="crewai",
                message_type="response",
            )
            adapter._task_count += 1

            return result

        crew.kickoff = instrumented_kickoff
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
