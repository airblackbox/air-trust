"""
AutoGen A2A Transaction Adapter.

Wraps AutoGen agents to record every message exchange and tool call
as signed A2A transactions. Supports both legacy pyautogen (v0.2.x with
generate_reply) and modern autogen-agentchat (v0.4+ with on_messages).

Version detection is automatic via duck typing.

Usage:
    # Legacy pyautogen
    from autogen import AssistantAgent, UserProxyAgent
    from air_blackbox.a2a.adapters.autogen_adapter import A2AAutoGenAdapter

    adapter = A2AAutoGenAdapter(
        agent_id="autogen-assistant",
        agent_name="AutoGen Assistant",
    )

    assistant = AssistantAgent(name="assistant", llm_config={...})
    adapter.wrap(assistant)

    user_proxy.initiate_chat(assistant, message="Hello")

    # Modern autogen-agentchat
    from autogen_agentchat.agents import AssistantAgent
    from air_blackbox.a2a.adapters.autogen_adapter import A2AAutoGenAdapter

    adapter = A2AAutoGenAdapter(
        agent_id="autogen-assistant",
        agent_name="AutoGen Assistant",
    )
    adapter.wrap(assistant)
"""

from typing import Any, Dict, List, Optional

from ..gateway import A2AGateway


class A2AAutoGenAdapter:
    """Wraps AutoGen agent message processing for A2A transaction recording.

    Supports both legacy pyautogen v0.2.x (with generate_reply) and
    modern autogen-agentchat v0.4+ (with on_messages). Version detection
    is automatic via hasattr checks.

    For legacy agents: Wraps generate_reply and _function_map entries.
    For modern agents: Wraps on_messages method.

    Args:
        agent_id: Unique identifier for this agent.
        agent_name: Human-readable name for this agent.
        gateway: Optional pre-configured A2AGateway.
        ledger_dir: Directory for the transaction ledger.
        signing_key: HMAC key for the chain.
        signer: Optional EvidenceSigner for ML-DSA-65 signatures.
    """

    def __init__(
        self,
        agent_id: str = "autogen-agent",
        agent_name: str = "AutoGen Agent",
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
                framework="autogen",
                ledger_dir=ledger_dir,
                signing_key=signing_key,
                signer=signer,
            )

        self._message_count = 0
        self._tool_count = 0

    @property
    def stats(self) -> Dict[str, Any]:
        """Return adapter statistics."""
        return {
            "messages_recorded": self._message_count,
            "tools_recorded": self._tool_count,
            **self.gateway.stats,
        }

    def wrap(self, agent: Any) -> Any:
        """Wrap an AutoGen agent with A2A transaction recording.

        Automatically detects the AutoGen version and applies appropriate
        wrapping strategy:
        - Legacy pyautogen v0.2.x: Wraps generate_reply and _function_map
        - Modern autogen-agentchat v0.4+: Wraps on_messages

        Args:
            agent: An AutoGen agent (AssistantAgent, UserProxyAgent, etc.).

        Returns:
            The same agent with instrumented methods.

        Raises:
            ValueError: If the agent type is not supported.
        """
        agent_name = getattr(agent, "name", self.agent_name)

        # Detect and delegate to appropriate wrapper
        if hasattr(agent, "generate_reply"):
            # Legacy pyautogen v0.2.x
            self._wrap_legacy_autogen(agent, agent_name)
        elif hasattr(agent, "on_messages"):
            # Modern autogen-agentchat v0.4+
            self._wrap_modern_autogen(agent, agent_name)
        else:
            raise ValueError(
                f"Agent {agent_name} does not appear to be a supported AutoGen "
                "agent. Expected either generate_reply (legacy pyautogen) or "
                "on_messages (modern autogen-agentchat)."
            )

        return agent

    def _wrap_legacy_autogen(self, agent: Any, agent_name: str) -> None:
        """Wrap legacy pyautogen v0.2.x agents with generate_reply."""
        # Wrap generate_reply
        original_generate_reply = agent.generate_reply

        adapter = self  # capture reference for closure

        def instrumented_generate_reply(
            messages: Optional[List[Dict]] = None,
            sender: Any = None,
            **kwargs: Any,
        ) -> Any:
            sender_name = getattr(sender, "name", "unknown")

            # Record incoming message
            if messages:
                last_msg = messages[-1]
                if isinstance(last_msg, dict):
                    content_text = str(last_msg.get("content", ""))
                else:
                    content_text = str(last_msg)

                adapter.gateway.receive(
                    content=content_text.encode("utf-8"),
                    sender_id=f"autogen-{sender_name}",
                    sender_name=sender_name,
                    sender_framework="autogen",
                    message_type="request",
                )
                adapter._message_count += 1

            # Call original
            result = original_generate_reply(messages=messages, sender=sender, **kwargs)

            # Record outgoing response
            if result is not None:
                if isinstance(result, dict):
                    response_text = str(result.get("content", ""))[:500]
                else:
                    response_text = str(result)[:500]

                adapter.gateway.send(
                    content=response_text.encode("utf-8"),
                    receiver_id=f"autogen-{sender_name}",
                    receiver_name=sender_name,
                    receiver_framework="autogen",
                    message_type="response",
                )
                adapter._message_count += 1

            return result

        agent.generate_reply = instrumented_generate_reply

        # Wrap function_map entries (tool calls) if present
        function_map = getattr(agent, "_function_map", {})
        if function_map:
            for func_name, func in list(function_map.items()):
                wrapped = self._wrap_function(func, func_name, agent_name)
                function_map[func_name] = wrapped

    def _wrap_modern_autogen(self, agent: Any, agent_name: str) -> None:
        """Wrap modern autogen-agentchat v0.4+ agents with on_messages."""
        original_on_messages = agent.on_messages

        adapter = self  # capture reference for closure

        def instrumented_on_messages(messages: List[Any], cancellation_token: Optional[Any] = None) -> Any:
            # Record incoming messages
            for msg in messages:
                msg_content = ""
                if isinstance(msg, dict):
                    msg_content = str(msg.get("content", ""))
                else:
                    msg_content = str(getattr(msg, "content", str(msg)))

                adapter.gateway.receive(
                    content=msg_content.encode("utf-8"),
                    sender_id=f"autogen-{agent_name}",
                    sender_name=agent_name,
                    sender_framework="autogen-agentchat",
                    message_type="request",
                )
                adapter._message_count += 1

            # Call original
            result = original_on_messages(messages, cancellation_token)

            # Record outgoing response if it's a generator, consume it carefully
            if result is not None:
                result_text = str(result)[:500]
                adapter.gateway.send(
                    content=result_text.encode("utf-8"),
                    receiver_id=f"autogen-{agent_name}",
                    receiver_name=agent_name,
                    receiver_framework="autogen-agentchat",
                    message_type="response",
                )
                adapter._message_count += 1

            return result

        agent.on_messages = instrumented_on_messages

    def wrap_agents(self, agents: List[Any]) -> List[Any]:
        """Wrap multiple AutoGen agents.

        Args:
            agents: List of AutoGen agents.

        Returns:
            The same agents, instrumented.
        """
        for agent in agents:
            self.wrap(agent)
        return agents

    def _wrap_function(self, func: Any, func_name: str, agent_name: str) -> Any:
        """Wrap a single function from the agent's function_map.

        Used only for legacy pyautogen v0.2.x agents.
        """
        adapter = self

        def wrapped(*args: Any, **kwargs: Any) -> Any:
            # Record tool call
            adapter.gateway.send(
                content=f"TOOL_CALL:{func_name}:{str(kwargs)[:500]}".encode("utf-8"),
                receiver_id=f"tool-{func_name}",
                receiver_name=func_name,
                receiver_framework="autogen-tool",
                message_type="tool_call",
            )
            adapter._tool_count += 1

            try:
                result = func(*args, **kwargs)

                # Record tool result
                adapter.gateway.receive(
                    content=f"TOOL_RESULT:{str(result)[:500]}".encode("utf-8"),
                    sender_id=f"tool-{func_name}",
                    sender_name=func_name,
                    sender_framework="autogen-tool",
                    message_type="tool_result",
                )

                return result
            except Exception as e:
                # Record tool error
                adapter.gateway.receive(
                    content=f"TOOL_ERROR:{func_name}:{str(e)[:500]}".encode("utf-8"),
                    sender_id=f"tool-{func_name}",
                    sender_name=func_name,
                    sender_framework="autogen-tool",
                    message_type="tool_result",
                )
                raise

        return wrapped

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
