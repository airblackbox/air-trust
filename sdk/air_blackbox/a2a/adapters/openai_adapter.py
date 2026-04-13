"""
OpenAI A2A Transaction Adapter.

Wraps an OpenAI client so every chat completion call is recorded as
a signed A2A transaction. The wrapper is transparent -- the OpenAI
API works exactly the same, but every request/response pair gets
hashed, signed, and chained.

Usage:
    from openai import OpenAI
    from air_blackbox.a2a.adapters.openai_adapter import A2AOpenAIWrapper

    client = OpenAI()
    wrapped = A2AOpenAIWrapper(client, agent_id="my-agent", agent_name="My Agent")

    # Use exactly like a normal OpenAI client
    response = wrapped.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "Hello"}],
    )
"""

import json
import time
from typing import Any, Dict, List, Optional

from ..gateway import A2AGateway


class A2AOpenAIWrapper:
    """Wraps OpenAI chat completions to record A2A transactions.

    Proxies calls to client.chat.completions.create() and records
    both the request and response as signed transactions.

    Args:
        client: An OpenAI() client instance.
        agent_id: Unique identifier for this agent.
        agent_name: Human-readable name for this agent.
        gateway: Optional pre-configured A2AGateway.
        ledger_dir: Directory for the transaction ledger.
        signing_key: HMAC key for the chain.
        signer: Optional EvidenceSigner for ML-DSA-65 signatures.
    """

    def __init__(
        self,
        client: Any,
        agent_id: str = "openai-agent",
        agent_name: str = "OpenAI Agent",
        gateway: Optional[A2AGateway] = None,
        ledger_dir: Optional[str] = None,
        signing_key: Optional[str] = None,
        signer: Optional[Any] = None,
    ) -> None:
        self._client = client
        self.agent_id = agent_id
        self.agent_name = agent_name

        if gateway is not None:
            self.gateway = gateway
        else:
            self.gateway = A2AGateway(
                agent_id=agent_id,
                agent_name=agent_name,
                framework="openai",
                ledger_dir=ledger_dir,
                signing_key=signing_key,
                signer=signer,
            )

    def create(self, **kwargs: Any) -> Any:
        """Proxy for client.chat.completions.create().

        Records the request messages as a sent transaction and the
        response as a received transaction. Then returns the original
        response unchanged.

        Args:
            **kwargs: All arguments passed to chat.completions.create().

        Returns:
            The OpenAI ChatCompletion response, unchanged.
        """
        model = kwargs.get("model", "unknown")
        messages = kwargs.get("messages", [])

        # Record the outgoing request
        request_content = json.dumps(messages, ensure_ascii=False).encode("utf-8")
        self.gateway.send(
            content=request_content,
            receiver_id=f"openai-{model}",
            receiver_name=f"OpenAI {model}",
            receiver_framework="openai-api",
            message_type="request",
        )

        # Make the actual API call
        start = time.time()
        response = self._client.chat.completions.create(**kwargs)
        duration_ms = int((time.time() - start) * 1000)

        # Record the incoming response
        response_text = ""
        try:
            if response.choices:
                response_text = response.choices[0].message.content or ""
        except Exception:
            response_text = str(response)[:500]

        response_content = response_text.encode("utf-8")
        self.gateway.receive(
            content=response_content,
            sender_id=f"openai-{model}",
            sender_name=f"OpenAI {model}",
            sender_framework="openai-api",
            message_type="response",
        )

        return response

    def send_to_agent(
        self,
        content: bytes,
        receiver_id: str,
        receiver_name: str,
        receiver_framework: str,
        message_type: str = "handoff",
    ) -> Any:
        """Send a message to another agent through the gateway.

        Use this for agent-to-agent handoffs where the OpenAI agent
        is delegating work to another agent (not calling the OpenAI API).

        Args:
            content: Raw message bytes.
            receiver_id: Unique ID of the receiving agent.
            receiver_name: Name of the receiving agent.
            receiver_framework: Framework the receiver runs on.
            message_type: Type of message (default: handoff).

        Returns:
            GatewayResult with transaction record.
        """
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
        """Receive a message from another agent through the gateway.

        Args:
            content: Raw message bytes.
            sender_id: Unique ID of the sending agent.
            sender_name: Name of the sending agent.
            sender_framework: Framework the sender runs on.
            message_type: Type of message (default: handoff).

        Returns:
            GatewayResult with transaction record.
        """
        return self.gateway.receive(
            content=content,
            sender_id=sender_id,
            sender_name=sender_name,
            sender_framework=sender_framework,
            message_type=message_type,
        )
