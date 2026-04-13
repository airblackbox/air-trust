"""
LangChain A2A Transaction Adapter.

Hooks into LangChain's BaseCallbackHandler system to record every
LLM call, tool call, and chain invocation as a signed A2A transaction.

Usage:
    from air_blackbox.a2a.adapters.langchain_adapter import A2ALangChainHandler

    handler = A2ALangChainHandler(
        agent_id="my-rag-agent",
        agent_name="RAG Research Agent",
    )

    # Attach to any LangChain chain/agent
    chain.invoke(input, config={"callbacks": [handler]})

    # Or attach to an LLM directly
    llm = ChatOpenAI(model="gpt-4o-mini", callbacks=[handler])
"""

import time
from typing import Any, Dict, List, Optional, Union

from ..gateway import A2AGateway


class A2ALangChainHandler:
    """LangChain callback handler that records A2A transactions.

    Implements the same interface as LangChain's BaseCallbackHandler
    without importing LangChain (so it works even if LangChain is not
    installed -- it just won't be called).

    Each LLM call, tool call, and error is recorded as a signed
    transaction in the A2A Gateway's tamper-evident ledger.

    Args:
        agent_id: Unique identifier for this agent.
        agent_name: Human-readable name for this agent.
        gateway: Optional pre-configured A2AGateway. If not provided,
                 one is created with default settings.
        peer_id: Default peer agent ID (for LLM provider).
        peer_name: Default peer agent name.
        ledger_dir: Directory for the transaction ledger.
        signing_key: HMAC key for the chain.
        signer: Optional EvidenceSigner for ML-DSA-65 signatures.
    """

    def __init__(
        self,
        agent_id: str = "langchain-agent",
        agent_name: str = "LangChain Agent",
        gateway: Optional[A2AGateway] = None,
        peer_id: str = "llm-provider",
        peer_name: str = "LLM Provider",
        ledger_dir: Optional[str] = None,
        signing_key: Optional[str] = None,
        signer: Optional[Any] = None,
    ) -> None:
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.peer_id = peer_id
        self.peer_name = peer_name

        if gateway is not None:
            self.gateway = gateway
        else:
            self.gateway = A2AGateway(
                agent_id=agent_id,
                agent_name=agent_name,
                framework="langchain",
                ledger_dir=ledger_dir,
                signing_key=signing_key,
                signer=signer,
            )

        self._start_times: Dict[str, float] = {}

    # -- LLM hooks ----------------------------------------------------------

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        """Called when an LLM call starts. Records the prompt as a request."""
        run_id = str(kwargs.get("run_id", ""))
        self._start_times[run_id] = time.time()

        model = serialized.get("id", ["unknown"])
        if isinstance(model, list):
            model = model[-1] if model else "unknown"

        content = "\n".join(prompts).encode("utf-8")

        self.gateway.send(
            content=content,
            receiver_id=self.peer_id,
            receiver_name=self.peer_name,
            receiver_framework="openai",
            message_type="request",
        )

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Called when an LLM call finishes. Records the response."""
        run_id = str(kwargs.get("run_id", ""))
        start = self._start_times.pop(run_id, None)
        duration_ms = int((time.time() - start) * 1000) if start else 0

        # Extract text from response
        text = ""
        try:
            if hasattr(response, "generations") and response.generations:
                gen = response.generations[0]
                if isinstance(gen, list) and gen:
                    text = gen[0].text if hasattr(gen[0], "text") else str(gen[0])
                else:
                    text = str(gen)
        except Exception:
            text = str(response)[:500]

        content = text.encode("utf-8")

        self.gateway.receive(
            content=content,
            sender_id=self.peer_id,
            sender_name=self.peer_name,
            sender_framework="openai",
            message_type="response",
        )

    def on_llm_error(self, error: Exception, **kwargs: Any) -> None:
        """Called when an LLM call errors. Records the error."""
        content = f"LLM_ERROR: {type(error).__name__}: {str(error)[:500]}".encode("utf-8")

        self.gateway.receive(
            content=content,
            sender_id=self.peer_id,
            sender_name=self.peer_name,
            sender_framework="openai",
            message_type="response",
        )

    # -- Tool hooks ---------------------------------------------------------

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Called when a tool is invoked. Records the tool call."""
        run_id = str(kwargs.get("run_id", ""))
        self._start_times[run_id] = time.time()

        tool_name = serialized.get("name", "unknown_tool")
        content = f"TOOL_CALL:{tool_name}:{input_str}".encode("utf-8")

        self.gateway.send(
            content=content,
            receiver_id=f"tool-{tool_name}",
            receiver_name=tool_name,
            receiver_framework="langchain-tool",
            message_type="tool_call",
        )

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Called when a tool returns. Records the result."""
        content = f"TOOL_RESULT:{output[:1000]}".encode("utf-8")

        self.gateway.receive(
            content=content,
            sender_id="tool",
            sender_name="Tool",
            sender_framework="langchain-tool",
            message_type="tool_result",
        )

    def on_tool_error(self, error: Exception, **kwargs: Any) -> None:
        """Called when a tool errors. Records the error."""
        content = f"TOOL_ERROR: {type(error).__name__}: {str(error)[:500]}".encode("utf-8")

        self.gateway.receive(
            content=content,
            sender_id="tool",
            sender_name="Tool",
            sender_framework="langchain-tool",
            message_type="tool_result",
        )
