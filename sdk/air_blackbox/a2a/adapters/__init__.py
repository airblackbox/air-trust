"""A2A Transaction Layer adapters for AI frameworks.

Each adapter hooks into a framework's native callback/event system
and routes agent-to-agent messages through the A2A Gateway for
signed, tamper-evident transaction recording.

Supported frameworks:
  - LangChain (via BaseCallbackHandler)
  - OpenAI Agents SDK (via client wrapper)
  - CrewAI (via step/task callbacks)
  - AutoGen (via generate_reply wrapping)

Usage:
    from air_blackbox.a2a.adapters import A2ALangChainHandler
    from air_blackbox.a2a.adapters import A2AOpenAIWrapper
    from air_blackbox.a2a.adapters import A2ACrewAIAdapter
    from air_blackbox.a2a.adapters import A2AAutoGenAdapter
"""

from air_blackbox.a2a.adapters.autogen_adapter import A2AAutoGenAdapter
from air_blackbox.a2a.adapters.crewai_adapter import A2ACrewAIAdapter
from air_blackbox.a2a.adapters.langchain_adapter import A2ALangChainHandler
from air_blackbox.a2a.adapters.openai_adapter import A2AOpenAIWrapper

__all__ = [
    "A2ALangChainHandler",
    "A2AOpenAIWrapper",
    "A2ACrewAIAdapter",
    "A2AAutoGenAdapter",
]
