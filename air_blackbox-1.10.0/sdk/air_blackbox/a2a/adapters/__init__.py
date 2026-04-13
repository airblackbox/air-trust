"""A2A Transaction Layer adapters for AI frameworks.

Each adapter hooks into a framework's native callback/event system
and routes agent-to-agent messages through the A2A Gateway for
signed, tamper-evident transaction recording.

Supported frameworks:
  - LangChain (via BaseCallbackHandler)
  - OpenAI Agents SDK (via client wrapper)
  - CrewAI (via step/task callbacks)
  - AutoGen (via generate_reply wrapping)
"""

__all__ = []
