"""
Adapter registry.

Five adapter types cover every AI framework:
  1. proxy    - intercepts LLM API calls (OpenAI, Anthropic, Google, local models)
  2. callback - hooks into framework event systems (LangChain, LlamaIndex, Haystack)
  3. decorator - wraps functions/methods (CrewAI, Smolagents, PydanticAI, DSPy, custom)
  4. otel     - reads OpenTelemetry gen_ai spans (Semantic Kernel, any OTel system)
  5. mcp      - protocol-level for MCP clients (Claude Desktop, Cursor, Claude Code)
"""

from air_trust.adapters.proxy import ProxyAdapter
from air_trust.adapters.callback import CallbackAdapter
from air_trust.adapters.decorator import DecoratorAdapter
from air_trust.adapters.otel import OTelAdapter
from air_trust.adapters.mcp import MCPAdapter

__all__ = [
    "ProxyAdapter",
    "CallbackAdapter",
    "DecoratorAdapter",
    "OTelAdapter",
    "MCPAdapter",
]
