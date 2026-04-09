"""
MCP Adapter — protocol-level auditing for Model Context Protocol.

Covers: Claude Desktop, Cursor, Claude Code, Windsurf, any MCP client.

Strategy: wrap MCP tool execution at the protocol layer so every
tool call through any MCP server gets audited automatically.
"""

from __future__ import annotations
import time
import functools
from typing import Any, Callable, Optional

from air_trust.events import Event
from air_trust.scan import scan_pii, scan_injection
from air_trust.chain import AuditChain


class MCPAdapter:
    """Audits MCP tool calls at the protocol level."""

    def __init__(self, chain: AuditChain, framework: str = "mcp"):
        self._chain = chain
        self._framework = framework
        self._event_count = 0

    def _record(self, event: Event):
        self._chain.write(event)
        self._event_count += 1

    @property
    def event_count(self) -> int:
        return self._event_count

    def wrap_server(self, server: Any) -> Any:
        """Wrap an MCP Server to audit all tool calls.

        Works with the official mcp Python SDK's Server class.

        Usage:
            from mcp.server import Server
            from air_trust.adapters.mcp import MCPAdapter

            server = Server("my-server")
            adapter = MCPAdapter(chain)
            server = adapter.wrap_server(server)
        """
        adapter = self

        # The MCP SDK uses @server.call_tool() decorator pattern.
        # We wrap the tool handler registry to intercept calls.
        if hasattr(server, "_tool_handlers"):
            # Wrap existing handlers
            for name, handler in list(server._tool_handlers.items()):
                server._tool_handlers[name] = adapter._wrap_tool_handler(
                    handler, name
                )

            # Wrap the registration method to catch future tools
            original_call_tool = getattr(server, "call_tool", None)
            if original_call_tool:
                @functools.wraps(original_call_tool)
                def wrapped_call_tool():
                    def decorator(fn):
                        wrapped = adapter._wrap_tool_handler(fn, fn.__name__)
                        return original_call_tool()(wrapped)
                    return decorator
                server.call_tool = wrapped_call_tool

        return server

    def wrap_tool_handler(self, name: str):
        """Decorator for individual MCP tool handlers.

        Usage:
            adapter = MCPAdapter(chain)

            @server.call_tool()
            @adapter.wrap_tool_handler("search_docs")
            async def handle_search(arguments: dict):
                ...
        """
        adapter = self

        def decorator(fn: Callable) -> Callable:
            return adapter._wrap_tool_handler(fn, name)
        return decorator

    def _wrap_tool_handler(self, fn: Callable, tool_name: str) -> Callable:
        """Internal: wrap a single tool handler."""
        adapter = self
        import asyncio

        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                start = time.time()
                error_msg = None
                result = None

                # Scan tool arguments
                input_text = _extract_input(args, kwargs)
                pii = scan_pii(input_text) if input_text else []
                inj, score = scan_injection(input_text) if input_text else ([], 0.0)

                try:
                    result = await fn(*args, **kwargs)
                    return result
                except Exception as e:
                    error_msg = str(e)
                    raise
                finally:
                    duration = int((time.time() - start) * 1000)
                    adapter._record(Event(
                        type="tool_call",
                        framework="mcp",
                        tool_name=tool_name,
                        duration_ms=duration,
                        status="error" if error_msg else "success",
                        error=error_msg,
                        input_preview=input_text[:500] if input_text else None,
                        output_preview=str(result)[:500] if result else None,
                        pii_alerts=pii if pii else None,
                        injection_alerts=inj if inj else None,
                        injection_score=score if score > 0 else None,
                    ))

            return async_wrapper
        else:
            @functools.wraps(fn)
            def sync_wrapper(*args, **kwargs):
                start = time.time()
                error_msg = None
                result = None

                input_text = _extract_input(args, kwargs)
                pii = scan_pii(input_text) if input_text else []
                inj, score = scan_injection(input_text) if input_text else ([], 0.0)

                try:
                    result = fn(*args, **kwargs)
                    return result
                except Exception as e:
                    error_msg = str(e)
                    raise
                finally:
                    duration = int((time.time() - start) * 1000)
                    adapter._record(Event(
                        type="tool_call",
                        framework="mcp",
                        tool_name=tool_name,
                        duration_ms=duration,
                        status="error" if error_msg else "success",
                        error=error_msg,
                        input_preview=input_text[:500] if input_text else None,
                        output_preview=str(result)[:500] if result else None,
                        pii_alerts=pii if pii else None,
                        injection_alerts=inj if inj else None,
                        injection_score=score if score > 0 else None,
                    ))

            return sync_wrapper

    def log_request(self, method: str, params: Optional[dict] = None):
        """Manually log an MCP protocol request.

        For custom MCP implementations that don't use the SDK.

        Usage:
            adapter.log_request("tools/call", {"name": "search", "arguments": {...}})
        """
        input_text = str(params) if params else ""
        pii = scan_pii(input_text)
        inj, score = scan_injection(input_text)

        tool_name = "unknown"
        if params and isinstance(params, dict):
            tool_name = params.get("name", "unknown")

        self._record(Event(
            type="tool_call",
            framework="mcp",
            tool_name=tool_name,
            description=f"MCP {method}",
            status="logged",
            input_preview=input_text[:500] if input_text else None,
            pii_alerts=pii if pii else None,
            injection_alerts=inj if inj else None,
            injection_score=score if score > 0 else None,
        ))

    def log_response(self, method: str, result: Any = None,
                     error: Optional[str] = None, duration_ms: int = 0):
        """Manually log an MCP protocol response."""
        self._record(Event(
            type="tool_call",
            framework="mcp",
            description=f"MCP {method} response",
            duration_ms=duration_ms,
            status="error" if error else "success",
            error=error,
            output_preview=str(result)[:500] if result else None,
        ))


def _extract_input(args: tuple, kwargs: dict) -> str:
    """Extract input text from MCP tool handler arguments."""
    parts = []

    # MCP tool handlers typically get (arguments: dict) or (name, arguments)
    for arg in args:
        if isinstance(arg, dict):
            parts.extend(str(v) for v in arg.values())
        else:
            parts.append(str(arg))

    # Also check kwargs
    arguments = kwargs.get("arguments", kwargs.get("params", {}))
    if isinstance(arguments, dict):
        parts.extend(str(v) for v in arguments.values())

    return " ".join(parts)
