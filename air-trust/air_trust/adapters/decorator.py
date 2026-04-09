"""
Decorator Adapter — wraps functions and methods with audit logging.

Covers: CrewAI, Smolagents, PydanticAI, DSPy, AutoGen, Browser Use,
        and any custom Python function/class.

Strategy: provide decorators that wrap agent tasks, tool calls, and
arbitrary functions to capture inputs, outputs, timing, and safety scans.
"""

from __future__ import annotations
import time
import functools
from typing import Any, Callable, Optional

from air_trust.events import Event
from air_trust.scan import scan_pii, scan_injection
from air_trust.chain import AuditChain


class DecoratorAdapter:
    """Wraps functions and agent methods with audit logging."""

    def __init__(self, chain: AuditChain, framework: str = "unknown"):
        self._chain = chain
        self._framework = framework
        self._event_count = 0

    def _record(self, event: Event):
        self._chain.write(event)
        self._event_count += 1

    @property
    def event_count(self) -> int:
        return self._event_count

    # ── Generic function decorator ──────────────────────────────

    def trace(self, event_type: str = "function_call", scan: bool = True):
        """Decorator that wraps any function with audit logging.

        Usage:
            adapter = DecoratorAdapter(chain)

            @adapter.trace()
            def my_tool(query: str) -> str:
                ...

            @adapter.trace(event_type="llm_call")
            def call_model(prompt):
                ...
        """
        adapter = self

        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                start = time.time()
                error_msg = None
                result = None

                # Build input text for scanning
                input_text = ""
                if scan:
                    parts = [str(a) for a in args] + [f"{k}={v}" for k, v in kwargs.items()]
                    input_text = " ".join(parts)

                try:
                    result = fn(*args, **kwargs)
                    return result
                except Exception as e:
                    error_msg = str(e)
                    raise
                finally:
                    duration = int((time.time() - start) * 1000)
                    event_kwargs = dict(
                        type=event_type,
                        framework=adapter._framework,
                        tool_name=fn.__qualname__,
                        duration_ms=duration,
                        status="error" if error_msg else "success",
                        error=error_msg,
                        output_preview=str(result)[:500] if result else None,
                    )

                    if scan and input_text:
                        pii = scan_pii(input_text)
                        inj, score = scan_injection(input_text)
                        event_kwargs.update(
                            input_preview=input_text[:500],
                            pii_alerts=pii if pii else None,
                            injection_alerts=inj if inj else None,
                            injection_score=score if score > 0 else None,
                        )

                    adapter._record(Event(**event_kwargs))

            return wrapper
        return decorator

    # ── Async version ───────────────────────────────────────────

    def trace_async(self, event_type: str = "function_call", scan: bool = True):
        """Async version of trace() for async functions."""
        adapter = self

        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            async def wrapper(*args, **kwargs):
                start = time.time()
                error_msg = None
                result = None

                input_text = ""
                if scan:
                    parts = [str(a) for a in args] + [f"{k}={v}" for k, v in kwargs.items()]
                    input_text = " ".join(parts)

                try:
                    result = await fn(*args, **kwargs)
                    return result
                except Exception as e:
                    error_msg = str(e)
                    raise
                finally:
                    duration = int((time.time() - start) * 1000)
                    event_kwargs = dict(
                        type=event_type,
                        framework=adapter._framework,
                        tool_name=fn.__qualname__,
                        duration_ms=duration,
                        status="error" if error_msg else "success",
                        error=error_msg,
                        output_preview=str(result)[:500] if result else None,
                    )

                    if scan and input_text:
                        pii = scan_pii(input_text)
                        inj, score = scan_injection(input_text)
                        event_kwargs.update(
                            input_preview=input_text[:500],
                            pii_alerts=pii if pii else None,
                            injection_alerts=inj if inj else None,
                            injection_score=score if score > 0 else None,
                        )

                    adapter._record(Event(**event_kwargs))

            return wrapper
        return decorator

    # ── Framework-specific wrappers ─────────────────────────────

    def wrap_crewai(self, crew: Any) -> Any:
        """Wrap a CrewAI Crew object to audit all task executions.

        Usage:
            from air_trust.adapters.decorator import DecoratorAdapter
            adapter = DecoratorAdapter(chain, "crewai")
            crew = adapter.wrap_crewai(crew)
            result = crew.kickoff()
        """
        if not hasattr(crew, "kickoff"):
            return crew

        adapter = self
        original_kickoff = crew.kickoff

        @functools.wraps(original_kickoff)
        def wrapped_kickoff(*args, **kwargs):
            start = time.time()
            error_msg = None
            result = None

            # Log crew start
            adapter._record(Event(
                type="agent_start",
                framework="crewai",
                description=f"Crew kickoff: {len(getattr(crew, 'tasks', []))} tasks",
                status="running",
            ))

            try:
                result = original_kickoff(*args, **kwargs)
                return result
            except Exception as e:
                error_msg = str(e)
                raise
            finally:
                duration = int((time.time() - start) * 1000)
                adapter._record(Event(
                    type="agent_end",
                    framework="crewai",
                    duration_ms=duration,
                    status="error" if error_msg else "success",
                    error=error_msg,
                    output_preview=str(result)[:500] if result else None,
                ))

        crew.kickoff = wrapped_kickoff

        # Also wrap individual task execute methods if accessible
        for task in getattr(crew, "tasks", []):
            if hasattr(task, "execute_sync"):
                original_exec = task.execute_sync

                @functools.wraps(original_exec)
                def wrapped_exec(*a, _orig=original_exec, _task=task, **kw):
                    start = time.time()
                    err = None
                    res = None
                    try:
                        res = _orig(*a, **kw)
                        return res
                    except Exception as e:
                        err = str(e)
                        raise
                    finally:
                        adapter._record(Event(
                            type="function_call",
                            framework="crewai",
                            tool_name=getattr(_task, "description", "task")[:100],
                            duration_ms=int((time.time() - start) * 1000),
                            status="error" if err else "success",
                            error=err,
                        ))

                task.execute_sync = wrapped_exec

        return crew

    def wrap_smolagents(self, agent: Any) -> Any:
        """Wrap a Smolagents agent to audit all runs.

        Usage:
            from air_trust.adapters.decorator import DecoratorAdapter
            adapter = DecoratorAdapter(chain, "smolagents")
            agent = adapter.wrap_smolagents(agent)
            result = agent.run("query")
        """
        if not hasattr(agent, "run"):
            return agent

        adapter = self
        original_run = agent.run

        @functools.wraps(original_run)
        def wrapped_run(*args, **kwargs):
            start = time.time()
            error_msg = None
            result = None

            # Scan input
            input_text = str(args[0]) if args else str(kwargs.get("task", ""))
            pii = scan_pii(input_text)
            inj, score = scan_injection(input_text)

            adapter._record(Event(
                type="agent_start",
                framework="smolagents",
                input_preview=input_text[:500],
                pii_alerts=pii if pii else None,
                injection_alerts=inj if inj else None,
                injection_score=score if score > 0 else None,
                status="running",
            ))

            try:
                result = original_run(*args, **kwargs)
                return result
            except Exception as e:
                error_msg = str(e)
                raise
            finally:
                duration = int((time.time() - start) * 1000)
                adapter._record(Event(
                    type="agent_end",
                    framework="smolagents",
                    duration_ms=duration,
                    status="error" if error_msg else "success",
                    error=error_msg,
                    output_preview=str(result)[:500] if result else None,
                ))

        agent.run = wrapped_run
        return agent

    def wrap_pydantic_ai(self, agent: Any) -> Any:
        """Wrap a PydanticAI Agent to audit all runs.

        Usage:
            from air_trust.adapters.decorator import DecoratorAdapter
            adapter = DecoratorAdapter(chain, "pydantic_ai")
            agent = adapter.wrap_pydantic_ai(agent)
        """
        adapter = self

        for method_name in ("run", "run_sync"):
            if not hasattr(agent, method_name):
                continue

            original = getattr(agent, method_name)

            if method_name == "run":
                @functools.wraps(original)
                async def wrapped_async(*args, _orig=original, **kwargs):
                    start = time.time()
                    error_msg = None
                    result = None
                    try:
                        result = await _orig(*args, **kwargs)
                        return result
                    except Exception as e:
                        error_msg = str(e)
                        raise
                    finally:
                        adapter._record(Event(
                            type="agent_end",
                            framework="pydantic_ai",
                            duration_ms=int((time.time() - start) * 1000),
                            status="error" if error_msg else "success",
                            error=error_msg,
                        ))

                setattr(agent, method_name, wrapped_async)
            else:
                @functools.wraps(original)
                def wrapped_sync(*args, _orig=original, **kwargs):
                    start = time.time()
                    error_msg = None
                    result = None
                    try:
                        result = _orig(*args, **kwargs)
                        return result
                    except Exception as e:
                        error_msg = str(e)
                        raise
                    finally:
                        adapter._record(Event(
                            type="agent_end",
                            framework="pydantic_ai",
                            duration_ms=int((time.time() - start) * 1000),
                            status="error" if error_msg else "success",
                            error=error_msg,
                        ))

                setattr(agent, method_name, wrapped_sync)

        return agent

    def wrap_dspy(self, module: Any) -> Any:
        """Wrap a DSPy module to audit forward() calls.

        Usage:
            from air_trust.adapters.decorator import DecoratorAdapter
            adapter = DecoratorAdapter(chain, "dspy")
            module = adapter.wrap_dspy(module)
        """
        if not hasattr(module, "forward"):
            return module

        adapter = self
        original_forward = module.forward

        @functools.wraps(original_forward)
        def wrapped_forward(*args, **kwargs):
            start = time.time()
            error_msg = None
            result = None
            try:
                result = original_forward(*args, **kwargs)
                return result
            except Exception as e:
                error_msg = str(e)
                raise
            finally:
                adapter._record(Event(
                    type="function_call",
                    framework="dspy",
                    tool_name=type(module).__name__,
                    duration_ms=int((time.time() - start) * 1000),
                    status="error" if error_msg else "success",
                    error=error_msg,
                ))

        module.forward = wrapped_forward
        return module

    def wrap_autogen(self, agent: Any) -> Any:
        """Wrap an AutoGen agent to audit message handling.

        Usage:
            from air_trust.adapters.decorator import DecoratorAdapter
            adapter = DecoratorAdapter(chain, "autogen")
            agent = adapter.wrap_autogen(agent)
        """
        adapter = self

        # AutoGen agents use generate_reply or a_generate_reply
        if hasattr(agent, "generate_reply"):
            original = agent.generate_reply

            @functools.wraps(original)
            def wrapped(*args, **kwargs):
                start = time.time()
                error_msg = None
                result = None
                try:
                    result = original(*args, **kwargs)
                    return result
                except Exception as e:
                    error_msg = str(e)
                    raise
                finally:
                    adapter._record(Event(
                        type="llm_call",
                        framework="autogen",
                        agent=getattr(agent, "name", "unknown"),
                        duration_ms=int((time.time() - start) * 1000),
                        status="error" if error_msg else "success",
                        error=error_msg,
                        output_preview=str(result)[:500] if result else None,
                    ))

            agent.generate_reply = wrapped

        return agent

    def wrap_browser_use(self, agent: Any) -> Any:
        """Wrap a Browser Use agent to audit browser actions.

        Usage:
            from air_trust.adapters.decorator import DecoratorAdapter
            adapter = DecoratorAdapter(chain, "browser_use")
            agent = adapter.wrap_browser_use(agent)
        """
        adapter = self

        if hasattr(agent, "run"):
            original = agent.run

            @functools.wraps(original)
            async def wrapped(*args, **kwargs):
                start = time.time()
                error_msg = None
                result = None

                adapter._record(Event(
                    type="agent_start",
                    framework="browser_use",
                    description="Browser agent run",
                    status="running",
                ))

                try:
                    result = await original(*args, **kwargs)
                    return result
                except Exception as e:
                    error_msg = str(e)
                    raise
                finally:
                    adapter._record(Event(
                        type="agent_end",
                        framework="browser_use",
                        duration_ms=int((time.time() - start) * 1000),
                        status="error" if error_msg else "success",
                        error=error_msg,
                    ))

            agent.run = wrapped

        return agent
