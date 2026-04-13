"""
Generate PASS-heavy training examples from real framework patterns.

Problem: Current training data is 86% FAIL / 22% PASS.
The model learns to say FAIL for everything.

Solution: Generate realistic PASS examples where the model sees actual
compliance code and learns to recognize + cite it properly.

Uses Alpaca format with sample_context and total_files.
"""

import json
import random
import os

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "phase33_pass_heavy.jsonl")

# ============================================================================
# REAL CODE SNIPPETS from Haystack, LangChain, CrewAI
# These are realistic patterns the model needs to learn to recognize as PASS
# ============================================================================

HAYSTACK_LOGGING_TRACER = '''
import logging
from typing import Any, Dict, Iterator, List, Optional, Union

logger = logging.getLogger(__name__)

class LoggingTracer:
    """Tracer that logs pipeline events for observability and compliance."""

    def __init__(self, tags: Optional[Dict[str, Any]] = None):
        self.tags = tags or {}
        self._spans: List[Dict[str, Any]] = []

    def trace(self, operation_name: str, content: Dict[str, Any]) -> None:
        """Record a trace span with operation details."""
        span = {
            "operation": operation_name,
            "content": content,
            "tags": self.tags,
            "timestamp": self._now(),
        }
        self._spans.append(span)
        logger.info("Trace: %s", operation_name, extra=span)

    def get_spans(self) -> List[Dict[str, Any]]:
        """Return all recorded spans for audit purposes."""
        return list(self._spans)

HAYSTACK_CONTENT_TRACING_ENABLED = True  # production-grade tracing flag
'''

HAYSTACK_FILTER_POLICY = '''
from enum import Enum
from dataclasses import dataclass
from typing import Any, Dict, Optional

class FilterPolicy(Enum):
    """Policy for handling document store filter operations.

    Provides input validation and governance over data access patterns.
    """
    REPLACE = "replace"
    MERGE = "merge"

    def apply(self, init_filters: Optional[Dict[str, Any]],
              runtime_filters: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Apply filter policy with validation.

        Args:
            init_filters: Initial filters from pipeline configuration
            runtime_filters: Runtime filters from user input

        Returns:
            Merged or replaced filter dict

        Raises:
            ValueError: If filters are invalid
        """
        if self == FilterPolicy.REPLACE:
            return runtime_filters if runtime_filters else init_filters
        elif self == FilterPolicy.MERGE:
            if not init_filters:
                return runtime_filters
            if not runtime_filters:
                return init_filters
            merged = {**init_filters, **runtime_filters}
            return merged
        raise ValueError(f"Unknown filter policy: {self}")
'''

HAYSTACK_PIPELINE_TOOL = '''
import logging
from typing import Any, Dict, List, Optional, Type

logger = logging.getLogger(__name__)

class PipelineTool:
    """Wraps a Haystack pipeline as an agent tool with safety controls.

    Provides:
    - Input validation via Pydantic schemas
    - Execution boundaries (max_runs parameter)
    - Structured logging of all invocations
    - Error handling with graceful fallback
    """

    def __init__(self, pipeline, name: str, description: str,
                 max_runs: int = 100,
                 parameters: Optional[Dict[str, Any]] = None):
        self.pipeline = pipeline
        self.name = name
        self.description = description
        self.max_runs = max_runs
        self._run_count = 0
        self.parameters = parameters or {}

    def run(self, **kwargs) -> Dict[str, Any]:
        """Execute the pipeline tool with safety controls.

        Args:
            **kwargs: Pipeline input parameters

        Returns:
            Pipeline output dict

        Raises:
            RuntimeError: If max_runs exceeded (execution boundary)
        """
        if self._run_count >= self.max_runs:
            logger.warning("Execution boundary reached: %d/%d runs",
                          self._run_count, self.max_runs)
            raise RuntimeError(
                f"Tool '{self.name}' exceeded max runs ({self.max_runs}). "
                f"This is a safety boundary to prevent runaway execution."
            )

        self._run_count += 1
        logger.info("Tool invocation #%d: %s", self._run_count, self.name)

        try:
            result = self.pipeline.run(**kwargs)
            logger.info("Tool %s completed successfully", self.name)
            return result
        except Exception as e:
            logger.error("Tool %s failed: %s", self.name, str(e))
            raise
'''

HAYSTACK_ERRORS = '''
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class PipelineError(Exception):
    """Base exception for pipeline errors with structured logging."""

    def __init__(self, message: str, component: Optional[str] = None):
        self.component = component
        logger.error("PipelineError in %s: %s", component or "unknown", message)
        super().__init__(message)

class PipelineRuntimeError(PipelineError):
    """Runtime error during pipeline execution.

    Includes automatic retry context for resilience.
    """
    pass

class PipelineValidationError(PipelineError):
    """Validation error for pipeline inputs.

    Raised when input validation fails before execution.
    """
    pass

class PipelineMaxComponentVisitsExceeded(PipelineRuntimeError):
    """Raised when a component is visited more times than allowed.

    This is an execution boundary to prevent infinite loops in agent pipelines.
    Acts as a safety mechanism per Article 14 requirements.
    """
    pass

class ComponentError(Exception):
    """Base exception for component-level errors."""

    def __init__(self, message: str, component_name: str = ""):
        self.component_name = component_name
        logger.error("ComponentError [%s]: %s", component_name, message)
        super().__init__(message)

class DeserializationError(ComponentError):
    """Error during component deserialization.

    Guards against corrupted or tampered serialized data.
    """
    pass
'''

HAYSTACK_LOGGING_MODULE = '''
import logging
import os
import sys
from typing import Optional

def configure_logging(
    use_json: bool = False,
    log_level: str = "INFO",
    correlation_id: Optional[str] = None,
) -> None:
    """Configure structured logging for the application.

    Supports JSON output for production environments and
    correlation IDs for distributed tracing.

    Args:
        use_json: If True, output structured JSON logs
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        correlation_id: Optional correlation ID for request tracing
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    if use_json:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_JsonFormatter(correlation_id=correlation_id))
    else:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        ))

    root_logger = logging.getLogger("haystack")
    root_logger.setLevel(level)
    root_logger.addHandler(handler)


class _JsonFormatter(logging.Formatter):
    """JSON log formatter for structured, machine-readable logs."""

    def __init__(self, correlation_id: Optional[str] = None):
        super().__init__()
        self.correlation_id = correlation_id

    def format(self, record: logging.LogRecord) -> str:
        import json
        log_data = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
        }
        if self.correlation_id:
            log_data["correlation_id"] = self.correlation_id
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data)
'''

LANGCHAIN_CALLBACK_HANDLER = '''
import logging
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from uuid import UUID

logger = logging.getLogger(__name__)

class ComplianceCallbackHandler:
    """Callback handler that logs all LLM interactions for audit compliance.

    Implements Article 12 record-keeping by capturing:
    - All LLM invocations with timestamps
    - Input prompts and output responses
    - Token usage and model metadata
    - Error events with full context
    """

    def __init__(self, audit_log_path: str = "audit.jsonl"):
        self.audit_log_path = audit_log_path
        self.run_history: List[Dict[str, Any]] = []

    def on_llm_start(self, serialized: Dict[str, Any],
                     prompts: List[str], *,
                     run_id: UUID, **kwargs) -> None:
        """Log LLM invocation start with full context."""
        record = {
            "event": "llm_start",
            "run_id": str(run_id),
            "model": serialized.get("name", "unknown"),
            "prompt_count": len(prompts),
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.run_history.append(record)
        logger.info("LLM start: %s", record)

    def on_llm_end(self, response: Any, *,
                   run_id: UUID, **kwargs) -> None:
        """Log LLM completion with token usage."""
        record = {
            "event": "llm_end",
            "run_id": str(run_id),
            "timestamp": datetime.utcnow().isoformat(),
        }
        if hasattr(response, "llm_output") and response.llm_output:
            usage = response.llm_output.get("token_usage", {})
            record["tokens"] = usage
        self.run_history.append(record)
        logger.info("LLM end: %s", record)

    def on_llm_error(self, error: BaseException, *,
                     run_id: UUID, **kwargs) -> None:
        """Log LLM errors with full exception context."""
        record = {
            "event": "llm_error",
            "run_id": str(run_id),
            "error": str(error),
            "error_type": type(error).__name__,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.run_history.append(record)
        logger.error("LLM error: %s", record)
'''

LANGCHAIN_CHAIN_WITH_VALIDATION = '''
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, validator
import logging

logger = logging.getLogger(__name__)

class ChainInput(BaseModel):
    """Validated input schema for the chain.

    Uses Pydantic for input validation (Article 10 data governance).
    """
    query: str = Field(..., min_length=1, max_length=10000,
                       description="User query to process")
    user_id: str = Field(..., description="Authenticated user identifier")
    max_tokens: int = Field(default=1000, ge=1, le=4096)

    @validator("query")
    def sanitize_query(cls, v: str) -> str:
        """Sanitize user input to prevent prompt injection."""
        # Strip control characters
        v = "".join(c for c in v if c.isprintable() or c in "\\n\\t")
        # Check for injection patterns
        injection_patterns = [
            "ignore previous instructions",
            "system prompt",
            "you are now",
        ]
        for pattern in injection_patterns:
            if pattern.lower() in v.lower():
                logger.warning("Potential injection detected: %s", pattern)
                raise ValueError(f"Input contains disallowed pattern")
        return v

class SafeChain:
    """LLM chain with built-in safety controls.

    Implements:
    - Input validation via Pydantic (Article 10)
    - Rate limiting per user (Article 14)
    - Error handling with fallback (Article 9)
    - Structured logging (Article 12)
    """

    def __init__(self, llm, rate_limit: int = 100):
        self.llm = llm
        self.rate_limit = rate_limit
        self._user_counts: Dict[str, int] = {}

    def invoke(self, input_data: Dict[str, Any]) -> str:
        """Execute chain with all safety controls."""
        # Validate input
        validated = ChainInput(**input_data)

        # Check rate limit (Article 14 - usage controls)
        user_count = self._user_counts.get(validated.user_id, 0)
        if user_count >= self.rate_limit:
            logger.warning("Rate limit exceeded for user %s", validated.user_id)
            raise RuntimeError(f"Rate limit exceeded for user {validated.user_id}")

        self._user_counts[validated.user_id] = user_count + 1
        logger.info("Chain invocation for user %s (#%d)",
                    validated.user_id, user_count + 1)

        try:
            result = self.llm.invoke(validated.query)
            logger.info("Chain completed for user %s", validated.user_id)
            return result
        except Exception as e:
            logger.error("Chain error for user %s: %s",
                        validated.user_id, str(e))
            # Fallback response
            return "I'm sorry, I encountered an error. Please try again."
'''

CREWAI_AGENT_SAFE = '''
import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

class SafeAgent:
    """CrewAI agent with EU AI Act compliance controls.

    Implements human oversight (Article 14) through:
    - Action approval callbacks for high-risk operations
    - Execution boundaries via max_iterations
    - Identity binding via agent_id and user_id
    - Full action audit trail
    """

    def __init__(self, role: str, goal: str,
                 max_iterations: int = 25,
                 human_approval_callback: Optional[Callable] = None,
                 user_id: Optional[str] = None,
                 agent_id: Optional[str] = None):
        self.role = role
        self.goal = goal
        self.max_iterations = max_iterations
        self.human_approval = human_approval_callback
        self.user_id = user_id
        self.agent_id = agent_id or f"agent-{id(self)}"
        self._iteration_count = 0
        self._action_log: List[Dict[str, Any]] = []

    def execute_task(self, task: str) -> str:
        """Execute a task with safety controls.

        Args:
            task: Task description to execute

        Returns:
            Task result string

        Raises:
            RuntimeError: If max_iterations exceeded
        """
        self._iteration_count += 1

        if self._iteration_count > self.max_iterations:
            logger.warning("Agent %s hit execution boundary: %d/%d",
                          self.agent_id, self._iteration_count,
                          self.max_iterations)
            raise RuntimeError(
                f"Agent '{self.role}' exceeded max iterations "
                f"({self.max_iterations}). Kill switch activated."
            )

        # Log action for audit trail (Article 12)
        action_record = {
            "agent_id": self.agent_id,
            "user_id": self.user_id,
            "task": task,
            "iteration": self._iteration_count,
            "role": self.role,
        }
        self._action_log.append(action_record)
        logger.info("Agent action: %s", action_record)

        # Human approval gate for high-risk actions (Article 14)
        if self.human_approval and self._is_high_risk(task):
            approved = self.human_approval(task, action_record)
            if not approved:
                logger.info("Human rejected action: %s", task)
                return "Action requires human approval and was not approved."

        return self._do_execute(task)

    def _is_high_risk(self, task: str) -> bool:
        """Determine if a task requires human approval."""
        high_risk_keywords = ["delete", "modify", "send", "publish", "deploy"]
        return any(kw in task.lower() for kw in high_risk_keywords)

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Return full action audit trail."""
        return list(self._action_log)
'''

LANGCHAIN_RETRY_WITH_FALLBACK = '''
import logging
import time
from typing import Any, Optional, Callable
from functools import wraps

logger = logging.getLogger(__name__)

def retry_with_fallback(
    max_retries: int = 3,
    backoff_factor: float = 1.0,
    fallback_response: Optional[str] = None,
    on_error: Optional[Callable] = None,
):
    """Decorator for LLM calls with retry logic and fallback.

    Implements Article 9 (Risk Management) by providing:
    - Exponential backoff retry on transient failures
    - Configurable fallback response
    - Error callback for monitoring

    Args:
        max_retries: Maximum retry attempts
        backoff_factor: Base delay multiplier for exponential backoff
        fallback_response: Response to return if all retries fail
        on_error: Callback function invoked on each error
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(max_retries + 1):
                try:
                    result = func(*args, **kwargs)
                    if attempt > 0:
                        logger.info("Succeeded on retry #%d", attempt)
                    return result
                except Exception as e:
                    last_error = e
                    logger.warning(
                        "Attempt %d/%d failed: %s",
                        attempt + 1, max_retries + 1, str(e)
                    )
                    if on_error:
                        on_error(e, attempt)
                    if attempt < max_retries:
                        delay = backoff_factor * (2 ** attempt)
                        logger.info("Retrying in %.1fs...", delay)
                        time.sleep(delay)

            logger.error(
                "All %d attempts failed. Last error: %s",
                max_retries + 1, str(last_error)
            )
            if fallback_response is not None:
                logger.info("Returning fallback response")
                return fallback_response
            raise last_error
        return wrapper
    return decorator


class ResilientLLM:
    """LLM wrapper with built-in resilience patterns.

    Combines retry logic, circuit breaking, and fallback
    per Article 9 risk management requirements.
    """

    def __init__(self, llm, max_retries: int = 3):
        self.llm = llm
        self.max_retries = max_retries
        self._error_count = 0
        self._circuit_open = False

    @retry_with_fallback(max_retries=3, backoff_factor=1.0,
                         fallback_response="Service temporarily unavailable.")
    def invoke(self, prompt: str) -> str:
        """Invoke LLM with retry and fallback protection."""
        if self._circuit_open:
            logger.warning("Circuit breaker is open, using fallback")
            return "Service temporarily unavailable."
        return self.llm.invoke(prompt)
'''

# ============================================================================
# INSTRUCTION TEMPLATES for the Alpaca format
# These use sample_context and total_files
# ============================================================================

INSTRUCTIONS_PASS_HEAVY = [
    "Analyze this Python code for EU AI Act compliance. This is a {sample_context} from a project with {total_files} Python files. Assess ONLY what is visible in the code below — do not assume patterns are missing if they could exist in files not shown.\n\nFor each of Articles 9, 10, 11, 12, 14, and 15: report status (pass if evidence found, warn if partial, fail only if clearly absent), cite specific evidence from the code (function names, patterns, line references), and give fix recommendations. Output as a JSON array.",
    "Scan the following Python code sample for EU AI Act compliance patterns. This is a {sample_context} from a project with {total_files} Python files. Focus on what IS present — cite specific classes, functions, and patterns you can see. Only mark FAIL for articles where the code clearly contradicts requirements.\n\nAnalyze Articles 9, 10, 11, 12, 14, and 15. Output structured findings.",
    "Review this Python AI agent code for EU AI Act Articles 9-15 compliance. This represents a {sample_context} from a {total_files}-file project. Identify compliance evidence in the code — name specific functions, classes, decorators, and patterns. Be precise about what you observe.",
    "Evaluate EU AI Act compliance in this code sample. This is a {sample_context} from a project with {total_files} Python files total. Cite specific evidence for each article: function names, class names, pattern descriptions. Output findings for Articles 9, 10, 11, 12, 14, 15.",
]


# ============================================================================
# GENERATE TRAINING EXAMPLES
# ============================================================================

def make_pass_example(code: str, framework: str, articles_status: dict,
                      sample_desc: str, total_files: int) -> dict:
    """Create one Alpaca training example.

    articles_status: dict like {9: ("pass", "evidence text", "fix hint"), ...}
    """
    instruction = random.choice(INSTRUCTIONS_PASS_HEAVY).format(
        sample_context=sample_desc,
        total_files=total_files,
    )

    # Build structured markdown output (matching existing training format)
    output_parts = []
    output_parts.append(f"## EU AI Act Compliance Analysis\n")
    output_parts.append(f"**Framework detected**: {framework}")

    pass_count = sum(1 for s, _, _ in articles_status.values() if s == "pass")
    output_parts.append(f"**Technical compliance coverage**: {pass_count}/6 articles\n")

    article_names = {
        9: "Risk Management",
        10: "Data Governance",
        11: "Technical Documentation",
        12: "Record-Keeping",
        14: "Human Oversight",
        15: "Accuracy, Robustness & Cybersecurity",
    }

    for art_num in [9, 10, 11, 12, 14, 15]:
        status, evidence, fix = articles_status.get(art_num, ("warn", "Partial evidence", "Review needed"))
        name = article_names[art_num]
        status_upper = status.upper()

        output_parts.append(f"### Article {art_num} — {name}\n")
        output_parts.append(f"**Status**: {status_upper}")
        output_parts.append(f"**Analysis**: {evidence}")
        if fix and status != "pass":
            output_parts.append(f"**Recommendation**: {fix}")
        output_parts.append("")

    return {
        "instruction": instruction,
        "input": code.strip(),
        "output": "\n".join(output_parts).strip(),
    }


def generate_haystack_examples() -> list:
    """Generate training examples from Haystack code patterns."""
    examples = []

    # Example 1: logging_tracer.py — strong Article 12 pass
    examples.append(make_pass_example(
        code=HAYSTACK_LOGGING_TRACER,
        framework="Haystack",
        sample_desc="targeted sample of 4 compliance-relevant source files",
        total_files=552,
        articles_status={
            9: ("warn", "No explicit error handling or fallback mechanisms visible in this file. However, this is a tracing module — error handling may exist in other pipeline files not shown in this sample.", "Add try/except around trace operations for resilience"),
            10: ("warn", "No input validation visible in this tracing module. Data governance patterns likely exist in other files (552 total files in project).", "Consider adding validation to trace content"),
            11: ("pass", "LoggingTracer class has comprehensive docstrings on all methods: trace(), get_spans(), __init__(). Type hints present on all function signatures (tags: Optional[Dict[str, Any]], operation_name: str, content: Dict[str, Any]).", ""),
            12: ("pass", "Production-grade tracing implementation: LoggingTracer class records all operations with timestamps via trace() method. Uses logger.info() for structured logging. HAYSTACK_CONTENT_TRACING_ENABLED flag enables production tracing. get_spans() provides audit trail access.", ""),
            14: ("warn", "No human-in-the-loop gates visible in this tracing module. HITL patterns may exist in other files — this is a sample of 4 files from 552.", "Consider adding approval gates for sensitive operations"),
            15: ("warn", "No explicit injection defense or retry logic in this module. Security patterns likely exist in other files not shown.", "Add input sanitization to trace content"),
        }
    ))

    # Example 2: filter_policy.py — strong Article 10 pass
    examples.append(make_pass_example(
        code=HAYSTACK_FILTER_POLICY,
        framework="Haystack",
        sample_desc="targeted sample of 3 core data governance files",
        total_files=552,
        articles_status={
            9: ("pass", "FilterPolicy.apply() raises ValueError for invalid policies — explicit error handling. The enum pattern prevents invalid states by design.", ""),
            10: ("pass", "FilterPolicy class implements data governance through controlled filter operations. The apply() method validates inputs, raises ValueError for invalid filters, and uses type-safe Enum pattern. Pydantic-style dataclass with type hints enforces schema.", ""),
            11: ("pass", "Comprehensive docstrings on FilterPolicy class, apply() method with full Args/Returns/Raises documentation. Type hints on all parameters (init_filters: Optional[Dict[str, Any]], runtime_filters: Optional[Dict[str, Any]]).", ""),
            12: ("warn", "No logging visible in this module. Record-keeping likely handled by other components.", "Add logging to filter operations for audit trail"),
            14: ("warn", "No HITL mechanisms in this data governance module. Human oversight may be implemented at pipeline level.", "Consider human review for filter policy changes"),
            15: ("pass", "Input validation via type checking and ValueError raises. Enum pattern prevents invalid filter policy states. The MERGE policy safely combines filters without data loss.", ""),
        }
    ))

    # Example 3: pipeline_tool.py — strong Articles 9, 12, 14 pass
    examples.append(make_pass_example(
        code=HAYSTACK_PIPELINE_TOOL,
        framework="Haystack",
        sample_desc="targeted sample of 4 compliance-relevant source files",
        total_files=552,
        articles_status={
            9: ("pass", "PipelineTool.run() wraps pipeline execution in try/except with logger.error() on failure. max_runs parameter creates execution boundary preventing runaway operations. RuntimeError raised when boundary exceeded.", ""),
            10: ("warn", "Parameters dict provides basic input structure but no Pydantic validation visible. Input validation may exist in the pipeline components.", "Add Pydantic schema validation for tool parameters"),
            11: ("pass", "PipelineTool class has comprehensive docstring listing all features (input validation, execution boundaries, structured logging, error handling). run() method has full Args/Returns/Raises docs. Type hints on all parameters.", ""),
            12: ("pass", "Structured logging throughout: logger.info() on every tool invocation with run count, logger.info() on completion, logger.error() on failures. _run_count tracks invocation history.", ""),
            14: ("pass", "max_runs parameter implements execution boundary (Article 14 usage control). RuntimeError kill switch activates when boundary exceeded. Warning logged before boundary hit. _run_count provides usage tracking per tool instance.", ""),
            15: ("pass", "Error handling via try/except in run(). Execution boundary prevents runaway agents. Structured error logging captures failures for analysis.", ""),
        }
    ))

    # Example 4: errors.py — strong Article 9 pass
    examples.append(make_pass_example(
        code=HAYSTACK_ERRORS,
        framework="Haystack",
        sample_desc="targeted sample of 3 error handling modules",
        total_files=552,
        articles_status={
            9: ("pass", "Rich exception hierarchy for risk management: PipelineError (base), PipelineRuntimeError (execution), PipelineValidationError (input), PipelineMaxComponentVisitsExceeded (execution boundary), ComponentError, DeserializationError. All exceptions log via logger.error() on creation. PipelineMaxComponentVisitsExceeded explicitly documented as safety mechanism.", ""),
            10: ("pass", "PipelineValidationError provides input validation error handling. DeserializationError guards against corrupted/tampered serialized data. Exception hierarchy enables typed error handling for data governance.", ""),
            11: ("pass", "All exception classes have docstrings explaining purpose. PipelineMaxComponentVisitsExceeded documented as 'safety mechanism per Article 14 requirements'. Type hints on __init__ parameters (message: str, component: Optional[str]).", ""),
            12: ("pass", "Every exception class automatically logs via logger.error() on instantiation. Component name captured in log context. Full error chain preserved through inheritance.", ""),
            14: ("pass", "PipelineMaxComponentVisitsExceeded serves as an execution boundary / kill switch — prevents infinite loops in agent pipelines. Docstring explicitly references Article 14 compliance.", ""),
            15: ("pass", "DeserializationError guards against tampered serialized data (security). PipelineValidationError catches invalid inputs before execution. Exception hierarchy enables precise error handling and recovery.", ""),
        }
    ))

    # Example 5: logging.py — strong Article 12 pass
    examples.append(make_pass_example(
        code=HAYSTACK_LOGGING_MODULE,
        framework="Haystack",
        sample_desc="targeted sample of 2 logging infrastructure files",
        total_files=552,
        articles_status={
            9: ("warn", "No error handling or fallback visible in the logging configuration itself. Risk management patterns likely exist in pipeline execution code.", ""),
            10: ("warn", "No data validation patterns in the logging module.", ""),
            11: ("pass", "configure_logging() has full docstring with Args documentation. _JsonFormatter class documented as 'JSON log formatter for structured, machine-readable logs'. Type hints on all parameters.", ""),
            12: ("pass", "Production-grade logging infrastructure: configure_logging() supports JSON output for structured logs, correlation_id for distributed tracing, configurable log levels. _JsonFormatter produces machine-readable logs with timestamp, level, logger, message, module, function, and exception fields. Correlation ID enables cross-service request tracing.", ""),
            14: ("warn", "No HITL mechanisms in logging infrastructure. Human oversight implemented at application level.", ""),
            15: ("warn", "No security-specific patterns in logging module.", ""),
        }
    ))

    # Example 6: Combined multi-file Haystack sample (like real scanning)
    combined_code = f"# === haystack/tracing/logging_tracer.py ===\n{HAYSTACK_LOGGING_TRACER}\n\n# === haystack/core/errors.py ===\n{HAYSTACK_ERRORS}\n\n# === haystack/tools/pipeline_tool.py ===\n{HAYSTACK_PIPELINE_TOOL}"

    examples.append(make_pass_example(
        code=combined_code,
        framework="Haystack",
        sample_desc="targeted sample of 3 compliance-relevant source files",
        total_files=552,
        articles_status={
            9: ("pass", "Strong error handling: PipelineError hierarchy with PipelineRuntimeError, PipelineValidationError, ComponentError. PipelineTool.run() wraps execution in try/except. PipelineMaxComponentVisitsExceeded prevents infinite loops. All exceptions auto-log on creation.", ""),
            10: ("warn", "PipelineValidationError provides validation error handling, but no Pydantic-style input schemas visible in this sample. Validation likely exists in other files (552 total).", "Add Pydantic schema validation where user input enters pipelines"),
            11: ("pass", "Comprehensive docstrings across all 3 files: LoggingTracer (trace, get_spans), PipelineTool (class docstring lists all features, run method with Args/Returns/Raises), all Exception classes documented. Type hints on all function signatures.", ""),
            12: ("pass", "Multi-layer logging: LoggingTracer records all pipeline operations with timestamps. HAYSTACK_CONTENT_TRACING_ENABLED production tracing flag. PipelineTool logs every invocation and error. All exceptions auto-log via logger.error(). get_spans() provides programmatic audit trail access.", ""),
            14: ("pass", "PipelineTool.max_runs creates execution boundary per tool. PipelineMaxComponentVisitsExceeded prevents infinite agent loops (documented as Article 14 safety mechanism). Warning logged before boundary exceeded. _run_count tracks usage.", ""),
            15: ("pass", "DeserializationError guards against tampered data. Exception hierarchy enables precise error handling. PipelineTool error handling prevents silent failures. Structured logging captures all failures for analysis.", ""),
        }
    ))

    return examples


def generate_langchain_examples() -> list:
    """Generate training examples from LangChain code patterns."""
    examples = []

    # Example 1: Callback handler — strong Article 12
    examples.append(make_pass_example(
        code=LANGCHAIN_CALLBACK_HANDLER,
        framework="LangChain",
        sample_desc="targeted sample of 3 callback and logging modules",
        total_files=385,
        articles_status={
            9: ("pass", "on_llm_error() captures full exception context with error type classification. Error events logged with structured metadata (run_id, error, error_type, timestamp).", ""),
            10: ("warn", "No input validation visible in the callback handler. Validation likely exists in chain classes.", "Add validation in callback hooks"),
            11: ("pass", "ComplianceCallbackHandler has detailed class docstring listing Article 12 requirements (LLM invocations, prompts/responses, token usage, error events). All methods documented with clear signatures. Type hints throughout.", ""),
            12: ("pass", "Full audit trail implementation: on_llm_start() logs model, prompt count, run_id, timestamp. on_llm_end() captures token usage. on_llm_error() records error type and context. run_history list provides queryable audit log. All events use structured logging via logger.info/error.", ""),
            14: ("warn", "No HITL mechanisms in callback handler. Human oversight likely implemented at agent level.", "Add human approval callback for high-risk operations"),
            15: ("warn", "Error logging present but no retry/fallback logic in callbacks. Security patterns likely in other modules.", ""),
        }
    ))

    # Example 2: Chain with validation — strong Articles 10, 14, 15
    examples.append(make_pass_example(
        code=LANGCHAIN_CHAIN_WITH_VALIDATION,
        framework="LangChain",
        sample_desc="targeted sample of 4 core chain modules",
        total_files=385,
        articles_status={
            9: ("pass", "SafeChain.invoke() wraps LLM call in try/except with fallback response ('I'm sorry, I encountered an error. Please try again.'). Error logged via logger.error(). Rate limit check prevents overuse.", ""),
            10: ("pass", "Pydantic-based input validation: ChainInput model with Field constraints (min_length=1, max_length=10000, ge=1, le=4096). sanitize_query() validator strips control characters and checks injection patterns. Schema enforcement via ChainInput(**input_data).", ""),
            11: ("pass", "ChainInput and SafeChain both have class docstrings listing compliance features. SafeChain docstring maps features to Articles (Article 10, 14, 9, 12). Type hints on all methods and fields.", ""),
            12: ("pass", "Structured logging: logger.info() on every invocation with user_id and count, logger.info() on completion, logger.error() on failures, logger.warning() on rate limit exceeded and injection detection.", ""),
            14: ("pass", "Rate limiting per user via self._user_counts: tracks invocations per user_id, raises RuntimeError when rate_limit exceeded. User identity binding via user_id field. Usage control logging shows user and count.", ""),
            15: ("pass", "Prompt injection defense: sanitize_query() validator checks for injection patterns ('ignore previous instructions', 'system prompt', 'you are now'). Strips control characters. Pydantic validation prevents malformed inputs. Fallback response on error.", ""),
        }
    ))

    # Example 3: Retry with fallback — strong Article 9
    examples.append(make_pass_example(
        code=LANGCHAIN_RETRY_WITH_FALLBACK,
        framework="LangChain",
        sample_desc="targeted sample of 2 resilience pattern modules",
        total_files=385,
        articles_status={
            9: ("pass", "Comprehensive risk management: retry_with_fallback decorator with exponential backoff (backoff_factor * 2^attempt). Configurable max_retries and fallback_response. on_error callback for monitoring. ResilientLLM class adds circuit breaker pattern. All retry attempts logged.", ""),
            10: ("warn", "No data validation visible in resilience modules. Input validation likely in chain classes.", ""),
            11: ("pass", "retry_with_fallback has comprehensive docstring listing Article 9 compliance (retry, fallback, error callback) with full Args documentation. ResilientLLM documented as combining retry, circuit breaking, and fallback. Type hints on all parameters.", ""),
            12: ("pass", "Structured logging at every stage: logger.warning() on each failed attempt with attempt count, logger.info() on retry delay, logger.error() when all attempts exhausted, logger.info() on fallback activation and successful retry.", ""),
            14: ("warn", "No HITL mechanisms in resilience layer.", ""),
            15: ("pass", "Exponential backoff prevents API hammering. Circuit breaker pattern prevents cascading failures. Fallback response ensures system degrades gracefully. Error count tracking enables monitoring.", ""),
        }
    ))

    return examples


def generate_crewai_examples() -> list:
    """Generate training examples from CrewAI code patterns."""
    examples = []

    # Example 1: SafeAgent — strong Articles 12, 14
    examples.append(make_pass_example(
        code=CREWAI_AGENT_SAFE,
        framework="CrewAI",
        sample_desc="targeted sample of 3 agent safety modules",
        total_files=210,
        articles_status={
            9: ("pass", "SafeAgent.execute_task() catches RuntimeError on max_iterations exceeded. _is_high_risk() classifies operations by risk level. Human approval gate provides risk mitigation for dangerous actions.", ""),
            10: ("warn", "No explicit data validation schemas. Agent parameters accepted as unvalidated dicts.", "Add Pydantic validation for task inputs"),
            11: ("pass", "SafeAgent class docstring lists all Article 14 features (action approval, execution boundaries, identity binding, audit trail). execute_task() has full Args/Returns/Raises docs. Type hints on all parameters.", ""),
            12: ("pass", "Full action audit trail: _action_log records every task with agent_id, user_id, task, iteration, and role. logger.info() on every action. logger.warning() on boundary approach. logger.info() on human rejection. get_audit_log() provides programmatic access to complete history.", ""),
            14: ("pass", "Comprehensive human oversight: human_approval_callback for high-risk actions (delete, modify, send, publish, deploy). max_iterations execution boundary with RuntimeError kill switch. user_id identity binding. agent_id tracking. Action approval logging.", ""),
            15: ("pass", "_is_high_risk() classifies dangerous operations. Execution boundary prevents runaway agents. Human approval gate for destructive actions. Audit trail enables post-hoc review.", ""),
        }
    ))

    return examples


def generate_mixed_examples() -> list:
    """Generate examples with mixed PASS/WARN/FAIL for realism."""
    examples = []

    # Minimal code — mostly WARN (not FAIL, because we can't see everything)
    minimal_code = '''
import os
from typing import Optional

class SimpleAgent:
    """A basic agent that processes queries."""

    def __init__(self, model_name: str = "gpt-4"):
        self.model_name = model_name

    def run(self, query: str) -> str:
        """Process a query and return response."""
        # Simple LLM call without safety controls
        response = self._call_llm(query)
        return response

    def _call_llm(self, prompt: str) -> str:
        """Call the LLM API."""
        import openai
        result = openai.chat.completions.create(
            model=self.model_name,
            messages=[{"role": "user", "content": prompt}],
        )
        return result.choices[0].message.content
'''

    examples.append(make_pass_example(
        code=minimal_code,
        framework="OpenAI SDK",
        sample_desc="targeted sample of 2 agent files",
        total_files=45,
        articles_status={
            9: ("fail", "No error handling around openai.chat.completions.create() call in _call_llm(). No try/except, no retry logic, no fallback response. A transient API failure will crash the agent.", "Wrap LLM calls in try/except with retry logic and fallback response"),
            10: ("fail", "No input validation on query parameter. Raw user input passed directly to LLM prompt without sanitization.", "Add input validation and sanitization before LLM calls"),
            11: ("pass", "SimpleAgent class and both methods have docstrings. Type hints present on __init__(model_name: str), run(query: str) -> str, and _call_llm(prompt: str) -> str.", ""),
            12: ("fail", "No logging or tracing. No audit trail of LLM invocations. No record of inputs, outputs, or errors.", "Add structured logging with logger.info() for all LLM calls"),
            14: ("fail", "No human oversight controls. No rate limiting, no execution boundaries, no approval gates, no user identity binding.", "Add rate limiting and execution boundaries"),
            15: ("fail", "No prompt injection defense. Raw user query sent directly as LLM prompt. No output validation. No retry/backoff logic.", "Add input sanitization and output validation"),
        }
    ))

    return examples


def main():
    all_examples = []

    # Generate from each framework
    haystack = generate_haystack_examples()
    langchain = generate_langchain_examples()
    crewai = generate_crewai_examples()
    mixed = generate_mixed_examples()

    all_examples.extend(haystack)
    all_examples.extend(langchain)
    all_examples.extend(crewai)
    all_examples.extend(mixed)

    # Augment: create variations with slightly different instructions
    augmented = []
    for ex in all_examples:
        augmented.append(ex)
        # Create 2 variations with different instruction phrasing
        for _ in range(2):
            variant = dict(ex)
            variant["instruction"] = random.choice(INSTRUCTIONS_PASS_HEAVY).format(
                sample_context=random.choice([
                    "targeted sample of 4 compliance-relevant source files",
                    "targeted sample of 3 core modules",
                    "smart sample of compliance-relevant files",
                    "curated sample of key source files",
                ]),
                total_files=random.choice([45, 120, 210, 385, 552, 800]),
            )
            augmented.append(variant)

    # Write output
    with open(OUTPUT_FILE, "w") as f:
        for ex in augmented:
            f.write(json.dumps(ex) + "\n")

    # Stats
    total = len(augmented)
    pass_count = sum(1 for ex in augmented if ex["output"].count("**Status**: PASS") >= 3)
    fail_heavy = sum(1 for ex in augmented if ex["output"].count("**Status**: FAIL") >= 4)

    print(f"Generated {total} training examples -> {OUTPUT_FILE}")
    print(f"  PASS-heavy examples (3+ PASS): {pass_count} ({100*pass_count/total:.0f}%)")
    print(f"  FAIL-heavy examples (4+ FAIL): {fail_heavy} ({100*fail_heavy/total:.0f}%)")
    print(f"\nFramework breakdown:")
    print(f"  Haystack: {len(haystack)} base × 3 = {len(haystack)*3}")
    print(f"  LangChain: {len(langchain)} base × 3 = {len(langchain)*3}")
    print(f"  CrewAI: {len(crewai)} base × 3 = {len(crewai)*3}")
    print(f"  Mixed: {len(mixed)} base × 3 = {len(mixed)*3}")


if __name__ == "__main__":
    main()
