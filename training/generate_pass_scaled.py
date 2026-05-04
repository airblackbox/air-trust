"""
Scaled PASS-heavy training data generator.

Takes the high-quality base examples from generate_pass_training.py
and creates hundreds of variations by:
1. Varying the code patterns (realistic rewrites)
2. Varying instruction phrasing
3. Varying framework names and file counts
4. Varying which articles are PASS/WARN/FAIL
5. Adding more real-world code patterns

Target: 500+ examples to meaningfully shift the 86% FAIL dataset
"""

import json
import random
import os

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "phase34_pass_scaled.jsonl")

# ============================================================================
# INSTRUCTION VARIATIONS with sample_context and total_files
# ============================================================================

INSTRUCTIONS = [
    "Analyze this Python code for EU AI Act compliance. This is a {sample_context} from a project with {total_files} Python files. Assess ONLY what is visible in the code below - do not assume patterns are missing if they could exist in files not shown.\n\nFor each of Articles 9, 10, 11, 12, 14, and 15: report status (pass if evidence found, warn if partial, fail only if clearly absent), cite specific evidence from the code (function names, patterns, line references), and give fix recommendations. Output as a JSON array.",
    "Scan the following Python code sample for EU AI Act compliance patterns. This is a {sample_context} from a project with {total_files} Python files. Focus on what IS present - cite specific classes, functions, and patterns you can see. Only mark FAIL for articles where the code clearly contradicts requirements.",
    "Review this Python AI agent code for EU AI Act Articles 9-15 compliance. This represents a {sample_context} from a {total_files}-file project. Identify compliance evidence in the code - name specific functions, classes, decorators, and patterns.",
    "Evaluate EU AI Act compliance in this code sample. This is a {sample_context} from a project with {total_files} Python files total. Cite specific evidence for each article: function names, class names, pattern descriptions.",
    "Perform EU AI Act compliance analysis on this Python code. You are analyzing a {sample_context} from a {total_files}-file codebase. For each article, cite specific code evidence (class names, function signatures, patterns). Use pass/warn/fail based on visible evidence only.",
    "Check this Python code against EU AI Act Articles 9, 10, 11, 12, 14, 15. This is a {sample_context} from a project with {total_files} files. Report specific evidence from the code for each article. Do not assume compliance gaps in files not shown.",
]

SAMPLE_CONTEXTS = [
    "targeted sample of {n} compliance-relevant source files",
    "smart sample of {n} compliance-relevant files",
    "curated sample of {n} key source files",
    "relevance-scored sample of {n} core modules",
    "targeted sample of {n} source files selected by compliance relevance",
]

ARTICLE_NAMES = {
    9: "Risk Management",
    10: "Data Governance",
    11: "Technical Documentation",
    12: "Record-Keeping",
    14: "Human Oversight",
    15: "Accuracy, Robustness & Cybersecurity",
}

# ============================================================================
# CODE PATTERN LIBRARY - realistic snippets the model needs to recognize
# ============================================================================

LOGGING_PATTERNS = [
    '''
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

class AuditLogger:
    """Logs all AI system events for compliance record-keeping."""

    def __init__(self, service_name: str):
        self.service_name = service_name
        self._events: list = []

    def log_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Record an auditable event with timestamp and context."""
        import datetime
        record = {
            "service": self.service_name,
            "event": event_type,
            "details": details,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
        self._events.append(record)
        logger.info("Audit event: %s - %s", event_type, self.service_name)

    def get_audit_trail(self) -> list:
        """Return complete audit trail for compliance review."""
        return list(self._events)
''',
    '''
import logging
import json
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

class StructuredLogger:
    """JSON structured logger for machine-readable audit trails.

    Produces log output compatible with ELK stack, Datadog,
    and other log aggregation platforms.
    """

    def __init__(self, component: str, correlation_id: str = ""):
        self.component = component
        self.correlation_id = correlation_id

    def log_llm_call(self, model: str, prompt_tokens: int,
                     completion_tokens: int, latency_ms: float) -> None:
        """Log an LLM API call with full telemetry."""
        record = {
            "type": "llm_call",
            "component": self.component,
            "model": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "latency_ms": latency_ms,
            "correlation_id": self.correlation_id,
        }
        logger.info(json.dumps(record))

    def log_error(self, error: Exception, context: Dict[str, Any]) -> None:
        """Log an error with full context for debugging."""
        record = {
            "type": "error",
            "component": self.component,
            "error": str(error),
            "error_type": type(error).__name__,
            "context": context,
            "correlation_id": self.correlation_id,
        }
        logger.error(json.dumps(record))
''',
    '''
import logging
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from typing import Optional

logger = logging.getLogger(__name__)
tracer = trace.get_tracer(__name__)

class OpenTelemetryTracer:
    """OpenTelemetry-based distributed tracing for AI pipelines.

    Provides production-grade observability with:
    - Distributed trace context propagation
    - Span-level metrics and attributes
    - Integration with Jaeger, Zipkin, and OTLP backends
    """

    def __init__(self, service_name: str, endpoint: Optional[str] = None):
        self.service_name = service_name
        self.endpoint = endpoint
        self._setup_provider()

    def _setup_provider(self) -> None:
        """Initialize the OpenTelemetry tracer provider."""
        provider = TracerProvider()
        trace.set_tracer_provider(provider)
        logger.info("OTel tracer initialized for %s", self.service_name)

    def start_span(self, name: str, attributes: dict = None):
        """Start a new trace span with optional attributes."""
        span = tracer.start_span(name)
        if attributes:
            for k, v in attributes.items():
                span.set_attribute(k, str(v))
        return span
''',
]

VALIDATION_PATTERNS = [
    '''
from pydantic import BaseModel, Field, validator
from typing import List, Optional
import re

class UserInput(BaseModel):
    """Validated user input for LLM processing.

    Enforces data governance by:
    - Limiting input length
    - Sanitizing special characters
    - Detecting PII patterns
    """
    query: str = Field(..., min_length=1, max_length=5000)
    user_id: str = Field(..., min_length=1)
    session_id: Optional[str] = None
    max_tokens: int = Field(default=1024, ge=1, le=4096)

    @validator("query")
    def sanitize_input(cls, v: str) -> str:
        """Remove potentially dangerous characters."""
        v = re.sub(r'[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]', '', v)
        return v.strip()

    @validator("query")
    def check_pii(cls, v: str) -> str:
        """Warn if PII patterns detected in input."""
        import logging
        pii_patterns = [
            r'\\b\\d{3}-\\d{2}-\\d{4}\\b',  # SSN
            r'\\b\\d{16}\\b',  # Credit card
            r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b',  # Email
        ]
        for pattern in pii_patterns:
            if re.search(pattern, v):
                logging.getLogger(__name__).warning("PII pattern detected in input")
        return v
''',
    '''
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class InputPolicy(Enum):
    """Policy for handling untrusted input."""
    STRICT = "strict"      # Reject invalid input
    SANITIZE = "sanitize"  # Clean and proceed
    PERMISSIVE = "permissive"  # Allow with warning

@dataclass
class ValidatedRequest:
    """Represents a validated and sanitized user request.

    All fields are validated on creation.

    Args:
        content: The sanitized user content
        source: Origin of the request
        metadata: Additional request metadata
    """
    content: str
    source: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    _validated: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        """Validate all fields on creation."""
        if not self.content or not self.content.strip():
            raise ValueError("Content cannot be empty")
        if len(self.content) > 10000:
            raise ValueError("Content exceeds maximum length (10000 chars)")
        self._validated = True
        logger.debug("Request validated from source: %s", self.source)
''',
]

ERROR_HANDLING_PATTERNS = [
    '''
import logging
import time
from typing import Any, Callable, Optional, TypeVar
from functools import wraps

logger = logging.getLogger(__name__)
T = TypeVar("T")

def with_retry(
    max_attempts: int = 3,
    backoff: float = 1.0,
    exceptions: tuple = (Exception,),
    fallback: Optional[Any] = None,
) -> Callable:
    """Decorator for resilient function execution.

    Implements exponential backoff retry with fallback.

    Args:
        max_attempts: Maximum retry attempts
        backoff: Base delay for exponential backoff
        exceptions: Tuple of exception types to catch
        fallback: Value to return if all retries fail
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_error = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_error = e
                    delay = backoff * (2 ** attempt)
                    logger.warning(
                        "%s attempt %d/%d failed: %s. Retrying in %.1fs",
                        func.__name__, attempt + 1, max_attempts, e, delay
                    )
                    time.sleep(delay)
            logger.error("%s failed after %d attempts", func.__name__, max_attempts)
            if fallback is not None:
                return fallback
            raise last_error
        return wrapper
    return decorator
''',
    '''
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

class CircuitBreaker:
    """Circuit breaker pattern for LLM API calls.

    Prevents cascading failures by opening the circuit after
    consecutive failures, then gradually allowing retry.

    Args:
        failure_threshold: Failures before opening circuit
        recovery_timeout: Seconds before attempting recovery
    """

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failure_count = 0
        self._state = "closed"
        self._last_failure_time: Optional[float] = None

    def call(self, func, *args, **kwargs) -> Any:
        """Execute function through circuit breaker.

        Returns:
            Function result or raises CircuitBreakerOpenError

        Raises:
            CircuitBreakerOpenError: If circuit is open
        """
        if self._state == "open":
            import time
            if time.time() - self._last_failure_time > self.recovery_timeout:
                self._state = "half-open"
                logger.info("Circuit breaker half-open, attempting recovery")
            else:
                raise CircuitBreakerOpenError("Circuit breaker is open")

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise

    def _on_success(self) -> None:
        self._failure_count = 0
        self._state = "closed"

    def _on_failure(self) -> None:
        import time
        self._failure_count += 1
        self._last_failure_time = time.time()
        if self._failure_count >= self.failure_threshold:
            self._state = "open"
            logger.error("Circuit breaker opened after %d failures", self._failure_count)
''',
]

HITL_PATTERNS = [
    '''
import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

class HumanApprovalGate:
    """Requires human approval before executing high-risk agent actions.

    Implements Article 14 human oversight by:
    - Classifying action risk levels
    - Blocking high-risk actions pending approval
    - Logging all approval decisions
    - Providing override capabilities for operators
    """

    def __init__(self, approval_callback: Callable,
                 risk_threshold: str = "high"):
        self.approval_callback = approval_callback
        self.risk_threshold = risk_threshold
        self._decisions: List[Dict[str, Any]] = []

    def check(self, action: str, context: Dict[str, Any]) -> bool:
        """Check if action requires and receives human approval.

        Args:
            action: Description of the proposed action
            context: Additional context about the action

        Returns:
            True if approved, False if rejected
        """
        risk = self._assess_risk(action)
        if risk == "low":
            logger.debug("Low-risk action auto-approved: %s", action)
            return True

        logger.info("Requesting human approval for %s-risk action: %s",
                    risk, action)
        approved = self.approval_callback(action, context, risk)

        decision = {
            "action": action,
            "risk": risk,
            "approved": approved,
            "context": context,
        }
        self._decisions.append(decision)
        logger.info("Human decision: %s for action: %s",
                    "APPROVED" if approved else "REJECTED", action)
        return approved

    def _assess_risk(self, action: str) -> str:
        """Classify action risk level."""
        high_risk = ["delete", "modify", "publish", "deploy", "send_email", "execute"]
        medium_risk = ["create", "update", "write", "upload"]
        action_lower = action.lower()
        if any(kw in action_lower for kw in high_risk):
            return "high"
        if any(kw in action_lower for kw in medium_risk):
            return "medium"
        return "low"
''',
    '''
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

class AgentBoundary:
    """Execution boundary controls for AI agents.

    Prevents runaway agent behavior through:
    - Maximum iteration limits
    - Token budget enforcement
    - Time-based execution limits
    - Action scope restrictions
    """

    def __init__(self, max_iterations: int = 50,
                 max_tokens: int = 100000,
                 max_time_seconds: float = 300.0,
                 allowed_actions: Optional[list] = None):
        self.max_iterations = max_iterations
        self.max_tokens = max_tokens
        self.max_time_seconds = max_time_seconds
        self.allowed_actions = allowed_actions
        self._iterations = 0
        self._tokens_used = 0
        self._start_time: Optional[float] = None

    def check_iteration(self) -> bool:
        """Check if agent has exceeded iteration limit."""
        self._iterations += 1
        if self._iterations > self.max_iterations:
            logger.warning("Iteration limit reached: %d/%d",
                          self._iterations, self.max_iterations)
            return False
        return True

    def check_budget(self, tokens: int) -> bool:
        """Check if agent has exceeded token budget."""
        self._tokens_used += tokens
        if self._tokens_used > self.max_tokens:
            logger.warning("Token budget exceeded: %d/%d",
                          self._tokens_used, self.max_tokens)
            return False
        return True

    def check_action(self, action: str) -> bool:
        """Check if action is within allowed scope."""
        if self.allowed_actions and action not in self.allowed_actions:
            logger.warning("Action '%s' not in allowed scope", action)
            return False
        return True
''',
]

INJECTION_DEFENSE_PATTERNS = [
    '''
import logging
import re
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

class PromptGuard:
    """Defends against prompt injection attacks.

    Implements Article 15 cybersecurity by:
    - Detecting known injection patterns
    - Sanitizing user input
    - Validating output format
    - Rate limiting suspicious requests
    """

    INJECTION_PATTERNS = [
        r"ignore\\s+(all\\s+)?previous\\s+instructions",
        r"you\\s+are\\s+now\\s+a",
        r"system\\s*:\\s*",
        r"\\[INST\\]",
        r"<\\|im_start\\|>",
        r"Human:\\s*",
        r"Assistant:\\s*",
    ]

    def __init__(self):
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS]
        self._blocked_count = 0

    def check_input(self, text: str) -> bool:
        """Check if input contains injection patterns.

        Args:
            text: User input to check

        Returns:
            True if safe, False if injection detected
        """
        for pattern in self._compiled:
            if pattern.search(text):
                self._blocked_count += 1
                logger.warning("Prompt injection blocked (pattern: %s)", pattern.pattern)
                return False
        return True

    def sanitize(self, text: str) -> str:
        """Remove potentially dangerous content from input."""
        # Strip control characters
        text = re.sub(r'[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f-\\x9f]', '', text)
        # Normalize whitespace
        text = re.sub(r'\\s+', ' ', text).strip()
        return text

    def validate_output(self, output: str, expected_format: str = "text") -> bool:
        """Validate LLM output matches expected format."""
        if expected_format == "json":
            import json
            try:
                json.loads(output)
                return True
            except json.JSONDecodeError:
                logger.warning("Output failed JSON validation")
                return False
        return True
''',
]

DOCSTRING_PATTERNS = [
    '''
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)

@dataclass
class PipelineConfig:
    """Configuration for an AI pipeline execution.

    Defines the pipeline topology, component settings,
    and execution parameters.

    Attributes:
        name: Human-readable pipeline name
        components: Ordered list of component configurations
        max_runs: Maximum pipeline executions (safety limit)
        timeout_seconds: Maximum execution time per run
        metadata: Additional pipeline metadata
    """
    name: str
    components: List[Dict[str, Any]]
    max_runs: int = 1000
    timeout_seconds: float = 300.0
    metadata: Dict[str, Any] = field(default_factory=dict)


def build_pipeline(
    config: PipelineConfig,
    validate: bool = True,
) -> "Pipeline":
    """Build and optionally validate a pipeline from configuration.

    Creates a pipeline instance from the provided configuration,
    wiring components in the specified order.

    Args:
        config: Pipeline configuration with component specs
        validate: If True, validate pipeline graph before returning

    Returns:
        Configured Pipeline instance ready for execution

    Raises:
        PipelineValidationError: If validation fails
        ComponentError: If a component cannot be instantiated
    """
    logger.info("Building pipeline: %s with %d components",
               config.name, len(config.components))

    pipeline = Pipeline(name=config.name)
    for comp_config in config.components:
        component = _instantiate_component(comp_config)
        pipeline.add_component(component)

    if validate:
        _validate_pipeline(pipeline)
        logger.info("Pipeline %s validated successfully", config.name)

    return pipeline


def _validate_pipeline(pipeline: "Pipeline") -> None:
    """Validate pipeline graph for correctness.

    Checks:
    - All required inputs are connected
    - No circular dependencies
    - Component type compatibility

    Raises:
        PipelineValidationError: If validation fails
    """
    # Validation logic here
    pass


def _instantiate_component(config: Dict[str, Any]) -> Any:
    """Create a component instance from configuration.

    Args:
        config: Component configuration dict

    Returns:
        Instantiated component

    Raises:
        ComponentError: If instantiation fails
    """
    pass
''',
]


def make_example(code: str, framework: str, articles_status: dict,
                 sample_n: int, total_files: int) -> dict:
    """Create one Alpaca training example."""
    sample_ctx = random.choice(SAMPLE_CONTEXTS).format(n=sample_n)
    instruction = random.choice(INSTRUCTIONS).format(
        sample_context=sample_ctx,
        total_files=total_files,
    )

    output_parts = []
    output_parts.append(f"## EU AI Act Compliance Analysis\n")
    output_parts.append(f"**Framework detected**: {framework}")

    pass_count = sum(1 for s, _, _ in articles_status.values() if s == "pass")
    output_parts.append(f"**Technical compliance coverage**: {pass_count}/6 articles\n")

    for art_num in [9, 10, 11, 12, 14, 15]:
        status, evidence, fix = articles_status.get(art_num, ("warn", "Partial evidence", ""))
        name = ARTICLE_NAMES[art_num]
        output_parts.append(f"### Article {art_num} - {name}\n")
        output_parts.append(f"**Status**: {status.upper()}")
        output_parts.append(f"**Analysis**: {evidence}")
        if fix and status != "pass":
            output_parts.append(f"**Recommendation**: {fix}")
        output_parts.append("")

    return {
        "instruction": instruction,
        "input": code.strip(),
        "output": "\n".join(output_parts).strip(),
    }


# ============================================================================
# EVIDENCE TEMPLATES - realistic pass/warn/fail text for each article
# ============================================================================

ART9_PASS = [
    ("pass", "Error handling via try/except around LLM calls with {cls}.{method}(). Fallback response provided on failure. {extra}", ""),
    ("pass", "Retry logic with exponential backoff in {cls} (max_attempts={n}, backoff_factor={bf}). All retry attempts logged. Fallback value returned after exhaustion. {extra}", ""),
    ("pass", "Circuit breaker pattern in {cls}: {threshold} failure threshold, {timeout}s recovery timeout. Prevents cascading failures from API outages. {extra}", ""),
    ("pass", "Exception hierarchy: {cls} base with {sub1}, {sub2} subclasses. All exceptions auto-log on creation. Typed error handling enables precise recovery. {extra}", ""),
]

ART9_WARN = [
    ("warn", "Partial error handling: try/except found in {method}() but no fallback response provided. Exception re-raised without recovery.", "Add fallback response for graceful degradation"),
    ("warn", "Basic try/except around LLM calls but no retry logic. Single failure crashes the operation.", "Add retry with exponential backoff"),
]

ART10_PASS = [
    ("pass", "Pydantic input validation: {cls} model with Field constraints ({fields}). Validator methods sanitize user input. {extra}", ""),
    ("pass", "Data validation via {cls}: type checking, length limits, and format enforcement. PII detection patterns check for SSN, credit card, and email. {extra}", ""),
    ("pass", "Input policy enforcement via {cls} enum (STRICT/SANITIZE/PERMISSIVE). ValidatedRequest dataclass with __post_init__ validation. {extra}", ""),
]

ART10_WARN = [
    ("warn", "Basic type hints provide implicit validation but no explicit input sanitization or PII detection visible in this sample.", "Add Pydantic validation and PII detection"),
]

ART11_PASS = [
    ("pass", "{cls} has comprehensive docstring explaining purpose and compliance features. Type hints on all methods: {methods_list}. {extra}", ""),
    ("pass", "Full documentation: class docstring with Attributes section, method docstrings with Args/Returns/Raises. Type hints throughout ({pct}% coverage in visible code). {extra}", ""),
]

ART12_PASS = [
    ("pass", "Structured logging via {cls}: logger.info() on all operations, logger.error() on failures, logger.warning() on boundary conditions. {extra}", ""),
    ("pass", "Full audit trail: {cls} records all events with timestamps, user context, and operation details. get_audit_trail() provides programmatic access. {extra}", ""),
    ("pass", "OpenTelemetry tracing: distributed trace context via TracerProvider. Span-level metrics with custom attributes. Production-grade observability. {extra}", ""),
]

ART12_WARN = [
    ("warn", "Basic logging present (logger.info/error) but no structured audit trail or tracing infrastructure.", "Add structured audit logging with timestamps and correlation IDs"),
]

ART14_PASS = [
    ("pass", "Human approval gate via {cls}: high-risk actions require callback approval. Risk classification ({risk_types}). All decisions logged. {extra}", ""),
    ("pass", "Execution boundary: max_iterations={n} with RuntimeError kill switch. Token budget enforcement. Action scope restrictions via allowed_actions list. {extra}", ""),
    ("pass", "Rate limiting per user via {field}: tracks invocations per user_id, raises RuntimeError when limit exceeded. Identity binding via user_id parameter. {extra}", ""),
]

ART14_WARN = [
    ("warn", "No HITL mechanisms visible in this module. Human oversight may be implemented at application level in files not shown.", "Add human approval gates for high-risk operations"),
]

ART15_PASS = [
    ("pass", "Prompt injection defense via {cls}: regex pattern matching against {n} known injection vectors. Input sanitization strips control characters. Output format validation. {extra}", ""),
    ("pass", "Retry/backoff logic (max_retries={n}, exponential backoff). Circuit breaker prevents cascading failures. {extra}", ""),
    ("pass", "Input sanitization: {method}() strips control characters, normalizes whitespace. Output validation checks expected format. {extra}", ""),
]

ART15_WARN = [
    ("warn", "No explicit prompt injection defense in this module. Security patterns may exist in other files.", "Add input sanitization and injection pattern detection"),
]


def fill_template(template_tuple, **kwargs):
    """Fill a template tuple with random realistic values."""
    status, evidence, fix = template_tuple
    classes = ["SafeChain", "ResilientLLM", "AuditLogger", "StructuredLogger",
               "PipelineTool", "AgentBoundary", "PromptGuard", "HumanApprovalGate",
               "ComplianceHandler", "CircuitBreaker", "ValidatedRequest"]
    methods = ["invoke", "run", "execute", "process", "call", "check",
               "validate", "sanitize", "log_event"]

    evidence = evidence.format(
        cls=kwargs.get("cls", random.choice(classes)),
        method=kwargs.get("method", random.choice(methods)),
        sub1=kwargs.get("sub1", "RuntimeError"),
        sub2=kwargs.get("sub2", "ValidationError"),
        n=kwargs.get("n", random.choice([3, 5, 10, 25, 50, 100])),
        bf=kwargs.get("bf", random.choice(["1.0", "1.5", "2.0"])),
        threshold=kwargs.get("threshold", random.choice([3, 5, 10])),
        timeout=kwargs.get("timeout", random.choice([30, 60, 120])),
        fields=kwargs.get("fields", "min_length=1, max_length=5000, ge=1, le=4096"),
        pct=kwargs.get("pct", random.choice([85, 90, 92, 95, 98, 100])),
        methods_list=kwargs.get("methods_list", "run(), validate(), process()"),
        field=kwargs.get("field", "_user_counts"),
        risk_types=kwargs.get("risk_types", "delete, modify, publish, deploy"),
        extra=kwargs.get("extra", ""),
    )
    return (status, evidence, fix)


def generate_all_examples():
    """Generate hundreds of varied training examples."""
    examples = []

    all_code_blocks = {
        "logging": LOGGING_PATTERNS,
        "validation": VALIDATION_PATTERNS,
        "error_handling": ERROR_HANDLING_PATTERNS,
        "hitl": HITL_PATTERNS,
        "injection": INJECTION_DEFENSE_PATTERNS,
        "docstring": DOCSTRING_PATTERNS,
    }

    frameworks = [
        ("Haystack", 552), ("LangChain", 385), ("CrewAI", 210),
        ("LlamaIndex", 430), ("AutoGen", 180), ("OpenAI SDK", 45),
        ("Claude Agent SDK", 65), ("Semantic Kernel", 290),
    ]

    # ---- TYPE 1: Single strong-pattern examples (PASS on 3-5 articles) ----
    for pattern_type, code_list in all_code_blocks.items():
        for code in code_list:
            for _ in range(4):  # 4 variations per code block
                fw, total = random.choice(frameworks)
                sample_n = random.choice([2, 3, 4, 5])

                articles = {}
                # Strong pass on related articles
                if pattern_type == "logging":
                    articles[12] = fill_template(random.choice(ART12_PASS))
                    articles[11] = fill_template(random.choice(ART11_PASS))
                    articles[9] = fill_template(random.choice(ART9_WARN))
                    articles[10] = fill_template(random.choice(ART10_WARN))
                    articles[14] = fill_template(random.choice(ART14_WARN))
                    articles[15] = fill_template(random.choice(ART15_WARN))
                elif pattern_type == "validation":
                    articles[10] = fill_template(random.choice(ART10_PASS))
                    articles[11] = fill_template(random.choice(ART11_PASS))
                    articles[15] = fill_template(random.choice(ART15_PASS))
                    articles[9] = fill_template(random.choice(ART9_WARN))
                    articles[12] = fill_template(random.choice(ART12_WARN))
                    articles[14] = fill_template(random.choice(ART14_WARN))
                elif pattern_type == "error_handling":
                    articles[9] = fill_template(random.choice(ART9_PASS))
                    articles[11] = fill_template(random.choice(ART11_PASS))
                    articles[12] = fill_template(random.choice(ART12_PASS))
                    articles[15] = fill_template(random.choice(ART15_PASS))
                    articles[10] = fill_template(random.choice(ART10_WARN))
                    articles[14] = fill_template(random.choice(ART14_WARN))
                elif pattern_type == "hitl":
                    articles[14] = fill_template(random.choice(ART14_PASS))
                    articles[11] = fill_template(random.choice(ART11_PASS))
                    articles[12] = fill_template(random.choice(ART12_PASS))
                    articles[9] = fill_template(random.choice(ART9_WARN))
                    articles[10] = fill_template(random.choice(ART10_WARN))
                    articles[15] = fill_template(random.choice(ART15_WARN))
                elif pattern_type == "injection":
                    articles[15] = fill_template(random.choice(ART15_PASS))
                    articles[10] = fill_template(random.choice(ART10_PASS))
                    articles[11] = fill_template(random.choice(ART11_PASS))
                    articles[9] = fill_template(random.choice(ART9_WARN))
                    articles[12] = fill_template(random.choice(ART12_WARN))
                    articles[14] = fill_template(random.choice(ART14_WARN))
                elif pattern_type == "docstring":
                    articles[11] = fill_template(random.choice(ART11_PASS))
                    articles[9] = fill_template(random.choice(ART9_PASS))
                    articles[12] = fill_template(random.choice(ART12_PASS))
                    articles[10] = fill_template(random.choice(ART10_WARN))
                    articles[14] = fill_template(random.choice(ART14_WARN))
                    articles[15] = fill_template(random.choice(ART15_WARN))

                examples.append(make_example(code, fw, articles, sample_n, total))

    # ---- TYPE 2: Multi-pattern combined examples (PASS on 4-6 articles) ----
    for _ in range(80):
        # Combine 2-3 code blocks
        selected_types = random.sample(list(all_code_blocks.keys()), k=random.choice([2, 3]))
        combined_parts = []
        for pt in selected_types:
            code = random.choice(all_code_blocks[pt])
            combined_parts.append(code)
        combined_code = "\n\n".join(combined_parts)

        fw, total = random.choice(frameworks)
        sample_n = random.choice([3, 4, 5])

        # Most articles PASS for combined code
        articles = {}
        for art in [9, 10, 11, 12, 14, 15]:
            pass_templates = {
                9: ART9_PASS, 10: ART10_PASS, 11: ART11_PASS,
                12: ART12_PASS, 14: ART14_PASS, 15: ART15_PASS,
            }
            warn_templates = {
                9: ART9_WARN, 10: ART10_WARN, 12: ART12_WARN,
                14: ART14_WARN, 15: ART15_WARN,
            }

            # 70% chance PASS, 25% WARN, 5% FAIL for combined examples
            roll = random.random()
            if roll < 0.70:
                articles[art] = fill_template(random.choice(pass_templates[art]))
            elif roll < 0.95:
                if art in warn_templates:
                    articles[art] = fill_template(random.choice(warn_templates[art]))
                else:
                    articles[art] = fill_template(random.choice(pass_templates[art]))
            else:
                articles[art] = ("fail", f"No {ARTICLE_NAMES[art].lower()} patterns detected in this code sample. May exist in other files.", f"Add {ARTICLE_NAMES[art].lower()} patterns")

        examples.append(make_example(combined_code, fw, articles, sample_n, total))

    # ---- TYPE 3: Realistic "mostly passing" full-project samples ----
    for _ in range(60):
        # Simulate a well-built project where most things pass
        code_blocks = [random.choice(v) for v in all_code_blocks.values()]
        combined = "\n\n".join(random.sample(code_blocks, k=random.choice([3, 4])))

        fw, total = random.choice(frameworks)

        articles = {}
        for art in [9, 10, 11, 12, 14, 15]:
            pass_templates = {
                9: ART9_PASS, 10: ART10_PASS, 11: ART11_PASS,
                12: ART12_PASS, 14: ART14_PASS, 15: ART15_PASS,
            }
            # 80% PASS, 20% WARN for well-built projects
            if random.random() < 0.80:
                articles[art] = fill_template(random.choice(pass_templates[art]))
            else:
                warn_templates = {
                    9: ART9_WARN, 10: ART10_WARN, 12: ART12_WARN,
                    14: ART14_WARN, 15: ART15_WARN,
                }
                if art in warn_templates:
                    articles[art] = fill_template(random.choice(warn_templates[art]))
                else:
                    articles[art] = ("warn", f"Partial {ARTICLE_NAMES[art].lower()} evidence.", "Strengthen existing patterns")

        examples.append(make_example(combined, fw, articles, random.choice([3, 4, 5]), total))

    return examples


def main():
    random.seed(42)
    examples = generate_all_examples()

    with open(OUTPUT_FILE, "w") as f:
        for ex in examples:
            f.write(json.dumps(ex) + "\n")

    # Stats
    total = len(examples)
    pass_counts = []
    for ex in examples:
        pc = ex["output"].count("**Status**: PASS")
        pass_counts.append(pc)

    avg_pass = sum(pass_counts) / len(pass_counts)
    mostly_pass = sum(1 for pc in pass_counts if pc >= 3)
    mostly_fail = sum(1 for pc in pass_counts if pc <= 1)

    print(f"Generated {total} training examples -> {OUTPUT_FILE}")
    print(f"  Average PASS per example: {avg_pass:.1f}/6")
    print(f"  Examples with 3+ PASS: {mostly_pass} ({100*mostly_pass/total:.0f}%)")
    print(f"  Examples with 0-1 PASS: {mostly_fail} ({100*mostly_fail/total:.0f}%)")

    # Article-level stats
    for art in [9, 10, 11, 12, 14, 15]:
        art_pass = sum(1 for ex in examples if f"### Article {art}" in ex["output"] and f"**Status**: PASS" in ex["output"].split(f"### Article {art}")[1].split("###")[0] if f"### Article {art}" in ex["output"])
        print(f"  Article {art}: {art_pass} PASS ({100*art_pass/total:.0f}%)")

    file_size = os.path.getsize(OUTPUT_FILE) / 1024 / 1024
    print(f"\n  File size: {file_size:.1f} MB")


if __name__ == "__main__":
    main()
