"""
Framework auto-detection.

Sniffs installed packages and object types to determine
which adapter to activate. Zero config required.
"""

from __future__ import annotations
import importlib
import importlib.util
from typing import Optional, List, Tuple


# ── Detection Registry ───────────────────────────────────────
# (package_name, framework_id, adapter_type)
FRAMEWORK_REGISTRY: List[Tuple[str, str, str]] = [
    # Callback-based frameworks
    ("langchain",         "langchain",        "callback"),
    ("langchain_core",    "langchain",        "callback"),
    ("langgraph",         "langchain",        "callback"),
    ("llama_index",       "llamaindex",       "callback"),
    ("haystack",          "haystack",         "callback"),

    # Decorator/wrap-based frameworks
    ("crewai",            "crewai",           "decorator"),
    ("smolagents",        "smolagents",       "decorator"),
    ("pydantic_ai",       "pydantic_ai",      "decorator"),
    ("dspy",              "dspy",             "decorator"),
    ("autogen",           "autogen",          "decorator"),

    # SDK proxy-based (intercept API calls)
    ("openai",            "openai",           "proxy"),
    ("anthropic",         "anthropic",        "proxy"),
    ("google.generativeai", "google",         "proxy"),
    ("google.adk",        "google_adk",       "proxy"),
    ("litellm",           "litellm",          "proxy"),
    ("ollama",            "ollama",           "proxy"),
    ("vllm",              "vllm",             "proxy"),
    ("together",          "together",         "proxy"),
    ("groq",              "groq",             "proxy"),
    ("mistralai",         "mistral",          "proxy"),
    ("cohere",            "cohere",           "proxy"),

    # OTel-based (enterprise stacks)
    ("semantic_kernel",   "semantic_kernel",  "otel"),
    ("opentelemetry",     "otel",             "otel"),

    # Browser/automation agents
    ("browser_use",       "browser_use",      "decorator"),
    ("playwright",        "playwright",       "decorator"),
]


def detect_installed() -> List[Tuple[str, str]]:
    """Detect which AI frameworks are installed.

    Returns: list of (framework_id, adapter_type) tuples
    """
    found = []
    seen = set()
    for package, framework_id, adapter_type in FRAMEWORK_REGISTRY:
        if framework_id in seen:
            continue
        if importlib.util.find_spec(package.split(".")[0]):
            found.append((framework_id, adapter_type))
            seen.add(framework_id)
    return found


def detect_object(obj) -> Optional[Tuple[str, str]]:
    """Detect framework from a runtime object (agent, chain, pipeline, etc).

    Returns: (framework_id, adapter_type) or None
    """
    module = type(obj).__module__ or ""
    cls_name = type(obj).__name__

    # Check module path for known frameworks
    detection_map = {
        "langchain":        ("langchain",    "callback"),
        "langgraph":        ("langchain",    "callback"),
        "llama_index":      ("llamaindex",   "callback"),
        "haystack":         ("haystack",     "callback"),
        "crewai":           ("crewai",       "decorator"),
        "smolagents":       ("smolagents",   "decorator"),
        "pydantic_ai":      ("pydantic_ai",  "decorator"),
        "dspy":             ("dspy",         "decorator"),
        "autogen":          ("autogen",      "decorator"),
        "openai":           ("openai",       "proxy"),
        "anthropic":        ("anthropic",    "proxy"),
        "google":           ("google",       "proxy"),
        "semantic_kernel":  ("semantic_kernel", "otel"),
        "browser_use":      ("browser_use",  "decorator"),
    }

    for keyword, (fid, atype) in detection_map.items():
        if keyword in module:
            return (fid, atype)

    # Check class names for common patterns
    cls_lower = cls_name.lower()
    if "crew" in cls_lower:
        return ("crewai", "decorator")
    if "pipeline" in cls_lower and "run" in dir(obj):
        return ("haystack", "callback")
    if "agent" in cls_lower and "invoke" in dir(obj):
        return ("google_adk", "proxy")
    if "chain" in cls_lower:
        return ("langchain", "callback")

    return None
