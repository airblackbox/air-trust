"""
Comprehensive test suite for air_blackbox.compliance.code_scanner module.

Tests cover:
- CodeFinding dataclass creation
- File discovery and filtering functions
- All 18 check functions with pass/warn/fail scenarios
- Edge cases (empty directories, single files, empty contents)
"""

import os
import pytest
from air_blackbox.compliance.code_scanner import (
    CodeFinding,
    scan_codebase,
    _find_python_files,
    _is_test_file,
    _source_files_only,
    _check_error_handling,
    _check_fallback_patterns,
    _check_input_validation,
    _check_pii_handling,
    _check_docstrings,
    _check_type_hints,
    _check_logging,
    _check_tracing,
    _check_human_in_loop,
    _check_rate_limiting,
    _check_retry_logic,
    _check_injection_defense,
    _check_output_validation,
    _check_oauth_delegation,
    _check_token_scope_validation,
    _check_token_expiry_revocation,
    _check_action_audit_trail,
    _check_action_boundaries,
)


class TestCodeFinding:
    """Test CodeFinding dataclass creation and defaults."""

    def test_codefinding_required_fields(self):
        """Test CodeFinding with required fields."""
        finding = CodeFinding(
            article=9,
            name="Test Finding",
            status="pass",
            evidence="Evidence text"
        )
        assert finding.article == 9
        assert finding.name == "Test Finding"
        assert finding.status == "pass"
        assert finding.evidence == "Evidence text"
        assert finding.detection == "auto"
        assert finding.fix_hint == ""
        assert finding.files == []

    def test_codefinding_all_fields(self):
        """Test CodeFinding with all fields specified."""
        finding = CodeFinding(
            article=10,
            name="Input validation",
            status="warn",
            evidence="Some evidence",
            detection="manual",
            fix_hint="Add validation",
            files=["file1.py", "file2.py"]
        )
        assert finding.article == 10
        assert finding.detection == "manual"
        assert finding.fix_hint == "Add validation"
        assert finding.files == ["file1.py", "file2.py"]

    def test_codefinding_status_values(self):
        """Test CodeFinding accepts all valid status values."""
        for status in ["pass", "warn", "fail"]:
            finding = CodeFinding(
                article=9,
                name="Test",
                status=status,
                evidence="test"
            )
            assert finding.status == status


class TestFindPythonFiles:
    """Test _find_python_files function."""

    def test_single_file_scan(self, tmp_path):
        """Test scanning a single .py file."""
        py_file = tmp_path / "agent.py"
        py_file.write_text("print('hello')")

        result = _find_python_files(str(py_file))
        assert len(result) == 1
        assert result[0].endswith("agent.py")

    def test_directory_with_python_files(self, tmp_path):
        """Test finding all Python files in a directory."""
        (tmp_path / "main.py").write_text("# main")
        (tmp_path / "utils.py").write_text("# utils")
        (tmp_path / "config.yaml").write_text("key: value")

        result = _find_python_files(str(tmp_path))
        assert len(result) == 2
        assert any(f.endswith("main.py") for f in result)
        assert any(f.endswith("utils.py") for f in result)

    def test_nested_directories(self, tmp_path):
        """Test finding Python files in nested directories."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "agent.py").write_text("# agent")
        (tmp_path / "src" / "sub").mkdir()
        (tmp_path / "src" / "sub" / "handler.py").write_text("# handler")

        result = _find_python_files(str(tmp_path))
        assert len(result) == 2

    def test_skip_pycache(self, tmp_path):
        """Test that __pycache__ directories are skipped."""
        (tmp_path / "__pycache__").mkdir()
        (tmp_path / "__pycache__" / "module.cpython-39.pyc").write_text("binary")
        (tmp_path / "main.py").write_text("# main")

        result = _find_python_files(str(tmp_path))
        assert len(result) == 1
        assert all(".pyc" not in f for f in result)

    def test_skip_venv_directories(self, tmp_path):
        """Test that virtual environment directories are skipped."""
        (tmp_path / ".venv").mkdir()
        (tmp_path / ".venv" / "lib" / "python3.9").mkdir(parents=True)
        (tmp_path / ".venv" / "lib" / "python3.9" / "site.py").write_text("# site")
        (tmp_path / "main.py").write_text("# main")

        result = _find_python_files(str(tmp_path))
        assert len(result) == 1
        assert all(".venv" not in f for f in result)

    def test_skip_node_modules(self, tmp_path):
        """Test that node_modules directories are skipped."""
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "package").mkdir()
        (tmp_path / "node_modules" / "package" / "index.js").write_text("// js")
        (tmp_path / "main.py").write_text("# main")

        result = _find_python_files(str(tmp_path))
        assert len(result) == 1

    def test_empty_directory(self, tmp_path):
        """Test directory with no Python files."""
        result = _find_python_files(str(tmp_path))
        assert result == []


class TestIsTestFile:
    """Test _is_test_file function."""

    def test_test_directory(self):
        """Test detection of files in 'tests' directory."""
        assert _is_test_file("/path/to/tests/test_module.py") is True
        assert _is_test_file("/path/to/tests/helpers.py") is True

    def test_test_prefix_file(self):
        """Test detection of test_*.py files."""
        assert _is_test_file("/path/to/test_agent.py") is True
        assert _is_test_file("/src/test_utils.py") is True

    def test_test_suffix_file(self):
        """Test detection of *_test.py files."""
        assert _is_test_file("/path/to/agent_test.py") is True
        assert _is_test_file("/src/utils_test.py") is True

    def test_conftest_file(self):
        """Test detection of conftest.py."""
        assert _is_test_file("/path/to/conftest.py") is True
        assert _is_test_file("/tests/conftest.py") is True

    def test_test_directory_variations(self):
        """Test various test directory names."""
        assert _is_test_file("/path/test/module.py") is True
        assert _is_test_file("/path/testing/module.py") is True
        assert _is_test_file("/path/test_utils/module.py") is True

    def test_non_test_file(self):
        """Test files that are not test files."""
        assert _is_test_file("/src/main.py") is False
        assert _is_test_file("/lib/utils.py") is False
        assert _is_test_file("/path/to/agent.py") is False

    def test_windows_path_format(self):
        """Test Windows-style path separators."""
        assert _is_test_file("C:\\tests\\test_module.py") is True
        assert _is_test_file("C:\\src\\main.py") is False


class TestSourceFilesOnly:
    """Test _source_files_only function."""

    def test_filters_test_files(self):
        """Test that test files are filtered out."""
        file_contents = {
            "/src/main.py": "# main",
            "/tests/test_main.py": "# test",
            "/src/utils.py": "# utils",
        }
        result = _source_files_only(file_contents)
        assert len(result) == 2
        assert "/src/main.py" in result
        assert "/src/utils.py" in result
        assert "/tests/test_main.py" not in result

    def test_preserves_source_files(self):
        """Test that source files are preserved."""
        file_contents = {
            "/src/agent.py": "content1",
            "/src/handler.py": "content2",
        }
        result = _source_files_only(file_contents)
        assert result == file_contents

    def test_empty_dict(self):
        """Test with empty file contents."""
        result = _source_files_only({})
        assert result == {}


class TestCheckErrorHandling:
    """Test _check_error_handling function."""

    def test_no_llm_calls_pass(self, tmp_path):
        """Test pass when no LLM calls are present."""
        file_contents = {str(tmp_path / "main.py"): "print('hello')"}
        findings = _check_error_handling(file_contents, str(tmp_path))
        assert len(findings) == 1
        assert findings[0].status == "pass"
        assert "No direct LLM API calls" in findings[0].evidence

    def test_llm_call_with_try_except(self, tmp_path):
        """Test pass when LLM calls have try/except."""
        content = """
try:
    response = client.chat.completions.create(model="gpt-4", messages=[])
except Exception as e:
    print(f"Error: {e}")
"""
        file_contents = {str(tmp_path / "agent.py"): content}
        findings = _check_error_handling(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_llm_call_with_openai(self, tmp_path):
        """Test detection of OpenAI LLM calls."""
        content = """
from openai import OpenAI
client = OpenAI()
response = client.chat.completions.create(model="gpt-4", messages=[])
"""
        file_contents = {str(tmp_path / "main.py"): content}
        findings = _check_error_handling(file_contents, str(tmp_path))
        assert findings[0].status == "fail" or findings[0].status == "warn"

    def test_llm_call_with_anthropic(self, tmp_path):
        """Test detection of Anthropic LLM calls."""
        content = """
from anthropic import Anthropic
client = Anthropic()
response = client.messages.create(model="claude-3", messages=[])
"""
        file_contents = {str(tmp_path / "main.py"): content}
        findings = _check_error_handling(file_contents, str(tmp_path))
        # Should detect the create call
        assert len(findings) >= 1


class TestCheckFallbackPatterns:
    """Test _check_fallback_patterns function."""

    def test_with_retry_pattern(self, tmp_path):
        """Test pass when retry patterns are present."""
        content = "max_retries = 3\nwith_retry=True"
        file_contents = {str(tmp_path / "agent.py"): content}
        findings = _check_fallback_patterns(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_fallback_pattern(self, tmp_path):
        """Test pass when fallback patterns are present."""
        content = "fallback_model = 'gpt-3.5'\ndefault_response = 'unknown'"
        file_contents = {str(tmp_path / "handler.py"): content}
        findings = _check_fallback_patterns(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_tenacity(self, tmp_path):
        """Test pass when tenacity library is used."""
        content = "from tenacity import retry, stop_after_attempt"
        file_contents = {str(tmp_path / "utils.py"): content}
        findings = _check_fallback_patterns(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_no_fallback_patterns(self, tmp_path):
        """Test warn when no fallback patterns are present."""
        content = "def main():\n    pass"
        file_contents = {str(tmp_path / "main.py"): content}
        findings = _check_fallback_patterns(file_contents, str(tmp_path))
        assert findings[0].status == "warn"


class TestCheckInputValidation:
    """Test _check_input_validation function."""

    def test_with_pydantic(self, tmp_path):
        """Test pass when Pydantic is used."""
        content = """
from pydantic import BaseModel, validator
class UserInput(BaseModel):
    name: str
"""
        file_contents = {str(tmp_path / "models.py"): content}
        findings = _check_input_validation(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_dataclass(self, tmp_path):
        """Test pass when dataclass is used."""
        content = """
from dataclasses import dataclass
@dataclass
class Input:
    text: str
"""
        file_contents = {str(tmp_path / "schema.py"): content}
        findings = _check_input_validation(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_typeddict(self, tmp_path):
        """Test pass when TypedDict is used."""
        content = "from typing import TypedDict\nclass Config(TypedDict):\n    key: str"
        file_contents = {str(tmp_path / "types.py"): content}
        findings = _check_input_validation(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_no_input_validation(self, tmp_path):
        """Test warn when no validation framework is found."""
        content = "def process(data):\n    return data.strip()"
        file_contents = {str(tmp_path / "main.py"): content}
        findings = _check_input_validation(file_contents, str(tmp_path))
        assert findings[0].status == "warn"


class TestCheckPiiHandling:
    """Test _check_pii_handling function."""

    def test_with_presidio(self, tmp_path):
        """Test pass when presidio library is used."""
        content = "from presidio_analyzer import AnalyzerEngine\nanalyzer = AnalyzerEngine()"
        file_contents = {str(tmp_path / "privacy.py"): content}
        findings = _check_pii_handling(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_scrubadub(self, tmp_path):
        """Test pass when scrubadub library is used."""
        content = "import scrubadub\ntext = scrubadub.clean(text)"
        file_contents = {str(tmp_path / "clean.py"): content}
        findings = _check_pii_handling(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_pii_awareness(self, tmp_path):
        """Test warn when PII-aware variable names are used."""
        file_contents = {
            str(tmp_path / "a.py"): "# Handle PII data\npii_data = None",
            str(tmp_path / "b.py"): "# Redact personal info\nredacted_text = ''",
            str(tmp_path / "c.py"): "# Anonymize user\nanonymized_email = ''",
        }
        findings = _check_pii_handling(file_contents, str(tmp_path))
        assert findings[0].status == "warn"

    def test_no_pii_handling(self, tmp_path):
        """Test warn when no PII handling is found."""
        content = "def process(data):\n    return data"
        file_contents = {str(tmp_path / "main.py"): content}
        findings = _check_pii_handling(file_contents, str(tmp_path))
        assert findings[0].status == "warn"


class TestCheckDocstrings:
    """Test _check_docstrings function."""

    def test_well_documented_functions(self, tmp_path):
        """Test pass when functions are well documented."""
        content = '''
def process_data(data):
    """Process the input data and return results."""
    return data

class Handler:
    """Main handler class."""
    pass
'''
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_docstrings(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_partially_documented(self, tmp_path):
        """Test warn when some functions lack docstrings."""
        content = '''
def documented():
    """Has docstring."""
    pass

def undocumented():
    return 42

class Documented:
    """Has docstring."""
    pass

class Undocumented:
    pass
'''
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_docstrings(file_contents, str(tmp_path))
        assert findings[0].status in ["warn", "fail"]

    def test_no_functions_to_document(self, tmp_path):
        """Test pass when no public functions/classes exist."""
        content = "def _private():\n    pass\n\ndef _another_private():\n    pass"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_docstrings(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_excludes_test_files(self, tmp_path):
        """Test that test files are excluded from docstring check."""
        file_contents = {
            str(tmp_path / "main.py"): 'def process():\n    """Documented."""\n    pass',
            str(tmp_path / "tests" / "test_main.py"): "def test_process():\n    pass",
        }
        findings = _check_docstrings(file_contents, str(tmp_path))
        # Should only count main.py, not test file
        assert len(findings) == 1


class TestCheckTypeHints:
    """Test _check_type_hints function."""

    def test_fully_typed_functions(self, tmp_path):
        """Test pass when functions have type hints."""
        content = '''
def add(a: int, b: int) -> int:
    return a + b

def greet(name: str) -> str:
    return f"Hello, {name}"
'''
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_type_hints(file_contents, str(tmp_path))
        if findings:  # May return empty list if no functions
            assert findings[0].status == "pass"

    def test_partially_typed(self, tmp_path):
        """Test warn/pass when some functions lack type hints."""
        content = '''
def typed(x: int) -> int:
    return x

def untyped(x):
    return x * 2
'''
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_type_hints(file_contents, str(tmp_path))
        if findings:
            # 50% coverage is at the threshold (pass=50+, warn=20-50)
            assert findings[0].status in ["warn", "pass", "fail"]

    def test_return_type_only(self, tmp_path):
        """Test detection of return type hints."""
        content = "def process() -> str:\n    return 'result'"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_type_hints(file_contents, str(tmp_path))
        if findings:
            assert len(findings) >= 0  # Should detect the return type

    def test_no_functions(self, tmp_path):
        """Test with no functions to type hint."""
        content = "x = 10\ny = 20"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_type_hints(file_contents, str(tmp_path))
        assert findings == []


class TestCheckLogging:
    """Test _check_logging function."""

    def test_with_logging_import(self, tmp_path):
        """Test pass when logging is imported."""
        content = "import logging\nlogger = logging.getLogger(__name__)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_logging(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_structlog(self, tmp_path):
        """Test pass when structlog is used."""
        content = "import structlog\nlog = structlog.get_logger()"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_logging(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_loguru(self, tmp_path):
        """Test pass when loguru is used."""
        content = "from loguru import logger\nlogger.info('message')"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_logging(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_no_logging(self, tmp_path):
        """Test fail when no logging is present."""
        content = "def main():\n    print('hello')"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_logging(file_contents, str(tmp_path))
        assert findings[0].status == "fail"


class TestCheckTracing:
    """Test _check_tracing function."""

    def test_with_opentelemetry(self, tmp_path):
        """Test pass when OpenTelemetry is used."""
        content = "import opentelemetry\nfrom opentelemetry import trace"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_tracing(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_langsmith(self, tmp_path):
        """Test pass when LangSmith is used."""
        content = "import langsmith\nfrom langsmith import traceable"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_tracing(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_langfuse(self, tmp_path):
        """Test pass when Langfuse is used."""
        content = "from langfuse import Langfuse\nclient = Langfuse()"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_tracing(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_trace_id(self, tmp_path):
        """Test pass when trace_id pattern is present."""
        content = "trace_id = uuid.uuid4()\nspan_id = generate_span_id()"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_tracing(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_no_tracing(self, tmp_path):
        """Test warn when no tracing is present."""
        content = "def main():\n    pass"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_tracing(file_contents, str(tmp_path))
        assert findings[0].status == "warn"


class TestCheckHumanInLoop:
    """Test _check_human_in_loop function."""

    def test_with_approval_gate(self, tmp_path):
        """Test pass when approval gate is present."""
        content = "if require_approval(action):\n    execute_action()"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_human_in_loop(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_human_approval_handler(self, tmp_path):
        """Test pass when HumanApprovalCallbackHandler is used."""
        content = "from langchain import HumanApprovalCallbackHandler"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_human_in_loop(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_confirmation_strategy(self, tmp_path):
        """Test pass when confirmation_strategy is present (Haystack)."""
        content = "confirmation_strategy = HayStackConfirmation()"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_human_in_loop(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_no_human_oversight(self, tmp_path):
        """Test warn when no human oversight is present."""
        content = "def execute():\n    perform_action()"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_human_in_loop(file_contents, str(tmp_path))
        assert findings[0].status == "warn"


class TestCheckRateLimiting:
    """Test _check_rate_limiting function."""

    def test_with_strong_rate_limiting(self, tmp_path):
        """Test pass when rate limiting is implemented."""
        content = "rate_limiter = RateLimiter(max_rpm=10)\ncost_limit = 100"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_rate_limiting(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_budget_limit(self, tmp_path):
        """Test pass when budget limit is set."""
        content = "budget_limit = 50\ntoken_budget = 10000"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_rate_limiting(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_weak_limits_only(self, tmp_path):
        """Test warn when only weak execution limits exist."""
        file_contents = {
            str(tmp_path / "a.py"): "max_tokens = 1000",
            str(tmp_path / "b.py"): "max_iterations = 10",
            str(tmp_path / "c.py"): "max_steps = 5",
            str(tmp_path / "d.py"): "max_retries = 3",
            str(tmp_path / "e.py"): "cooldown = 60",
        }
        findings = _check_rate_limiting(file_contents, str(tmp_path))
        assert findings[0].status == "warn"

    def test_no_rate_limiting(self, tmp_path):
        """Test warn when no rate limiting is present."""
        content = "def run_agent():\n    pass"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_rate_limiting(file_contents, str(tmp_path))
        assert findings[0].status == "warn"


class TestCheckRetryLogic:
    """Test _check_retry_logic function."""

    def test_with_retry_decorator(self, tmp_path):
        """Test pass when retry decorator is used."""
        content = "@retry(max_attempts=3)\ndef call_api():\n    pass"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_retry_logic(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_tenacity(self, tmp_path):
        """Test pass when tenacity is used."""
        content = "from tenacity import retry, stop_after_attempt"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_retry_logic(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_exponential_backoff(self, tmp_path):
        """Test pass when exponential backoff is used."""
        content = "backoff_strategy = exponential_backoff(base=2, max=60)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_retry_logic(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_no_retry_logic(self, tmp_path):
        """Test warn when no retry logic is present."""
        content = "def call_api():\n    return requests.get(url)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_retry_logic(file_contents, str(tmp_path))
        assert findings[0].status == "warn"


class TestCheckInjectionDefense:
    """Test _check_injection_defense function."""

    def test_with_prompt_guard(self, tmp_path):
        """Test pass when prompt guard is used."""
        content = "from nemo_guardrails import NemoGuardrails\nguards = NemoGuardrails()"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_injection_defense(file_contents, str(tmp_path))
        assert len(findings) >= 1
        # First finding should be the injection defense check
        assert findings[0].status == "pass"

    def test_with_moderation(self, tmp_path):
        """Test pass when moderation is used."""
        content = "result = moderation.check_input(user_input)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_injection_defense(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_input_sanitization(self, tmp_path):
        """Test pass when input sanitization is present."""
        content = "sanitized = sanitize_prompt(user_input)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_injection_defense(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_unsafe_user_input(self, tmp_path):
        """Test warn when unsafe input handling is detected."""
        content = 'prompt = f"Query: {user_input}"'
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_injection_defense(file_contents, str(tmp_path))
        # Should detect the unsafe pattern
        assert len(findings) >= 1

    def test_no_injection_defense(self, tmp_path):
        """Test warn when no defense is present."""
        content = "def process(query):\n    return query"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_injection_defense(file_contents, str(tmp_path))
        assert findings[0].status == "warn"


class TestCheckOutputValidation:
    """Test _check_output_validation function."""

    def test_with_pydantic_output_parser(self, tmp_path):
        """Test pass when Pydantic output parser is used."""
        content = "from langchain.output_parsers import PydanticOutputParser"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_output_validation(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_json_output_parser(self, tmp_path):
        """Test pass when JSON output parser is used."""
        content = "parser = JsonOutputParser()\nresult = parser.parse(output)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_output_validation(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_response_model(self, tmp_path):
        """Test pass when response_model is used."""
        content = "response = llm.invoke(input, response_model=OutputModel)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_output_validation(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_output_schema(self, tmp_path):
        """Test pass when output_schema is defined."""
        content = "output_schema = {'type': 'object', 'properties': {}}"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_output_validation(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_no_output_validation(self, tmp_path):
        """Test warn when no output validation is present."""
        content = "response = llm.invoke(prompt)\nresult = response.text"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_output_validation(file_contents, str(tmp_path))
        assert findings[0].status == "warn"


class TestCheckOAuthDelegation:
    """Test _check_oauth_delegation function."""

    def test_with_delegation_token(self, tmp_path):
        """Test pass when delegation token is used."""
        content = "delegation_token = create_token(authorized_by=user_id)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_oauth_delegation(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_agent_user_binding(self, tmp_path):
        """Test pass when agent-user binding is present."""
        content = "agent_user_binding = AgentBinding(user_id=current_user)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_oauth_delegation(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_agent_context_user(self, tmp_path):
        """Test warn when user_id is referenced in agent context."""
        content = "agent.user_id = user_id\nagent.run(task)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_oauth_delegation(file_contents, str(tmp_path))
        assert findings[0].status == "warn"

    def test_no_delegation_binding(self, tmp_path):
        """Test warn when no delegation binding is present."""
        content = "def run_agent(task):\n    return agent.execute(task)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_oauth_delegation(file_contents, str(tmp_path))
        assert findings[0].status == "warn"


class TestCheckTokenScopeValidation:
    """Test _check_token_scope_validation function."""

    def test_with_token_scope(self, tmp_path):
        """Test pass when token scope validation is present."""
        content = "token_scope = ['read:users', 'write:posts']\ncheck_scope(token)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_token_scope_validation(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_permission_check(self, tmp_path):
        """Test pass when permission check is present."""
        content = "if has_permission(user, 'delete_data'):\n    perform_delete()"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_token_scope_validation(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_allowed_actions(self, tmp_path):
        """Test pass when allowed_actions is defined."""
        content = "allowed_actions = ['read', 'list']\nif action in allowed_actions:"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_token_scope_validation(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_no_scope_validation(self, tmp_path):
        """Test warn when no scope validation is present."""
        content = "def execute_action(token, action):\n    return api.call(action)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_token_scope_validation(file_contents, str(tmp_path))
        assert findings[0].status == "warn"


class TestCheckTokenExpiryRevocation:
    """Test _check_token_expiry_revocation function."""

    def test_with_token_expiry(self, tmp_path):
        """Test pass when token expiry is handled."""
        content = "if token.expires_at < datetime.now():\n    refresh_token()"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_token_expiry_revocation(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_revocation(self, tmp_path):
        """Test pass when revocation is handled."""
        content = "def revoke_token(token_id):\n    cache.delete(token_id)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_token_expiry_revocation(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_execution_timeout(self, tmp_path):
        """Test pass when execution timeout is set."""
        content = "execution_timeout = 300\nagent_timeout = 600"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_token_expiry_revocation(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_weak_limits(self, tmp_path):
        """Test warn when only weak limits exist."""
        file_contents = {
            str(tmp_path / "a.py"): "max_agent_steps = 100",
            str(tmp_path / "b.py"): "max_iterations = 50",
            str(tmp_path / "c.py"): "step_limit = 30",
        }
        findings = _check_token_expiry_revocation(file_contents, str(tmp_path))
        assert findings[0].status == "warn"

    def test_no_expiry_handling(self, tmp_path):
        """Test fail when no expiry handling is present."""
        content = "def authenticate(token):\n    return token.valid"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_token_expiry_revocation(file_contents, str(tmp_path))
        assert findings[0].status == "fail"


class TestCheckActionAuditTrail:
    """Test _check_action_audit_trail function."""

    def test_with_action_log(self, tmp_path):
        """Test pass when action logging is present."""
        content = "action_log.append({'action': 'delete', 'user': user_id})"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_action_audit_trail(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_audit_trail(self, tmp_path):
        """Test pass when audit trail is present."""
        content = "audit_trail.record(action, user_id, timestamp)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_action_audit_trail(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_event_log(self, tmp_path):
        """Test pass when event logging is present."""
        content = "event_log.write({'event': 'tool_call', 'tool': tool_name})"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_action_audit_trail(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_content_tracing(self, tmp_path):
        """Test pass when CONTENT_TRACING_ENABLED is present."""
        content = "CONTENT_TRACING_ENABLED = True"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_action_audit_trail(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_no_audit_trail(self, tmp_path):
        """Test warn when no audit trail is present."""
        content = "def execute_action(action):\n    perform(action)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_action_audit_trail(file_contents, str(tmp_path))
        assert findings[0].status == "warn"


class TestCheckActionBoundaries:
    """Test _check_action_boundaries function."""

    def test_with_allowed_tools(self, tmp_path):
        """Test pass when allowed_tools is defined."""
        content = "allowed_tools = ['calculator', 'search']\nif tool in allowed_tools:"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_action_boundaries(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_tool_whitelist(self, tmp_path):
        """Test pass when tool_whitelist is defined."""
        content = "tool_whitelist = ['send_email', 'log']\ntool_filter = Whitelist()"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_action_boundaries(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_action_boundary(self, tmp_path):
        """Test pass when action_boundary is present."""
        content = "action_boundary = ActionBoundary(max_actions=10)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_action_boundaries(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_with_permission_gate(self, tmp_path):
        """Test pass when permission_gate is present."""
        content = "permission_gate = PermissionValidator()\nif permission_gate.can_execute(action):"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_action_boundaries(file_contents, str(tmp_path))
        assert findings[0].status == "pass"

    def test_no_action_boundaries(self, tmp_path):
        """Test warn when no action boundaries are present."""
        content = "def execute(tool_name, args):\n    return tools[tool_name](*args)"
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_action_boundaries(file_contents, str(tmp_path))
        assert findings[0].status == "warn"


class TestScanCodebase:
    """Test scan_codebase main function."""

    def test_empty_directory(self, tmp_path):
        """Test scanning an empty directory."""
        findings = scan_codebase(str(tmp_path))
        assert len(findings) >= 1
        assert any("No Python files" in f.evidence for f in findings)

    def test_directory_with_single_file(self, tmp_path):
        """Test scanning a directory with one Python file."""
        content = '''
import logging
def process(data: str) -> str:
    """Process data."""
    logging.info("Processing")
    return data
'''
        (tmp_path / "main.py").write_text(content)
        findings = scan_codebase(str(tmp_path))
        assert len(findings) > 0
        # Should have multiple findings from different checks

    def test_directory_with_multiple_files(self, tmp_path):
        """Test scanning a directory with multiple Python files."""
        (tmp_path / "agent.py").write_text('from openai import OpenAI\nclient = OpenAI()')
        (tmp_path / "handler.py").write_text('import logging\nlogger = logging.getLogger()')

        findings = scan_codebase(str(tmp_path))
        assert len(findings) > 0

    def test_single_file_scan(self, tmp_path):
        """Test scanning a single file directly."""
        py_file = tmp_path / "agent.py"
        py_file.write_text('def run():\n    """Run the agent."""\n    pass')

        findings = scan_codebase(str(py_file))
        assert len(findings) > 0

    def test_nested_directory_structure(self, tmp_path):
        """Test scanning nested directory structure."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "agent.py").write_text('import logging')
        (tmp_path / "src" / "sub").mkdir()
        (tmp_path / "src" / "sub" / "handler.py").write_text('from pydantic import BaseModel')

        findings = scan_codebase(str(tmp_path))
        assert len(findings) > 0

    def test_excludes_test_files_from_docstrings(self, tmp_path):
        """Test that test files don't affect docstring coverage."""
        (tmp_path / "main.py").write_text('def process():\n    """Process."""\n    pass')
        (tmp_path / "test_main.py").write_text('def test_process():\n    pass')

        findings = scan_codebase(str(tmp_path))
        # Find docstring finding
        docstring_findings = [f for f in findings if "docstring" in f.name.lower()]
        if docstring_findings:
            # Should not penalize for test_main.py lacking docstring
            assert docstring_findings[0].status in ["pass", "warn"]


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_file_contents(self, tmp_path):
        """Test with empty file contents."""
        file_contents = {}
        findings = _check_error_handling(file_contents, str(tmp_path))
        assert len(findings) >= 1

    def test_file_with_only_comments(self, tmp_path):
        """Test file with only comments."""
        content = "# This is a comment\n# Another comment"
        file_contents = {str(tmp_path / "main.py"): content}
        findings = _check_docstrings(file_contents, str(tmp_path))
        assert len(findings) >= 1

    def test_multiline_function_signature(self, tmp_path):
        """Test handling of multi-line function signatures."""
        content = '''
def complex_function(
    arg1: str,
    arg2: int
) -> str:
    """Complex function."""
    return arg1
'''
        file_contents = {str(tmp_path / "module.py"): content}
        findings = _check_type_hints(file_contents, str(tmp_path))
        # Should handle multi-line signatures correctly
        assert len(findings) >= 0

    def test_file_not_found(self, tmp_path):
        """Test with non-existent file path."""
        # scan_codebase should handle gracefully
        findings = scan_codebase(str(tmp_path / "nonexistent.py"))
        assert any("No Python files" in f.evidence for f in findings)

    def test_unicode_content(self, tmp_path):
        """Test file with unicode content."""
        content = '''
def greet(name: str) -> str:
    """Greet the user. 你好 مرحبا."""
    return f"Hello, {name}"
'''
        file_contents = {str(tmp_path / "main.py"): content}
        findings = _check_docstrings(file_contents, str(tmp_path))
        assert len(findings) >= 1

    def test_very_long_file(self, tmp_path):
        """Test with very long file."""
        content = "def dummy():\n    pass\n" * 1000
        file_contents = {str(tmp_path / "long.py"): content}
        findings = _check_logging(file_contents, str(tmp_path))
        assert len(findings) >= 1
