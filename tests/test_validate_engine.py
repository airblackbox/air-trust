"""
Comprehensive test suite for air_blackbox.validate.engine module.

Tests all classes, methods, and edge cases:
- ValidationResult dataclass
- ValidationReport dataclass + to_dict()
- ValidationRule base class
- ToolAllowlistRule - allowed/blocked tools
- SchemaValidationRule - valid/invalid schemas
- ContentPolicyRule - clean/dangerous content
- PiiOutputRule - with/without PII
- HallucinationGuardRule - with/without hallucination patterns
- RuntimeValidator - add_rule(), validate(), _write_record()
"""

import pytest
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

from air_blackbox.validate.engine import (
    ValidationResult,
    ValidationReport,
    ValidationRule,
    ToolAllowlistRule,
    SchemaValidationRule,
    ContentPolicyRule,
    PiiOutputRule,
    HallucinationGuardRule,
    RuntimeValidator,
)


# =====================================================================
# ValidationResult Tests
# =====================================================================

class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_validation_result_basic(self):
        """Test creating a basic ValidationResult."""
        result = ValidationResult(
            rule_name="test_rule",
            passed=True,
            severity="info",
            message="Test passed",
        )
        assert result.rule_name == "test_rule"
        assert result.passed is True
        assert result.severity == "info"
        assert result.message == "Test passed"
        assert result.timestamp != ""
        assert result.details == {}

    def test_validation_result_with_timestamp(self):
        """Test ValidationResult with explicit timestamp."""
        ts = "2025-01-01T12:00:00.000Z"
        result = ValidationResult(
            rule_name="test",
            passed=False,
            severity="block",
            message="Failed",
            timestamp=ts,
        )
        assert result.timestamp == ts

    def test_validation_result_with_details(self):
        """Test ValidationResult with details dict."""
        details = {"tool": "read_file", "reason": "not allowed"}
        result = ValidationResult(
            rule_name="tool_check",
            passed=False,
            severity="block",
            message="Tool blocked",
            details=details,
        )
        assert result.details == details

    def test_validation_result_auto_timestamp(self):
        """Test that timestamp is auto-generated if not provided."""
        result = ValidationResult(
            rule_name="auto_ts",
            passed=True,
            severity="info",
            message="Auto timestamp",
        )
        assert result.timestamp
        assert "T" in result.timestamp
        assert result.timestamp.endswith("Z")

    def test_validation_result_severity_levels(self):
        """Test all valid severity levels."""
        for severity in ["block", "warn", "info"]:
            result = ValidationResult(
                rule_name="test",
                passed=True,
                severity=severity,
                message="Test",
            )
            assert result.severity == severity


# =====================================================================
# ValidationReport Tests
# =====================================================================

class TestValidationReport:
    """Tests for ValidationReport dataclass."""

    def test_validation_report_basic(self):
        """Test creating a basic ValidationReport."""
        result = ValidationResult(
            rule_name="test_rule",
            passed=True,
            severity="info",
            message="Passed",
        )
        report = ValidationReport(
            action_id="action_123",
            action_type="tool_call",
            results=[result],
            passed=True,
        )
        assert report.action_id == "action_123"
        assert report.action_type == "tool_call"
        assert len(report.results) == 1
        assert report.passed is True
        assert report.timestamp != ""
        assert report.validated_in_ms >= 0

    def test_validation_report_with_multiple_results(self):
        """Test ValidationReport with multiple results."""
        results = [
            ValidationResult("rule1", True, "info", "Pass 1"),
            ValidationResult("rule2", False, "warn", "Fail 1"),
            ValidationResult("rule3", True, "info", "Pass 2"),
        ]
        report = ValidationReport(
            action_id="multi_123",
            action_type="agent_decision",
            results=results,
            passed=True,
        )
        assert len(report.results) == 3

    def test_validation_report_to_dict(self):
        """Test ValidationReport.to_dict() method."""
        result = ValidationResult(
            rule_name="test_rule",
            passed=True,
            severity="info",
            message="Passed",
            details={"key": "value"},
        )
        report = ValidationReport(
            action_id="action_456",
            action_type="llm_response",
            results=[result],
            passed=True,
            validated_in_ms=42,
        )
        report_dict = report.to_dict()

        assert report_dict["action_id"] == "action_456"
        assert report_dict["action_type"] == "llm_response"
        assert report_dict["passed"] is True
        assert report_dict["validated_in_ms"] == 42
        assert len(report_dict["results"]) == 1

        check = report_dict["results"][0]
        assert check["rule"] == "test_rule"
        assert check["passed"] is True
        assert check["severity"] == "info"
        assert check["message"] == "Passed"
        assert check["details"] == {"key": "value"}

    def test_validation_report_to_dict_multiple_results(self):
        """Test to_dict with multiple results."""
        results = [
            ValidationResult("rule1", True, "info", "Pass 1", details={"a": 1}),
            ValidationResult("rule2", False, "block", "Block", details={"b": 2}),
        ]
        report = ValidationReport(
            action_id="id_789",
            action_type="tool_call",
            results=results,
            passed=False,
        )
        report_dict = report.to_dict()

        assert len(report_dict["results"]) == 2
        assert report_dict["results"][0]["rule"] == "rule1"
        assert report_dict["results"][1]["rule"] == "rule2"
        assert report_dict["results"][0]["details"] == {"a": 1}
        assert report_dict["results"][1]["details"] == {"b": 2}

    def test_validation_report_auto_timestamp(self):
        """Test that timestamp is auto-generated."""
        report = ValidationReport(
            action_id="ts_test",
            action_type="tool_call",
            results=[],
            passed=True,
        )
        assert report.timestamp
        assert report.timestamp.endswith("Z")


# =====================================================================
# ValidationRule Base Class Tests
# =====================================================================

class TestValidationRule:
    """Tests for ValidationRule base class."""

    def test_validation_rule_base_attributes(self):
        """Test ValidationRule base class attributes."""
        rule = ValidationRule()
        assert rule.name == "base_rule"
        assert rule.severity == "warn"

    def test_validation_rule_check_not_implemented(self):
        """Test that check() method raises NotImplementedError."""
        rule = ValidationRule()
        with pytest.raises(NotImplementedError):
            rule.check({})


# =====================================================================
# ToolAllowlistRule Tests
# =====================================================================

class TestToolAllowlistRule:
    """Tests for ToolAllowlistRule."""

    def test_tool_allowlist_allowed_tool(self):
        """Test tool that is in allowlist."""
        rule = ToolAllowlistRule(["read_file", "web_search", "calculator"])
        result = rule.check({"tool_name": "read_file"})
        assert result.passed is True
        assert result.severity == "info"
        assert "approved list" in result.message

    def test_tool_allowlist_blocked_tool(self):
        """Test tool that is NOT in allowlist."""
        rule = ToolAllowlistRule(["read_file", "web_search"])
        result = rule.check({"tool_name": "delete_file"})
        assert result.passed is False
        assert result.severity == "block"
        assert "NOT on the approved list" in result.message
        assert result.details["tool"] == "delete_file"
        assert result.details["allowed"] == ["read_file", "web_search"]

    def test_tool_allowlist_case_insensitive(self):
        """Test that tool name matching is case-insensitive."""
        rule = ToolAllowlistRule(["Read_File", "WEB_SEARCH"])
        result = rule.check({"tool_name": "read_file"})
        assert result.passed is True

        result = rule.check({"tool_name": "WEB_SEARCH"})
        assert result.passed is True

    def test_tool_allowlist_empty_action(self):
        """Test with empty action dict."""
        rule = ToolAllowlistRule(["read_file"])
        result = rule.check({})
        assert result.passed is False

    def test_tool_allowlist_missing_tool_name(self):
        """Test action without tool_name key."""
        rule = ToolAllowlistRule(["read_file"])
        result = rule.check({"arguments": {}})
        assert result.passed is False

    def test_tool_allowlist_rule_attributes(self):
        """Test rule attributes."""
        rule = ToolAllowlistRule(["test"])
        assert rule.name == "tool_allowlist"
        assert rule.severity == "block"


# =====================================================================
# SchemaValidationRule Tests
# =====================================================================

class TestSchemaValidationRule:
    """Tests for SchemaValidationRule."""

    def test_schema_validation_no_schema_defined(self):
        """Test when no schema is defined for the tool."""
        rule = SchemaValidationRule({"other_tool": {"arg1": "str"}})
        result = rule.check({"tool_name": "read_file", "arguments": {}})
        assert result.passed is True
        assert "No schema defined" in result.message

    def test_schema_validation_valid_string_arg(self):
        """Test valid string argument."""
        rule = SchemaValidationRule({
            "read_file": {"path": "str"}
        })
        result = rule.check({
            "tool_name": "read_file",
            "arguments": {"path": "/tmp/test.txt"}
        })
        assert result.passed is True

    def test_schema_validation_valid_int_arg(self):
        """Test valid integer argument."""
        rule = SchemaValidationRule({
            "sleep": {"duration": "int"}
        })
        result = rule.check({
            "tool_name": "sleep",
            "arguments": {"duration": 5}
        })
        assert result.passed is True

    def test_schema_validation_missing_required_arg(self):
        """Test missing required argument."""
        rule = SchemaValidationRule({
            "read_file": {"path": "str"}
        })
        result = rule.check({
            "tool_name": "read_file",
            "arguments": {}
        })
        assert result.passed is False
        assert "Missing required arg: path" in result.message
        assert "errors" in result.details

    def test_schema_validation_wrong_type_string(self):
        """Test argument with wrong type (expected str, got int)."""
        rule = SchemaValidationRule({
            "read_file": {"path": "str"}
        })
        result = rule.check({
            "tool_name": "read_file",
            "arguments": {"path": 123}
        })
        assert result.passed is False
        assert "expected string" in result.message

    def test_schema_validation_wrong_type_int(self):
        """Test argument with wrong type (expected int, got str)."""
        rule = SchemaValidationRule({
            "sleep": {"duration": "int"}
        })
        result = rule.check({
            "tool_name": "sleep",
            "arguments": {"duration": "five"}
        })
        assert result.passed is False
        assert "expected int" in result.message

    def test_schema_validation_multiple_args(self):
        """Test schema with multiple arguments."""
        rule = SchemaValidationRule({
            "write_file": {"path": "str", "content": "str"}
        })
        result = rule.check({
            "tool_name": "write_file",
            "arguments": {"path": "/tmp/test.txt", "content": "data"}
        })
        assert result.passed is True

    def test_schema_validation_multiple_errors(self):
        """Test multiple validation errors."""
        rule = SchemaValidationRule({
            "write_file": {"path": "str", "content": "str"}
        })
        result = rule.check({
            "tool_name": "write_file",
            "arguments": {"path": 123, "content": 456}
        })
        assert result.passed is False
        assert len(result.details["errors"]) == 2

    def test_schema_validation_rule_attributes(self):
        """Test rule attributes."""
        rule = SchemaValidationRule({})
        assert rule.name == "schema_validation"
        assert rule.severity == "block"


# =====================================================================
# ContentPolicyRule Tests
# =====================================================================

class TestContentPolicyRule:
    """Tests for ContentPolicyRule."""

    def test_content_policy_clean_content(self):
        """Test with clean content."""
        rule = ContentPolicyRule()
        result = rule.check({
            "tool_name": "read_file",
            "arguments": {"path": "/tmp/test.txt"}
        })
        assert result.passed is True
        assert "passed" in result.message

    def test_content_policy_drop_table_pattern(self):
        """Test SQL injection pattern: DROP TABLE."""
        rule = ContentPolicyRule()
        result = rule.check({
            "tool_name": "db_query",
            "arguments": {"query": "DROP TABLE users"}
        })
        assert result.passed is False
        assert result.severity == "block"

    def test_content_policy_drop_table_lowercase(self):
        """Test DROP TABLE pattern is case-insensitive."""
        rule = ContentPolicyRule()
        result = rule.check({
            "tool_name": "db_query",
            "arguments": {"query": "drop table users"}
        })
        assert result.passed is False

    def test_content_policy_rm_rf_pattern(self):
        """Test dangerous pattern: rm -rf /."""
        rule = ContentPolicyRule()
        result = rule.check({
            "tool_name": "shell_exec",
            "arguments": {"command": "rm -rf /"}
        })
        assert result.passed is False

    def test_content_policy_sudo_rm_pattern(self):
        """Test dangerous pattern: sudo rm."""
        rule = ContentPolicyRule()
        result = rule.check({
            "tool_name": "shell_exec",
            "arguments": {"command": "sudo rm -rf /important"}
        })
        assert result.passed is False

    def test_content_policy_eval_pattern(self):
        """Test code injection pattern: eval()."""
        rule = ContentPolicyRule()
        result = rule.check({
            "tool_name": "execute_code",
            "arguments": {"code": "eval(user_input)"}
        })
        assert result.passed is False

    def test_content_policy_exec_pattern(self):
        """Test code injection pattern: exec()."""
        rule = ContentPolicyRule()
        result = rule.check({
            "tool_name": "execute_code",
            "arguments": {"code": "exec('malicious code')"}
        })
        assert result.passed is False

    def test_content_policy_os_system_pattern(self):
        """Test os.system() pattern."""
        rule = ContentPolicyRule()
        result = rule.check({
            "tool_name": "execute",
            "arguments": {"command": "os.system('rm file')"}
        })
        assert result.passed is False

    def test_content_policy_custom_patterns(self):
        """Test with custom blocked patterns."""
        rule = ContentPolicyRule(blocked_patterns=[r'(?i)secret', r'(?i)api.key'])
        result = rule.check({
            "content": "This is a secret"
        })
        assert result.passed is False

    def test_content_policy_custom_patterns_not_matched(self):
        """Test custom patterns that don't match."""
        rule = ContentPolicyRule(blocked_patterns=[r'(?i)secret'])
        result = rule.check({
            "content": "This is safe content"
        })
        assert result.passed is True

    def test_content_policy_with_content_field(self):
        """Test checking 'content' field instead of 'arguments'."""
        rule = ContentPolicyRule()
        result = rule.check({
            "content": "DELETE FROM users WHERE 1=1"
        })
        assert result.passed is False

    def test_content_policy_rule_attributes(self):
        """Test rule attributes."""
        rule = ContentPolicyRule()
        assert rule.name == "content_policy"
        assert rule.severity == "block"


# =====================================================================
# PiiOutputRule Tests
# =====================================================================

class TestPiiOutputRule:
    """Tests for PiiOutputRule."""

    def test_pii_no_pii_detected(self):
        """Test content without PII."""
        rule = PiiOutputRule()
        result = rule.check({
            "tool_name": "web_search",
            "arguments": {"query": "weather in New York"}
        })
        assert result.passed is True
        assert "No PII" in result.message

    def test_pii_email_detected(self):
        """Test detection of email address."""
        rule = PiiOutputRule()
        result = rule.check({
            "arguments": {"email": "user@example.com"}
        })
        assert result.passed is False
        assert "PII detected" in result.message
        assert "email" in result.details["pii_types"]

    def test_pii_ssn_detected(self):
        """Test detection of SSN."""
        rule = PiiOutputRule()
        result = rule.check({
            "arguments": {"ssn": "123-45-6789"}
        })
        assert result.passed is False
        assert "ssn" in result.details["pii_types"]

    def test_pii_credit_card_detected_dashes(self):
        """Test detection of credit card with dashes."""
        rule = PiiOutputRule()
        result = rule.check({
            "arguments": {"card": "4532-1234-5678-9010"}
        })
        assert result.passed is False
        assert "credit_card" in result.details["pii_types"]

    def test_pii_credit_card_detected_spaces(self):
        """Test detection of credit card with spaces."""
        rule = PiiOutputRule()
        result = rule.check({
            "arguments": {"card": "4532 1234 5678 9010"}
        })
        assert result.passed is False
        assert "credit_card" in result.details["pii_types"]

    def test_pii_credit_card_detected_no_separators(self):
        """Test detection of credit card without separators."""
        rule = PiiOutputRule()
        result = rule.check({
            "arguments": {"card": "4532123456789010"}
        })
        assert result.passed is False
        assert "credit_card" in result.details["pii_types"]

    def test_pii_multiple_types_detected(self):
        """Test detection of multiple PII types."""
        rule = PiiOutputRule()
        result = rule.check({
            "arguments": {
                "email": "user@example.com",
                "ssn": "987-65-4321"
            }
        })
        assert result.passed is False
        assert "email" in result.details["pii_types"]
        assert "ssn" in result.details["pii_types"]

    def test_pii_with_content_field(self):
        """Test PII checking with 'content' field."""
        rule = PiiOutputRule()
        result = rule.check({
            "content": "Contact: john@example.com"
        })
        assert result.passed is False

    def test_pii_rule_attributes(self):
        """Test rule attributes."""
        rule = PiiOutputRule()
        assert rule.name == "pii_output_check"
        assert rule.severity == "warn"


# =====================================================================
# HallucinationGuardRule Tests
# =====================================================================

class TestHallucinationGuardRule:
    """Tests for HallucinationGuardRule."""

    def test_hallucination_no_flags(self):
        """Test content without hallucination indicators."""
        rule = HallucinationGuardRule()
        result = rule.check({
            "content": "The meeting is scheduled for tomorrow at 2pm."
        })
        assert result.passed is True

    def test_hallucination_suspicious_url_example(self):
        """Test detection of example.com URL."""
        rule = HallucinationGuardRule()
        result = rule.check({
            "content": "Visit https://www.example.com for details"
        })
        assert result.passed is False
        assert "suspicious_url" in result.details["flags"]

    def test_hallucination_suspicious_url_fake(self):
        """Test detection of fake.com URL."""
        rule = HallucinationGuardRule()
        result = rule.check({
            "content": "Go to https://fake.org"
        })
        assert result.passed is False

    def test_hallucination_suspicious_url_test(self):
        """Test detection of test.com URL."""
        rule = HallucinationGuardRule()
        result = rule.check({
            "content": "https://test.example.com"
        })
        assert result.passed is False

    def test_hallucination_fake_doi(self):
        """Test detection of fake DOI."""
        rule = HallucinationGuardRule()
        result = rule.check({
            "content": "doi: 10.0000/fake1234"
        })
        assert result.passed is False
        assert "fake_doi" in result.details["flags"]

    def test_hallucination_stale_knowledge_claim(self):
        """Test detection of stale knowledge claims."""
        rule = HallucinationGuardRule()
        result = rule.check({
            "content": "As of my latest data, the stock price is..."
        })
        assert result.passed is False
        assert "stale_knowledge_claim" in result.details["flags"]

    def test_hallucination_stale_knowledge_according_to(self):
        """Test 'According to our latest information' pattern."""
        rule = HallucinationGuardRule()
        result = rule.check({
            "content": "According to our most recent update, ..."
        })
        assert result.passed is False

    def test_hallucination_multiple_flags(self):
        """Test multiple hallucination indicators."""
        rule = HallucinationGuardRule()
        result = rule.check({
            "content": "According to my latest data, visit https://example.com for a doi: 10.0000/abc1"
        })
        assert result.passed is False
        assert len(result.details["flags"]) > 1

    def test_hallucination_valid_doi_not_flagged(self):
        """Test that valid DOIs are not flagged."""
        rule = HallucinationGuardRule()
        result = rule.check({
            "content": "See doi: 10.1234/science5678"
        })
        assert result.passed is True

    def test_hallucination_real_url_not_flagged(self):
        """Test that real URLs are not flagged."""
        rule = HallucinationGuardRule()
        result = rule.check({
            "content": "Visit https://www.google.com"
        })
        assert result.passed is True

    def test_hallucination_rule_attributes(self):
        """Test rule attributes."""
        rule = HallucinationGuardRule()
        assert rule.name == "hallucination_guard"
        assert rule.severity == "warn"


# =====================================================================
# RuntimeValidator Tests
# =====================================================================

class TestRuntimeValidator:
    """Tests for RuntimeValidator."""

    def test_runtime_validator_initialization(self):
        """Test RuntimeValidator initialization."""
        validator = RuntimeValidator()
        assert len(validator.rules) == 3  # Default rules
        assert isinstance(validator.rules[0], ContentPolicyRule)
        assert isinstance(validator.rules[1], PiiOutputRule)
        assert isinstance(validator.rules[2], HallucinationGuardRule)

    def test_runtime_validator_with_custom_runs_dir(self, tmp_path):
        """Test RuntimeValidator with custom runs_dir."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        assert validator.runs_dir == str(tmp_path)

    def test_runtime_validator_add_rule(self, tmp_path):
        """Test adding a custom rule."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        tool_rule = ToolAllowlistRule(["read_file"])
        validator.add_rule(tool_rule)
        assert len(validator.rules) == 4
        assert validator.rules[-1] == tool_rule

    def test_runtime_validator_add_multiple_rules(self, tmp_path):
        """Test adding multiple rules."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        rule1 = ToolAllowlistRule(["read_file"])
        rule2 = SchemaValidationRule({"read_file": {"path": "str"}})
        validator.add_rule(rule1)
        validator.add_rule(rule2)
        assert len(validator.rules) == 5

    def test_runtime_validator_validate_clean_action(self, tmp_path):
        """Test validation of clean action."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        report = validator.validate({
            "tool_name": "web_search",
            "arguments": {"query": "weather"}
        })
        assert report.passed is True
        assert report.action_id
        assert report.action_type == "tool_call"
        assert len(report.results) >= 3

    def test_runtime_validator_validate_blocked_by_content_policy(self, tmp_path):
        """Test validation blocked by content policy."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        report = validator.validate({
            "tool_name": "execute",
            "arguments": {"cmd": "DROP TABLE users"}
        })
        assert report.passed is False
        # Should have at least one blocking result
        blocked = [r for r in report.results if not r.passed and r.severity == "block"]
        assert len(blocked) > 0

    def test_runtime_validator_validate_pii_warning(self, tmp_path):
        """Test validation with PII warning."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        report = validator.validate({
            "tool_name": "send_email",
            "arguments": {"recipient": "user@example.com"}
        })
        assert report.passed is True  # Warning doesn't block
        # Should have at least one warning
        pii_results = [r for r in report.results if r.rule_name == "pii_output_check"]
        assert len(pii_results) > 0

    def test_runtime_validator_validate_action_type_tool_call(self, tmp_path):
        """Test validation with tool_call action type."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        report = validator.validate(
            {"tool_name": "test"},
            action_type="tool_call"
        )
        assert report.action_type == "tool_call"

    def test_runtime_validator_validate_action_type_llm_response(self, tmp_path):
        """Test validation with llm_response action type."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        report = validator.validate(
            {"content": "test"},
            action_type="llm_response"
        )
        assert report.action_type == "llm_response"

    def test_runtime_validator_validate_action_type_agent_decision(self, tmp_path):
        """Test validation with agent_decision action type."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        report = validator.validate(
            {"content": "test"},
            action_type="agent_decision"
        )
        assert report.action_type == "agent_decision"

    def test_runtime_validator_write_record(self, tmp_path):
        """Test that validation record is written to file."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        report = validator.validate({
            "tool_name": "test",
            "arguments": {"arg": "value"}
        })
        # Check that a file was created
        files = list(tmp_path.glob("*.air.json"))
        assert len(files) == 1
        record_file = files[0]

        # Check file content
        with open(record_file) as f:
            record = json.load(f)
        assert record["version"] == "1.0.0"
        assert record["run_id"] == report.action_id
        assert record["type"] == "validation"
        assert record["action_type"] == "tool_call"

    def test_runtime_validator_record_content(self, tmp_path):
        """Test detailed structure of validation record."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        report = validator.validate({
            "tool_name": "test",
            "arguments": {"arg": "value"}
        })
        files = list(tmp_path.glob("*.air.json"))
        with open(files[0]) as f:
            record = json.load(f)

        assert "timestamp" in record
        assert "passed" in record
        assert "validated_in_ms" in record
        assert "status" in record
        assert "checks" in record
        assert isinstance(record["checks"], list)

    def test_runtime_validator_rule_exception_handling(self, tmp_path):
        """Test handling of rule exceptions."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))

        class BrokenRule(ValidationRule):
            name = "broken_rule"
            def check(self, action):
                raise ValueError("Simulated error")

        validator.add_rule(BrokenRule())
        report = validator.validate({"test": "action"})
        # Should not raise, but include failed result
        broken_results = [r for r in report.results if r.rule_name == "broken_rule"]
        assert len(broken_results) > 0
        assert broken_results[0].passed is False

    def test_runtime_validator_validated_in_ms(self, tmp_path):
        """Test that validated_in_ms is recorded."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        report = validator.validate({"test": "action"})
        assert report.validated_in_ms >= 0

    def test_runtime_validator_multiple_validations(self, tmp_path):
        """Test running multiple validations."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        report1 = validator.validate({"tool_name": "test1"})
        report2 = validator.validate({"tool_name": "test2"})
        report3 = validator.validate({"tool_name": "test3"})

        files = list(tmp_path.glob("*.air.json"))
        assert len(files) == 3
        assert report1.action_id != report2.action_id
        assert report2.action_id != report3.action_id

    def test_runtime_validator_runs_dir_creation(self, tmp_path):
        """Test that runs_dir is created if it doesn't exist."""
        new_dir = tmp_path / "new_runs"
        assert not new_dir.exists()
        validator = RuntimeValidator(runs_dir=str(new_dir))
        assert new_dir.exists()

    def test_runtime_validator_integration_tool_allowlist(self, tmp_path):
        """Integration test: tool allowlist with other rules."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        validator.add_rule(ToolAllowlistRule(["read_file", "web_search"]))

        # Allowed tool
        report = validator.validate({
            "tool_name": "read_file",
            "arguments": {"path": "/tmp/test.txt"}
        })
        assert report.passed is True

        # Blocked tool
        report = validator.validate({
            "tool_name": "execute_shell",
            "arguments": {"cmd": "ls"}
        })
        assert report.passed is False

    def test_runtime_validator_integration_schema_validation(self, tmp_path):
        """Integration test: schema validation with other rules."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        validator.add_rule(SchemaValidationRule({
            "read_file": {"path": "str"}
        }))

        # Valid schema
        report = validator.validate({
            "tool_name": "read_file",
            "arguments": {"path": "/tmp/test.txt"}
        })
        assert report.passed is True

        # Invalid schema
        report = validator.validate({
            "tool_name": "read_file",
            "arguments": {"path": 123}
        })
        assert report.passed is False

    def test_runtime_validator_passed_when_only_warnings(self, tmp_path):
        """Test that passed=True when only warnings, no blocks."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        # PII warning doesn't block
        report = validator.validate({
            "arguments": {"email": "test@example.com"}
        })
        assert report.passed is True
        # But should have results
        assert len(report.results) > 0

    def test_runtime_validator_failed_when_any_block(self, tmp_path):
        """Test that passed=False when any rule blocks."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        validator.add_rule(ToolAllowlistRule(["safe_tool"]))
        report = validator.validate({
            "tool_name": "dangerous_tool"
        })
        assert report.passed is False

    def test_runtime_validator_all_rules_evaluated(self, tmp_path):
        """Test that all rules are evaluated even if one fails."""
        validator = RuntimeValidator(runs_dir=str(tmp_path))
        # Even dangerous content, should evaluate all rules
        report = validator.validate({
            "arguments": {"cmd": "DROP TABLE users"},
            "content": "https://example.com"
        })
        # Should have results from all default rules
        assert len(report.results) >= 3
