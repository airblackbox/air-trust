"""Comprehensive pytest tests for AIR Blackbox compliance engine.

Tests the EU AI Act compliance checking engine that examines GatewayStatus
(runtime data) and scans directories (static analysis) to assess compliance
with Articles 9-15 of the EU AI Act.
"""

import os
import json
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Literal

import pytest
from air_blackbox.compliance.engine import (
    ComplianceCheck,
    detect_frameworks,
    get_trust_layer_recommendation,
    run_all_checks,
    _c2d,
    _check_article_9,
    _check_article_10,
    _check_article_11,
    _check_article_12,
    _check_article_14,
    _check_article_15,
)
from air_blackbox.gateway_client import GatewayStatus


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def temp_scan_dir(tmp_path):
    """Create a temporary directory with some Python files for scanning."""
    # Create a basic Python module
    (tmp_path / "main.py").write_text(
        "import logging\nlogger = logging.getLogger(__name__)\nlogger.info('test')\n"
    )
    # Create a subdirectory with another module
    subdir = tmp_path / "src"
    subdir.mkdir()
    (subdir / "utils.py").write_text("import os\nprint('utils')\n")
    return tmp_path


@pytest.fixture
def scan_dir_with_langchain(tmp_path):
    """Create a directory with LangChain imports."""
    (tmp_path / "agent.py").write_text(
        "from langchain import LLMChain\n"
        "from langchain.agents import Tool\n"
        "print('LangChain agent')\n"
    )
    return tmp_path


@pytest.fixture
def scan_dir_with_crewai(tmp_path):
    """Create a directory with CrewAI imports."""
    (tmp_path / "crew.py").write_text(
        "from crewai import Agent, Task, Crew\n"
        "print('CrewAI')\n"
    )
    return tmp_path


@pytest.fixture
def scan_dir_with_openai(tmp_path):
    """Create a directory with OpenAI imports."""
    (tmp_path / "openai_client.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
    )
    return tmp_path


@pytest.fixture
def scan_dir_with_multiple_frameworks(tmp_path):
    """Create a directory with multiple framework imports."""
    (tmp_path / "main.py").write_text(
        "from langchain import LLMChain\n"
        "from anthropic import Anthropic\n"
    )
    (tmp_path / "crew.py").write_text("from crewai import Agent\n")
    return tmp_path


@pytest.fixture
def scan_dir_with_risk_assessment(tmp_path):
    """Create a directory with RISK_ASSESSMENT.md."""
    (tmp_path / "RISK_ASSESSMENT.md").write_text(
        "# Risk Assessment\n"
        "\n"
        "## Risk Classification\n"
        "This system is classified as high-risk per Article 6.\n"
        "Risk level: high-risk\n"
    )
    return tmp_path


@pytest.fixture
def scan_dir_with_data_governance(tmp_path):
    """Create a directory with DATA_GOVERNANCE.md."""
    (tmp_path / "DATA_GOVERNANCE.md").write_text(
        "# Data Governance\n"
        "\n"
        "## Data Sources\n"
        "All input data is validated and logged.\n"
        "\n"
        "## Retention Policy\n"
        "Data retained for 30 days.\n"
    )
    return tmp_path


@pytest.fixture
def scan_dir_with_readme(tmp_path):
    """Create a directory with README.md."""
    (tmp_path / "README.md").write_text(
        "# AI System\n"
        "\n"
        "This is an AI-powered system.\n"
    )
    return tmp_path


@pytest.fixture
def scan_dir_with_model_card(tmp_path):
    """Create a directory with MODEL_CARD.md."""
    (tmp_path / "MODEL_CARD.md").write_text(
        "# Model Card\n"
        "\n"
        "## Model Details\n"
        "Base model: GPT-4\n"
    )
    return tmp_path


@pytest.fixture
def scan_dir_with_logging(tmp_path):
    """Create a directory with logging infrastructure."""
    (tmp_path / "app.py").write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "logger.info('Starting application')\n"
    )
    return tmp_path


@pytest.fixture
def scan_dir_with_structured_logging(tmp_path):
    """Create a directory with structlog."""
    (tmp_path / "app.py").write_text(
        "from structlog import get_logger\n"
        "log = get_logger()\n"
        "log.info('event', key='value')\n"
    )
    return tmp_path


@pytest.fixture
def scan_dir_with_hmac(tmp_path):
    """Create a directory with HMAC patterns."""
    (tmp_path / "audit.py").write_text(
        "import hmac\n"
        "import hashlib\n"
        "\n"
        "def chain_hash(data, previous_hash):\n"
        "    return hmac.new(data.encode(), previous_hash.encode(), hashlib.sha256).hexdigest()\n"
    )
    return tmp_path


@pytest.fixture
def scan_dir_with_hitl(tmp_path):
    """Create a directory with human-in-the-loop patterns."""
    (tmp_path / "agent.py").write_text(
        "def require_approval(action):\n"
        "    \"\"\"Require human approval before executing action.\"\"\"\n"
        "    return human_review(action)\n"
    )
    return tmp_path


@pytest.fixture
def scan_dir_with_kill_switch(tmp_path):
    """Create a directory with kill switch pattern."""
    (tmp_path / "control.py").write_text(
        "def kill_switch():\n"
        "    \"\"\"Emergency stop mechanism.\"\"\"\n"
        "    shutdown()\n"
    )
    return tmp_path


@pytest.fixture
def scan_dir_with_operator_guide(tmp_path):
    """Create a directory with OPERATOR_GUIDE.md."""
    (tmp_path / "OPERATOR_GUIDE.md").write_text(
        "# Operator Guide\n"
        "\n"
        "## How to operate this system\n"
        "1. Start the system\n"
        "2. Monitor logs\n"
        "3. Shut down if needed\n"
    )
    return tmp_path


@pytest.fixture
def scan_dir_with_redteam(tmp_path):
    """Create a directory with REDTEAM.md."""
    (tmp_path / "REDTEAM.md").write_text(
        "# Red Team Results\n"
        "\n"
        "## Adversarial Testing\n"
        "System tested against 100 adversarial prompts.\n"
    )
    return tmp_path


@pytest.fixture
def scan_dir_with_retention(tmp_path):
    """Create a directory with retention configuration."""
    (tmp_path / "config.yaml").write_text(
        "logging:\n"
        "  retention: 90  # days\n"
        "  ttl: 7776000\n"
    )
    return tmp_path


@pytest.fixture
def gateway_status_active():
    """Create an active GatewayStatus with realistic data."""
    return GatewayStatus(
        reachable=True,
        url="http://localhost:8080",
        audit_chain_intact=True,
        audit_chain_length=1000,
        compliance_controls={"article_9": "pass", "article_10": "pass"},
        total_runs=100,
        models_observed=["gpt-4", "gpt-3.5-turbo"],
        providers_observed=["openai", "anthropic"],
        total_tokens=50000,
        date_range_start="2026-04-01",
        date_range_end="2026-04-12",
        recent_runs=[
            {
                "run_id": "run_001",
                "model": "gpt-4",
                "timestamp": "2026-04-12T12:00:00Z",
                "tokens": 500,
                "provider": "openai",
            },
            {
                "run_id": "run_002",
                "model": "gpt-3.5-turbo",
                "timestamp": "2026-04-12T12:05:00Z",
                "tokens": 300,
                "provider": "openai",
            },
        ],
        pii_detected_count=2,
        injection_attempts=5,
        error_count=2,
        timeout_count=1,
        vault_enabled=True,
        guardrails_enabled=True,
        trust_signing_key_set=True,
        otel_enabled=True,
    )


@pytest.fixture
def gateway_status_empty():
    """Create an empty GatewayStatus (default state)."""
    return GatewayStatus()


@pytest.fixture
def gateway_status_with_high_errors():
    """Create GatewayStatus with high error rate."""
    return GatewayStatus(
        reachable=True,
        total_runs=100,
        error_count=20,  # 20% error rate
        injection_attempts=0,
    )


@pytest.fixture
def gateway_status_with_pii():
    """Create GatewayStatus with PII detected."""
    return GatewayStatus(
        reachable=True,
        total_runs=50,
        pii_detected_count=10,
    )


# ============================================================================
# TESTS: ComplianceCheck dataclass
# ============================================================================

class TestComplianceCheckDataclass:
    """Tests for ComplianceCheck dataclass."""

    def test_compliance_check_creation(self):
        """Test creating a ComplianceCheck with all fields."""
        check = ComplianceCheck(
            name="Test Check",
            article=9,
            status="pass",
            evidence="Test evidence",
            detection="auto",
            fix_hint="Test fix",
            tier="runtime",
        )
        assert check.name == "Test Check"
        assert check.article == 9
        assert check.status == "pass"
        assert check.evidence == "Test evidence"
        assert check.detection == "auto"
        assert check.fix_hint == "Test fix"
        assert check.tier == "runtime"

    def test_compliance_check_defaults(self):
        """Test ComplianceCheck with default values."""
        check = ComplianceCheck(
            name="Minimal Check",
            article=10,
            status="warn",
            evidence="Evidence",
            detection="hybrid",
        )
        assert check.fix_hint == ""
        assert check.tier == "static"

    def test_c2d_converts_to_dict(self):
        """Test _c2d() converts ComplianceCheck to dict."""
        check = ComplianceCheck(
            name="Dict Test",
            article=11,
            status="fail",
            evidence="Missing file",
            detection="static",
            fix_hint="Create the file",
            tier="static",
        )
        result = _c2d(check)
        assert isinstance(result, dict)
        assert result["name"] == "Dict Test"
        assert result["status"] == "fail"
        assert result["evidence"] == "Missing file"
        assert result["detection"] == "static"
        assert result["fix_hint"] == "Create the file"
        assert result["tier"] == "static"
        assert "article" not in result  # article is not included in dict

    def test_c2d_dict_keys(self):
        """Test _c2d() includes exactly the expected keys."""
        check = ComplianceCheck(
            name="Test",
            article=12,
            status="pass",
            evidence="Found",
            detection="auto",
        )
        result = _c2d(check)
        expected_keys = {"name", "status", "evidence", "detection", "fix_hint", "tier"}
        assert set(result.keys()) == expected_keys


# ============================================================================
# TESTS: detect_frameworks()
# ============================================================================

class TestDetectFrameworks:
    """Tests for detect_frameworks() function."""

    def test_empty_directory(self, tmp_path):
        """Empty directory returns empty list."""
        result = detect_frameworks(str(tmp_path))
        assert result == []

    def test_langchain_detected(self, scan_dir_with_langchain):
        """LangChain imports are detected."""
        result = detect_frameworks(str(scan_dir_with_langchain))
        assert "langchain" in result

    def test_crewai_detected(self, scan_dir_with_crewai):
        """CrewAI imports are detected."""
        result = detect_frameworks(str(scan_dir_with_crewai))
        assert "crewai" in result

    def test_openai_detected(self, scan_dir_with_openai):
        """OpenAI imports are detected."""
        result = detect_frameworks(str(scan_dir_with_openai))
        assert "openai" in result

    def test_multiple_frameworks(self, scan_dir_with_multiple_frameworks):
        """Multiple frameworks are detected and sorted."""
        result = detect_frameworks(str(scan_dir_with_multiple_frameworks))
        assert "langchain" in result
        assert "anthropic" in result
        assert "crewai" in result
        # Should be sorted
        assert result == sorted(result)

    def test_non_python_files_ignored(self, tmp_path):
        """Non-Python files are ignored."""
        (tmp_path / "readme.txt").write_text("from langchain import ...")
        (tmp_path / "config.json").write_text('{"import": "langchain"}')
        result = detect_frameworks(str(tmp_path))
        assert result == []

    def test_single_py_file_as_scan_path(self, tmp_path):
        """Single .py file can be scanned directly."""
        py_file = tmp_path / "script.py"
        py_file.write_text("from langchain import LLMChain\n")
        result = detect_frameworks(str(py_file))
        assert "langchain" in result

    def test_single_non_py_file(self, tmp_path):
        """Non-Python file as scan path returns empty."""
        txt_file = tmp_path / "script.txt"
        txt_file.write_text("from langchain import ...")
        result = detect_frameworks(str(txt_file))
        assert result == []

    def test_file_not_found(self):
        """Non-existent path returns empty list."""
        result = detect_frameworks("/nonexistent/path")
        assert result == []

    def test_subdirectory_scanning(self, tmp_path):
        """Subdirectories are scanned recursively."""
        subdir = tmp_path / "deeply" / "nested" / "code"
        subdir.mkdir(parents=True)
        (subdir / "agent.py").write_text("from langchain import Agent\n")
        result = detect_frameworks(str(tmp_path))
        assert "langchain" in result


# ============================================================================
# TESTS: get_trust_layer_recommendation()
# ============================================================================

class TestGetTrustLayerRecommendation:
    """Tests for get_trust_layer_recommendation() function."""

    def test_langchain_maps_to_air_langchain_trust(self, scan_dir_with_langchain):
        """LangChain detected -> air-langchain-trust."""
        result = get_trust_layer_recommendation(str(scan_dir_with_langchain))
        assert result == "air-langchain-trust"

    def test_crewai_maps_to_air_crewai_trust(self, scan_dir_with_crewai):
        """CrewAI detected -> air-crewai-trust."""
        result = get_trust_layer_recommendation(str(scan_dir_with_crewai))
        assert result == "air-crewai-trust"

    def test_openai_maps_to_air_openai_trust(self, scan_dir_with_openai):
        """OpenAI detected -> air-openai-trust."""
        result = get_trust_layer_recommendation(str(scan_dir_with_openai))
        assert result == "air-openai-trust"

    def test_no_framework_defaults_to_langchain(self, tmp_path):
        """No framework detected -> default air-langchain-trust."""
        (tmp_path / "code.py").write_text("print('hello')\n")
        result = get_trust_layer_recommendation(str(tmp_path))
        assert result == "air-langchain-trust"

    def test_empty_directory_defaults(self, tmp_path):
        """Empty directory -> default air-langchain-trust."""
        result = get_trust_layer_recommendation(str(tmp_path))
        assert result == "air-langchain-trust"


# ============================================================================
# TESTS: Article 9 (Risk Management)
# ============================================================================

class TestArticle9RiskManagement:
    """Tests for Article 9 risk management checks."""

    def test_no_risk_assessment_doc_fails(self, temp_scan_dir, gateway_status_empty):
        """No RISK_ASSESSMENT.md -> fail on risk doc check."""
        result = _check_article_9(gateway_status_empty, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Risk assessment document"]["status"] == "fail"

    def test_risk_assessment_exists_passes(self, scan_dir_with_risk_assessment, gateway_status_empty):
        """RISK_ASSESSMENT.md exists -> pass on risk doc check."""
        result = _check_article_9(gateway_status_empty, str(scan_dir_with_risk_assessment))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Risk assessment document"]["status"] == "pass"

    def test_risk_classification_with_content_passes(self, scan_dir_with_risk_assessment, gateway_status_empty):
        """Risk doc with classification keywords -> pass on risk classification."""
        result = _check_article_9(gateway_status_empty, str(scan_dir_with_risk_assessment))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Risk classification (Article 6)"]["status"] == "pass"

    def test_risk_doc_without_classification_warns(self, tmp_path, gateway_status_empty):
        """Risk doc exists but no classification -> warn."""
        (tmp_path / "RISK_ASSESSMENT.md").write_text("# Risk Assessment\n\nWe identified risks.\n")
        result = _check_article_9(gateway_status_empty, str(tmp_path))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Risk classification (Article 6)"]["status"] == "warn"

    def test_mitigations_none_fails(self, temp_scan_dir, gateway_status_empty):
        """No mitigations active -> fail."""
        result = _check_article_9(gateway_status_empty, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        mit_check = checks["Risk mitigations active"]
        assert mit_check["status"] == "fail"
        assert "0/4" in mit_check["evidence"]

    def test_mitigations_one_warns(self, temp_scan_dir):
        """1 mitigation active -> warn."""
        status = GatewayStatus(guardrails_enabled=True)
        result = _check_article_9(status, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        mit_check = checks["Risk mitigations active"]
        assert mit_check["status"] == "warn"

    def test_mitigations_three_or_more_passes(self, temp_scan_dir):
        """3+ mitigations active -> pass."""
        status = GatewayStatus(
            guardrails_enabled=True,
            vault_enabled=True,
            trust_signing_key_set=True,
        )
        result = _check_article_9(status, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        mit_check = checks["Risk mitigations active"]
        assert mit_check["status"] == "pass"


# ============================================================================
# TESTS: Article 10 (Data Governance)
# ============================================================================

class TestArticle10DataGovernance:
    """Tests for Article 10 data governance checks."""

    def test_pii_detection_pass_no_pii(self, temp_scan_dir):
        """Gateway active, no PII -> pass."""
        status = GatewayStatus(reachable=True, total_runs=100, pii_detected_count=0)
        result = _check_article_10(status, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["PII detection in prompts"]["status"] == "pass"

    def test_pii_detection_warn_with_pii(self, temp_scan_dir, gateway_status_with_pii):
        """Gateway active, PII detected -> warn."""
        result = _check_article_10(gateway_status_with_pii, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["PII detection in prompts"]["status"] == "warn"
        assert "PII detected" in checks["PII detection in prompts"]["evidence"]

    def test_pii_detection_fail_no_gateway(self, temp_scan_dir, gateway_status_empty):
        """Gateway not reachable, no runs -> fail."""
        result = _check_article_10(gateway_status_empty, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["PII detection in prompts"]["status"] == "fail"

    def test_data_governance_doc_pass(self, scan_dir_with_data_governance, gateway_status_empty):
        """DATA_GOVERNANCE.md exists -> pass."""
        result = _check_article_10(gateway_status_empty, str(scan_dir_with_data_governance))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Data governance documentation"]["status"] == "pass"

    def test_data_governance_doc_fail(self, temp_scan_dir, gateway_status_empty):
        """No DATA_GOVERNANCE.md -> fail."""
        result = _check_article_10(gateway_status_empty, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Data governance documentation"]["status"] == "fail"

    def test_vault_enabled_pass(self, temp_scan_dir):
        """Vault enabled -> pass."""
        status = GatewayStatus(vault_enabled=True)
        result = _check_article_10(status, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Data vault (controlled storage)"]["status"] == "pass"

    def test_vault_disabled_fail(self, temp_scan_dir, gateway_status_empty):
        """Vault disabled -> fail."""
        result = _check_article_10(gateway_status_empty, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Data vault (controlled storage)"]["status"] == "fail"


# ============================================================================
# TESTS: Article 11 (Technical Documentation)
# ============================================================================

class TestArticle11TechnicalDocumentation:
    """Tests for Article 11 technical documentation checks."""

    def test_readme_exists_pass(self, scan_dir_with_readme, gateway_status_empty):
        """README.md exists -> pass."""
        result = _check_article_11(gateway_status_empty, str(scan_dir_with_readme))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["System description (README)"]["status"] == "pass"

    def test_readme_missing_fail(self, temp_scan_dir, gateway_status_empty):
        """No README.md -> fail."""
        result = _check_article_11(gateway_status_empty, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["System description (README)"]["status"] == "fail"

    def test_runtime_inventory_with_runs_pass(self, temp_scan_dir):
        """Total runs > 0 with models -> pass."""
        status = GatewayStatus(
            total_runs=50,
            models_observed=["gpt-4"],
            providers_observed=["openai"],
            total_tokens=10000,
        )
        result = _check_article_11(status, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Runtime system inventory (AI-BOM data)"]["status"] == "pass"

    def test_runtime_inventory_no_runs_fail(self, temp_scan_dir, gateway_status_empty):
        """No runs -> fail."""
        result = _check_article_11(gateway_status_empty, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Runtime system inventory (AI-BOM data)"]["status"] == "fail"

    def test_model_card_exists_pass(self, scan_dir_with_model_card, gateway_status_empty):
        """MODEL_CARD.md exists -> pass."""
        result = _check_article_11(gateway_status_empty, str(scan_dir_with_model_card))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Model card / system card"]["status"] == "pass"

    def test_model_card_missing_warn(self, temp_scan_dir, gateway_status_empty):
        """No model card -> warn."""
        result = _check_article_11(gateway_status_empty, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Model card / system card"]["status"] == "warn"


# ============================================================================
# TESTS: Article 12 (Record-Keeping)
# ============================================================================

class TestArticle12RecordKeeping:
    """Tests for Article 12 record-keeping checks."""

    def test_gateway_active_logging_pass(self, temp_scan_dir, gateway_status_active):
        """Gateway active with runs -> pass for event logging."""
        result = _check_article_12(gateway_status_active, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Automatic event logging (runtime)"]["status"] == "pass"

    def test_no_logging_fails(self, temp_scan_dir, gateway_status_empty):
        """No runtime logging and no static logging -> fail."""
        result = _check_article_12(gateway_status_empty, str(temp_scan_dir))
        # Should have a fail check for logging
        statuses = [c["status"] for c in result["checks"]]
        assert "fail" in statuses

    def test_static_logging_detected(self, scan_dir_with_logging, gateway_status_empty):
        """Python logging in code -> pass for static logging."""
        result = _check_article_12(gateway_status_empty, str(scan_dir_with_logging))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Logging infrastructure in code"]["status"] == "pass"

    def test_structured_logging_detected(self, scan_dir_with_structured_logging, gateway_status_empty):
        """structlog in code -> pass for logging infrastructure."""
        result = _check_article_12(gateway_status_empty, str(scan_dir_with_structured_logging))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Logging infrastructure in code"]["status"] == "pass"

    def test_audit_chain_intact_pass(self, temp_scan_dir):
        """Audit chain intact -> pass for tamper-evident."""
        status = GatewayStatus(audit_chain_intact=True, audit_chain_length=1000)
        result = _check_article_12(status, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Tamper-evident audit chain (runtime)"]["status"] == "pass"

    def test_trust_signing_key_set_pass(self, temp_scan_dir):
        """TRUST_SIGNING_KEY set -> pass for tamper-evident."""
        status = GatewayStatus(trust_signing_key_set=True)
        result = _check_article_12(status, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Tamper-evident audit chain (runtime)"]["status"] == "pass"

    def test_hmac_pattern_in_code_pass(self, scan_dir_with_hmac, gateway_status_empty):
        """HMAC patterns in code -> pass for tamper-evident."""
        result = _check_article_12(gateway_status_empty, str(scan_dir_with_hmac))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Tamper-evident patterns in code"]["status"] == "pass"

    def test_traceability_with_complete_runs_pass(self, temp_scan_dir, gateway_status_active):
        """Runs with all required fields -> pass for traceability."""
        result = _check_article_12(gateway_status_active, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Log detail and traceability"]["status"] == "pass"

    def test_retention_with_runs_pass(self, temp_scan_dir, gateway_status_active):
        """Runs with date range -> pass for retention."""
        result = _check_article_12(gateway_status_active, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Log retention"]["status"] == "pass"

    def test_retention_config_in_code_pass(self, scan_dir_with_retention, gateway_status_empty):
        """Retention configuration in code -> pass."""
        result = _check_article_12(gateway_status_empty, str(scan_dir_with_retention))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Log retention"]["status"] == "pass"


# ============================================================================
# TESTS: Article 14 (Human Oversight)
# ============================================================================

class TestArticle14HumanOversight:
    """Tests for Article 14 human oversight checks."""

    def test_hitl_pattern_in_code_pass(self, scan_dir_with_hitl, gateway_status_empty):
        """require_approval pattern in code -> pass."""
        result = _check_article_14(gateway_status_empty, str(scan_dir_with_hitl))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Human-in-the-loop mechanism"]["status"] == "pass"

    def test_no_hitl_pattern_warn(self, temp_scan_dir):
        """No HITL pattern but runs exist -> warn."""
        status = GatewayStatus(total_runs=50)
        result = _check_article_14(status, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Human-in-the-loop mechanism"]["status"] == "warn"

    def test_guardrails_kill_switch_pass(self, temp_scan_dir):
        """Gateway with guardrails -> pass for kill switch."""
        status = GatewayStatus(reachable=True, guardrails_enabled=True)
        result = _check_article_14(status, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Kill switch / stop mechanism"]["status"] == "pass"

    def test_kill_switch_pattern_in_code_pass(self, scan_dir_with_kill_switch, gateway_status_empty):
        """kill_switch pattern in code -> pass."""
        result = _check_article_14(gateway_status_empty, str(scan_dir_with_kill_switch))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Kill switch / stop mechanism"]["status"] == "pass"

    def test_operator_guide_exists_pass(self, scan_dir_with_operator_guide, gateway_status_empty):
        """OPERATOR_GUIDE.md exists -> pass."""
        result = _check_article_14(gateway_status_empty, str(scan_dir_with_operator_guide))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Operator understanding documentation"]["status"] == "pass"

    def test_operator_guide_missing_warn(self, temp_scan_dir, gateway_status_empty):
        """No operator guide -> warn."""
        result = _check_article_14(gateway_status_empty, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Operator understanding documentation"]["status"] == "warn"


# ============================================================================
# TESTS: Article 15 (Accuracy & Security)
# ============================================================================

class TestArticle15AccuracyAndSecurity:
    """Tests for Article 15 accuracy and security checks."""

    def test_gateway_reachable_injection_protection_pass(self, temp_scan_dir, gateway_status_active):
        """Gateway reachable -> pass for injection protection."""
        result = _check_article_15(gateway_status_active, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Prompt injection protection"]["status"] == "pass"

    def test_no_injection_protection_fail(self, temp_scan_dir, gateway_status_empty):
        """No protection -> fail for injection."""
        result = _check_article_15(gateway_status_empty, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Prompt injection protection"]["status"] == "fail"

    def test_low_error_rate_pass(self, temp_scan_dir):
        """Error rate < 5% -> pass."""
        status = GatewayStatus(total_runs=100, error_count=3)
        result = _check_article_15(status, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Error resilience"]["status"] == "pass"

    def test_medium_error_rate_warn(self, temp_scan_dir):
        """Error rate 5-15% -> warn."""
        status = GatewayStatus(total_runs=100, error_count=10)
        result = _check_article_15(status, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Error resilience"]["status"] == "warn"

    def test_high_error_rate_fail(self, temp_scan_dir, gateway_status_with_high_errors):
        """Error rate > 15% -> fail."""
        result = _check_article_15(gateway_status_with_high_errors, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Error resilience"]["status"] == "fail"

    def test_api_keys_configured_pass(self, temp_scan_dir, monkeypatch, gateway_status_empty):
        """API keys present -> pass."""
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        result = _check_article_15(gateway_status_empty, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["API access control"]["status"] == "pass"

    def test_redteam_doc_exists_pass(self, scan_dir_with_redteam, gateway_status_empty):
        """REDTEAM.md exists -> pass."""
        result = _check_article_15(gateway_status_empty, str(scan_dir_with_redteam))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Adversarial robustness testing"]["status"] == "pass"

    def test_redteam_doc_missing_warn(self, temp_scan_dir, gateway_status_empty):
        """No red team doc -> warn."""
        result = _check_article_15(gateway_status_empty, str(temp_scan_dir))
        checks = {c["name"]: c for c in result["checks"]}
        assert checks["Adversarial robustness testing"]["status"] == "warn"


# ============================================================================
# TESTS: run_all_checks() integration
# ============================================================================

class TestRunAllChecksIntegration:
    """Integration tests for run_all_checks() function."""

    def test_returns_tuple_of_three(self, temp_scan_dir, gateway_status_empty):
        """run_all_checks returns (results, frameworks, rec_pkg)."""
        result = run_all_checks(gateway_status_empty, str(temp_scan_dir))
        assert isinstance(result, tuple)
        assert len(result) == 3
        results, frameworks, rec_pkg = result
        assert isinstance(results, list)
        assert isinstance(frameworks, list)
        assert isinstance(rec_pkg, str)

    def test_results_have_required_articles(self, temp_scan_dir, gateway_status_active):
        """Results contain all required EU AI Act articles."""
        results, _, _ = run_all_checks(gateway_status_active, str(temp_scan_dir))
        article_numbers = [r["number"] for r in results]
        assert 9 in article_numbers
        assert 10 in article_numbers
        assert 11 in article_numbers
        assert 12 in article_numbers
        assert 14 in article_numbers
        assert 15 in article_numbers

    def test_each_article_has_structure(self, temp_scan_dir, gateway_status_active):
        """Each article has required structure."""
        results, _, _ = run_all_checks(gateway_status_active, str(temp_scan_dir))
        for result in results[:6]:  # Check the main articles
            assert "number" in result
            assert "title" in result
            assert "checks" in result
            assert isinstance(result["checks"], list)
            for check in result["checks"]:
                assert "name" in check
                assert "status" in check
                assert check["status"] in ["pass", "warn", "fail"]

    def test_frameworks_detected(self, scan_dir_with_multiple_frameworks, gateway_status_empty):
        """Frameworks are detected and returned."""
        _, frameworks, _ = run_all_checks(gateway_status_empty, str(scan_dir_with_multiple_frameworks))
        assert len(frameworks) > 0
        assert "langchain" in frameworks

    def test_recommendation_with_framework(self, scan_dir_with_crewai, gateway_status_empty):
        """Recommendation matches detected framework."""
        _, _, rec_pkg = run_all_checks(gateway_status_empty, str(scan_dir_with_crewai))
        assert rec_pkg == "air-crewai-trust"

    def test_recommendation_default_no_framework(self, temp_scan_dir, gateway_status_empty):
        """Default recommendation when no framework detected."""
        _, _, rec_pkg = run_all_checks(gateway_status_empty, str(temp_scan_dir))
        assert rec_pkg == "air-langchain-trust"

    def test_single_file_scanning(self, tmp_path, gateway_status_active):
        """run_all_checks works with single .py file."""
        py_file = tmp_path / "script.py"
        py_file.write_text("from langchain import LLMChain\nprint('test')\n")
        results, frameworks, _ = run_all_checks(gateway_status_active, str(py_file))
        assert len(results) > 0
        assert "langchain" in frameworks

    def test_checks_have_evidence(self, temp_scan_dir, gateway_status_active):
        """All checks have evidence field populated."""
        results, _, _ = run_all_checks(gateway_status_active, str(temp_scan_dir))
        for result in results[:6]:
            for check in result["checks"]:
                assert "evidence" in check
                assert isinstance(check["evidence"], str)
                assert len(check["evidence"]) > 0

    def test_tier_field_present(self, temp_scan_dir, gateway_status_active):
        """All checks have tier field."""
        results, _, _ = run_all_checks(gateway_status_active, str(temp_scan_dir))
        for result in results[:6]:
            for check in result["checks"]:
                assert "tier" in check
                assert check["tier"] in ["static", "runtime"]


# ============================================================================
# TESTS: Full system scenarios
# ============================================================================

class TestFullSystemScenarios:
    """End-to-end scenario tests."""

    def test_compliant_system(self, tmp_path):
        """Fully compliant system passes all checks."""
        # Set up directories with all required docs
        (tmp_path / "README.md").write_text("# System\n")
        (tmp_path / "DATA_GOVERNANCE.md").write_text("# Data Governance\n")
        (tmp_path / "RISK_ASSESSMENT.md").write_text(
            "# Risk\n\n"
            "Risk level: limited-risk\n"
            "Article 6 classification provided.\n"
        )
        (tmp_path / "MODEL_CARD.md").write_text("# Model Card\n")
        (tmp_path / "OPERATOR_GUIDE.md").write_text("# Guide\n")
        (tmp_path / "REDTEAM.md").write_text("# Red Team\n")

        # Code with all patterns
        (tmp_path / "app.py").write_text(
            "import logging\n"
            "import hmac\n"
            "def require_approval(x): pass\n"
            "def kill_switch(): pass\n"
        )

        # Active gateway
        status = GatewayStatus(
            reachable=True,
            audit_chain_intact=True,
            audit_chain_length=500,
            total_runs=100,
            models_observed=["gpt-4"],
            providers_observed=["openai"],
            total_tokens=50000,
            pii_detected_count=0,
            injection_attempts=0,
            error_count=2,
            vault_enabled=True,
            guardrails_enabled=True,
            trust_signing_key_set=True,
            otel_enabled=True,
        )

        results, _, _ = run_all_checks(status, str(tmp_path))

        # Should have mostly passes
        all_statuses = []
        for result in results:
            for check in result["checks"]:
                all_statuses.append(check["status"])

        # Count outcomes (should have many passes)
        passes = all_statuses.count("pass")
        fails = all_statuses.count("fail")
        assert passes > fails, "Compliant system should have more passes than fails"

    def test_minimal_system(self, tmp_path):
        """Minimal system with no setup fails many checks."""
        status = GatewayStatus()
        results, _, _ = run_all_checks(status, str(tmp_path))

        # Should have failures
        all_statuses = []
        for result in results:
            for check in result["checks"]:
                all_statuses.append(check["status"])

        fails = all_statuses.count("fail")
        assert fails > 0, "Minimal system should fail some checks"
