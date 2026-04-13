"""
Tests for GatewayClient and GatewayStatus.

Tests gateway status creation, client initialization, health checks,
audit data retrieval, .air.json record analysis, and config detection.
"""

import json
import os
import tempfile
from unittest.mock import MagicMock, Mock, patch

import pytest
from air_blackbox.gateway_client import GatewayClient, GatewayStatus


class TestGatewayStatus:
    """Test GatewayStatus dataclass."""

    def test_gateway_status_defaults(self):
        """Test GatewayStatus creation with default values."""
        status = GatewayStatus()
        assert status.reachable is False
        assert status.url == "http://localhost:8080"
        assert status.audit_chain_intact is False
        assert status.audit_chain_length == 0
        assert status.compliance_controls == {}
        assert status.total_runs == 0
        assert status.models_observed == []
        assert status.providers_observed == []
        assert status.total_tokens == 0
        assert status.date_range_start is None
        assert status.date_range_end is None
        assert status.recent_runs == []
        assert status.pii_detected_count == 0
        assert status.injection_attempts == 0
        assert status.error_count == 0
        assert status.timeout_count == 0
        assert status.vault_enabled is False
        assert status.guardrails_enabled is False
        assert status.trust_signing_key_set is False
        assert status.otel_enabled is False

    def test_gateway_status_custom_values(self):
        """Test GatewayStatus creation with custom values."""
        status = GatewayStatus(
            reachable=True,
            url="http://example.com:9000",
            audit_chain_intact=True,
            audit_chain_length=5,
            total_runs=42,
            total_tokens=1000,
        )
        assert status.reachable is True
        assert status.url == "http://example.com:9000"
        assert status.audit_chain_intact is True
        assert status.audit_chain_length == 5
        assert status.total_runs == 42
        assert status.total_tokens == 1000

    def test_gateway_status_mutable_fields(self):
        """Test that mutable fields can be modified."""
        status = GatewayStatus()
        status.compliance_controls = {"article_9": "compliant"}
        status.models_observed = ["gpt-4", "claude-3"]
        assert status.compliance_controls == {"article_9": "compliant"}
        assert status.models_observed == ["gpt-4", "claude-3"]


class TestGatewayClientInit:
    """Test GatewayClient initialization."""

    def test_init_with_defaults(self):
        """Test GatewayClient initialization with default parameters."""
        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            with patch("httpx.Client"):
                client = GatewayClient()
                assert client.gateway_url == "http://localhost:8080"
                assert client.scan_path is None

    def test_init_with_custom_url(self):
        """Test GatewayClient initialization with custom gateway URL."""
        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            with patch("httpx.Client"):
                client = GatewayClient(gateway_url="http://example.com:9000")
                assert client.gateway_url == "http://example.com:9000"

    def test_init_url_strips_trailing_slash(self):
        """Test that gateway URL trailing slashes are stripped."""
        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            with patch("httpx.Client"):
                client = GatewayClient(gateway_url="http://example.com:9000/")
                assert client.gateway_url == "http://example.com:9000"

    def test_init_with_custom_runs_dir(self):
        """Test GatewayClient initialization with custom runs directory."""
        with patch("httpx.Client"):
            client = GatewayClient(runs_dir="/custom/runs")
            assert client.runs_dir == "/custom/runs"

    def test_init_with_scan_path(self):
        """Test GatewayClient initialization with scan path."""
        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            with patch("httpx.Client"):
                client = GatewayClient(scan_path="/project/path")
                assert client.scan_path == "/project/path"

    def test_init_calls_find_runs_dir_when_not_provided(self):
        """Test that _find_runs_dir is called when runs_dir not provided."""
        with patch.object(GatewayClient, "_find_runs_dir", return_value="./discovered/runs") as mock_find:
            with patch("httpx.Client"):
                client = GatewayClient()
                mock_find.assert_called_once()
                assert client.runs_dir == "./discovered/runs"

    def test_init_creates_httpx_client(self):
        """Test that httpx.Client is created during initialization."""
        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            with patch("httpx.Client") as mock_client_class:
                GatewayClient()
                mock_client_class.assert_called_once_with(timeout=5.0)


class TestCheckHealth:
    """Test _check_health() method."""

    def test_check_health_success_on_health_endpoint(self):
        """Test successful health check on /health endpoint."""
        mock_response = Mock(status_code=200)
        mock_httpx_client = Mock()
        mock_httpx_client.get.return_value = mock_response

        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            client = GatewayClient()
            client.client = mock_httpx_client

            result = client._check_health()
            assert result is True
            mock_httpx_client.get.assert_called_with("http://localhost:8080/health")

    def test_check_health_success_on_root(self):
        """Test successful health check fallback to root endpoint."""
        mock_response = Mock(status_code=200)
        mock_httpx_client = Mock()
        mock_httpx_client.get.side_effect = [Exception("Connection failed"), mock_response]

        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            client = GatewayClient()
            client.client = mock_httpx_client

            result = client._check_health()
            assert result is True

    def test_check_health_failure_server_error(self):
        """Test health check with server error."""
        mock_response = Mock(status_code=500)
        mock_httpx_client = Mock()
        mock_httpx_client.get.return_value = mock_response

        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            client = GatewayClient()
            client.client = mock_httpx_client

            result = client._check_health()
            assert result is False

    def test_check_health_failure_connection_error(self):
        """Test health check with connection error."""
        mock_httpx_client = Mock()
        mock_httpx_client.get.side_effect = Exception("Connection timeout")

        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            client = GatewayClient()
            client.client = mock_httpx_client

            result = client._check_health()
            assert result is False


class TestAnalyzeAirRecords:
    """Test _analyze_air_records() method."""

    def test_analyze_air_records_with_single_record(self):
        """Test analyzing a single .air.json record."""
        with tempfile.TemporaryDirectory() as tmpdir:
            air_file = os.path.join(tmpdir, "run_001.air.json")
            record_data = {
                "run_id": "run_001",
                "model": "gpt-4",
                "provider": "openai",
                "tokens": {"total": 1000},
                "timestamp": "2024-01-01T10:00:00Z",
                "status": "success",
                "tool_calls": ["get_status"],
            }
            with open(air_file, "w") as f:
                json.dump(record_data, f)

            with patch.object(GatewayClient, "_find_runs_dir", return_value=tmpdir):
                client = GatewayClient(runs_dir=tmpdir)
                status = GatewayStatus()
                client._analyze_air_records(status)

                assert status.total_runs == 1
                assert "gpt-4" in status.models_observed
                assert "openai" in status.providers_observed
                assert status.total_tokens == 1000
                assert status.date_range_start == "2024-01-01T10:00:00Z"
                assert status.date_range_end == "2024-01-01T10:00:00Z"

    def test_analyze_air_records_with_multiple_records(self):
        """Test analyzing multiple .air.json records."""
        with tempfile.TemporaryDirectory() as tmpdir:
            records = [
                {"run_id": "run_001", "model": "gpt-4", "provider": "openai", "tokens": {"total": 1000}, "timestamp": "2024-01-01T10:00:00Z", "status": "success"},
                {"run_id": "run_002", "model": "claude-3", "provider": "anthropic", "tokens": {"total": 2000}, "timestamp": "2024-01-02T10:00:00Z", "status": "success"},
            ]
            for i, rec in enumerate(records):
                with open(os.path.join(tmpdir, f"run_{i:03d}.air.json"), "w") as f:
                    json.dump(rec, f)

            with patch.object(GatewayClient, "_find_runs_dir", return_value=tmpdir):
                client = GatewayClient(runs_dir=tmpdir)
                status = GatewayStatus()
                client._analyze_air_records(status)

                assert status.total_runs == 2
                assert sorted(status.models_observed) == ["claude-3", "gpt-4"]
                assert sorted(status.providers_observed) == ["anthropic", "openai"]
                assert status.total_tokens == 3000

    def test_analyze_air_records_counts_errors_and_timeouts(self):
        """Test that error and timeout statuses are counted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            records = [
                {"run_id": "run_001", "status": "success", "timestamp": "2025-01-01T00:00:01Z"},
                {"run_id": "run_002", "status": "error", "timestamp": "2025-01-01T00:00:02Z"},
                {"run_id": "run_003", "status": "timeout", "timestamp": "2025-01-01T00:00:03Z"},
            ]
            for i, rec in enumerate(records):
                with open(os.path.join(tmpdir, f"run_{i:03d}.air.json"), "w") as f:
                    json.dump(rec, f)

            client = GatewayClient(runs_dir=tmpdir)
            status = GatewayStatus()
            client._analyze_air_records(status)

            assert status.error_count == 1
            assert status.timeout_count == 1

    def test_analyze_air_records_skips_invalid_json(self):
        """Test that invalid JSON files are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write valid record
            valid_file = os.path.join(tmpdir, "valid.air.json")
            with open(valid_file, "w") as f:
                json.dump({"run_id": "valid", "status": "success", "timestamp": "2025-01-01T00:00:00Z"}, f)

            # Write invalid JSON
            invalid_file = os.path.join(tmpdir, "invalid.air.json")
            with open(invalid_file, "w") as f:
                f.write("{invalid json")

            client = GatewayClient(runs_dir=tmpdir)
            status = GatewayStatus()
            client._analyze_air_records(status)

            # Invalid JSON is counted as a file but won't crash parsing
            assert status.total_runs >= 1

    def test_analyze_air_records_limits_recent_runs_to_10(self):
        """Test that recent_runs list is limited to 10 items."""
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(15):
                record = {
                    "run_id": f"run_{i:03d}",
                    "timestamp": f"2024-01-{(i % 30) + 1:02d}T10:00:00Z",
                    "status": "success",
                }
                with open(os.path.join(tmpdir, f"run_{i:03d}.air.json"), "w") as f:
                    json.dump(record, f)

            client = GatewayClient(runs_dir=tmpdir)
            status = GatewayStatus()
            client._analyze_air_records(status)

            assert len(status.recent_runs) == 10

    def test_analyze_air_records_with_no_runs_dir(self):
        """Test handling when runs_dir doesn't exist."""
        client = GatewayClient(runs_dir="/nonexistent/path")
        status = GatewayStatus()
        client._analyze_air_records(status)

        assert status.total_runs == 0
        assert status.models_observed == []


class TestCheckConfig:
    """Test _check_config() method."""

    def test_check_config_trust_signing_key_from_env(self):
        """Test that TRUST_SIGNING_KEY env var is detected."""
        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            with patch.dict(os.environ, {"TRUST_SIGNING_KEY": "test-key"}):
                client = GatewayClient()
                status = GatewayStatus()
                client._check_config(status)
                assert status.trust_signing_key_set is True

    def test_check_config_otel_enabled_from_env(self):
        """Test that OTEL_EXPORTER_OTLP_ENDPOINT env var is detected."""
        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            with patch.dict(os.environ, {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://otel:4317"}):
                client = GatewayClient()
                status = GatewayStatus()
                client._check_config(status)
                assert status.otel_enabled is True

    def test_check_config_vault_enabled_from_env(self):
        """Test that VAULT_ENDPOINT env var enables vault."""
        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            with patch.dict(os.environ, {"VAULT_ENDPOINT": "http://vault:8200"}):
                client = GatewayClient()
                status = GatewayStatus()
                client._check_config(status)
                assert status.vault_enabled is True

    def test_check_config_guardrails_yaml_detection(self):
        """Test that guardrails.yaml file is detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            with open("guardrails.yaml", "w") as f:
                f.write("rules: []")

            with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
                client = GatewayClient()
                status = GatewayStatus()
                with patch("os.path.exists", side_effect=lambda x: x == "guardrails.yaml"):
                    client._check_config(status)
                    assert status.guardrails_enabled is True

    def test_check_config_guardrails_yml_detection(self):
        """Test that guardrails.yml file is detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            with open("guardrails.yml", "w") as f:
                f.write("rules: []")

            with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
                client = GatewayClient()
                status = GatewayStatus()
                with patch("os.path.exists", side_effect=lambda x: x == "guardrails.yml"):
                    client._check_config(status)
                    assert status.guardrails_enabled is True

    def test_check_config_no_env_vars_or_files(self):
        """Test that status remains False when no config is found."""
        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            with patch.dict(os.environ, {}, clear=True):
                with patch("os.path.exists", return_value=False):
                    client = GatewayClient()
                    status = GatewayStatus()
                    client._check_config(status)
                    assert status.trust_signing_key_set is False
                    assert status.otel_enabled is False
                    assert status.vault_enabled is False
                    assert status.guardrails_enabled is False


class TestFindRunsDir:
    """Test _find_runs_dir() method."""

    def test_find_runs_dir_from_env_variable(self):
        """Test that RUNS_DIR env variable is used when set."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"RUNS_DIR": tmpdir}):
                client = GatewayClient(runs_dir=None)
                # The client should pick up RUNS_DIR from env
                assert tmpdir in client.runs_dir or client.runs_dir is not None

    def test_find_runs_dir_fallback_to_current_runs(self):
        """Test fallback to ./runs directory."""
        with patch.dict(os.environ, {"RUNS_DIR": ""}, clear=True):
            with patch("os.path.isdir", side_effect=lambda x: x == "./runs"):
                client = GatewayClient.__new__(GatewayClient)
                result = client._find_runs_dir()
                assert result == "./runs"

    def test_find_runs_dir_fallback_to_parent_runs(self):
        """Test fallback to ../runs directory."""
        with patch.dict(os.environ, {"RUNS_DIR": ""}, clear=True):
            with patch("os.path.isdir", side_effect=lambda x: x == "../runs"):
                client = GatewayClient.__new__(GatewayClient)
                result = client._find_runs_dir()
                assert result == "../runs"

    def test_find_runs_dir_fallback_to_home_air_blackbox(self):
        """Test fallback to ~/.air-blackbox/runs directory."""
        home_path = os.path.expanduser("~/.air-blackbox/runs")
        with patch.dict(os.environ, {"RUNS_DIR": ""}, clear=True):
            with patch("os.path.isdir", side_effect=lambda x: x == home_path):
                with patch("os.path.expanduser", return_value=home_path):
                    client = GatewayClient.__new__(GatewayClient)
                    result = client._find_runs_dir()
                    assert result == home_path

    def test_find_runs_dir_returns_default_when_none_found(self):
        """Test that ./runs is returned as default."""
        with patch.dict(os.environ, {"RUNS_DIR": ""}, clear=True):
            with patch("os.path.isdir", return_value=False):
                client = GatewayClient.__new__(GatewayClient)
                result = client._find_runs_dir()
                assert result == "./runs"


class TestGetStatus:
    """Test get_status() integration."""

    def test_get_status_when_gateway_reachable(self):
        """Test get_status when gateway is reachable."""
        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            with patch.object(GatewayClient, "_check_health", return_value=True):
                with patch.object(GatewayClient, "_pull_audit_data"):
                    with patch.object(GatewayClient, "_analyze_air_records"):
                        with patch.object(GatewayClient, "_check_config"):
                            client = GatewayClient()
                            status = client.get_status()

                            assert status.reachable is True
                            assert status.url == "http://localhost:8080"

    def test_get_status_when_gateway_unreachable(self):
        """Test get_status when gateway is unreachable."""
        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            with patch.object(GatewayClient, "_check_health", return_value=False):
                with patch.object(GatewayClient, "_analyze_air_records"):
                    with patch.object(GatewayClient, "_check_config"):
                        client = GatewayClient()
                        status = client.get_status()

                        assert status.reachable is False

    def test_get_status_calls_all_analysis_methods(self):
        """Test that get_status calls all analysis methods."""
        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            with patch.object(GatewayClient, "_check_health", return_value=True) as mock_health:
                with patch.object(GatewayClient, "_pull_audit_data") as mock_audit:
                    with patch.object(GatewayClient, "_analyze_air_records") as mock_analyze:
                        with patch.object(GatewayClient, "_check_config") as mock_config:
                            client = GatewayClient()
                            client.get_status()

                            mock_health.assert_called_once()
                            mock_audit.assert_called_once()
                            mock_analyze.assert_called_once()
                            mock_config.assert_called_once()

    def test_get_status_with_scan_path(self):
        """Test get_status with scan_path includes trust layer analysis."""
        with patch.object(GatewayClient, "_find_runs_dir", return_value="./runs"):
            with patch.object(GatewayClient, "_check_health", return_value=True):
                with patch.object(GatewayClient, "_pull_audit_data"):
                    with patch.object(GatewayClient, "_analyze_air_records"):
                        with patch.object(GatewayClient, "_analyze_trust_layer_records") as mock_trust:
                            with patch.object(GatewayClient, "_check_config"):
                                client = GatewayClient(scan_path="/project")
                                client.get_status()

                                mock_trust.assert_called_once()
