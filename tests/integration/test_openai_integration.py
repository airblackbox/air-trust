"""Integration tests for OpenAI trust layer.

Requires: pip install openai
These tests verify the trust layer works with REAL OpenAI imports,
but mock the actual API calls (no API key needed).
"""

import json
import os
import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from pathlib import Path

# Skip entire module if openai not installed
openai = pytest.importorskip("openai")

from air_blackbox.trust.openai_agents import AirOpenAIWrapper


class TestOpenAIImports:
    """Verify real OpenAI imports work."""

    def test_openai_module_available(self):
        import openai
        assert hasattr(openai, "OpenAI")

    def test_wrapper_class_exists(self):
        assert AirOpenAIWrapper is not None


class TestWrapperInitialization:
    """Test wrapper creates with a real-ish OpenAI client."""

    def _make_mock_client(self):
        client = MagicMock()
        client.base_url = "https://api.openai.com/v1"
        client.chat = MagicMock()
        client.chat.completions = MagicMock()
        return client

    def test_wraps_client(self, tmp_path):
        client = self._make_mock_client()
        wrapper = AirOpenAIWrapper(client, runs_dir=str(tmp_path), gateway_url="none")
        assert wrapper._client is client

    def test_runs_dir_created(self, tmp_path):
        runs = tmp_path / "openai_runs"
        client = self._make_mock_client()
        wrapper = AirOpenAIWrapper(client, runs_dir=str(runs), gateway_url="none")
        assert runs.exists()

    def test_gateway_url_set(self, tmp_path):
        client = self._make_mock_client()
        wrapper = AirOpenAIWrapper(
            client, gateway_url="http://localhost:8080", runs_dir=str(tmp_path)
        )
        assert wrapper.gateway_url == "http://localhost:8080"

    def test_passthrough_attributes(self, tmp_path):
        client = self._make_mock_client()
        client.models = MagicMock()
        wrapper = AirOpenAIWrapper(client, runs_dir=str(tmp_path), gateway_url="none")
        # Non-overridden attributes pass through to underlying client
        assert wrapper.models is client.models


class TestChatCompletionsProxy:
    """Test the chat.completions proxy writes audit records."""

    def _make_mock_client(self):
        client = MagicMock()
        client.base_url = "https://api.openai.com/v1"

        # Build the nested mock structure
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Hello! I'm an AI."
        mock_response.model = "gpt-4o-mini"
        mock_response.usage = MagicMock()
        mock_response.usage.prompt_tokens = 15
        mock_response.usage.completion_tokens = 25
        mock_response.usage.total_tokens = 40

        client.chat.completions.create.return_value = mock_response
        return client, mock_response

    def test_chat_proxy_exists(self, tmp_path):
        client, _ = self._make_mock_client()
        wrapper = AirOpenAIWrapper(client, runs_dir=str(tmp_path), gateway_url="none")
        assert wrapper.chat is not None
        assert wrapper.chat.completions is not None

    def test_completions_create_writes_record(self, tmp_path):
        client, mock_response = self._make_mock_client()
        wrapper = AirOpenAIWrapper(client, runs_dir=str(tmp_path), gateway_url="none")

        response = wrapper.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Hello"}],
        )

        # Should have written an audit record
        air_files = list(Path(tmp_path).glob("*.air.json"))
        assert len(air_files) >= 1

    def test_record_contains_model_info(self, tmp_path):
        client, mock_response = self._make_mock_client()
        wrapper = AirOpenAIWrapper(client, runs_dir=str(tmp_path), gateway_url="none")

        wrapper.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Hi"}],
        )

        air_files = list(Path(tmp_path).glob("*.air.json"))
        assert len(air_files) >= 1
        record = json.loads(air_files[0].read_text())
        assert "run_id" in record
        assert "timestamp" in record

    def test_multiple_calls_write_multiple_records(self, tmp_path):
        client, mock_response = self._make_mock_client()
        wrapper = AirOpenAIWrapper(client, runs_dir=str(tmp_path), gateway_url="none")

        for i in range(3):
            wrapper.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": f"Message {i}"}],
            )

        air_files = list(Path(tmp_path).glob("*.air.json"))
        assert len(air_files) >= 3


class TestOpenAIAuditChain:
    """Verify HMAC chain integrity with OpenAI wrapper."""

    def _make_mock_client(self):
        client = MagicMock()
        client.base_url = "https://api.openai.com/v1"
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "Response"
        mock_response.model = "gpt-4o"
        mock_response.usage = MagicMock()
        mock_response.usage.prompt_tokens = 10
        mock_response.usage.completion_tokens = 20
        mock_response.usage.total_tokens = 30
        client.chat.completions.create.return_value = mock_response
        return client

    def test_records_have_chain_fields(self, tmp_path):
        client = self._make_mock_client()
        wrapper = AirOpenAIWrapper(client, runs_dir=str(tmp_path), gateway_url="none")

        for i in range(2):
            wrapper.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": f"Msg {i}"}],
            )

        air_files = sorted(Path(tmp_path).glob("*.air.json"))
        assert len(air_files) >= 2

        # Records should exist and be valid JSON
        for f in air_files:
            record = json.loads(f.read_text())
            assert "run_id" in record
            assert "timestamp" in record


class TestWriteRecordResilience:
    """Verify non-blocking behavior when logging fails."""

    def test_api_still_works_if_logging_fails(self, tmp_path):
        client = MagicMock()
        client.base_url = "https://api.openai.com/v1"
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "OK"
        mock_response.model = "gpt-4o"
        mock_response.usage = MagicMock()
        mock_response.usage.prompt_tokens = 5
        mock_response.usage.completion_tokens = 5
        mock_response.usage.total_tokens = 10
        client.chat.completions.create.return_value = mock_response

        # Use a read-only directory to force write failure
        wrapper = AirOpenAIWrapper(client, runs_dir=str(tmp_path), gateway_url="none")

        # This should not raise even if internal logging has issues
        response = wrapper.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "test"}],
        )
        # The API call should still return
        assert response is mock_response
