"""
Tests for AIR Blackbox main module (__init__.py).

Tests AirBlackbox and AirTrust classes including version, initialization,
client wrapping, framework detection, and trust layer attachment.
"""

from unittest.mock import MagicMock, Mock, patch

import pytest
from air_blackbox import AirBlackbox, AirTrust, __version__


class TestVersion:
    """Test version constant."""

    def test_version_exists(self):
        """Test that __version__ is defined."""
        assert __version__ is not None

    def test_version_is_string(self):
        """Test that __version__ is a string."""
        assert isinstance(__version__, str)

    def test_version_format(self):
        """Test that __version__ follows semantic versioning."""
        parts = __version__.split(".")
        assert len(parts) >= 2
        assert all(part.isdigit() for part in parts)


class TestAirBlackboxInit:
    """Test AirBlackbox initialization."""

    def test_init_with_defaults(self):
        """Test AirBlackbox initialization with default parameters."""
        air = AirBlackbox()
        assert air.gateway_url == "http://localhost:8080"
        assert air.config == {}

    def test_init_with_custom_gateway_url(self):
        """Test AirBlackbox initialization with custom gateway URL."""
        air = AirBlackbox(gateway_url="http://example.com:9000")
        assert air.gateway_url == "http://example.com:9000"

    def test_init_with_custom_config(self):
        """Test AirBlackbox initialization with custom config."""
        custom_config = {"timeout": 10, "retries": 3}
        air = AirBlackbox(config=custom_config)
        assert air.config == custom_config

    def test_init_with_both_custom_params(self):
        """Test AirBlackbox initialization with both custom parameters."""
        custom_config = {"timeout": 10}
        air = AirBlackbox(gateway_url="http://custom.com", config=custom_config)
        assert air.gateway_url == "http://custom.com"
        assert air.config == custom_config

    def test_init_with_none_config(self):
        """Test that None config defaults to empty dict."""
        air = AirBlackbox(config=None)
        assert air.config == {}


class TestAirBlackboxWrap:
    """Test AirBlackbox.wrap() method."""

    def test_wrap_client_with_base_url(self):
        """Test wrapping a client with base_url attribute."""
        mock_client = Mock()
        mock_client.base_url = "https://api.openai.com/v1"

        air = AirBlackbox(gateway_url="http://localhost:8080")
        result = air.wrap(mock_client)

        assert result is mock_client
        assert mock_client.base_url == "http://localhost:8080/v1"

    def test_wrap_client_without_base_url(self):
        """Test wrapping a client without base_url attribute."""
        mock_client = Mock(spec=[])  # No base_url attribute
        air = AirBlackbox()
        result = air.wrap(mock_client)

        assert result is mock_client

    def test_wrap_returns_same_client_object(self):
        """Test that wrap() returns the same client object."""
        mock_client = Mock()
        mock_client.base_url = "https://api.openai.com/v1"

        air = AirBlackbox()
        result = air.wrap(mock_client)

        assert result is mock_client

    def test_wrap_with_custom_gateway_url(self):
        """Test wrapping with custom gateway URL."""
        mock_client = Mock()
        mock_client.base_url = "https://api.openai.com/v1"

        air = AirBlackbox(gateway_url="http://custom.gateway.com:9000")
        air.wrap(mock_client)

        assert mock_client.base_url == "http://custom.gateway.com:9000/v1"

    def test_wrap_multiple_clients(self):
        """Test wrapping multiple different clients."""
        client1 = Mock()
        client1.base_url = "https://api.openai.com/v1"

        client2 = Mock()
        client2.base_url = "https://api.anthropic.com/v1"

        air = AirBlackbox(gateway_url="http://localhost:8080")
        air.wrap(client1)
        air.wrap(client2)

        assert client1.base_url == "http://localhost:8080/v1"
        assert client2.base_url == "http://localhost:8080/v1"


class TestAirTrustInit:
    """Test AirTrust initialization."""

    def test_init_with_defaults(self):
        """Test AirTrust initialization with default parameters."""
        trust = AirTrust()
        assert trust.gateway_url == "http://localhost:8080"
        assert trust._detected_framework is None

    def test_init_with_custom_gateway_url(self):
        """Test AirTrust initialization with custom gateway URL."""
        trust = AirTrust(gateway_url="http://example.com:9000")
        assert trust.gateway_url == "http://example.com:9000"

    def test_init_detected_framework_is_none(self):
        """Test that _detected_framework starts as None."""
        trust = AirTrust()
        assert trust._detected_framework is None


class TestDetectFramework:
    """Test AirTrust._detect_framework() method."""

    def test_detect_langchain_by_module(self):
        """Test detecting LangChain framework by module name."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "langchain.agents.something"

        trust = AirTrust()
        framework = trust._detect_framework(mock_agent)
        assert framework == "langchain"

    def test_detect_langgraph_by_module(self):
        """Test detecting LangGraph (LangChain variant) by module name."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "langgraph.graph.state_graph"

        trust = AirTrust()
        framework = trust._detect_framework(mock_agent)
        assert framework == "langchain"

    def test_detect_crewai_by_module(self):
        """Test detecting CrewAI framework by module name."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "crewai.crew.crew"

        trust = AirTrust()
        framework = trust._detect_framework(mock_agent)
        assert framework == "crewai"

    def test_detect_haystack_by_module(self):
        """Test detecting Haystack framework by module name."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "haystack.pipeline.pipeline"

        trust = AirTrust()
        framework = trust._detect_framework(mock_agent)
        assert framework == "haystack"

    def test_detect_openai_by_module(self):
        """Test detecting OpenAI framework by module name."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "openai.types.agent"

        trust = AirTrust()
        framework = trust._detect_framework(mock_agent)
        assert framework == "openai"

    def test_detect_autogen_by_module(self):
        """Test detecting AutoGen framework by module name."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "autogen.agentchat.agent"

        trust = AirTrust()
        framework = trust._detect_framework(mock_agent)
        assert framework == "autogen"

    def test_detect_adk_by_module(self):
        """Test detecting Google ADK framework by module name."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "google.adk.agent.something"

        trust = AirTrust()
        framework = trust._detect_framework(mock_agent)
        assert framework == "adk"

    def test_detect_claude_agent_by_module(self):
        """Test detecting Claude Agent SDK by module name."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "claude_agent_sdk.agent.core"

        trust = AirTrust()
        framework = trust._detect_framework(mock_agent)
        assert framework == "claude_agent"

    def test_detect_claude_agent_alternate_module(self):
        """Test detecting Claude Agent SDK by alternate module name."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "claude_agent.client"

        trust = AirTrust()
        framework = trust._detect_framework(mock_agent)
        assert framework == "claude_agent"

    def test_detect_haystack_by_class_name(self):
        """Test detecting Haystack by class name and 'run' method."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "my_custom_module"
        mock_agent.__class__.__name__ = "Pipeline"
        mock_agent.run = Mock()

        trust = AirTrust()
        framework = trust._detect_framework(mock_agent)
        assert framework == "haystack"

    def test_detect_crewai_by_class_name(self):
        """Test detecting CrewAI by class name and 'kickoff' method."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "my_custom_module"
        mock_agent.__class__.__name__ = "Crew"
        mock_agent.kickoff = Mock()

        trust = AirTrust()
        framework = trust._detect_framework(mock_agent)
        assert framework == "crewai"

    def test_detect_unknown_framework(self):
        """Test that unknown framework returns 'unknown'."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "unknown_framework.module"
        mock_agent.__class__.__name__ = "UnknownAgent"

        trust = AirTrust()
        framework = trust._detect_framework(mock_agent)
        assert framework == "unknown"

    def test_detect_framework_priority_module_over_classname(self):
        """Test that module-based detection takes priority over class name."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "langchain.agents.something"
        mock_agent.__class__.__name__ = "Crew"  # Would be CrewAI by class name
        mock_agent.kickoff = Mock()

        trust = AirTrust()
        framework = trust._detect_framework(mock_agent)
        assert framework == "langchain"


class TestAttachTrust:
    """Test AirTrust.attach() method."""

    def test_attach_to_langchain_agent(self):
        """Test attaching trust layer to LangChain agent."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "langchain.agents.something"

        with patch("air_blackbox.AirTrust._detect_framework", return_value="langchain"):
            with patch("air_blackbox.trust.langchain.attach_trust") as mock_attach:
                mock_attach.return_value = mock_agent

                trust = AirTrust(gateway_url="http://localhost:8080")
                result = trust.attach(mock_agent)

                assert trust._detected_framework == "langchain"
                mock_attach.assert_called_once_with(mock_agent, "http://localhost:8080")
                assert result is mock_agent

    def test_attach_to_crewai_agent(self):
        """Test attaching trust layer to CrewAI agent."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "crewai.crew.crew"

        with patch("air_blackbox.AirTrust._detect_framework", return_value="crewai"):
            with patch("air_blackbox.trust.crewai.attach_trust") as mock_attach:
                mock_attach.return_value = mock_agent

                trust = AirTrust()
                result = trust.attach(mock_agent)

                assert trust._detected_framework == "crewai"
                mock_attach.assert_called_once()

    def test_attach_to_haystack_agent(self):
        """Test attaching trust layer to Haystack agent."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "haystack.pipeline.pipeline"

        with patch("air_blackbox.AirTrust._detect_framework", return_value="haystack"):
            with patch("air_blackbox.trust.haystack.attach_trust") as mock_attach:
                mock_attach.return_value = mock_agent

                trust = AirTrust()
                result = trust.attach(mock_agent)

                assert trust._detected_framework == "haystack"

    def test_attach_to_openai_agent(self):
        """Test attaching trust layer to OpenAI agent."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "openai.types.agent"

        with patch("air_blackbox.AirTrust._detect_framework", return_value="openai"):
            with patch("air_blackbox.trust.openai_agents.attach_trust") as mock_attach:
                mock_attach.return_value = mock_agent

                trust = AirTrust()
                result = trust.attach(mock_agent)

                assert trust._detected_framework == "openai"

    def test_attach_to_autogen_agent(self):
        """Test attaching trust layer to AutoGen agent."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "autogen.agentchat.agent"

        with patch("air_blackbox.AirTrust._detect_framework", return_value="autogen"):
            with patch("air_blackbox.trust.autogen.attach_trust") as mock_attach:
                mock_attach.return_value = mock_agent

                trust = AirTrust()
                result = trust.attach(mock_agent)

                assert trust._detected_framework == "autogen"

    def test_attach_to_adk_agent(self):
        """Test attaching trust layer to ADK agent."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "google.adk.agent.something"

        with patch("air_blackbox.AirTrust._detect_framework", return_value="adk"):
            with patch("air_blackbox.trust.adk.attach_trust") as mock_attach:
                mock_attach.return_value = mock_agent

                trust = AirTrust()
                result = trust.attach(mock_agent)

                assert trust._detected_framework == "adk"

    def test_attach_to_claude_agent(self):
        """Test attaching trust layer to Claude Agent SDK."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "claude_agent_sdk.agent.core"

        with patch("air_blackbox.AirTrust._detect_framework", return_value="claude_agent"):
            with patch("air_blackbox.trust.claude_agent.attach_trust") as mock_attach:
                mock_attach.return_value = mock_agent

                trust = AirTrust()
                result = trust.attach(mock_agent)

                assert trust._detected_framework == "claude_agent"

    def test_attach_to_unknown_framework(self):
        """Test attaching to unknown framework returns agent unchanged."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "unknown_framework"

        with patch("air_blackbox.AirTrust._detect_framework", return_value="unknown"):
            trust = AirTrust()
            result = trust.attach(mock_agent)

            assert result is mock_agent
            assert trust._detected_framework == "unknown"

    def test_attach_handles_import_error(self):
        """Test that import errors are handled gracefully."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "langchain.agents.something"

        with patch("air_blackbox.AirTrust._detect_framework", return_value="langchain"):
            with patch("air_blackbox.trust.langchain.attach_trust", side_effect=ImportError("Module not found")):
                trust = AirTrust()
                result = trust.attach(mock_agent)

                assert result is mock_agent

    def test_attach_handles_generic_exception(self):
        """Test that generic exceptions are handled gracefully."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "langchain.agents.something"

        with patch("air_blackbox.AirTrust._detect_framework", return_value="langchain"):
            with patch("air_blackbox.trust.langchain.attach_trust", side_effect=Exception("Unexpected error")):
                trust = AirTrust()
                result = trust.attach(mock_agent)

                assert result is mock_agent

    def test_attach_preserves_detected_framework(self):
        """Test that detected framework is stored after attach."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "crewai.crew.crew"

        with patch("air_blackbox.AirTrust._detect_framework", return_value="crewai"):
            with patch("air_blackbox.trust.crewai.attach_trust") as mock_attach:
                mock_attach.return_value = mock_agent

                trust = AirTrust()
                assert trust._detected_framework is None

                trust.attach(mock_agent)
                assert trust._detected_framework == "crewai"

    def test_attach_with_custom_gateway_url(self):
        """Test that custom gateway URL is passed to attach functions."""
        mock_agent = Mock()
        mock_agent.__class__.__module__ = "langchain.agents.something"

        with patch("air_blackbox.AirTrust._detect_framework", return_value="langchain"):
            with patch("air_blackbox.trust.langchain.attach_trust") as mock_attach:
                mock_attach.return_value = mock_agent

                custom_url = "http://custom.gateway.com:9000"
                trust = AirTrust(gateway_url=custom_url)
                trust.attach(mock_agent)

                mock_attach.assert_called_once_with(mock_agent, custom_url)
