"""Tests for auto-detection engine."""

import pytest
from air_trust.detection import detect_installed, detect_object, FRAMEWORK_REGISTRY


class TestFrameworkRegistry:
    """Test the framework registry data."""

    def test_registry_not_empty(self):
        assert len(FRAMEWORK_REGISTRY) > 0

    def test_registry_has_major_frameworks(self):
        """All major frameworks should be in the registry."""
        expected = ["openai", "anthropic", "langchain_core", "crewai", "dspy"]
        package_names = {entry[0] for entry in FRAMEWORK_REGISTRY}
        for name in expected:
            assert name in package_names, f"{name} missing from registry"

    def test_registry_entries_have_correct_shape(self):
        """Each entry should be (package_name, framework_id, adapter_type)."""
        valid_types = {"proxy", "callback", "decorator", "otel", "mcp"}
        for entry in FRAMEWORK_REGISTRY:
            assert len(entry) == 3, f"Entry should be 3-tuple: {entry}"
            pkg, fid, atype = entry
            assert isinstance(fid, str)
            assert atype in valid_types, f"{pkg}: {atype} not in valid adapter types"


class TestDetectInstalled:
    """Test installed package detection."""

    def test_returns_list(self):
        result = detect_installed()
        assert isinstance(result, list)

    def test_entries_are_tuples(self):
        result = detect_installed()
        for item in result:
            assert isinstance(item, tuple)
            assert len(item) == 2


class TestDetectObject:
    """Test runtime object detection."""

    def test_none_returns_none(self):
        result = detect_object(None)
        assert result is None

    def test_unknown_object(self):
        """Random object should return None."""
        result = detect_object("just a string")
        assert result is None or result[0] == "unknown"

    def test_dict_returns_none(self):
        result = detect_object({"key": "value"})
        assert result is None or result[0] == "unknown"
