"""
Tests for AIBOM generator module.

Tests AIBOMEntry dataclass, AIBOMGenerator initialization,
component validation, addition, and report generation.
"""

from datetime import datetime
from unittest.mock import Mock, patch

import pytest
from air_blackbox.aibom.generator import AIBOMEntry, AIBOMGenerator


class TestAIBOMEntry:
    """Test AIBOMEntry dataclass."""

    def test_aibom_entry_creation(self):
        """Test creating an AIBOMEntry instance."""
        now = datetime.utcnow()
        entry = AIBOMEntry(
            component_name="Auth Handler",
            article=14,
            risk_level="high",
            documentation="https://docs.example.com/auth",
            timestamp=now,
        )

        assert entry.component_name == "Auth Handler"
        assert entry.article == 14
        assert entry.risk_level == "high"
        assert entry.documentation == "https://docs.example.com/auth"
        assert entry.timestamp == now

    def test_aibom_entry_with_all_articles(self):
        """Test AIBOMEntry with valid article numbers."""
        for article in [9, 10, 11, 12, 14, 15]:
            entry = AIBOMEntry(
                component_name=f"Component_Article_{article}",
                article=article,
                risk_level="low",
                documentation="doc",
                timestamp=datetime.utcnow(),
            )
            assert entry.article == article

    def test_aibom_entry_with_all_risk_levels(self):
        """Test AIBOMEntry with all valid risk levels."""
        for risk in ["critical", "high", "medium", "low"]:
            entry = AIBOMEntry(
                component_name=f"Component_{risk}",
                article=9,
                risk_level=risk,
                documentation="doc",
                timestamp=datetime.utcnow(),
            )
            assert entry.risk_level == risk


class TestAIBOMGeneratorInit:
    """Test AIBOMGenerator initialization."""

    def test_generator_init_creates_empty_entries(self):
        """Test that AIBOMGenerator initializes with empty entries list."""
        gen = AIBOMGenerator()
        assert gen.entries == []

    def test_generator_init_logs_initialization(self):
        """Test that initialization is logged."""
        with patch("air_blackbox.aibom.generator.logger") as mock_logger:
            gen = AIBOMGenerator()
            mock_logger.info.assert_called_once_with("aibom_generator_initialized")


class TestValidateComponentData:
    """Test validate_component_data() method."""

    def test_validate_valid_component(self):
        """Test validation of valid component data."""
        gen = AIBOMGenerator()
        result = gen.validate_component_data(
            component_name="Test Component",
            article=9,
            risk_level="high",
        )
        assert result is True

    def test_validate_empty_component_name(self):
        """Test validation fails with empty component name."""
        gen = AIBOMGenerator()
        with pytest.raises(ValueError, match="Component name must be a non-empty string"):
            gen.validate_component_data(
                component_name="",
                article=9,
                risk_level="high",
            )

    def test_validate_none_component_name(self):
        """Test validation fails with None component name."""
        gen = AIBOMGenerator()
        with pytest.raises(ValueError, match="Component name must be a non-empty string"):
            gen.validate_component_data(
                component_name=None,
                article=9,
                risk_level="high",
            )

    def test_validate_non_string_component_name(self):
        """Test validation fails with non-string component name."""
        gen = AIBOMGenerator()
        with pytest.raises(ValueError, match="Component name must be a non-empty string"):
            gen.validate_component_data(
                component_name=123,
                article=9,
                risk_level="high",
            )

    def test_validate_valid_articles(self):
        """Test validation succeeds for all valid articles."""
        gen = AIBOMGenerator()
        for article in [9, 10, 11, 12, 14, 15]:
            result = gen.validate_component_data(
                component_name="Component",
                article=article,
                risk_level="high",
            )
            assert result is True

    def test_validate_invalid_article_too_low(self):
        """Test validation fails for article number too low."""
        gen = AIBOMGenerator()
        with pytest.raises(ValueError, match="Invalid article number: 8"):
            gen.validate_component_data(
                component_name="Component",
                article=8,
                risk_level="high",
            )

    def test_validate_invalid_article_too_high(self):
        """Test validation fails for article number too high."""
        gen = AIBOMGenerator()
        with pytest.raises(ValueError, match="Invalid article number: 16"):
            gen.validate_component_data(
                component_name="Component",
                article=16,
                risk_level="high",
            )

    def test_validate_invalid_article_13(self):
        """Test validation fails for article 13 (not in EU AI Act compliance set)."""
        gen = AIBOMGenerator()
        with pytest.raises(ValueError, match="Invalid article number: 13"):
            gen.validate_component_data(
                component_name="Component",
                article=13,
                risk_level="high",
            )

    def test_validate_valid_risk_levels(self):
        """Test validation succeeds for all valid risk levels."""
        gen = AIBOMGenerator()
        for risk in ["critical", "high", "medium", "low"]:
            result = gen.validate_component_data(
                component_name="Component",
                article=9,
                risk_level=risk,
            )
            assert result is True

    def test_validate_invalid_risk_level_severe(self):
        """Test validation fails for invalid risk level."""
        gen = AIBOMGenerator()
        with pytest.raises(ValueError, match="Invalid risk level: severe"):
            gen.validate_component_data(
                component_name="Component",
                article=9,
                risk_level="severe",
            )

    def test_validate_invalid_risk_level_extreme(self):
        """Test validation fails for extreme risk level."""
        gen = AIBOMGenerator()
        with pytest.raises(ValueError, match="Invalid risk level: extreme"):
            gen.validate_component_data(
                component_name="Component",
                article=9,
                risk_level="extreme",
            )

    def test_validate_case_sensitive_risk_level(self):
        """Test that risk level validation is case sensitive."""
        gen = AIBOMGenerator()
        with pytest.raises(ValueError, match="Invalid risk level: HIGH"):
            gen.validate_component_data(
                component_name="Component",
                article=9,
                risk_level="HIGH",
            )

    def test_validate_multiple_errors_reports_first(self):
        """Test that validation reports first encountered error."""
        gen = AIBOMGenerator()
        with pytest.raises(ValueError, match="Component name must be a non-empty string"):
            gen.validate_component_data(
                component_name="",
                article=99,
                risk_level="invalid",
            )


class TestAddComponent:
    """Test add_component() method."""

    def test_add_component_success(self):
        """Test successfully adding a component."""
        gen = AIBOMGenerator()
        entry = gen.add_component(
            component_name="Auth Handler",
            article=14,
            risk_level="high",
            documentation="https://docs.example.com/auth",
        )

        assert isinstance(entry, AIBOMEntry)
        assert entry.component_name == "Auth Handler"
        assert entry.article == 14
        assert entry.risk_level == "high"
        assert len(gen.entries) == 1

    def test_add_component_multiple_components(self):
        """Test adding multiple components."""
        gen = AIBOMGenerator()

        gen.add_component("Component 1", 9, "low", "doc1")
        gen.add_component("Component 2", 10, "medium", "doc2")
        gen.add_component("Component 3", 11, "high", "doc3")

        assert len(gen.entries) == 3
        assert gen.entries[0].component_name == "Component 1"
        assert gen.entries[1].component_name == "Component 2"
        assert gen.entries[2].component_name == "Component 3"

    def test_add_component_sets_timestamp(self):
        """Test that timestamp is automatically set."""
        gen = AIBOMGenerator()
        before = datetime.utcnow()
        entry = gen.add_component("Component", 9, "low", "doc")
        after = datetime.utcnow()

        assert before <= entry.timestamp <= after

    def test_add_component_validation_failure(self):
        """Test that invalid component raises ValueError."""
        gen = AIBOMGenerator()
        with pytest.raises(ValueError, match="Component name must be a non-empty string"):
            gen.add_component(
                component_name="",
                article=9,
                risk_level="high",
                documentation="doc",
            )

    def test_add_component_logs_success(self):
        """Test that successful addition is logged."""
        gen = AIBOMGenerator()
        with patch("air_blackbox.aibom.generator.logger") as mock_logger:
            gen.add_component("Component", 9, "low", "doc")

            # Check that info was called with component addition
            calls = [call for call in mock_logger.info.call_args_list if "aibom_component_added" in str(call)]
            assert len(calls) > 0

    def test_add_component_logs_validation_error(self):
        """Test that validation errors are logged."""
        gen = AIBOMGenerator()
        with patch("air_blackbox.aibom.generator.logger") as mock_logger:
            with pytest.raises(ValueError):
                gen.add_component("", 9, "high", "doc")

            # Check that error was logged
            error_calls = [call for call in mock_logger.error.call_args_list if "aibom_validation_error" in str(call)]
            assert len(error_calls) > 0

    def test_add_component_preserves_order(self):
        """Test that components are added in order."""
        gen = AIBOMGenerator()
        names = ["First", "Second", "Third", "Fourth"]

        for name in names:
            gen.add_component(name, 9, "low", "doc")

        assert [e.component_name for e in gen.entries] == names


class TestGenerateReport:
    """Test generate_report() method."""

    def test_generate_report_empty(self):
        """Test generating report with no components."""
        gen = AIBOMGenerator()
        report = gen.generate_report()

        assert report["components_count"] == 0
        assert report["entries"] == []
        assert "generated_at" in report

    def test_generate_report_single_component(self):
        """Test generating report with single component."""
        gen = AIBOMGenerator()
        gen.add_component("Auth Handler", 14, "high", "https://docs.example.com")

        report = gen.generate_report()

        assert report["components_count"] == 1
        assert len(report["entries"]) == 1
        assert report["entries"][0]["component_name"] == "Auth Handler"
        assert report["entries"][0]["article"] == 14
        assert report["entries"][0]["risk_level"] == "high"

    def test_generate_report_multiple_components(self):
        """Test generating report with multiple components."""
        gen = AIBOMGenerator()
        gen.add_component("Component 1", 9, "critical", "doc1")
        gen.add_component("Component 2", 10, "high", "doc2")
        gen.add_component("Component 3", 11, "medium", "doc3")
        gen.add_component("Component 4", 12, "low", "doc4")

        report = gen.generate_report()

        assert report["components_count"] == 4
        assert len(report["entries"]) == 4

    def test_generate_report_includes_timestamps(self):
        """Test that report includes added_at timestamp for each entry."""
        gen = AIBOMGenerator()
        gen.add_component("Component", 9, "low", "doc")

        report = gen.generate_report()

        assert "added_at" in report["entries"][0]
        assert isinstance(report["entries"][0]["added_at"], str)

    def test_generate_report_includes_generated_at(self):
        """Test that report includes generated_at timestamp."""
        gen = AIBOMGenerator()
        before = datetime.utcnow()
        report = gen.generate_report()
        after = datetime.utcnow()

        assert "generated_at" in report
        # Parse ISO format timestamp
        generated_time = datetime.fromisoformat(report["generated_at"])
        assert before <= generated_time <= after

    def test_generate_report_risk_distribution_with_components(self):
        """Test risk distribution when components exist."""
        gen = AIBOMGenerator()
        gen.add_component("A", 9, "critical", "doc")
        gen.add_component("B", 10, "high", "doc")
        report = gen.generate_report()

        assert "risk_distribution" in report
        assert report["risk_distribution"]["critical"] == 1
        assert report["risk_distribution"]["high"] == 1

    def test_generate_report_risk_distribution_single_critical(self):
        """Test risk distribution with single critical component."""
        gen = AIBOMGenerator()
        gen.add_component("Critical Component", 9, "critical", "doc")

        report = gen.generate_report()

        assert report["risk_distribution"]["critical"] == 1
        assert report["risk_distribution"]["high"] == 0
        assert report["risk_distribution"]["medium"] == 0
        assert report["risk_distribution"]["low"] == 0

    def test_generate_report_risk_distribution_mixed(self):
        """Test risk distribution with mixed risk levels."""
        gen = AIBOMGenerator()
        gen.add_component("Component 1", 9, "critical", "doc")
        gen.add_component("Component 2", 10, "critical", "doc")
        gen.add_component("Component 3", 11, "high", "doc")
        gen.add_component("Component 4", 12, "high", "doc")
        gen.add_component("Component 5", 14, "medium", "doc")
        gen.add_component("Component 6", 15, "low", "doc")

        report = gen.generate_report()

        assert report["risk_distribution"]["critical"] == 2
        assert report["risk_distribution"]["high"] == 2
        assert report["risk_distribution"]["medium"] == 1
        assert report["risk_distribution"]["low"] == 1

    def test_generate_report_logs_empty_warning(self):
        """Test that empty report generation logs a warning."""
        gen = AIBOMGenerator()
        with patch("air_blackbox.aibom.generator.logger") as mock_logger:
            gen.generate_report()
            mock_logger.warning.assert_called_once_with("aibom_empty_report")

    def test_generate_report_logs_success(self):
        """Test that successful report generation is logged."""
        gen = AIBOMGenerator()
        gen.add_component("Component", 9, "low", "doc")

        with patch("air_blackbox.aibom.generator.logger") as mock_logger:
            report = gen.generate_report()

            # Check that info was called with report generated
            info_calls = [call for call in mock_logger.info.call_args_list if "aibom_report_generated" in str(call)]
            assert len(info_calls) > 0

    def test_generate_report_does_not_modify_entries(self):
        """Test that report generation doesn't modify original entries."""
        gen = AIBOMGenerator()
        gen.add_component("Component", 9, "low", "doc")
        original_count = len(gen.entries)

        report = gen.generate_report()

        assert len(gen.entries) == original_count

    def test_generate_report_exception_handling(self):
        """Test that exceptions during report generation are logged."""
        gen = AIBOMGenerator()
        gen.add_component("Component", 9, "low", "doc")

        # Mock _calculate_risk_distribution to raise exception
        with patch.object(gen, "_calculate_risk_distribution", side_effect=Exception("Test error")):
            with patch("air_blackbox.aibom.generator.logger") as mock_logger:
                with pytest.raises(Exception):
                    gen.generate_report()

                # Check that error was logged
                error_calls = [call for call in mock_logger.error.call_args_list if "aibom_report_generation_error" in str(call)]
                assert len(error_calls) > 0


class TestCalculateRiskDistribution:
    """Test _calculate_risk_distribution() method (indirect testing)."""

    def test_calculate_risk_distribution_via_report(self):
        """Test risk distribution calculation via generate_report."""
        gen = AIBOMGenerator()

        # Add components with specific risk levels
        gen.add_component("Critical 1", 9, "critical", "doc")
        gen.add_component("Critical 2", 10, "critical", "doc")
        gen.add_component("High 1", 11, "high", "doc")
        gen.add_component("Medium 1", 12, "medium", "doc")
        gen.add_component("Low 1", 14, "low", "doc")
        gen.add_component("Low 2", 15, "low", "doc")

        report = gen.generate_report()
        dist = report["risk_distribution"]

        assert dist["critical"] == 2
        assert dist["high"] == 1
        assert dist["medium"] == 1
        assert dist["low"] == 2

    def test_calculate_risk_distribution_single_level(self):
        """Test risk distribution with single risk level."""
        gen = AIBOMGenerator()
        gen.add_component("A", 9, "high", "doc")
        gen.add_component("B", 10, "high", "doc")
        report = gen.generate_report()
        dist = report["risk_distribution"]

        assert dist["high"] == 2
        assert dist.get("critical", 0) == 0
        assert dist["low"] == 0

    def test_calculate_risk_distribution_all_same_level(self):
        """Test risk distribution when all components have same risk level."""
        gen = AIBOMGenerator()
        for i in range(5):
            gen.add_component(f"Component {i}", 9, "high", "doc")

        report = gen.generate_report()
        dist = report["risk_distribution"]

        assert dist["critical"] == 0
        assert dist["high"] == 5
        assert dist["medium"] == 0
        assert dist["low"] == 0


class TestAIBOMGeneratorIntegration:
    """Integration tests for AIBOMGenerator."""

    def test_full_workflow(self):
        """Test complete workflow from creation to report generation."""
        gen = AIBOMGenerator()

        # Add various components
        gen.add_component("Risk Management", 9, "critical", "https://docs.example.com/risk")
        gen.add_component("Data Governance", 10, "high", "https://docs.example.com/data")
        gen.add_component("Documentation", 11, "medium", "https://docs.example.com/docs")
        gen.add_component("Audit Trail", 12, "high", "https://docs.example.com/audit")
        gen.add_component("Human Oversight", 14, "medium", "https://docs.example.com/oversight")
        gen.add_component("Security", 15, "high", "https://docs.example.com/security")

        # Generate report
        report = gen.generate_report()

        # Verify report structure
        assert report["components_count"] == 6
        assert len(report["entries"]) == 6
        assert report["risk_distribution"]["critical"] == 1
        assert report["risk_distribution"]["high"] == 3
        assert report["risk_distribution"]["medium"] == 2
        assert report["risk_distribution"]["low"] == 0

    def test_multiple_reports_same_generator(self):
        """Test generating multiple reports from same generator."""
        gen = AIBOMGenerator()
        gen.add_component("Component 1", 9, "low", "doc")

        report1 = gen.generate_report()
        assert report1["components_count"] == 1

        gen.add_component("Component 2", 10, "high", "doc")
        report2 = gen.generate_report()
        assert report2["components_count"] == 2

    def test_generator_with_all_articles(self):
        """Test adding components for all valid articles."""
        gen = AIBOMGenerator()

        for article in [9, 10, 11, 12, 14, 15]:
            gen.add_component(f"Component Article {article}", article, "low", "doc")

        report = gen.generate_report()
        assert report["components_count"] == 6

        # Verify all articles are in the report
        articles = [e["article"] for e in report["entries"]]
        assert sorted(articles) == [9, 10, 11, 12, 14, 15]
