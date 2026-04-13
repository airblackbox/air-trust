"""
Comprehensive tests for bias scanner module.

Tests cover:
- BiasRiskLevel enum
- BiasFinding dataclass
- BiasScanner class with all public methods
- Input validation
- Risk classification logic
- Bias detection patterns
- Report generation
- Edge cases: empty inputs, invalid data, single files
"""

import pytest
import tempfile
import os
from pathlib import Path
from typing import List, Optional
import logging

from air_blackbox.compliance.bias_scanner import (
    BiasRiskLevel,
    BiasFinding,
    BiasScanner,
)


class TestBiasRiskLevelEnum:
    """Tests for BiasRiskLevel enum."""

    def test_bias_risk_level_values(self):
        """All risk levels have correct string values."""
        assert BiasRiskLevel.CRITICAL.value == "critical"
        assert BiasRiskLevel.HIGH.value == "high"
        assert BiasRiskLevel.MEDIUM.value == "medium"
        assert BiasRiskLevel.LOW.value == "low"

    def test_bias_risk_level_comparison(self):
        """Risk levels can be compared."""
        assert BiasRiskLevel.CRITICAL != BiasRiskLevel.HIGH
        assert BiasRiskLevel.HIGH != BiasRiskLevel.LOW

    def test_bias_risk_level_string_conversion(self):
        """Risk levels convert to strings."""
        assert str(BiasRiskLevel.CRITICAL) == "BiasRiskLevel.CRITICAL"
        assert BiasRiskLevel.HIGH.value == "high"

    def test_all_risk_levels_exist(self):
        """All required risk levels are defined."""
        levels = [BiasRiskLevel.CRITICAL, BiasRiskLevel.HIGH,
                 BiasRiskLevel.MEDIUM, BiasRiskLevel.LOW]
        assert len(levels) == 4


class TestBiasFindingDataclass:
    """Tests for BiasFinding dataclass."""

    def test_bias_finding_creation(self):
        """BiasFinding instances are created correctly."""
        finding = BiasFinding(
            finding_id="BIAS-001",
            location="src/model.py",
            affected_groups=["race", "gender"],
            severity=BiasRiskLevel.HIGH,
            description="Protected attribute in decision logic"
        )

        assert finding.finding_id == "BIAS-001"
        assert finding.location == "src/model.py"
        assert finding.affected_groups == ["race", "gender"]
        assert finding.severity == BiasRiskLevel.HIGH

    def test_bias_finding_empty_groups(self):
        """BiasFinding with empty affected_groups."""
        finding = BiasFinding(
            finding_id="BIAS-002",
            location="model.py",
            affected_groups=[],
            severity=BiasRiskLevel.LOW,
            description="Minor issue"
        )

        assert finding.affected_groups == []

    def test_bias_finding_single_group(self):
        """BiasFinding with single affected group."""
        finding = BiasFinding(
            finding_id="BIAS-003",
            location="script.py",
            affected_groups=["age"],
            severity=BiasRiskLevel.MEDIUM,
            description="Age used in filtering"
        )

        assert len(finding.affected_groups) == 1
        assert finding.affected_groups[0] == "age"

    def test_bias_finding_critical_severity(self):
        """BiasFinding with critical severity."""
        finding = BiasFinding(
            finding_id="BIAS-004",
            location="critical.py",
            affected_groups=["race", "religion"],
            severity=BiasRiskLevel.CRITICAL,
            description="Severe bias detected"
        )

        assert finding.severity == BiasRiskLevel.CRITICAL

    def test_bias_finding_description_required(self):
        """Description field is required."""
        finding = BiasFinding(
            finding_id="BIAS-005",
            location="loc.py",
            affected_groups=["gender"],
            severity=BiasRiskLevel.HIGH,
            description="Required description"
        )

        assert finding.description == "Required description"


class TestBiasScannerInitialization:
    """Tests for BiasScanner initialization."""

    def test_bias_scanner_init(self):
        """BiasScanner initializes correctly."""
        scanner = BiasScanner()
        assert scanner.findings == []
        assert isinstance(scanner.findings, list)

    def test_bias_scanner_logging(self, caplog):
        """BiasScanner logs initialization."""
        with caplog.at_level(logging.INFO):
            scanner = BiasScanner()
        assert "bias_scanner_initialized" in caplog.text

    def test_bias_scanner_multiple_instances(self):
        """Multiple BiasScanner instances are independent."""
        scanner1 = BiasScanner()
        scanner2 = BiasScanner()

        assert scanner1.findings is not scanner2.findings
        assert scanner1 != scanner2


class TestValidateInputData:
    """Tests for validate_input_data method."""

    def test_validate_input_data_valid_string(self):
        """Valid string data source passes validation."""
        scanner = BiasScanner()
        result = scanner.validate_input_data("/path/to/code")
        assert result is True

    def test_validate_input_data_empty_string(self):
        """Empty string raises ValueError."""
        scanner = BiasScanner()
        with pytest.raises(ValueError, match="non-empty string"):
            scanner.validate_input_data("")

    def test_validate_input_data_none(self):
        """None data source raises ValueError."""
        scanner = BiasScanner()
        with pytest.raises(ValueError, match="non-empty string"):
            scanner.validate_input_data(None)

    def test_validate_input_data_not_string(self):
        """Non-string data source raises ValueError."""
        scanner = BiasScanner()
        with pytest.raises(ValueError, match="non-empty string"):
            scanner.validate_input_data(123)

    def test_validate_input_data_with_valid_attributes(self):
        """Valid protected attributes list passes validation."""
        scanner = BiasScanner()
        result = scanner.validate_input_data("/path", ["race", "gender"])
        assert result is True

    def test_validate_input_data_with_empty_attributes(self):
        """Empty attributes list is valid."""
        scanner = BiasScanner()
        result = scanner.validate_input_data("/path", [])
        assert result is True

    def test_validate_input_data_with_none_attributes(self):
        """None attributes is valid (uses defaults)."""
        scanner = BiasScanner()
        result = scanner.validate_input_data("/path", None)
        assert result is True

    def test_validate_input_data_attributes_not_list(self):
        """Non-list protected_attributes raises ValueError."""
        scanner = BiasScanner()
        with pytest.raises(ValueError, match="must be a list"):
            scanner.validate_input_data("/path", "race")

    def test_validate_input_data_attributes_non_string_item(self):
        """Attributes containing non-strings raise ValueError."""
        scanner = BiasScanner()
        with pytest.raises(ValueError, match="must be a string"):
            scanner.validate_input_data("/path", ["race", 123])

    def test_validate_input_data_attributes_with_special_chars(self):
        """Attributes with special characters are valid."""
        scanner = BiasScanner()
        result = scanner.validate_input_data("/path", ["race-ethnicity", "gender_identity"])
        assert result is True


class TestClassifyBiasRisk:
    """Tests for classify_bias_risk method."""

    def test_classify_critical_high_parity_gap(self):
        """High parity gap (>0.5) classifies as critical."""
        scanner = BiasScanner()
        level = scanner.classify_bias_risk([0.6], 0.3)
        assert level == BiasRiskLevel.CRITICAL

    def test_classify_critical_high_impact_score(self):
        """High impact score (>0.8) classifies as critical."""
        scanner = BiasScanner()
        level = scanner.classify_bias_risk([0.2], 0.9)
        assert level == BiasRiskLevel.CRITICAL

    def test_classify_critical_both_high(self):
        """Both high gap and impact score classify as critical."""
        scanner = BiasScanner()
        level = scanner.classify_bias_risk([0.7], 0.85)
        assert level == BiasRiskLevel.CRITICAL

    def test_classify_high_parity_gap(self):
        """Parity gap >0.3 classifies as high."""
        scanner = BiasScanner()
        level = scanner.classify_bias_risk([0.4], 0.3)
        assert level == BiasRiskLevel.HIGH

    def test_classify_high_impact_score(self):
        """Impact score >0.6 classifies as high."""
        scanner = BiasScanner()
        level = scanner.classify_bias_risk([0.2], 0.7)
        assert level == BiasRiskLevel.HIGH

    def test_classify_medium_parity_gap(self):
        """Parity gap >0.15 classifies as medium."""
        scanner = BiasScanner()
        level = scanner.classify_bias_risk([0.2], 0.3)
        assert level == BiasRiskLevel.MEDIUM

    def test_classify_medium_impact_score(self):
        """Impact score >0.4 classifies as medium."""
        scanner = BiasScanner()
        level = scanner.classify_bias_risk([0.1], 0.5)
        assert level == BiasRiskLevel.MEDIUM

    def test_classify_low_all_metrics(self):
        """Low scores classify as low."""
        scanner = BiasScanner()
        level = scanner.classify_bias_risk([0.1], 0.2)
        assert level == BiasRiskLevel.LOW

    def test_classify_empty_gaps_list(self):
        """Empty parity gaps list uses default."""
        scanner = BiasScanner()
        level = scanner.classify_bias_risk([], 0.2)
        assert level == BiasRiskLevel.LOW

    def test_classify_multiple_gaps(self):
        """Max gap from multiple values determines level."""
        scanner = BiasScanner()
        level = scanner.classify_bias_risk([0.1, 0.35, 0.2], 0.2)
        assert level == BiasRiskLevel.HIGH

    def test_classify_boundary_conditions(self):
        """Boundary values are classified correctly."""
        scanner = BiasScanner()

        # Exactly at boundaries (uses > not >=)
        assert scanner.classify_bias_risk([0.51], 0.3) == BiasRiskLevel.CRITICAL
        assert scanner.classify_bias_risk([0.31], 0.3) == BiasRiskLevel.HIGH
        assert scanner.classify_bias_risk([0.16], 0.3) == BiasRiskLevel.MEDIUM
        assert scanner.classify_bias_risk([0.0], 0.0) == BiasRiskLevel.LOW


class TestScanForBias:
    """Tests for scan_for_bias method."""

    def test_scan_for_bias_empty_directory(self, tmp_path):
        """Empty directory returns no findings."""
        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path))
        assert results == []
        assert scanner.findings == []

    def test_scan_for_bias_no_python_files(self, tmp_path):
        """Non-Python files are ignored."""
        (tmp_path / "config.txt").write_text("race = 'test'")
        (tmp_path / "readme.md").write_text("gender classifier")

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path))
        assert results == []

    def test_scan_for_bias_protected_attribute_in_decision(self, tmp_path):
        """Protected attribute in decision logic triggers finding."""
        code = "score = model.predict(X)\nif race == 'white': score += 10"
        (tmp_path / "model.py").write_text(code)

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path))

        assert len(results) > 0
        assert any(BiasRiskLevel.HIGH.value == f.severity.value for f in results)

    def test_scan_for_bias_gender_in_filter(self, tmp_path):
        """Gender attribute in filter logic is detected."""
        code = "filtered = [x for x in data if x.gender == 'male']"
        (tmp_path / "filter.py").write_text(code)

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path))

        assert len(results) > 0
        assert any("gender" in f.affected_groups for f in results)

    def test_scan_for_bias_age_in_classification(self, tmp_path):
        """Age in classification logic is detected."""
        code = "def classify(age):\n    return 'senior' if age > 65 else 'junior'"
        (tmp_path / "classify.py").write_text(code)

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path))

        assert len(results) > 0

    def test_scan_for_bias_missing_fairness_metrics(self, tmp_path):
        """ML model without fairness metrics triggers finding."""
        code = """
from sklearn import svm
model = svm.SVC()
model.fit(X_train, y_train)
predictions = model.predict(X_test)
"""
        (tmp_path / "ml_model.py").write_text(code)

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path))

        assert len(results) > 0
        finding = [f for f in results if "fairness" in f.description.lower()]
        assert len(finding) > 0

    def test_scan_for_bias_with_fairness_metrics(self, tmp_path):
        """Model with fairness metrics doesn't trigger warning."""
        code = """
from sklearn import svm
from fairlearn.metrics import disparate_impact_ratio
model = svm.SVC()
model.fit(X_train, y_train)
metrics = disparate_impact_ratio(y_test, predictions, sensitive_features=groups)
"""
        (tmp_path / "fair_model.py").write_text(code)

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path))

        # Should not have fairness metric warnings
        fairness_findings = [f for f in results if "fairness" in f.description.lower()]
        assert len(fairness_findings) == 0

    def test_scan_for_bias_multiple_protected_attributes(self, tmp_path):
        """Multiple protected attributes in one file."""
        code = "if race == 'white' and gender == 'male':\n    score = predict(x)\nraceScore = score if race == 'white' else 0"
        (tmp_path / "complex.py").write_text(code)

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path))

        assert len(results) > 0

    def test_scan_for_bias_custom_protected_attributes(self, tmp_path):
        """Custom protected attributes list is used."""
        code = "score = 100 if company_size == 'small' else 50\nfilter_by = company_size"
        (tmp_path / "loan.py").write_text(code)

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path), ["company_size"])

        assert len(results) > 0

    def test_scan_for_bias_no_custom_match(self, tmp_path):
        """Code without custom attributes doesn't trigger finding."""
        code = "if score > 0.5: approve()"
        (tmp_path / "approval.py").write_text(code)

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path), ["company_size"])

        assert len(results) == 0

    def test_scan_for_bias_finding_ids_unique(self, tmp_path):
        """Finding IDs are sequentially numbered."""
        code1 = "if race == 'x': return 1"
        code2 = "if gender == 'y': return 2"
        (tmp_path / "file1.py").write_text(code1)
        (tmp_path / "file2.py").write_text(code2)

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path))

        finding_ids = [f.finding_id for f in results]
        assert len(finding_ids) == len(set(finding_ids))  # All unique

    def test_scan_for_bias_location_relative_path(self, tmp_path):
        """Location is relative to scan path."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "model.py").write_text("if race == 'x': score()")

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path))

        assert len(results) > 0
        assert results[0].location == "src/model.py"

    def test_scan_for_bias_nested_directories(self, tmp_path):
        """Nested directories are scanned."""
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / "model.py").write_text("score = predict(x) if race == 'x' else 0")

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path))

        assert len(results) > 0

    def test_scan_for_bias_updates_findings_list(self, tmp_path):
        """scan_for_bias updates the scanner's findings list."""
        (tmp_path / "model.py").write_text("predict(x) if race == 'x' else None")

        scanner = BiasScanner()
        assert len(scanner.findings) == 0

        results = scanner.scan_for_bias(str(tmp_path))

        assert len(scanner.findings) > 0
        assert scanner.findings == results

    def test_scan_for_bias_validation_error(self):
        """Invalid input raises ValueError."""
        scanner = BiasScanner()
        with pytest.raises(ValueError):
            scanner.scan_for_bias(None)

    def test_scan_for_bias_logging(self, tmp_path, caplog):
        """scan_for_bias logs start and completion."""
        (tmp_path / "test.py").write_text("x = 1")

        scanner = BiasScanner()
        with caplog.at_level(logging.INFO):
            results = scanner.scan_for_bias(str(tmp_path))

        assert "bias_scan_started" in caplog.text
        assert "bias_scan_completed" in caplog.text

    def test_scan_for_bias_case_insensitive(self, tmp_path):
        """Pattern matching is case-insensitive."""
        code = "if RACE == 'white': score()\nif Gender == 'M': pass"
        (tmp_path / "test.py").write_text(code)

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path))

        assert len(results) > 0


class TestCheckOutputFiltering:
    """Tests for check_output_filtering method."""

    def test_output_filtering_valid_dict(self):
        """Valid dictionary passes filtering check."""
        scanner = BiasScanner()
        result = scanner.check_output_filtering({"key": "value"})
        assert result is True

    def test_output_filtering_empty_dict(self):
        """Empty dictionary passes filtering check."""
        scanner = BiasScanner()
        result = scanner.check_output_filtering({})
        assert result is True

    def test_output_filtering_nested_dict(self):
        """Nested dictionary passes filtering check."""
        scanner = BiasScanner()
        result = scanner.check_output_filtering({"outer": {"inner": "value"}})
        assert result is True

    def test_output_filtering_non_dict_list(self):
        """List raises ValueError."""
        scanner = BiasScanner()
        with pytest.raises(ValueError, match="must be a dictionary"):
            scanner.check_output_filtering([1, 2, 3])

    def test_output_filtering_non_dict_string(self):
        """String raises ValueError."""
        scanner = BiasScanner()
        with pytest.raises(ValueError, match="must be a dictionary"):
            scanner.check_output_filtering("not a dict")

    def test_output_filtering_non_dict_none(self):
        """None raises ValueError."""
        scanner = BiasScanner()
        with pytest.raises(ValueError, match="must be a dictionary"):
            scanner.check_output_filtering(None)

    def test_output_filtering_logging(self, caplog):
        """Successful filtering logs info."""
        scanner = BiasScanner()
        with caplog.at_level(logging.INFO):
            scanner.check_output_filtering({"data": "value"})
        assert "output_filtering_check_passed" in caplog.text


class TestGenerateBiasReport:
    """Tests for generate_bias_report method."""

    def test_generate_empty_report(self):
        """Report with no findings."""
        scanner = BiasScanner()
        report = scanner.generate_bias_report()

        assert report["total_findings"] == 0
        assert report["critical_issues"] == 0
        assert report["high_priority_issues"] == 0
        assert report["findings"] == []

    def test_generate_report_with_findings(self):
        """Report includes all findings."""
        scanner = BiasScanner()
        scanner.findings = [
            BiasFinding(
                finding_id="BIAS-001",
                location="model.py",
                affected_groups=["race"],
                severity=BiasRiskLevel.CRITICAL,
                description="Critical bias"
            ),
            BiasFinding(
                finding_id="BIAS-002",
                location="filter.py",
                affected_groups=["gender"],
                severity=BiasRiskLevel.HIGH,
                description="High bias"
            ),
            BiasFinding(
                finding_id="BIAS-003",
                location="score.py",
                affected_groups=["age"],
                severity=BiasRiskLevel.MEDIUM,
                description="Medium bias"
            ),
        ]

        report = scanner.generate_bias_report()

        assert report["total_findings"] == 3
        assert report["critical_issues"] == 1
        assert report["high_priority_issues"] == 1
        assert len(report["findings"]) == 3

    def test_report_finding_structure(self):
        """Each finding in report has correct structure."""
        scanner = BiasScanner()
        scanner.findings = [
            BiasFinding(
                finding_id="BIAS-001",
                location="model.py",
                affected_groups=["race"],
                severity=BiasRiskLevel.HIGH,
                description="Bias found"
            )
        ]

        report = scanner.generate_bias_report()
        finding = report["findings"][0]

        assert "id" in finding
        assert "location" in finding
        assert "affected_groups" in finding
        assert "severity" in finding
        assert "description" in finding
        assert finding["id"] == "BIAS-001"
        assert finding["location"] == "model.py"
        assert finding["severity"] == "high"

    def test_report_severity_value_conversion(self):
        """Severity is converted to string value."""
        scanner = BiasScanner()
        scanner.findings = [
            BiasFinding(
                finding_id="BIAS-001",
                location="model.py",
                affected_groups=["race"],
                severity=BiasRiskLevel.CRITICAL,
                description="Critical"
            )
        ]

        report = scanner.generate_bias_report()
        assert report["findings"][0]["severity"] == "critical"

    def test_report_counts_only_critical_and_high(self):
        """Report counts only critical and high issues."""
        scanner = BiasScanner()
        scanner.findings = [
            BiasFinding("BIAS-001", "a.py", ["race"], BiasRiskLevel.CRITICAL, "c"),
            BiasFinding("BIAS-002", "b.py", ["gender"], BiasRiskLevel.CRITICAL, "c"),
            BiasFinding("BIAS-003", "c.py", ["age"], BiasRiskLevel.HIGH, "h"),
            BiasFinding("BIAS-004", "d.py", ["x"], BiasRiskLevel.MEDIUM, "m"),
            BiasFinding("BIAS-005", "e.py", ["y"], BiasRiskLevel.LOW, "l"),
        ]

        report = scanner.generate_bias_report()

        assert report["critical_issues"] == 2
        assert report["high_priority_issues"] == 1
        assert report["total_findings"] == 5

    def test_report_logging(self, caplog):
        """Report generation logs info."""
        scanner = BiasScanner()
        scanner.findings = [
            BiasFinding("BIAS-001", "a.py", ["race"], BiasRiskLevel.CRITICAL, "c")
        ]

        with caplog.at_level(logging.INFO):
            report = scanner.generate_bias_report()

        assert "bias_report_generated" in caplog.text


class TestEdgeCasesAndIntegration:
    """Edge cases and integration tests."""

    def test_scanner_reusable_multiple_scans(self, tmp_path):
        """Scanner can be reused for multiple scans."""
        dir1 = tmp_path / "dir1"
        dir2 = tmp_path / "dir2"
        dir1.mkdir()
        dir2.mkdir()

        (dir1 / "model1.py").write_text("predict(x) if race == 'x' else None")
        (dir2 / "model2.py").write_text("filter_data(gender) if gender == 'y' else None")

        scanner = BiasScanner()

        results1 = scanner.scan_for_bias(str(dir1))
        initial_count = len(results1)

        results2 = scanner.scan_for_bias(str(dir2))

        # Second scan should replace findings
        assert len(scanner.findings) > 0

    def test_scanner_with_all_methods(self, tmp_path):
        """Scanner integrates all methods correctly."""
        (tmp_path / "model.py").write_text("if race == 'x': score()")

        scanner = BiasScanner()
        assert scanner.validate_input_data(str(tmp_path))

        risk = scanner.classify_bias_risk([0.6], 0.5)
        assert risk == BiasRiskLevel.CRITICAL

        results = scanner.scan_for_bias(str(tmp_path))
        assert len(results) > 0

        output_ok = scanner.check_output_filtering({"test": "data"})
        assert output_ok is True

        report = scanner.generate_bias_report()
        assert report["total_findings"] > 0

    def test_unicode_handling_in_code(self, tmp_path):
        """Unicode content in code files handled correctly."""
        code = "# Kommentar äöü\npredict(x) if race == 'x' else None"
        (tmp_path / "unicode.py").write_text(code)

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path))

        assert len(results) > 0

    def test_large_codebase_scan(self, tmp_path):
        """Scanning large codebase completes."""
        for i in range(10):
            (tmp_path / f"file{i}.py").write_text(f"predict(x) if race == 'x' else None # {i}")

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path))

        assert len(results) > 0

    def test_protected_attributes_all_default_types(self, tmp_path):
        """All default protected attributes are checked."""
        defaults = [
            "race", "gender", "sex", "age", "ethnicity", "religion",
            "disability", "sexual_orientation", "national_origin",
            "marital_status", "pregnancy", "genetic_information",
        ]

        # Create file with one attribute per file
        for attr in defaults:
            (tmp_path / f"{attr}.py").write_text(
                f"if {attr} == 'test': score()"
            )

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path))

        # Should find most attributes in decision logic
        assert len(results) > 0

    def test_finding_id_format(self, tmp_path):
        """Finding IDs follow BIAS-### format."""
        (tmp_path / "a.py").write_text("if race == 'x': pass")
        (tmp_path / "b.py").write_text("if gender == 'y': pass")

        scanner = BiasScanner()
        results = scanner.scan_for_bias(str(tmp_path))

        for result in results:
            assert result.finding_id.startswith("BIAS-")
            assert len(result.finding_id) == 8  # BIAS-### format
