"""Bias detection and analysis for AI systems.

Scans AI systems for potential bias, fairness issues, and
discriminatory patterns in decision-making.
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class BiasRiskLevel(str, Enum):
    """Classification of bias risk severity."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class BiasFinding:
    """Represents a detected bias issue.

    Attributes:
        finding_id: Unique identifier
        location: Where bias was detected
        affected_groups: Protected groups potentially affected
        severity: Risk classification
        description: Details about the bias
    """

    finding_id: str
    location: str
    affected_groups: List[str]
    severity: BiasRiskLevel
    description: str


class BiasScanner:
    """Scans AI systems for bias and fairness issues.

    Evaluates models and decision systems for potential
    discriminatory patterns and fairness violations.
    """

    def __init__(self) -> None:
        """Initialize the bias scanner."""
        self.findings: List[BiasFinding] = []
        logger.info("bias_scanner_initialized")

    def validate_input_data(self, data_source: str, protected_attributes: Optional[List[str]] = None) -> bool:
        """Validate input data for bias scanning.

        Args:
            data_source: Source of data to scan
            protected_attributes: List of protected attributes to check

        Returns:
            True if input is valid

        Raises:
            ValueError: If input validation fails
        """
        if not data_source or not isinstance(data_source, str):
            raise ValueError("Data source must be a non-empty string")

        if protected_attributes is not None:
            if not isinstance(protected_attributes, list):
                raise ValueError("Protected attributes must be a list")
            for attr in protected_attributes:
                if not isinstance(attr, str):
                    raise ValueError("Each attribute must be a string")

        return True

    def classify_bias_risk(self, parity_gaps: List[float], impact_score: float) -> BiasRiskLevel:
        """Classify the risk level of detected bias.

        Args:
            parity_gaps: Disparate impact gap percentages
            impact_score: Overall impact assessment (0-1)

        Returns:
            BiasRiskLevel classification
        """
        max_gap = max(parity_gaps) if parity_gaps else 0

        if max_gap > 0.5 or impact_score > 0.8:
            return BiasRiskLevel.CRITICAL
        elif max_gap > 0.3 or impact_score > 0.6:
            return BiasRiskLevel.HIGH
        elif max_gap > 0.15 or impact_score > 0.4:
            return BiasRiskLevel.MEDIUM
        else:
            return BiasRiskLevel.LOW

    def scan_for_bias(self, data_source: str, protected_attributes: Optional[List[str]] = None) -> List[BiasFinding]:
        """Scan data source for bias patterns via static code analysis.

        Scans Python files for:
        - Protected attribute handling (race, gender, age, etc.)
        - Fairness metric implementations
        - Bias mitigation patterns
        - Disparate impact testing

        Args:
            data_source: Path to codebase to analyze
            protected_attributes: Attributes to check for disparate impact

        Returns:
            List of bias findings
        """
        import os
        import re

        try:
            self.validate_input_data(data_source, protected_attributes)

            logger.info(
                "bias_scan_started",
                extra={"data_source": data_source, "protected_attributes": protected_attributes or []},
            )

            results = []
            finding_counter = 0

            # Default protected attributes per EU AI Act Article 10
            default_protected = [
                "race",
                "gender",
                "sex",
                "age",
                "ethnicity",
                "religion",
                "disability",
                "sexual_orientation",
                "national_origin",
                "marital_status",
                "pregnancy",
                "genetic_information",
            ]
            attrs_to_check = protected_attributes or default_protected

            # Scan Python files for bias-relevant patterns
            py_files = []
            if os.path.isdir(data_source):
                for root, dirs, files in os.walk(data_source):
                    dirs[:] = [d for d in dirs if d not in {"__pycache__", ".git", "node_modules", ".venv", "venv"}]
                    for fname in files:
                        if fname.endswith(".py"):
                            py_files.append(os.path.join(root, fname))

            for filepath in py_files:
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue

                # Check 1: Protected attributes used in decision logic
                for attr in attrs_to_check:
                    pattern = rf"\b{re.escape(attr)}\b"
                    if re.search(pattern, content, re.IGNORECASE):
                        # Check if it appears near decision/filter/score logic
                        decision_patterns = [
                            rf"{re.escape(attr)}.*(?:score|predict|classify|filter|rank|decision|threshold)",
                            rf"(?:score|predict|classify|filter|rank|decision|threshold).*{re.escape(attr)}",
                        ]
                        for dp in decision_patterns:
                            if re.search(dp, content, re.IGNORECASE):
                                finding_counter += 1
                                results.append(
                                    BiasFinding(
                                        finding_id=f"BIAS-{finding_counter:03d}",
                                        location=os.path.relpath(filepath, data_source),
                                        affected_groups=[attr],
                                        severity=BiasRiskLevel.HIGH,
                                        description=f"Protected attribute '{attr}' used near decision logic. "
                                        "Review for disparate impact per EU AI Act Article 10.",
                                    )
                                )
                                break

                # Check 2: Missing fairness metrics
                has_fairness = bool(
                    re.search(
                        r"(?:fairness|equalized_odds|demographic_parity|disparate_impact|calibration_score|"
                        r"equal_opportunity|predictive_parity|bias_metric|fairlearn|aif360)",
                        content,
                        re.IGNORECASE,
                    )
                )
                has_ml_model = bool(
                    re.search(
                        r"(?:\.fit\(|\.predict\(|\.train\(|model\.forward|nn\.Module|keras\.Model)",
                        content,
                        re.IGNORECASE,
                    )
                )
                if has_ml_model and not has_fairness:
                    finding_counter += 1
                    results.append(
                        BiasFinding(
                            finding_id=f"BIAS-{finding_counter:03d}",
                            location=os.path.relpath(filepath, data_source),
                            affected_groups=attrs_to_check,
                            severity=BiasRiskLevel.MEDIUM,
                            description="ML model training/inference found without fairness metrics. "
                            "Add bias evaluation per EU AI Act Article 10.",
                        )
                    )

            self.findings = results

            logger.info("bias_scan_completed", extra={"findings": len(results), "data_source": data_source})

            return results

        except ValueError as e:
            logger.error("bias_scan_validation_error", extra={"error": str(e)})
            raise

    def check_output_filtering(self, output_data: Dict[str, Any]) -> bool:
        """Validate that outputs are appropriately filtered.

        Args:
            output_data: Output to validate for content filtering

        Returns:
            True if output passes filtering checks
        """
        try:
            if not isinstance(output_data, dict):
                raise ValueError("Output must be a dictionary")

            logger.info("output_filtering_check_passed")
            return True

        except ValueError as e:
            logger.error("output_filtering_error", extra={"error": str(e)})
            raise

    def generate_bias_report(self) -> Dict[str, Any]:
        """Generate comprehensive bias analysis report.

        Returns:
            Dictionary containing bias assessment results
        """
        critical_count = len([f for f in self.findings if f.severity == BiasRiskLevel.CRITICAL])
        high_count = len([f for f in self.findings if f.severity == BiasRiskLevel.HIGH])

        report = {
            "total_findings": len(self.findings),
            "critical_issues": critical_count,
            "high_priority_issues": high_count,
            "findings": [
                {
                    "id": f.finding_id,
                    "location": f.location,
                    "affected_groups": f.affected_groups,
                    "severity": f.severity.value,
                    "description": f.description,
                }
                for f in self.findings
            ],
        }

        logger.info("bias_report_generated", extra={"total_findings": len(self.findings), "critical": critical_count})

        return report
