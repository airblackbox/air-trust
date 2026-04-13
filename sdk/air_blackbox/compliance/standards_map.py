"""
Compliance standards crosswalk for AIR Blackbox scanner.

Maps AIR Blackbox scan results to four complementary standards:
1. EU AI Act Articles 9-15 (regulatory compliance)
2. ISO/IEC 42001:2023 (AI Management System)
3. NIST AI RMF (Artificial Intelligence Risk Management Framework)
4. Colorado SB 24-205 (first US state AI law, effective Feb 2026)

One scan, four reports. The crosswalk enables organizations to understand
their compliance posture across multiple frameworks simultaneously.
"""

from typing import Dict, List, Optional
import json
from datetime import datetime


STANDARDS_CROSSWALK = {
    "risk_management": {
        "eu_ai_act": "Article 9",
        "iso_42001": [
            "6.1 (Actions to address risks and opportunities)",
            "6.1.2 (AI risk assessment)",
            "A.6.2.1 (Risk management for AI systems)",
        ],
        "nist_ai_rmf": ["GOVERN 1", "MAP 1", "MAP 3"],
        "colorado_sb205": [
            "Section 6(2)(a) (Risk management program)",
            "Section 6(2)(b) (Risk management policy)",
        ],
        "description": "Risk identification, assessment, and mitigation for AI systems; includes threat modeling and control implementation",
    },
    "data_governance": {
        "eu_ai_act": "Article 10",
        "iso_42001": [
            "A.6.2.4 (Data quality for AI systems)",
            "A.6.2.5 (Acquisition of data)",
            "A.6.2.2 (Data governance)",
        ],
        "nist_ai_rmf": ["MAP 2", "MEASURE 2"],
        "colorado_sb205": [
            "Section 6(2)(c) (Data governance measures)",
        ],
        "description": "Data quality requirements, PII handling, bias detection in training data, data source validation",
    },
    "technical_documentation": {
        "eu_ai_act": "Article 11",
        "iso_42001": [
            "7.5 (Documented information)",
            "A.6.2.2 (AI system documentation)",
            "A.6.2.7 (Transparency and explainability)",
        ],
        "nist_ai_rmf": ["GOVERN 4", "MAP 5"],
        "colorado_sb205": [
            "Section 6(3) (Impact assessment documentation)",
            "Section 6(2)(d) (Documentation of high-risk systems)",
        ],
        "description": "System documentation, model cards, architecture descriptions, decision logic documentation",
    },
    "record_keeping": {
        "eu_ai_act": "Article 12",
        "iso_42001": [
            "A.6.2.6 (System logging and traceability)",
            "9.1 (Monitoring, measurement, analysis and evaluation)",
        ],
        "nist_ai_rmf": ["MEASURE 1", "MANAGE 4"],
        "colorado_sb205": [
            "Section 6(4) (Record retention -- 3 years minimum)",
        ],
        "description": "Audit trails, event logging, tamper-evident records, activity tracking and retrieval",
    },
    "human_oversight": {
        "eu_ai_act": "Article 14",
        "iso_42001": [
            "A.6.2.3 (Human oversight of AI systems)",
            "A.6.2.8 (AI system robustness and incident management)",
        ],
        "nist_ai_rmf": ["GOVERN 2", "MANAGE 1"],
        "colorado_sb205": [
            "Section 6(2)(e) (Human review of consequential decisions)",
            "Section 7 (Consumer right to human review)",
        ],
        "description": "Approval gates, kill switches, human-in-the-loop controls, override mechanisms",
    },
    "robustness": {
        "eu_ai_act": "Article 15",
        "iso_42001": [
            "A.6.2.8 (AI system robustness and resilience)",
            "A.6.2.9 (AI system security)",
        ],
        "nist_ai_rmf": ["MEASURE 3", "MANAGE 2", "MANAGE 3"],
        "colorado_sb205": [
            "Section 6(2)(f) (Ongoing testing and red teaming)",
        ],
        "description": "Injection defense, error resilience, adversarial robustness, recovery capabilities",
    },
    "consent_management": {
        # Note: Consent is a GDPR requirement (separate regulation), not an
        # EU AI Act article. The EU AI Act addresses data governance (Art. 10)
        # and transparency (Art. 13), which complement GDPR consent obligations.
        "eu_ai_act": "Article 10 (Data Governance) + Article 13 (Transparency)",
        "iso_42001": [
            "A.6.2.5 (Data management and governance)",
            "A.6.2.11 (Use of data subject rights)",
        ],
        "nist_ai_rmf": ["GOVERN 3"],
        "colorado_sb205": [
            "Section 5 (Consumer disclosure and notice requirements)",
        ],
        "gdpr": "Article 6 (Lawful basis) + Article 7 (Conditions for consent)",
        "description": "Lawful basis tracking, consent gates, data subject rights management, withdrawal mechanisms. "
                       "GDPR Article 6/7 applies when AI processes personal data; EU AI Act Article 10 governs data governance.",
    },
    "bias_fairness": {
        # Bias/fairness spans multiple EU AI Act articles:
        # Art. 10 (data governance/bias in training data),
        # Art. 14 (human oversight to catch bias), and
        # Art. 15 (robustness against discriminatory outcomes)
        "eu_ai_act": "Article 10 (Data Governance) + Article 14 (Human Oversight) + Article 15 (Robustness)",
        "iso_42001": [
            "A.6.2.4 (Data quality and fairness)",
            "A.6.2.10 (AI system fairness and non-discrimination)",
        ],
        "nist_ai_rmf": ["MAP 2", "MEASURE 2", "MANAGE 3"],
        "colorado_sb205": [
            "Section 2 (Algorithmic discrimination definition)",
            "Section 6(2)(c) (Bias detection and mitigation)",
        ],
        "description": "Fairness metrics, bias detection, protected attribute handling, fairness monitoring",
    },
}


# Framework display names and short IDs for CLI
SUPPORTED_FRAMEWORKS = {
    "eu": {"name": "EU AI Act", "key": "eu_ai_act"},
    "iso42001": {"name": "ISO/IEC 42001:2023", "key": "iso_42001"},
    "nist": {"name": "NIST AI RMF", "key": "nist_ai_rmf"},
    "colorado": {"name": "Colorado SB 24-205", "key": "colorado_sb205"},
}

ALL_FRAMEWORK_IDS = list(SUPPORTED_FRAMEWORKS.keys())


def generate_crosswalk_report(
    scan_results: List[Dict],
    frameworks: Optional[List[str]] = None,
) -> Dict:
    """
    Map scan results to multiple compliance frameworks simultaneously.

    Takes the output from run_all_checks() and enriches it with standards
    mappings. Groups results by category and counts pass/warn/fail per standard.

    Args:
        scan_results: List of check result dicts with keys: category, check_id,
                     status (pass/warn/fail), severity, description, remediation
        frameworks: List of framework IDs to include (eu, iso42001, nist, colorado).
                   If None, includes all four frameworks.

    Returns:
        Dict with per-framework summaries, category breakdowns, and scores.
    """
    if frameworks is None:
        frameworks = list(SUPPORTED_FRAMEWORKS.keys())
    report = {
        "eu_ai_act_summary": {"passed": 0, "warned": 0, "failed": 0, "total": 0},
        "iso_42001_summary": {"passed": 0, "warned": 0, "failed": 0, "total": 0},
        "nist_ai_rmf_summary": {"passed": 0, "warned": 0, "failed": 0, "total": 0},
        "colorado_sb205_summary": {"passed": 0, "warned": 0, "failed": 0, "total": 0},
        "by_category": {},
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_checks": len(scan_results),
        "frameworks_evaluated": list(frameworks) if frameworks else list(SUPPORTED_FRAMEWORKS.keys()),
    }

    category_status_map = {}
    for result in scan_results:
        category = result.get("category")
        result.get("status", "unknown")  # status used in future mapping

        if category not in category_status_map:
            category_status_map[category] = []
        category_status_map[category].append(result)

    for category, results in category_status_map.items():
        if category not in STANDARDS_CROSSWALK:
            continue

        mapping = STANDARDS_CROSSWALK[category]
        worst_status = _compute_category_status(results)

        category_entry = {
            "description": mapping["description"],
            "eu_ai_act": mapping["eu_ai_act"],
            "iso_42001": mapping["iso_42001"],
            "nist_ai_rmf": mapping["nist_ai_rmf"],
            "colorado_sb205": mapping.get("colorado_sb205", []),
            "worst_status": worst_status,
            "check_count": len(results),
            "pass_count": sum(1 for r in results if r.get("status") == "pass"),
            "warn_count": sum(1 for r in results if r.get("status") == "warn"),
            "fail_count": sum(1 for r in results if r.get("status") == "fail"),
        }
        report["by_category"][category] = category_entry

    # Aggregate summaries for each requested framework
    all_summary_keys = {
        "eu": "eu_ai_act_summary",
        "iso42001": "iso_42001_summary",
        "nist": "nist_ai_rmf_summary",
        "colorado": "colorado_sb205_summary",
    }
    status_to_summary_key = {"pass": "passed", "warn": "warned", "fail": "failed"}
    for category, entry in report["by_category"].items():
        for fw_id in frameworks:
            summary_key = all_summary_keys.get(fw_id)
            if summary_key and summary_key in report:
                report[summary_key]["total"] += entry["check_count"]
                summary_status = status_to_summary_key.get(entry["worst_status"])
                if summary_status:
                    report[summary_key][summary_status] += entry["check_count"]

    return report


def _compute_category_status(results: List[Dict]) -> str:
    """
    Determine worst status from a list of check results.

    Priority: fail > warn > pass

    Args:
        results: List of check result dicts with status key

    Returns:
        "fail" if any check failed, "warn" if any warned, "pass" otherwise
    """
    if any(r.get("status") == "fail" for r in results):
        return "fail"
    if any(r.get("status") == "warn" for r in results):
        return "warn"
    return "pass"


def render_crosswalk_markdown(report: Dict) -> str:
    """
    Render compliance report as markdown table with standards crosswalk.

    Produces a human-readable markdown table showing each category, its status,
    and the relevant clauses/functions across all three standards.

    Args:
        report: Output from generate_crosswalk_report()

    Returns:
        Markdown string with compliance summary and detailed table
    """
    lines = []
    lines.append("# AI Compliance Standards Crosswalk Report\n")
    lines.append(f"Generated: {report['timestamp']}\n")
    lines.append(f"Total Checks: {report['total_checks']}\n\n")

    lines.append("## Summary by Standard\n")
    lines.append("| Standard | Passed | Warned | Failed | Total |\n")
    lines.append("|----------|--------|--------|--------|-------|\n")

    for std_key, std_name in [
        ("eu_ai_act_summary", "EU AI Act"),
        ("iso_42001_summary", "ISO/IEC 42001:2023"),
        ("nist_ai_rmf_summary", "NIST AI RMF"),
        ("colorado_sb205_summary", "Colorado SB 24-205"),
    ]:
        summary = report[std_key]
        lines.append(
            f"| {std_name} | {summary['passed']} | "
            f"{summary['warned']} | {summary['failed']} | "
            f"{summary['total']} |\n"
        )

    lines.append("\n## Detailed Compliance Mapping\n\n")
    lines.append("| Category | Status | EU AI Act | ISO 42001 | NIST AI RMF | Colorado SB 205 |\n")
    lines.append("|----------|--------|-----------|-----------|-------------|------------------|\n")

    for category, entry in sorted(report["by_category"].items()):
        status_icon = _get_status_icon(entry["worst_status"])
        eu_ai = entry["eu_ai_act"]
        iso_clauses = "; ".join(entry["iso_42001"])
        nist_funcs = "; ".join(entry["nist_ai_rmf"])
        colorado_refs = "; ".join(entry.get("colorado_sb205", []))

        lines.append(
            f"| {category} | {status_icon} | {eu_ai} | {iso_clauses} | "
            f"{nist_funcs} | {colorado_refs} |\n"
        )

    lines.append("\n## Category Descriptions\n\n")
    for category, entry in sorted(report["by_category"].items()):
        lines.append(f"### {category.replace('_', ' ').title()}\n")
        lines.append(f"{entry['description']}\n\n")
        lines.append(
            f"- Checks: {entry['check_count']} "
            f"(Passed: {entry['pass_count']}, "
            f"Warned: {entry['warn_count']}, "
            f"Failed: {entry['fail_count']})\n\n"
        )

    return "".join(lines)


def _get_status_icon(status: str) -> str:
    """
    Map status string to markdown emoji icon.

    Args:
        status: "pass", "warn", or "fail"

    Returns:
        Markdown-compatible status indicator
    """
    status_icons = {
        "pass": "PASS",
        "warn": "WARN",
        "fail": "FAIL",
    }
    return status_icons.get(status, "UNKNOWN")


def render_crosswalk_json(report: Dict) -> str:
    """
    Render compliance report as JSON for machine consumption.

    Produces structured JSON suitable for programmatic consumption,
    REST API responses, or downstream compliance tooling integration.

    Args:
        report: Output from generate_crosswalk_report()

    Returns:
        JSON string with complete compliance data
    """
    return json.dumps(report, indent=2, default=str)


def get_relevant_standards_for_check(check_category: str) -> Optional[Dict]:
    """
    Look up standards mappings for a single check category.

    Args:
        check_category: One of the keys in STANDARDS_CROSSWALK

    Returns:
        Dict with eu_ai_act, iso_42001, nist_ai_rmf, description;
        or None if category not found
    """
    return STANDARDS_CROSSWALK.get(check_category)


def get_checks_for_iso_clause(iso_clause_pattern: str) -> List[str]:
    """
    Find all AIR Blackbox check categories that map to an ISO clause.

    Useful for reverse-lookup when starting from an ISO 42001 audit
    and needing to identify which checks to run.

    Args:
        iso_clause_pattern: Partial ISO clause (e.g., "6.1" or "A.6.2.4")

    Returns:
        List of check category names that map to matching clauses
    """
    matches = []
    for category, mapping in STANDARDS_CROSSWALK.items():
        iso_clauses = mapping.get("iso_42001", [])
        for clause in iso_clauses:
            if iso_clause_pattern.lower() in clause.lower():
                matches.append(category)
                break
    return matches


def get_checks_for_nist_function(nist_function: str) -> List[str]:
    """
    Find all AIR Blackbox checks that map to a NIST AI RMF function.

    Enables navigation from NIST functions (GOVERN, MAP, MEASURE, MANAGE)
    to the specific checks that address them.

    Args:
        nist_function: NIST function like "GOVERN 1", "MAP 2", etc.

    Returns:
        List of check category names that map to this function
    """
    matches = []
    nist_func_normalized = nist_function.upper().strip()
    for category, mapping in STANDARDS_CROSSWALK.items():
        nist_funcs = mapping.get("nist_ai_rmf", [])
        for func in nist_funcs:
            if nist_func_normalized in func.upper():
                matches.append(category)
                break
    return matches


def get_checks_for_eu_article(article_number: int) -> List[str]:
    """
    Find all AIR Blackbox checks that map to an EU AI Act article.

    Args:
        article_number: Article number (9, 10, 11, 12, 14, 15, or 6/7 for GDPR)

    Returns:
        List of check category names that address this article
    """
    matches = []
    article_pattern = f"Article {article_number}"
    for category, mapping in STANDARDS_CROSSWALK.items():
        eu_article = mapping.get("eu_ai_act", "")
        if article_pattern.lower() in eu_article.lower():
            matches.append(category)
    return matches


def calculate_compliance_scores(report: Dict) -> Dict[str, float]:
    """
    Calculate compliance maturity scores for each standard (0-100).

    Scores are weighted by check count per category. A fail reduces score
    by 25 points, a warn by 10 points. Passing all checks yields 100%.

    Formula: 100 - (10 * warn_count + 25 * fail_count) / total_checks

    Args:
        report: Output from generate_crosswalk_report()

    Returns:
        Dict with scores for eu_ai_act, iso_42001, nist_ai_rmf (0-100)
    """
    scores = {}
    total = report["total_checks"]

    if total == 0:
        return {
            "eu_ai_act": 0,
            "iso_42001": 0,
            "nist_ai_rmf": 0,
            "colorado_sb205": 0,
        }

    for std_key in [
        "eu_ai_act_summary",
        "iso_42001_summary",
        "nist_ai_rmf_summary",
        "colorado_sb205_summary",
    ]:
        summary = report[std_key]
        penalty = (10 * summary["warned"]) + (25 * summary["failed"])
        score = max(0, 100 - (penalty / total))
        std_name = std_key.replace("_summary", "")
        scores[std_name] = round(score, 2)

    return scores


def generate_compliance_narrative(report: Dict) -> str:
    """
    Generate a human-readable compliance narrative summary.

    Describes the overall compliance posture in plain language, highlights
    critical gaps, and provides actionable remediation priorities.

    Args:
        report: Output from generate_crosswalk_report()

    Returns:
        Narrative string with executive summary and key findings
    """
    scores = calculate_compliance_scores(report)
    lines = []

    lines.append("COMPLIANCE NARRATIVE SUMMARY\n")
    lines.append("=" * 50 + "\n\n")

    lines.append("COMPLIANCE SCORES (0-100)\n")
    lines.append(f"EU AI Act:        {scores['eu_ai_act']:5.1f}%\n")
    lines.append(f"ISO 42001:2023:   {scores['iso_42001']:5.1f}%\n")
    lines.append(f"NIST AI RMF:      {scores['nist_ai_rmf']:5.1f}%\n")
    lines.append(f"Colorado SB 205:  {scores['colorado_sb205']:5.1f}%\n\n")

    failed_categories = [
        (cat, entry) for cat, entry in report["by_category"].items()
        if entry["worst_status"] == "fail"
    ]
    warned_categories = [
        (cat, entry) for cat, entry in report["by_category"].items()
        if entry["worst_status"] == "warn"
    ]
    passed_categories = [
        (cat, entry) for cat, entry in report["by_category"].items()
        if entry["worst_status"] == "pass"
    ]

    lines.append(f"PASSED CATEGORIES ({len(passed_categories)})\n")
    lines.append("-" * 50 + "\n")
    if passed_categories:
        for cat, entry in passed_categories:
            lines.append(f"  + {cat.replace('_', ' ').title()}\n")
    else:
        lines.append("  (none)\n")
    lines.append("\n")

    lines.append(f"WARNED CATEGORIES ({len(warned_categories)})\n")
    lines.append("-" * 50 + "\n")
    if warned_categories:
        for cat, entry in warned_categories:
            lines.append(
                f"  ! {cat.replace('_', ' ').title()} "
                f"({entry['warn_count']} warnings)\n"
            )
    else:
        lines.append("  (none)\n")
    lines.append("\n")

    lines.append(f"FAILED CATEGORIES ({len(failed_categories)}) - CRITICAL\n")
    lines.append("-" * 50 + "\n")
    if failed_categories:
        for cat, entry in failed_categories:
            lines.append(
                f"  X {cat.replace('_', ' ').title()} "
                f"({entry['fail_count']} failures)\n"
            )
    else:
        lines.append("  (none)\n")
    lines.append("\n")

    lines.append("REMEDIATION PRIORITY\n")
    lines.append("-" * 50 + "\n")
    if failed_categories:
        lines.append("1. Address all FAILED categories immediately.\n")
        lines.append("2. Resolve WARNED categories within 30 days.\n")
        lines.append("3. Maintain PASSED categories through monitoring.\n")
    else:
        lines.append("No critical failures detected.\n")

    return "".join(lines)


def get_checks_for_colorado_section(section_pattern: str) -> List[str]:
    """
    Find all AIR Blackbox checks that map to a Colorado SB 205 section.

    Args:
        section_pattern: Partial section reference (e.g., "Section 6" or "Section 7")

    Returns:
        List of check category names that map to matching sections
    """
    matches = []
    for category, mapping in STANDARDS_CROSSWALK.items():
        colorado_refs = mapping.get("colorado_sb205", [])
        for ref in colorado_refs:
            if section_pattern.lower() in ref.lower():
                matches.append(category)
                break
    return matches


if __name__ == "__main__":
    print("AIR Blackbox Standards Crosswalk Module")
    print("Supports: EU AI Act, ISO/IEC 42001:2023, NIST AI RMF, Colorado SB 24-205")
    print("\nAvailable functions:")
    print("  - generate_crosswalk_report(scan_results, frameworks)")
    print("  - render_crosswalk_markdown(report)")
    print("  - render_crosswalk_json(report)")
    print("  - calculate_compliance_scores(report)")
    print("  - generate_compliance_narrative(report)")
    print("  - get_relevant_standards_for_check(category)")
    print("  - get_checks_for_iso_clause(pattern)")
    print("  - get_checks_for_nist_function(function)")
    print("  - get_checks_for_eu_article(article_number)")
    print("  - get_checks_for_colorado_section(section_pattern)")
