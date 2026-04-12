"""
Tests for the multi-framework compliance standards crosswalk.

Covers:
- STANDARDS_CROSSWALK structure and completeness
- SUPPORTED_FRAMEWORKS registry
- generate_crosswalk_report() with framework filtering
- calculate_compliance_scores() scoring logic
- render_crosswalk_markdown() output formatting
- Reverse lookup functions (EU, ISO, NIST, Colorado)
- generate_compliance_narrative() output

Run: python -m pytest tests/test_standards_map.py -v
  or: python tests/test_standards_map.py
"""

import json
import sys
import os

# Ensure sdk/ is on the import path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))

from air_blackbox.compliance.standards_map import (
    STANDARDS_CROSSWALK,
    SUPPORTED_FRAMEWORKS,
    ALL_FRAMEWORK_IDS,
    generate_crosswalk_report,
    render_crosswalk_markdown,
    render_crosswalk_json,
    calculate_compliance_scores,
    generate_compliance_narrative,
    get_relevant_standards_for_check,
    get_checks_for_eu_article,
    get_checks_for_iso_clause,
    get_checks_for_nist_function,
    get_checks_for_colorado_section,
)


# ── Test data ──────────────────────────────────────────────────────

SAMPLE_CHECKS = [
    {"category": "risk_management", "check_id": "rm-1", "status": "pass",
     "severity": "high", "description": "Risk assessment found", "remediation": ""},
    {"category": "risk_management", "check_id": "rm-2", "status": "warn",
     "severity": "medium", "description": "Threat model incomplete", "remediation": "Add threat model"},
    {"category": "data_governance", "check_id": "dg-1", "status": "fail",
     "severity": "high", "description": "No PII handling", "remediation": "Add PII detection"},
    {"category": "record_keeping", "check_id": "rk-1", "status": "pass",
     "severity": "medium", "description": "Audit logging present", "remediation": ""},
    {"category": "human_oversight", "check_id": "ho-1", "status": "pass",
     "severity": "high", "description": "Kill switch found", "remediation": ""},
    {"category": "robustness", "check_id": "rb-1", "status": "pass",
     "severity": "medium", "description": "Error handling present", "remediation": ""},
]


# ── Structure tests ────────────────────────────────────────────────

def test_crosswalk_has_all_expected_categories():
    """Every expected compliance category exists in the crosswalk."""
    expected = {
        "risk_management", "data_governance", "technical_documentation",
        "record_keeping", "human_oversight", "robustness",
        "consent_management", "bias_fairness",
    }
    assert expected == set(STANDARDS_CROSSWALK.keys())


def test_every_category_has_all_four_frameworks():
    """Each category must have eu_ai_act, iso_42001, nist_ai_rmf, and colorado_sb205."""
    for cat, mapping in STANDARDS_CROSSWALK.items():
        assert "eu_ai_act" in mapping, f"{cat} missing eu_ai_act"
        assert "iso_42001" in mapping, f"{cat} missing iso_42001"
        assert "nist_ai_rmf" in mapping, f"{cat} missing nist_ai_rmf"
        assert "colorado_sb205" in mapping, f"{cat} missing colorado_sb205"
        assert "description" in mapping, f"{cat} missing description"


def test_supported_frameworks_registry():
    """SUPPORTED_FRAMEWORKS has all four entries with name and key."""
    assert len(SUPPORTED_FRAMEWORKS) == 4
    for fw_id in ["eu", "iso42001", "nist", "colorado"]:
        assert fw_id in SUPPORTED_FRAMEWORKS
        assert "name" in SUPPORTED_FRAMEWORKS[fw_id]
        assert "key" in SUPPORTED_FRAMEWORKS[fw_id]


def test_all_framework_ids_matches_keys():
    """ALL_FRAMEWORK_IDS should match SUPPORTED_FRAMEWORKS keys."""
    assert set(ALL_FRAMEWORK_IDS) == set(SUPPORTED_FRAMEWORKS.keys())


def test_colorado_sb205_entries_are_lists():
    """Colorado SB 205 entries should always be lists of section references."""
    for cat, mapping in STANDARDS_CROSSWALK.items():
        co = mapping["colorado_sb205"]
        assert isinstance(co, list), f"{cat}: colorado_sb205 should be a list, got {type(co)}"
        assert len(co) >= 1, f"{cat}: colorado_sb205 should have at least one reference"


# ── generate_crosswalk_report tests ───────────────────────────────

def test_generate_report_default_all_frameworks():
    """Report with no framework filter includes all four summaries."""
    report = generate_crosswalk_report(SAMPLE_CHECKS)
    assert "eu_ai_act_summary" in report
    assert "iso_42001_summary" in report
    assert "nist_ai_rmf_summary" in report
    assert "colorado_sb205_summary" in report
    assert report["total_checks"] == len(SAMPLE_CHECKS)
    assert "frameworks_evaluated" in report


def test_generate_report_filters_frameworks():
    """Report with framework filter only includes requested frameworks."""
    report = generate_crosswalk_report(SAMPLE_CHECKS, frameworks=["eu", "nist"])
    assert "eu" in report["frameworks_evaluated"]
    assert "nist" in report["frameworks_evaluated"]
    # Summaries still exist as keys but only requested ones get populated
    assert report["eu_ai_act_summary"]["total"] > 0
    assert report["nist_ai_rmf_summary"]["total"] > 0


def test_generate_report_category_breakdown():
    """Report includes per-category entries for matched checks."""
    report = generate_crosswalk_report(SAMPLE_CHECKS)
    assert "risk_management" in report["by_category"]
    assert "data_governance" in report["by_category"]
    rm = report["by_category"]["risk_management"]
    assert rm["check_count"] == 2
    assert rm["pass_count"] == 1
    assert rm["warn_count"] == 1
    assert rm["fail_count"] == 0


def test_generate_report_worst_status():
    """Worst status per category: fail > warn > pass."""
    report = generate_crosswalk_report(SAMPLE_CHECKS)
    # risk_management has 1 pass + 1 warn = worst is warn
    assert report["by_category"]["risk_management"]["worst_status"] == "warn"
    # data_governance has 1 fail = worst is fail
    assert report["by_category"]["data_governance"]["worst_status"] == "fail"
    # record_keeping has 1 pass = worst is pass
    assert report["by_category"]["record_keeping"]["worst_status"] == "pass"


def test_generate_report_empty_input():
    """Report with empty checks should not crash."""
    report = generate_crosswalk_report([])
    assert report["total_checks"] == 0
    assert len(report["by_category"]) == 0


def test_generate_report_unknown_category_ignored():
    """Checks with unknown categories should be silently skipped."""
    checks = [{"category": "unknown_thing", "check_id": "x", "status": "pass"}]
    report = generate_crosswalk_report(checks)
    assert "unknown_thing" not in report["by_category"]


# ── Scoring tests ─────────────────────────────────────────────────

def test_scores_perfect_when_all_pass():
    """All passing checks should yield 100% across all frameworks."""
    checks = [
        {"category": "risk_management", "check_id": "rm-1", "status": "pass"},
        {"category": "human_oversight", "check_id": "ho-1", "status": "pass"},
    ]
    report = generate_crosswalk_report(checks)
    scores = calculate_compliance_scores(report)
    for key in ["eu_ai_act", "iso_42001", "nist_ai_rmf", "colorado_sb205"]:
        assert scores[key] == 100.0, f"{key} should be 100 when all pass"


def test_scores_zero_when_empty():
    """Empty scan produces zero scores."""
    report = generate_crosswalk_report([])
    scores = calculate_compliance_scores(report)
    for key in ["eu_ai_act", "iso_42001", "nist_ai_rmf", "colorado_sb205"]:
        assert scores[key] == 0


def test_scores_penalized_for_failures():
    """Failures should reduce scores below 100."""
    report = generate_crosswalk_report(SAMPLE_CHECKS)
    scores = calculate_compliance_scores(report)
    # With 1 fail and 1 warn out of 6 checks, scores should be < 100
    for key in scores:
        assert scores[key] < 100.0, f"{key} should be < 100 with failures"
        assert scores[key] >= 0, f"{key} should not go negative"


# ── Rendering tests ───────────────────────────────────────────────

def test_render_markdown_has_table():
    """Markdown output should contain a table header row."""
    report = generate_crosswalk_report(SAMPLE_CHECKS)
    md = render_crosswalk_markdown(report)
    assert "| Category |" in md
    assert "| EU AI Act |" in md or "EU AI Act" in md
    assert "Colorado" in md


def test_render_json_is_valid():
    """JSON output should be parseable."""
    report = generate_crosswalk_report(SAMPLE_CHECKS)
    json_str = render_crosswalk_json(report)
    parsed = json.loads(json_str)
    assert "by_category" in parsed
    assert "total_checks" in parsed


def test_narrative_contains_scores():
    """Narrative should include all four framework scores."""
    report = generate_crosswalk_report(SAMPLE_CHECKS)
    narrative = generate_compliance_narrative(report)
    assert "EU AI Act" in narrative
    assert "ISO 42001" in narrative
    assert "NIST AI RMF" in narrative
    assert "Colorado SB 205" in narrative
    assert "COMPLIANCE SCORES" in narrative


# ── Reverse lookup tests ──────────────────────────────────────────

def test_eu_article_lookup():
    """Looking up Article 9 should return risk_management."""
    matches = get_checks_for_eu_article(9)
    assert "risk_management" in matches


def test_eu_article_lookup_article_10():
    """Article 10 maps to data_governance and bias_fairness."""
    matches = get_checks_for_eu_article(10)
    assert "data_governance" in matches
    assert "bias_fairness" in matches


def test_iso_clause_lookup():
    """Looking up ISO clause 6.1 should match risk_management."""
    matches = get_checks_for_iso_clause("6.1")
    assert "risk_management" in matches


def test_nist_function_lookup():
    """Looking up GOVERN 1 should match risk_management."""
    matches = get_checks_for_nist_function("GOVERN 1")
    assert "risk_management" in matches


def test_nist_function_case_insensitive():
    """NIST lookup should be case-insensitive."""
    matches = get_checks_for_nist_function("govern 1")
    assert "risk_management" in matches


def test_colorado_section_lookup():
    """Looking up Section 6 should match multiple categories."""
    matches = get_checks_for_colorado_section("Section 6")
    assert len(matches) >= 3, "Section 6 covers most categories"
    assert "risk_management" in matches


def test_colorado_section_7_maps_to_human_oversight():
    """Section 7 (consumer right to human review) maps to human_oversight."""
    matches = get_checks_for_colorado_section("Section 7")
    assert "human_oversight" in matches


def test_lookup_nonexistent_returns_empty():
    """Looking up a nonexistent clause returns empty list."""
    assert get_checks_for_eu_article(999) == []
    assert get_checks_for_iso_clause("Z.99.99") == []
    assert get_checks_for_nist_function("NONEXIST 99") == []
    assert get_checks_for_colorado_section("Section 999") == []


def test_get_relevant_standards_returns_mapping():
    """get_relevant_standards_for_check returns full mapping for valid category."""
    result = get_relevant_standards_for_check("risk_management")
    assert result is not None
    assert "eu_ai_act" in result
    assert result["eu_ai_act"] == "Article 9"


def test_get_relevant_standards_returns_none_for_unknown():
    """get_relevant_standards_for_check returns None for unknown category."""
    result = get_relevant_standards_for_check("nonexistent_category")
    assert result is None


# ── Run directly ──────────────────────────────────────────────────

if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
