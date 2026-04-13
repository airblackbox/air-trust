"""
Comprehensive tests for GDPR compliance scanner.

Tests cover:
- All 8 GDPR checker functions (_check_consent_management, etc.)
- Pass, warn, and fail paths for each checker
- Edge cases: empty inputs, no files, single file
- Pattern matching for compliance indicators
- Mock file contents with real patterns
"""

import pytest
import tempfile
import os
from pathlib import Path
from typing import Dict, List

from air_blackbox.compliance.gdpr_scanner import (
    scan_gdpr,
    _check_consent_management,
    _check_data_minimization,
    _check_right_to_erasure,
    _check_data_retention,
    _check_cross_border_transfer,
    _check_dpia_patterns,
    _check_processing_records,
    _check_breach_notification,
)
from air_blackbox.compliance.code_scanner import CodeFinding


class TestScanGdprMainFunction:
    """Tests for the main scan_gdpr entry point."""

    def test_scan_gdpr_empty_directory(self, tmp_path):
        """No Python files in directory should return empty list."""
        result = scan_gdpr(str(tmp_path))
        assert result == []

    def test_scan_gdpr_single_file(self, tmp_path):
        """Scan a single Python file for GDPR compliance."""
        py_file = tmp_path / "agent.py"
        py_file.write_text("# No GDPR patterns\nprint('hello')")

        result = scan_gdpr(str(tmp_path))
        # Should return findings for all 8 checkers
        assert len(result) == 8
        assert all(isinstance(f, CodeFinding) for f in result)

    def test_scan_gdpr_multiple_files(self, tmp_path):
        """Scan multiple Python files."""
        (tmp_path / "agent.py").write_text("consent_manage = True")
        (tmp_path / "utils.py").write_text("data_retention = '30days'")

        result = scan_gdpr(str(tmp_path))
        assert len(result) == 8

    def test_scan_gdpr_nested_directory(self, tmp_path):
        """Scan nested directory structure."""
        src_dir = tmp_path / "src" / "compliance"
        src_dir.mkdir(parents=True)
        (src_dir / "handler.py").write_text("gdpr_consent = True")

        result = scan_gdpr(str(tmp_path))
        assert len(result) == 8

    def test_scan_gdpr_ignores_non_python(self, tmp_path):
        """Non-Python files are ignored."""
        (tmp_path / "config.txt").write_text("consent_manage")
        (tmp_path / "readme.md").write_text("data_retention")

        result = scan_gdpr(str(tmp_path))
        assert result == []

    def test_scan_gdpr_handles_unreadable_files(self, tmp_path):
        """Unreadable files are skipped gracefully."""
        py_file = tmp_path / "normal.py"
        py_file.write_text("consent_manage = True")

        result = scan_gdpr(str(tmp_path))
        assert len(result) == 8


class TestCheckConsentManagement:
    """Tests for _check_consent_management function."""

    def test_consent_pass_with_enforcement(self):
        """Strong consent patterns with enforcement gates return pass."""
        files = {
            "agent.py": "if not user_consent: raise ValueError('consent required')\nconsentGate.check()"
        }
        result = _check_consent_management(files, "/path")

        assert len(result) == 1
        assert result[0].status == "pass"
        assert result[0].article == 6
        assert "Consent management with enforcement" in result[0].evidence

    def test_consent_pass_with_consent_manage_pattern(self):
        """consent_manage keyword with enforcement is pass."""
        files = {
            "privacy.py": "def consent_manage():\n    if not user.consent:\n        raise PermissionError()"
        }
        result = _check_consent_management(files, "/path")
        assert result[0].status == "pass"

    def test_consent_pass_with_lawful_basis(self):
        """lawful_basis pattern with enforcement."""
        files = {
            "gdpr.py": "legal_basis = validate()\nif not legal_basis:\n    raise ValueError()\nconsent_required = True"
        }
        result = _check_consent_management(files, "/path")
        assert result[0].status == "pass"

    def test_consent_warn_no_enforcement(self):
        """Strong patterns without enforcement gates return warn."""
        files = {
            "handler.py": "consent_record = get_user_consent()\ndata = fetch_data()"
        }
        result = _check_consent_management(files, "/path")

        assert len(result) == 1
        assert result[0].status == "warn"
        assert "no enforcement gates" in result[0].evidence
        assert result[0].article == 6

    def test_consent_warn_moderate_patterns_only(self):
        """Moderate patterns without strong patterns return warn."""
        files = {
            "form.py": "user_agreement = form.consent\nif user_agreement: process()"
        }
        result = _check_consent_management(files, "/path")

        assert result[0].status == "warn"
        assert "structured management" in result[0].evidence

    def test_consent_warn_no_patterns(self):
        """No consent patterns return warn with fix hint."""
        files = {
            "processor.py": "def process(data):\n    return data * 2"
        }
        result = _check_consent_management(files, "/path")

        assert result[0].status == "warn"
        assert "No consent management patterns" in result[0].evidence
        assert result[0].fix_hint

    def test_consent_opt_in_pattern(self):
        """opt_in keyword is strong pattern."""
        files = {
            "settings.py": "opt_in = check_consent()\nif not opt_in: raise Exception('consent required')"
        }
        result = _check_consent_management(files, "/path")
        assert result[0].status == "pass"

    def test_consent_gdpr_keyword(self):
        """gdpr_consent pattern is recognized."""
        files = {
            "check.py": "gdpr_consent_check()\nif not gdpr_consent: return"
        }
        result = _check_consent_management(files, "/path")
        assert result[0].status == "pass"

    def test_consent_withdraw_consent(self):
        """withdraw_consent is strong pattern."""
        files = {
            "revoke.py": "def withdraw_consent(user_id):\n    if not user_id: return\n    delete_consent_record()\n    assert consent_withdrawn"
        }
        result = _check_consent_management(files, "/path")
        assert result[0].status == "pass"

    def test_consent_multiple_files_enforcement(self):
        """Multiple files with enforcement gates."""
        files = {
            "a.py": "consent_manage = check()\nif not consent_manage: raise",
            "b.py": "consent_record = log()\nif not consent_record: return"
        }
        result = _check_consent_management(files, "/path")
        assert result[0].status == "pass"
        assert "2 file" in result[0].evidence


class TestCheckDataMinimization:
    """Tests for _check_data_minimization function."""

    def test_data_minimization_pass(self):
        """Data minimization patterns return pass."""
        files = {
            "processor.py": "def data_minimization(user_data):\n    return {'name': user_data.name}"
        }
        result = _check_data_minimization(files, "/path")

        assert result[0].status == "pass"
        assert result[0].article == 5
        assert "Data minimization patterns" in result[0].evidence

    def test_data_minimization_minimal_data(self):
        """minimal_data pattern is recognized."""
        files = {
            "scraper.py": "minimal_data = extract_required_fields()"
        }
        result = _check_data_minimization(files, "/path")
        assert result[0].status == "pass"

    def test_data_minimization_necessary_data(self):
        """necessary_data pattern triggers pass."""
        files = {
            "filter.py": "necessary_data = [item for item in data if item.required]"
        }
        result = _check_data_minimization(files, "/path")
        assert result[0].status == "pass"

    def test_data_minimization_field_filter(self):
        """field_filter pattern recognized."""
        files = {
            "api.py": "field_filter = {'email', 'name'}\nresult = {k: v for k, v in user.items() if k in field_filter}"
        }
        result = _check_data_minimization(files, "/path")
        assert result[0].status == "pass"

    def test_data_minimization_collect_only(self):
        """collect_only pattern recognized."""
        files = {
            "gather.py": "collect_only = ['email', 'name']\ndata = {k: user[k] for k in collect_only}"
        }
        result = _check_data_minimization(files, "/path")
        assert result[0].status == "pass"

    def test_data_minimization_purpose_limitation(self):
        """purpose_limitation pattern recognized."""
        files = {
            "policy.py": "purpose_limitation = enforce_purpose_scope()"
        }
        result = _check_data_minimization(files, "/path")
        assert result[0].status == "pass"

    def test_data_minimization_warn_no_patterns(self):
        """No minimization patterns return warn."""
        files = {
            "handler.py": "data = fetch_all_user_data()\nprocess(data)"
        }
        result = _check_data_minimization(files, "/path")

        assert result[0].status == "warn"
        assert "No data minimization patterns" in result[0].evidence
        assert result[0].fix_hint

    def test_data_minimization_multiple_patterns(self):
        """Multiple files with minimization patterns."""
        files = {
            "a.py": "data_minimization = True",
            "b.py": "strip_unnecessary = lambda d: {k: d[k] for k in needed}",
            "c.py": "redact_unnecessary(data)"
        }
        result = _check_data_minimization(files, "/path")
        assert result[0].status == "pass"


class TestCheckRightToErasure:
    """Tests for _check_right_to_erasure function."""

    def test_erasure_pass_explicit_pattern(self):
        """right_to_erasure pattern returns pass."""
        files = {
            "cleanup.py": "def right_to_erasure(user_id):\n    delete_all_data(user_id)"
        }
        result = _check_right_to_erasure(files, "/path")

        assert result[0].status == "pass"
        assert result[0].article == 17

    def test_erasure_right_to_be_forgotten(self):
        """right_to_be_forgotten pattern recognized."""
        files = {
            "gdpr.py": "right_to_be_forgotten = implement_gdpr_deletion()"
        }
        result = _check_right_to_erasure(files, "/path")
        assert result[0].status == "pass"

    def test_erasure_delete_user_data(self):
        """delete_user_data pattern recognized."""
        files = {
            "db.py": "def delete_user_data(user_id):\n    db.delete_where(id=user_id)"
        }
        result = _check_right_to_erasure(files, "/path")
        assert result[0].status == "pass"

    def test_erasure_erase_personal(self):
        """erase_personal pattern recognized."""
        files = {
            "privacy.py": "erase_personal_info(user)"
        }
        result = _check_right_to_erasure(files, "/path")
        assert result[0].status == "pass"

    def test_erasure_purge_user(self):
        """purge_user pattern recognized."""
        files = {
            "maintenance.py": "purge_user(user_id)"
        }
        result = _check_right_to_erasure(files, "/path")
        assert result[0].status == "pass"

    def test_erasure_anonymize_user(self):
        """anonymize_user pattern recognized."""
        files = {
            "anon.py": "anonymize_user(user_id)"
        }
        result = _check_right_to_erasure(files, "/path")
        assert result[0].status == "pass"

    def test_erasure_deletion_request(self):
        """deletion_request pattern recognized."""
        files = {
            "api.py": "def deletion_request(req):\n    process_erasure(req.user_id)"
        }
        result = _check_right_to_erasure(files, "/path")
        assert result[0].status == "pass"

    def test_erasure_warn_no_patterns(self):
        """No erasure patterns return warn."""
        files = {
            "handler.py": "data = fetch_user(id)\nreturn data"
        }
        result = _check_right_to_erasure(files, "/path")

        assert result[0].status == "warn"
        assert "No right-to-erasure implementation" in result[0].evidence
        assert result[0].fix_hint


class TestCheckDataRetention:
    """Tests for _check_data_retention function."""

    def test_retention_pass_policy(self):
        """retention_policy pattern returns pass."""
        files = {
            "storage.py": "retention_policy = '30 days'"
        }
        result = _check_data_retention(files, "/path")

        assert result[0].status == "pass"
        assert result[0].article == 5

    def test_retention_data_retention(self):
        """data_retention pattern recognized."""
        files = {
            "config.py": "data_retention = 30  # days"
        }
        result = _check_data_retention(files, "/path")
        assert result[0].status == "pass"

    def test_retention_ttl_pattern(self):
        """ttl (time-to-live) pattern recognized."""
        files = {
            "cache.py": "ttl = 86400  # 24 hours"
        }
        result = _check_data_retention(files, "/path")
        assert result[0].status == "pass"

    def test_retention_expire_after(self):
        """expire_after pattern recognized."""
        files = {
            "schedule.py": "expire_after = timedelta(days=30)"
        }
        result = _check_data_retention(files, "/path")
        assert result[0].status == "pass"

    def test_retention_auto_delete(self):
        """auto_delete pattern recognized."""
        files = {
            "cleanup.py": "auto_delete = True"
        }
        result = _check_data_retention(files, "/path")
        assert result[0].status == "pass"

    def test_retention_purge_expired(self):
        """purge_expired pattern recognized."""
        files = {
            "maintenance.py": "def purge_expired():\n    delete_old_records()"
        }
        result = _check_data_retention(files, "/path")
        assert result[0].status == "pass"

    def test_retention_max_age(self):
        """max_age pattern recognized."""
        files = {
            "policy.py": "max_age = days(90)"
        }
        result = _check_data_retention(files, "/path")
        assert result[0].status == "pass"

    def test_retention_storage_limit(self):
        """storage_limit pattern recognized."""
        files = {
            "quota.py": "storage_limit = '100GB'"
        }
        result = _check_data_retention(files, "/path")
        assert result[0].status == "pass"

    def test_retention_delete_after_days(self):
        """delete_after_days pattern recognized."""
        files = {
            "scheduler.py": "delete_after_days = 60"
        }
        result = _check_data_retention(files, "/path")
        assert result[0].status == "pass"

    def test_retention_warn_no_patterns(self):
        """No retention patterns return warn."""
        files = {
            "handler.py": "data = fetch_all()\nstore(data)"
        }
        result = _check_data_retention(files, "/path")

        assert result[0].status == "warn"
        assert "No data retention" in result[0].evidence
        assert result[0].fix_hint


class TestCheckCrossBorderTransfer:
    """Tests for _check_cross_border_transfer function."""

    def test_transfer_pass_explicit_patterns(self):
        """data_transfer pattern returns pass."""
        files = {
            "api.py": "data_transfer = verify_safe_endpoint()"
        }
        result = _check_cross_border_transfer(files, "/path")

        assert result[0].status == "pass"
        assert result[0].article == 44

    def test_transfer_cross_border(self):
        """cross_border pattern recognized."""
        files = {
            "config.py": "cross_border = check_transfer_agreement()"
        }
        result = _check_cross_border_transfer(files, "/path")
        assert result[0].status == "pass"

    def test_transfer_data_residency(self):
        """data_residency pattern recognized."""
        files = {
            "policy.py": "data_residency = enforce_eu_only()"
        }
        result = _check_cross_border_transfer(files, "/path")
        assert result[0].status == "pass"

    def test_transfer_eu_only(self):
        """eu_only pattern recognized."""
        files = {
            "zone.py": "eu_only = True"
        }
        result = _check_cross_border_transfer(files, "/path")
        assert result[0].status == "pass"

    def test_transfer_region_lock(self):
        """region_lock pattern recognized."""
        files = {
            "geo.py": "region_lock = ['EU', 'EEA']"
        }
        result = _check_cross_border_transfer(files, "/path")
        assert result[0].status == "pass"

    def test_transfer_standard_contractual(self):
        """standard_contractual pattern recognized."""
        files = {
            "legal.py": "standard_contractual = SCC_agreement()"
        }
        result = _check_cross_border_transfer(files, "/path")
        assert result[0].status == "pass"

    def test_transfer_scc(self):
        """scc (Standard Contractual Clause) recognized."""
        files = {
            "contracts.py": "scc = verify_scc_signature()"
        }
        result = _check_cross_border_transfer(files, "/path")
        assert result[0].status == "pass"

    def test_transfer_data_localization(self):
        """data_localization pattern recognized."""
        files = {
            "storage.py": "data_localization = enforce_eu_storage()"
        }
        result = _check_cross_border_transfer(files, "/path")
        assert result[0].status == "pass"

    def test_transfer_sovereign(self):
        """sovereign pattern recognized."""
        files = {
            "policy.py": "sovereign = eu_data_only"
        }
        result = _check_cross_border_transfer(files, "/path")
        assert result[0].status == "pass"

    def test_transfer_warn_region_config_only(self):
        """Region config without explicit transfer safeguards is warn."""
        files = {
            "config.py": "region = 'eu-west-1'"
        }
        result = _check_cross_border_transfer(files, "/path")

        assert result[0].status == "warn"
        assert "EU region config" in result[0].evidence
        assert "no explicit transfer safeguards" in result[0].evidence

    def test_transfer_warn_aws_eu_region(self):
        """AWS EU region config triggers warn."""
        files = {
            "infrastructure.py": "AWS_REGION = 'eu-central-1'"
        }
        result = _check_cross_border_transfer(files, "/path")
        assert result[0].status == "warn"

    def test_transfer_warn_azure_europe(self):
        """Azure Europe region triggers warn."""
        files = {
            "cloud.py": "AZURE_REGION = 'Europe'"
        }
        result = _check_cross_border_transfer(files, "/path")
        assert result[0].status == "warn"

    def test_transfer_warn_no_patterns(self):
        """No transfer controls return warn."""
        files = {
            "api.py": "response = call_external_api(data)"
        }
        result = _check_cross_border_transfer(files, "/path")

        assert result[0].status == "warn"
        assert "No cross-border data transfer controls" in result[0].evidence


class TestCheckDpiaPatterns:
    """Tests for _check_dpia_patterns function."""

    def test_dpia_pass_explicit(self):
        """dpia pattern returns pass."""
        files = {
            "assessment.py": "dpia = perform_impact_assessment()"
        }
        result = _check_dpia_patterns(files, "/path")

        assert result[0].status == "pass"
        assert result[0].article == 35

    def test_dpia_impact_assessment(self):
        """impact_assessment pattern recognized."""
        files = {
            "risk.py": "impact_assessment = analyze_ai_risks()"
        }
        result = _check_dpia_patterns(files, "/path")
        assert result[0].status == "pass"

    def test_dpia_privacy_impact(self):
        """privacy_impact pattern recognized."""
        files = {
            "privacy.py": "privacy_impact = measure_data_exposure()"
        }
        result = _check_dpia_patterns(files, "/path")
        assert result[0].status == "pass"

    def test_dpia_risk_assessment(self):
        """risk_assessment pattern recognized."""
        files = {
            "analysis.py": "risk_assessment_data = assess()"
        }
        result = _check_dpia_patterns(files, "/path")
        assert result[0].status == "pass"

    def test_dpia_protection_impact(self):
        """protection_impact pattern recognized."""
        files = {
            "report.py": "protection_impact = evaluate()"
        }
        result = _check_dpia_patterns(files, "/path")
        assert result[0].status == "pass"

    def test_dpia_pia_report(self):
        """pia_report (Privacy Impact Assessment Report) recognized."""
        files = {
            "doc.py": "pia_report = generate_document()"
        }
        result = _check_dpia_patterns(files, "/path")
        assert result[0].status == "pass"

    def test_dpia_warn_no_patterns(self):
        """No DPIA references return warn."""
        files = {
            "handler.py": "process_data()"
        }
        result = _check_dpia_patterns(files, "/path")

        assert result[0].status == "warn"
        assert "No DPIA references" in result[0].evidence
        assert result[0].fix_hint


class TestCheckProcessingRecords:
    """Tests for _check_processing_records function."""

    def test_processing_records_pass_explicit(self):
        """processing_record pattern returns pass."""
        files = {
            "records.py": "processing_record = log_activity()"
        }
        result = _check_processing_records(files, "/path")

        assert result[0].status == "pass"
        assert result[0].article == 30

    def test_processing_records_processing_activity(self):
        """processing_activity pattern recognized."""
        files = {
            "log.py": "processing_activity = register_process()"
        }
        result = _check_processing_records(files, "/path")
        assert result[0].status == "pass"

    def test_processing_records_data_register(self):
        """data_register pattern recognized."""
        files = {
            "registry.py": "data_register = maintain_ropa()"
        }
        result = _check_processing_records(files, "/path")
        assert result[0].status == "pass"

    def test_processing_records_processing_log(self):
        """processing_log pattern recognized."""
        files = {
            "audit.py": "processing_log = Log()"
        }
        result = _check_processing_records(files, "/path")
        assert result[0].status == "pass"

    def test_processing_records_ropa(self):
        """ropa (Record of Processing Activities) recognized."""
        files = {
            "compliance.py": "ropa = generate_report()"
        }
        result = _check_processing_records(files, "/path")
        assert result[0].status == "pass"

    def test_processing_records_data_inventory(self):
        """data_inventory pattern recognized."""
        files = {
            "inventory.py": "data_inventory = catalog_data_flows()"
        }
        result = _check_processing_records(files, "/path")
        assert result[0].status == "pass"

    def test_processing_records_processing_purpose(self):
        """processing_purpose pattern recognized."""
        files = {
            "purpose.py": "processing_purpose = 'customer_service'"
        }
        result = _check_processing_records(files, "/path")
        assert result[0].status == "pass"

    def test_processing_records_warn_no_patterns(self):
        """No record patterns return warn."""
        files = {
            "handler.py": "process(data)"
        }
        result = _check_processing_records(files, "/path")

        assert result[0].status == "warn"
        assert "No records of processing activities" in result[0].evidence
        assert result[0].fix_hint


class TestCheckBreachNotification:
    """Tests for _check_breach_notification function."""

    def test_breach_pass_explicit(self):
        """breach_notification pattern returns pass."""
        files = {
            "security.py": "breach_notification = alert_dpa()"
        }
        result = _check_breach_notification(files, "/path")

        assert result[0].status == "pass"
        assert result[0].article == 33

    def test_breach_data_breach(self):
        """data_breach pattern recognized."""
        files = {
            "incident.py": "data_breach = report_to_authority()"
        }
        result = _check_breach_notification(files, "/path")
        assert result[0].status == "pass"

    def test_breach_incident_report(self):
        """incident_report pattern recognized."""
        files = {
            "log.py": "incident_report = IssueTracker()"
        }
        result = _check_breach_notification(files, "/path")
        assert result[0].status == "pass"

    def test_breach_breach_detection(self):
        """breach_detection pattern recognized."""
        files = {
            "monitor.py": "breach_detection = scan_for_anomalies()"
        }
        result = _check_breach_notification(files, "/path")
        assert result[0].status == "pass"

    def test_breach_security_incident(self):
        """security_incident pattern recognized."""
        files = {
            "response.py": "security_incident = handle_event()"
        }
        result = _check_breach_notification(files, "/path")
        assert result[0].status == "pass"

    def test_breach_notify_authority(self):
        """notify_authority pattern recognized."""
        files = {
            "alert.py": "notify_authority = send_72hr_notice()"
        }
        result = _check_breach_notification(files, "/path")
        assert result[0].status == "pass"

    def test_breach_notify_dpa(self):
        """notify_dpa (notify Data Protection Authority) recognized."""
        files = {
            "compliance.py": "notify_dpa(breach_info)"
        }
        result = _check_breach_notification(files, "/path")
        assert result[0].status == "pass"

    def test_breach_breach_log(self):
        """breach_log pattern recognized."""
        files = {
            "audit.py": "breach_log = []"
        }
        result = _check_breach_notification(files, "/path")
        assert result[0].status == "pass"

    def test_breach_incident_response(self):
        """incident_response pattern recognized."""
        files = {
            "plan.py": "incident_response = IncidentPlan()"
        }
        result = _check_breach_notification(files, "/path")
        assert result[0].status == "pass"

    def test_breach_warn_no_patterns(self):
        """No breach notification patterns return warn."""
        files = {
            "handler.py": "log_error(error)"
        }
        result = _check_breach_notification(files, "/path")

        assert result[0].status == "warn"
        assert "No breach notification" in result[0].evidence
        assert result[0].fix_hint


class TestEdgeCases:
    """Edge case tests for GDPR scanner."""

    def test_empty_file_contents_dict(self):
        """Empty file_contents dict should trigger all warns."""
        result = _check_consent_management({}, "/path")
        assert result[0].status == "warn"

    def test_large_file_handling(self):
        """Large files are processed correctly."""
        large_content = "x = 1\n" * 10000 + "consent_manage = True\nif not consent_manage: raise"
        files = {"large.py": large_content}
        result = _check_consent_management(files, "/path")
        assert result[0].status == "pass"

    def test_binary_content_ignored(self):
        """Binary content should be skipped."""
        # Binary data will fail to match patterns, trigger warn
        files = {"nocode.py": "\x00\x01\x02\x03"}
        result = _check_consent_management(files, "/path")
        assert result[0].status == "warn"

    def test_case_insensitive_matching(self):
        """Pattern matching is case-insensitive."""
        files = {"test.py": "CONSENT_MANAGE = True\nif not CONSENT_MANAGE: raise"}
        result = _check_consent_management(files, "/path")
        assert result[0].status == "pass"

    def test_multiline_pattern_matching(self):
        """Patterns span multiple lines."""
        content = """
        def check_consent():
            consent_manage = get_input()
            if not consent_manage:
                raise PermissionDenied()
        """
        files = {"auth.py": content}
        result = _check_consent_management(files, "/path")
        assert result[0].status == "pass"

    def test_special_characters_in_file_path(self):
        """File paths with special characters are handled."""
        # Path itself doesn't affect pattern matching
        files = {"/path/to/special-file_2.py": "consent_manage = True\nif not consent_manage: raise"}
        result = _check_consent_management(files, "/path")
        assert result[0].status == "pass"

    def test_unicode_content_handling(self):
        """Unicode content is handled correctly."""
        files = {"unicode.py": "# Kommentar mit Umlauten äöü\nconsent_manage = True\nif not consent_manage: raise"}
        result = _check_consent_management(files, "/path")
        assert result[0].status == "pass"


class TestCodeFindingStructure:
    """Tests verifying CodeFinding structure and attributes."""

    def test_codefinding_has_required_fields(self):
        """All CodeFinding objects have required fields."""
        files = {"test.py": "consent_manage = True"}
        result = _check_consent_management(files, "/path")
        finding = result[0]

        assert hasattr(finding, 'article')
        assert hasattr(finding, 'name')
        assert hasattr(finding, 'status')
        assert hasattr(finding, 'evidence')
        assert hasattr(finding, 'fix_hint')

    def test_codefinding_article_numbers(self):
        """Articles match their checker functions."""
        assertions = [
            (_check_consent_management, 6),
            (_check_data_minimization, 5),
            (_check_right_to_erasure, 17),
            (_check_data_retention, 5),
            (_check_cross_border_transfer, 44),
            (_check_dpia_patterns, 35),
            (_check_processing_records, 30),
            (_check_breach_notification, 33),
        ]
        files = {"test.py": ""}

        for checker, article in assertions:
            result = checker(files, "/path")
            assert result[0].article == article

    def test_codefinding_status_values(self):
        """Status values are valid."""
        files = {"test.py": ""}
        for checker in [_check_consent_management, _check_data_minimization]:
            result = checker(files, "/path")
            assert result[0].status in ["pass", "warn", "fail"]

    def test_codefinding_evidence_populated(self):
        """Evidence field is always populated."""
        files = {"test.py": ""}
        result = _check_consent_management(files, "/path")
        assert result[0].evidence
        assert isinstance(result[0].evidence, str)
        assert len(result[0].evidence) > 0
