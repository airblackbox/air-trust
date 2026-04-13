"""Tests for ComplianceHistory and ComplianceScanRecord."""

import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock

from air_blackbox.compliance.history import ComplianceHistory, ComplianceScanRecord


class TestComplianceScanRecord:
    """Test ComplianceScanRecord dataclass."""

    def test_scan_record_creation(self):
        """Test creating a ComplianceScanRecord with valid data."""
        now = datetime.utcnow()
        record = ComplianceScanRecord(
            scan_id="scan_001",
            timestamp=now,
            target="/path/to/file.py",
            articles_checked=[9, 10, 11],
            issues_found=5,
            severity_distribution={"high": 2, "medium": 3},
            remediation_status="pending",
        )

        assert record.scan_id == "scan_001"
        assert record.timestamp == now
        assert record.target == "/path/to/file.py"
        assert record.articles_checked == [9, 10, 11]
        assert record.issues_found == 5
        assert record.severity_distribution == {"high": 2, "medium": 3}
        assert record.remediation_status == "pending"

    def test_scan_record_with_resolved_status(self):
        """Test ComplianceScanRecord with resolved remediation status."""
        now = datetime.utcnow()
        record = ComplianceScanRecord(
            scan_id="scan_002",
            timestamp=now,
            target="module.py",
            articles_checked=[14, 15],
            issues_found=2,
            severity_distribution={"low": 2},
            remediation_status="resolved",
        )

        assert record.remediation_status == "resolved"

    def test_scan_record_with_empty_severity(self):
        """Test ComplianceScanRecord with empty severity distribution."""
        now = datetime.utcnow()
        record = ComplianceScanRecord(
            scan_id="scan_003",
            timestamp=now,
            target="test.py",
            articles_checked=[9],
            issues_found=0,
            severity_distribution={},
            remediation_status="pending",
        )

        assert record.issues_found == 0
        assert record.severity_distribution == {}


class TestComplianceHistoryInit:
    """Test ComplianceHistory initialization."""

    def test_init_creates_empty_records(self):
        """Test that __init__ creates an empty records list."""
        history = ComplianceHistory()
        assert isinstance(history.records, list)
        assert len(history.records) == 0

    @patch("air_blackbox.compliance.history.logger")
    def test_init_logs_message(self, mock_logger):
        """Test that __init__ logs an info message."""
        history = ComplianceHistory()
        mock_logger.info.assert_called_once_with("compliance_history_initialized")


class TestValidateScanRecord:
    """Test ComplianceHistory.validate_scan_record() method."""

    def test_validate_scan_record_valid(self):
        """Test validate_scan_record with valid inputs."""
        history = ComplianceHistory()
        result = history.validate_scan_record(
            scan_id="scan_001",
            target="file.py",
            articles=[9, 10, 11],
        )
        assert result is True

    def test_validate_scan_record_all_articles(self):
        """Test validate_scan_record with all valid articles."""
        history = ComplianceHistory()
        result = history.validate_scan_record(
            scan_id="scan_001",
            target="module.py",
            articles=[9, 10, 11, 12, 14, 15],
        )
        assert result is True

    def test_validate_scan_record_empty_scan_id(self):
        """Test validate_scan_record rejects empty scan_id."""
        history = ComplianceHistory()
        with pytest.raises(ValueError, match="Scan ID must be a non-empty string"):
            history.validate_scan_record(scan_id="", target="file.py", articles=[9])

    def test_validate_scan_record_none_scan_id(self):
        """Test validate_scan_record rejects None scan_id."""
        history = ComplianceHistory()
        with pytest.raises(ValueError, match="Scan ID must be a non-empty string"):
            history.validate_scan_record(scan_id=None, target="file.py", articles=[9])

    def test_validate_scan_record_non_string_scan_id(self):
        """Test validate_scan_record rejects non-string scan_id."""
        history = ComplianceHistory()
        with pytest.raises(ValueError, match="Scan ID must be a non-empty string"):
            history.validate_scan_record(scan_id=123, target="file.py", articles=[9])

    def test_validate_scan_record_empty_target(self):
        """Test validate_scan_record rejects empty target."""
        history = ComplianceHistory()
        with pytest.raises(ValueError, match="Target must be a non-empty string"):
            history.validate_scan_record(scan_id="scan_001", target="", articles=[9])

    def test_validate_scan_record_none_target(self):
        """Test validate_scan_record rejects None target."""
        history = ComplianceHistory()
        with pytest.raises(ValueError, match="Target must be a non-empty string"):
            history.validate_scan_record(scan_id="scan_001", target=None, articles=[9])

    def test_validate_scan_record_non_string_target(self):
        """Test validate_scan_record rejects non-string target."""
        history = ComplianceHistory()
        with pytest.raises(ValueError, match="Target must be a non-empty string"):
            history.validate_scan_record(scan_id="scan_001", target=456, articles=[9])

    def test_validate_scan_record_empty_articles(self):
        """Test validate_scan_record rejects empty articles list."""
        history = ComplianceHistory()
        with pytest.raises(ValueError, match="Articles must be a non-empty list"):
            history.validate_scan_record(scan_id="scan_001", target="file.py", articles=[])

    def test_validate_scan_record_none_articles(self):
        """Test validate_scan_record rejects None articles."""
        history = ComplianceHistory()
        with pytest.raises(ValueError, match="Articles must be a non-empty list"):
            history.validate_scan_record(scan_id="scan_001", target="file.py", articles=None)

    def test_validate_scan_record_non_list_articles(self):
        """Test validate_scan_record rejects non-list articles."""
        history = ComplianceHistory()
        with pytest.raises(ValueError, match="Articles must be a non-empty list"):
            history.validate_scan_record(scan_id="scan_001", target="file.py", articles="9,10")

    def test_validate_scan_record_invalid_article_number(self):
        """Test validate_scan_record rejects invalid article numbers."""
        history = ComplianceHistory()
        with pytest.raises(ValueError, match="Invalid article: 99"):
            history.validate_scan_record(scan_id="scan_001", target="file.py", articles=[9, 99])

    def test_validate_scan_record_article_13(self):
        """Test validate_scan_record rejects article 13 (not in scope)."""
        history = ComplianceHistory()
        with pytest.raises(ValueError, match="Invalid article: 13"):
            history.validate_scan_record(scan_id="scan_001", target="file.py", articles=[13])


class TestLogAction:
    """Test ComplianceHistory.log_action() method."""

    @patch("air_blackbox.compliance.history.logger")
    def test_log_action_scan_type(self, mock_logger):
        """Test log_action with scan action type."""
        history = ComplianceHistory()
        mock_logger.reset_mock()
        details = {"scan_id": "scan_001", "target": "file.py"}

        history.log_action("scan", details)

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert call_args[0][0] == "audit_log:scan"

    @patch("air_blackbox.compliance.history.logger")
    def test_log_action_remediation_type(self, mock_logger):
        """Test log_action with remediation action type."""
        history = ComplianceHistory()
        mock_logger.reset_mock()
        details = {"scan_id": "scan_001", "status": "resolved"}

        history.log_action("remediation", details)

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert call_args[0][0] == "audit_log:remediation"

    @patch("air_blackbox.compliance.history.logger")
    def test_log_action_includes_timestamp(self, mock_logger):
        """Test that log_action includes timestamp in extra dict."""
        history = ComplianceHistory()
        details = {"key": "value"}

        history.log_action("test", details)

        call_args = mock_logger.info.call_args
        assert "timestamp" in call_args[1]["extra"]


class TestRecordScan:
    """Test ComplianceHistory.record_scan() method."""

    def test_record_scan_valid(self):
        """Test record_scan with valid inputs."""
        history = ComplianceHistory()
        record = history.record_scan(
            scan_id="scan_001",
            target="file.py",
            articles=[9, 10],
            issues_found=3,
            severity_dist={"high": 1, "medium": 2},
        )

        assert record.scan_id == "scan_001"
        assert record.target == "file.py"
        assert record.articles_checked == [9, 10]
        assert record.issues_found == 3
        assert record.remediation_status == "pending"
        assert len(history.records) == 1

    def test_record_scan_stores_in_history(self):
        """Test that record_scan stores record in history."""
        history = ComplianceHistory()
        record1 = history.record_scan(
            scan_id="scan_001",
            target="file1.py",
            articles=[9],
            issues_found=1,
            severity_dist={"low": 1},
        )
        record2 = history.record_scan(
            scan_id="scan_002",
            target="file2.py",
            articles=[10],
            issues_found=2,
            severity_dist={"high": 2},
        )

        assert len(history.records) == 2
        assert history.records[0] == record1
        assert history.records[1] == record2

    def test_record_scan_sets_remediation_pending(self):
        """Test that record_scan sets remediation_status to pending."""
        history = ComplianceHistory()
        record = history.record_scan(
            scan_id="scan_001",
            target="file.py",
            articles=[9],
            issues_found=0,
            severity_dist={},
        )

        assert record.remediation_status == "pending"

    def test_record_scan_timestamps_record(self):
        """Test that record_scan sets timestamp."""
        history = ComplianceHistory()
        before = datetime.utcnow()
        record = history.record_scan(
            scan_id="scan_001",
            target="file.py",
            articles=[9],
            issues_found=1,
            severity_dist={"high": 1},
        )
        after = datetime.utcnow()

        assert before <= record.timestamp <= after

    @patch("air_blackbox.compliance.history.logger")
    def test_record_scan_logs_action(self, mock_logger):
        """Test that record_scan logs action."""
        history = ComplianceHistory()
        history.record_scan(
            scan_id="scan_001",
            target="file.py",
            articles=[9, 10],
            issues_found=3,
            severity_dist={"high": 1},
        )

        # Check that log_action was called (it logs twice: info + extra)
        assert mock_logger.info.called

    def test_record_scan_invalid_scan_id(self):
        """Test record_scan raises on invalid scan_id."""
        history = ComplianceHistory()
        with pytest.raises(ValueError):
            history.record_scan(
                scan_id="",
                target="file.py",
                articles=[9],
                issues_found=1,
                severity_dist={"high": 1},
            )

    def test_record_scan_invalid_articles(self):
        """Test record_scan raises on invalid articles."""
        history = ComplianceHistory()
        with pytest.raises(ValueError):
            history.record_scan(
                scan_id="scan_001",
                target="file.py",
                articles=[99],
                issues_found=1,
                severity_dist={"high": 1},
            )


class TestUpdateRemediationStatus:
    """Test ComplianceHistory.update_remediation_status() method."""

    def test_update_remediation_status_existing_scan(self):
        """Test update_remediation_status for existing scan."""
        history = ComplianceHistory()
        history.record_scan(
            scan_id="scan_001",
            target="file.py",
            articles=[9],
            issues_found=1,
            severity_dist={"high": 1},
        )

        history.update_remediation_status("scan_001", "resolved")

        assert history.records[0].remediation_status == "resolved"

    def test_update_remediation_status_to_in_progress(self):
        """Test updating status to in_progress."""
        history = ComplianceHistory()
        history.record_scan(
            scan_id="scan_001",
            target="file.py",
            articles=[9],
            issues_found=1,
            severity_dist={"high": 1},
        )

        history.update_remediation_status("scan_001", "in_progress")

        assert history.records[0].remediation_status == "in_progress"

    def test_update_remediation_status_with_notes(self):
        """Test update_remediation_status with optional notes."""
        history = ComplianceHistory()
        history.record_scan(
            scan_id="scan_001",
            target="file.py",
            articles=[9],
            issues_found=1,
            severity_dist={"high": 1},
        )

        history.update_remediation_status("scan_001", "resolved", notes="Fixed validation logic")

        assert history.records[0].remediation_status == "resolved"

    @patch("air_blackbox.compliance.history.logger")
    def test_update_remediation_status_nonexistent_scan(self, mock_logger):
        """Test update_remediation_status for nonexistent scan logs warning."""
        history = ComplianceHistory()
        history.update_remediation_status("nonexistent", "resolved")

        mock_logger.warning.assert_called_once()
        assert "scan_not_found_for_update" in str(mock_logger.warning.call_args)

    @patch("air_blackbox.compliance.history.logger")
    def test_update_remediation_status_logs_action(self, mock_logger):
        """Test that update_remediation_status logs action."""
        history = ComplianceHistory()
        history.record_scan(
            scan_id="scan_001",
            target="file.py",
            articles=[9],
            issues_found=1,
            severity_dist={"high": 1},
        )
        mock_logger.reset_mock()

        history.update_remediation_status("scan_001", "resolved", notes="Done")

        assert mock_logger.info.called


class TestGetScanHistory:
    """Test ComplianceHistory.get_scan_history() method."""

    def test_get_scan_history_all_records(self):
        """Test get_scan_history returns all records when no filter."""
        history = ComplianceHistory()
        history.record_scan("scan_001", "file.py", [9], 1, {"high": 1})
        history.record_scan("scan_002", "module.py", [10], 2, {"medium": 2})
        history.record_scan("scan_003", "test.py", [11], 3, {"low": 3})

        results = history.get_scan_history()

        assert len(results) == 3

    def test_get_scan_history_filtered_by_target(self):
        """Test get_scan_history filters by target."""
        history = ComplianceHistory()
        history.record_scan("scan_001", "file.py", [9], 1, {"high": 1})
        history.record_scan("scan_002", "module.py", [10], 2, {"medium": 2})
        history.record_scan("scan_003", "file_test.py", [11], 3, {"low": 3})

        results = history.get_scan_history(target="file")

        assert len(results) == 2
        assert all("file" in r.target for r in results)

    def test_get_scan_history_empty_filter_match(self):
        """Test get_scan_history with filter that matches nothing."""
        history = ComplianceHistory()
        history.record_scan("scan_001", "file.py", [9], 1, {"high": 1})
        history.record_scan("scan_002", "module.py", [10], 2, {"medium": 2})

        results = history.get_scan_history(target="nonexistent")

        assert len(results) == 0

    def test_get_scan_history_empty_records(self):
        """Test get_scan_history on empty history."""
        history = ComplianceHistory()

        results = history.get_scan_history()

        assert len(results) == 0

    @patch("air_blackbox.compliance.history.logger")
    def test_get_scan_history_logs_all(self, mock_logger):
        """Test get_scan_history logs when returning all records."""
        history = ComplianceHistory()
        history.record_scan("scan_001", "file.py", [9], 1, {"high": 1})
        mock_logger.reset_mock()

        history.get_scan_history()

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert "history_retrieved_all" in str(call_args)

    @patch("air_blackbox.compliance.history.logger")
    def test_get_scan_history_logs_filtered(self, mock_logger):
        """Test get_scan_history logs when filtered."""
        history = ComplianceHistory()
        history.record_scan("scan_001", "file.py", [9], 1, {"high": 1})
        mock_logger.reset_mock()

        history.get_scan_history(target="file")

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert "history_retrieved_filtered" in str(call_args)


class TestGenerateAuditReport:
    """Test ComplianceHistory.generate_audit_report() method."""

    def test_generate_audit_report_empty_history(self):
        """Test generate_audit_report with empty history."""
        history = ComplianceHistory()

        report = history.generate_audit_report()

        assert report["total_scans"] == 0
        assert report["total_issues_found"] == 0
        assert report["resolved_scans"] == 0
        assert report["pending_scans"] == 0
        assert report["scan_records"] == []

    def test_generate_audit_report_with_scans(self):
        """Test generate_audit_report with multiple scans."""
        history = ComplianceHistory()
        history.record_scan("scan_001", "file.py", [9], 3, {"high": 1, "medium": 2})
        history.record_scan("scan_002", "module.py", [10], 2, {"low": 2})

        report = history.generate_audit_report()

        assert report["total_scans"] == 2
        assert report["total_issues_found"] == 5
        assert report["pending_scans"] == 2
        assert report["resolved_scans"] == 0

    def test_generate_audit_report_tracks_resolved(self):
        """Test generate_audit_report counts resolved scans."""
        history = ComplianceHistory()
        history.record_scan("scan_001", "file.py", [9], 3, {"high": 1})
        history.record_scan("scan_002", "module.py", [10], 2, {"low": 2})

        history.update_remediation_status("scan_001", "resolved")

        report = history.generate_audit_report()

        assert report["total_scans"] == 2
        assert report["resolved_scans"] == 1
        assert report["pending_scans"] == 1

    def test_generate_audit_report_includes_timestamp(self):
        """Test generate_audit_report includes generated_at timestamp."""
        history = ComplianceHistory()
        history.record_scan("scan_001", "file.py", [9], 1, {"high": 1})

        report = history.generate_audit_report()

        assert "generated_at" in report
        assert isinstance(report["generated_at"], str)

    def test_generate_audit_report_scan_records_format(self):
        """Test generate_audit_report scan_records have correct format."""
        history = ComplianceHistory()
        history.record_scan("scan_001", "file.py", [9, 10], 3, {"high": 1, "medium": 2})

        report = history.generate_audit_report()

        assert len(report["scan_records"]) == 1
        record = report["scan_records"][0]
        assert record["scan_id"] == "scan_001"
        assert record["target"] == "file.py"
        assert record["articles"] == [9, 10]
        assert record["issues"] == 3
        assert record["status"] == "pending"
        assert "timestamp" in record

    @patch("air_blackbox.compliance.history.logger")
    def test_generate_audit_report_logs_action(self, mock_logger):
        """Test generate_audit_report logs action."""
        history = ComplianceHistory()
        history.record_scan("scan_001", "file.py", [9], 1, {"high": 1})
        mock_logger.reset_mock()

        history.generate_audit_report()

        assert mock_logger.info.called
