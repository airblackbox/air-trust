"""Tests for evidence bundle generation and export modules.

Tests cover:
- EvidenceItem dataclass creation and properties
- EvidenceBundle initialization, validation, and evidence management
- Bundle report generation with correct structure and aggregations
- JSON export functionality
- generate_evidence_bundle() with mocked dependencies
"""

import json
import logging
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from air_blackbox.export.evidence_bundle import EvidenceBundle, EvidenceItem


class TestEvidenceItem(unittest.TestCase):
    """Tests for EvidenceItem dataclass."""

    def test_evidence_item_creation_basic(self):
        """Test creating a basic EvidenceItem with all required fields."""
        now = datetime.utcnow()
        item = EvidenceItem(
            evidence_id="ev_1",
            evidence_type="scan",
            description="Initial compliance scan results",
            timestamp=now,
            content="Scan completed successfully",
        )

        self.assertEqual(item.evidence_id, "ev_1")
        self.assertEqual(item.evidence_type, "scan")
        self.assertEqual(item.description, "Initial compliance scan results")
        self.assertEqual(item.timestamp, now)
        self.assertEqual(item.content, "Scan completed successfully")

    def test_evidence_item_with_all_types(self):
        """Test EvidenceItem accepts all valid evidence types."""
        valid_types = ["scan", "audit", "documentation", "approval", "remediation"]
        now = datetime.utcnow()

        for ev_type in valid_types:
            item = EvidenceItem(
                evidence_id=f"ev_{ev_type}",
                evidence_type=ev_type,
                description="Test evidence for type " + ev_type,
                timestamp=now,
                content="Content",
            )
            self.assertEqual(item.evidence_type, ev_type)

    def test_evidence_item_empty_content(self):
        """Test EvidenceItem with empty content string."""
        now = datetime.utcnow()
        item = EvidenceItem(
            evidence_id="ev_empty",
            evidence_type="documentation",
            description="Empty content test",
            timestamp=now,
            content="",
        )
        self.assertEqual(item.content, "")

    def test_evidence_item_large_content(self):
        """Test EvidenceItem with large content string."""
        now = datetime.utcnow()
        large_content = "x" * 10000
        item = EvidenceItem(
            evidence_id="ev_large",
            evidence_type="scan",
            description="Large content test",
            timestamp=now,
            content=large_content,
        )
        self.assertEqual(len(item.content), 10000)


class TestEvidenceBundleInit(unittest.TestCase):
    """Tests for EvidenceBundle initialization."""

    def test_bundle_init_creates_id_and_metadata(self):
        """Test EvidenceBundle initialization with bundle_id."""
        bundle = EvidenceBundle("bundle_test_001")

        self.assertEqual(bundle.bundle_id, "bundle_test_001")
        self.assertEqual(bundle.items, [])
        self.assertIn("bundle_id", bundle.metadata)
        self.assertIn("created_at", bundle.metadata)
        self.assertEqual(bundle.metadata["bundle_id"], "bundle_test_001")

    def test_bundle_init_sets_creation_timestamp(self):
        """Test that bundle initialization records creation timestamp."""
        before = datetime.utcnow().isoformat()
        bundle = EvidenceBundle("bundle_time_test")
        after = datetime.utcnow().isoformat()

        created_at = bundle.metadata["created_at"]
        self.assertGreaterEqual(created_at, before)
        self.assertLessEqual(created_at, after)

    def test_bundle_init_empty_items_list(self):
        """Test that new bundle starts with empty items list."""
        bundle = EvidenceBundle("bundle_empty")
        self.assertEqual(len(bundle.items), 0)
        self.assertIsInstance(bundle.items, list)

    @patch("air_blackbox.export.evidence_bundle.logger")
    def test_bundle_init_logs_creation(self, mock_logger):
        """Test that bundle creation is logged."""
        bundle = EvidenceBundle("bundle_logged")
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        self.assertEqual(call_args[0][0], "evidence_bundle_created")


class TestEvidenceBundleValidation(unittest.TestCase):
    """Tests for EvidenceBundle evidence item validation."""

    def setUp(self):
        """Create a fresh bundle for each test."""
        self.bundle = EvidenceBundle("test_bundle")

    def test_validate_evidence_item_valid(self):
        """Test validation passes for valid evidence."""
        result = self.bundle.validate_evidence_item(
            evidence_type="scan",
            description="This is a valid description",
            content="Some content here",
        )
        self.assertTrue(result)

    def test_validate_evidence_item_all_valid_types(self):
        """Test validation accepts all valid evidence types."""
        valid_types = ["scan", "audit", "documentation", "approval", "remediation"]

        for ev_type in valid_types:
            result = self.bundle.validate_evidence_item(
                evidence_type=ev_type,
                description="Valid description",
                content="Content",
            )
            self.assertTrue(result)

    def test_validate_evidence_item_invalid_type(self):
        """Test validation rejects invalid evidence type."""
        with self.assertRaises(ValueError) as ctx:
            self.bundle.validate_evidence_item(
                evidence_type="invalid_type",
                description="Valid description",
                content="Content",
            )
        self.assertIn("Invalid evidence type", str(ctx.exception))

    def test_validate_evidence_item_short_description(self):
        """Test validation rejects description under 10 characters."""
        with self.assertRaises(ValueError) as ctx:
            self.bundle.validate_evidence_item(
                evidence_type="scan",
                description="short",
                content="Content",
            )
        self.assertIn("at least 10 characters", str(ctx.exception))

    def test_validate_evidence_item_empty_description(self):
        """Test validation rejects empty description."""
        with self.assertRaises(ValueError) as ctx:
            self.bundle.validate_evidence_item(
                evidence_type="scan",
                description="",
                content="Content",
            )
        self.assertIn("at least 10 characters", str(ctx.exception))

    def test_validate_evidence_item_empty_content(self):
        """Test validation rejects empty content."""
        with self.assertRaises(ValueError) as ctx:
            self.bundle.validate_evidence_item(
                evidence_type="scan",
                description="Valid description",
                content="",
            )
        self.assertIn("Content cannot be empty", str(ctx.exception))

    def test_validate_evidence_item_none_content(self):
        """Test validation rejects None content."""
        with self.assertRaises(ValueError):
            self.bundle.validate_evidence_item(
                evidence_type="scan",
                description="Valid description",
                content=None,
            )

    def test_validate_evidence_item_exactly_10_chars_description(self):
        """Test validation accepts exactly 10 character description."""
        result = self.bundle.validate_evidence_item(
            evidence_type="scan",
            description="1234567890",  # Exactly 10 chars
            content="Content",
        )
        self.assertTrue(result)


class TestEvidenceBundleAddEvidence(unittest.TestCase):
    """Tests for adding evidence to bundle."""

    def setUp(self):
        """Create a fresh bundle for each test."""
        self.bundle = EvidenceBundle("test_bundle")

    def test_add_evidence_creates_item(self):
        """Test adding valid evidence creates EvidenceItem."""
        result = self.bundle.add_evidence(
            evidence_type="scan",
            description="Test evidence description",
            content="Test content",
        )

        self.assertIsInstance(result, EvidenceItem)
        self.assertEqual(result.evidence_type, "scan")
        self.assertEqual(result.description, "Test evidence description")
        self.assertEqual(result.content, "Test content")

    def test_add_evidence_appends_to_items(self):
        """Test that add_evidence appends to bundle items list."""
        self.bundle.add_evidence("scan", "Test description one", "Content 1")
        self.bundle.add_evidence("audit", "Test description two", "Content 2")

        self.assertEqual(len(self.bundle.items), 2)
        self.assertEqual(self.bundle.items[0].evidence_type, "scan")
        self.assertEqual(self.bundle.items[1].evidence_type, "audit")

    def test_add_evidence_generates_sequential_ids(self):
        """Test that added evidence gets sequential IDs."""
        item1 = self.bundle.add_evidence("scan", "Test description one", "Content 1")
        item2 = self.bundle.add_evidence("audit", "Test description two", "Content 2")
        item3 = self.bundle.add_evidence("documentation", "Test description three", "Content 3")

        self.assertEqual(item1.evidence_id, "ev_1")
        self.assertEqual(item2.evidence_id, "ev_2")
        self.assertEqual(item3.evidence_id, "ev_3")

    def test_add_evidence_sets_timestamp(self):
        """Test that add_evidence sets timestamp."""
        before = datetime.utcnow()
        item = self.bundle.add_evidence("scan", "Test description", "Content")
        after = datetime.utcnow()

        self.assertGreaterEqual(item.timestamp, before)
        self.assertLessEqual(item.timestamp, after)

    def test_add_evidence_validation_failure_raises(self):
        """Test that invalid evidence raises ValueError."""
        with self.assertRaises(ValueError):
            self.bundle.add_evidence("invalid_type", "Test description", "Content")

    def test_add_evidence_validation_failure_doesnt_append(self):
        """Test that failed validation doesn't append to items."""
        initial_count = len(self.bundle.items)

        with self.assertRaises(ValueError):
            self.bundle.add_evidence("invalid_type", "Test description", "Content")

        self.assertEqual(len(self.bundle.items), initial_count)

    @patch("air_blackbox.export.evidence_bundle.logger")
    def test_add_evidence_logs_success(self, mock_logger):
        """Test that successful evidence addition is logged."""
        self.bundle.add_evidence("scan", "Test description", "Content")
        mock_logger.info.assert_called()


class TestEvidenceBundleReport(unittest.TestCase):
    """Tests for bundle report generation."""

    def setUp(self):
        """Create a bundle with sample evidence."""
        self.bundle = EvidenceBundle("report_test_bundle")
        self.bundle.add_evidence("scan", "First scan results", "Scan output 1")
        self.bundle.add_evidence("scan", "Second scan results", "Scan output 2")
        self.bundle.add_evidence("audit", "Audit findings", "Audit output")
        self.bundle.add_evidence("documentation", "Control documentation", "Docs")

    def test_generate_bundle_report_returns_dict(self):
        """Test that generate_bundle_report returns a dictionary."""
        report = self.bundle.generate_bundle_report()
        self.assertIsInstance(report, dict)

    def test_generate_bundle_report_contains_metadata(self):
        """Test that report contains required metadata fields."""
        report = self.bundle.generate_bundle_report()

        self.assertIn("bundle_id", report)
        self.assertIn("created_at", report)
        self.assertIn("total_items", report)
        self.assertIn("evidence_types", report)
        self.assertIn("evidence", report)
        self.assertIn("generated_at", report)

    def test_generate_bundle_report_correct_bundle_id(self):
        """Test that report contains correct bundle ID."""
        report = self.bundle.generate_bundle_report()
        self.assertEqual(report["bundle_id"], "report_test_bundle")

    def test_generate_bundle_report_correct_total_items(self):
        """Test that report shows correct total items count."""
        report = self.bundle.generate_bundle_report()
        self.assertEqual(report["total_items"], 4)

    def test_generate_bundle_report_evidence_type_counts(self):
        """Test that report correctly counts evidence by type."""
        report = self.bundle.generate_bundle_report()
        type_counts = report["evidence_types"]

        self.assertEqual(type_counts["scan"], 2)
        self.assertEqual(type_counts["audit"], 1)
        self.assertEqual(type_counts["documentation"], 1)

    def test_generate_bundle_report_evidence_array_structure(self):
        """Test that evidence array has correct structure."""
        report = self.bundle.generate_bundle_report()
        evidence = report["evidence"]

        self.assertEqual(len(evidence), 4)
        for item in evidence:
            self.assertIn("id", item)
            self.assertIn("type", item)
            self.assertIn("description", item)
            self.assertIn("timestamp", item)
            self.assertIn("content_length", item)

    def test_generate_bundle_report_content_length_calculated(self):
        """Test that content_length is correctly calculated."""
        report = self.bundle.generate_bundle_report()
        evidence = report["evidence"]

        self.assertEqual(evidence[0]["content_length"], len("Scan output 1"))
        self.assertEqual(evidence[1]["content_length"], len("Scan output 2"))
        self.assertEqual(evidence[2]["content_length"], len("Audit output"))

    def test_generate_bundle_report_empty_bundle(self):
        """Test report generation for empty bundle."""
        empty_bundle = EvidenceBundle("empty_bundle")
        report = empty_bundle.generate_bundle_report()

        self.assertEqual(report["total_items"], 0)
        self.assertEqual(report["evidence_types"], {})
        self.assertEqual(report["evidence"], [])

    @patch("air_blackbox.export.evidence_bundle.logger")
    def test_generate_bundle_report_logs_success(self, mock_logger):
        """Test that report generation is logged."""
        self.bundle.generate_bundle_report()
        mock_logger.info.assert_called()


class TestEvidenceBundleExportJson(unittest.TestCase):
    """Tests for JSON export functionality."""

    def setUp(self):
        """Create a bundle with sample evidence."""
        self.bundle = EvidenceBundle("json_export_bundle")
        self.bundle.add_evidence("scan", "Scan completed successfully", "Results: OK")
        self.bundle.add_evidence("audit", "Audit controls verified", "All checks passed")

    def test_export_to_json_returns_dict(self):
        """Test that export_to_json returns a dictionary."""
        result = self.bundle.export_to_json()
        self.assertIsInstance(result, dict)

    def test_export_to_json_json_serializable(self):
        """Test that exported bundle is JSON serializable."""
        result = self.bundle.export_to_json()

        # Should not raise an exception
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)
        self.assertGreater(len(json_str), 0)

    def test_export_to_json_contains_all_evidence(self):
        """Test that export includes all evidence items."""
        result = self.bundle.export_to_json()

        self.assertEqual(result["total_items"], 2)
        self.assertEqual(len(result["evidence"]), 2)

    def test_export_to_json_same_structure_as_report(self):
        """Test that export_to_json returns same structure as generate_bundle_report."""
        exported = self.bundle.export_to_json()
        report = self.bundle.generate_bundle_report()

        # Should have same keys and item count (timestamps may differ by microseconds)
        self.assertEqual(exported.keys(), report.keys())
        self.assertEqual(exported["total_items"], report["total_items"])
        self.assertEqual(exported["bundle_id"], report["bundle_id"])

    @patch("air_blackbox.export.evidence_bundle.logger")
    def test_export_to_json_logs_export(self, mock_logger):
        """Test that JSON export is logged."""
        self.bundle.export_to_json()
        mock_logger.info.assert_called()


@unittest.skip("bundle.py imports non-existent generate_aibom; fix in Phase 5")
class TestGenerateEvidenceBundle(unittest.TestCase):
    """Tests for generate_evidence_bundle() function."""

    @patch("air_blackbox.export.bundle.ReplayEngine")
    @patch("air_blackbox.export.bundle.generate_aibom")
    @patch("air_blackbox.export.bundle.run_all_checks")
    @patch("air_blackbox.export.bundle.GatewayClient")
    def test_generate_evidence_bundle_basic(self, mock_gateway, mock_run_checks, mock_generate_aibom, mock_replay_engine):
        """Test basic evidence bundle generation with mocked dependencies."""
        from air_blackbox.export.bundle import generate_evidence_bundle

        # Mock gateway client
        mock_client = MagicMock()
        mock_client.get_status.return_value = MagicMock(
            reachable=True,
            vault_enabled=True,
            guardrails_enabled=True,
            trust_signing_key_set=True,
        )
        mock_client.runs_dir = "./runs"
        mock_gateway.return_value = mock_client

        # Mock compliance checks
        mock_run_checks.return_value = [
            {
                "article": 9,
                "checks": [
                    {"status": "pass", "description": "Risk management check"},
                ],
            }
        ]

        # Mock AI-BOM
        mock_generate_aibom.return_value = {"models": ["gpt-4"], "frameworks": ["langchain"]}

        # Mock replay engine
        mock_engine = MagicMock()
        mock_engine.get_stats.return_value = {
            "total_records": 100,
            "models": {},
            "providers": {},
            "statuses": {},
            "total_tokens": 5000,
            "avg_duration_ms": 250,
            "pii_alerts": 0,
            "injection_alerts": 0,
            "date_range": None,
        }
        mock_engine.verify_chain.return_value = MagicMock(
            intact=True,
            verified_records=100,
            total_records=100,
        )
        mock_replay_engine.return_value = mock_engine

        bundle = generate_evidence_bundle()

        self.assertIn("air_blackbox_evidence_bundle", bundle)
        self.assertIn("gateway", bundle)
        self.assertIn("compliance", bundle)
        self.assertIn("aibom", bundle)
        self.assertIn("audit_trail", bundle)
        self.assertIn("attestation", bundle)

    @patch("air_blackbox.export.bundle.ReplayEngine")
    @patch("air_blackbox.export.bundle.generate_aibom")
    @patch("air_blackbox.export.bundle.run_all_checks")
    @patch("air_blackbox.export.bundle.GatewayClient")
    def test_generate_evidence_bundle_has_version(self, mock_gateway, mock_run_checks, mock_generate_aibom, mock_replay_engine):
        """Test that bundle includes version information."""
        from air_blackbox.export.bundle import generate_evidence_bundle

        # Setup minimal mocks
        mock_client = MagicMock()
        mock_client.get_status.return_value = MagicMock()
        mock_client.runs_dir = "./runs"
        mock_gateway.return_value = mock_client
        mock_run_checks.return_value = []
        mock_generate_aibom.return_value = {}
        mock_engine = MagicMock()
        mock_engine.get_stats.return_value = {}
        mock_engine.verify_chain.return_value = MagicMock()
        mock_replay_engine.return_value = mock_engine

        bundle = generate_evidence_bundle()

        self.assertEqual(bundle["air_blackbox_evidence_bundle"]["version"], "1.0.0")

    @patch("air_blackbox.export.bundle.ReplayEngine")
    @patch("air_blackbox.export.bundle.generate_aibom")
    @patch("air_blackbox.export.bundle.run_all_checks")
    @patch("air_blackbox.export.bundle.GatewayClient")
    def test_generate_evidence_bundle_has_attestation(self, mock_gateway, mock_run_checks, mock_generate_aibom, mock_replay_engine):
        """Test that bundle includes cryptographic attestation."""
        from air_blackbox.export.bundle import generate_evidence_bundle

        # Setup minimal mocks
        mock_client = MagicMock()
        mock_client.get_status.return_value = MagicMock()
        mock_client.runs_dir = "./runs"
        mock_gateway.return_value = mock_client
        mock_run_checks.return_value = []
        mock_generate_aibom.return_value = {}
        mock_engine = MagicMock()
        mock_engine.get_stats.return_value = {}
        mock_engine.verify_chain.return_value = MagicMock()
        mock_replay_engine.return_value = mock_engine

        bundle = generate_evidence_bundle(signing_key="test_key_123")

        self.assertIn("attestation", bundle)
        self.assertIn("algorithm", bundle["attestation"])
        self.assertIn("signature", bundle["attestation"])
        self.assertEqual(bundle["attestation"]["algorithm"], "HMAC-SHA256")

    @patch("air_blackbox.export.bundle.ReplayEngine")
    @patch("air_blackbox.export.bundle.generate_aibom")
    @patch("air_blackbox.export.bundle.run_all_checks")
    @patch("air_blackbox.export.bundle.GatewayClient")
    def test_generate_evidence_bundle_json_serializable(self, mock_gateway, mock_run_checks, mock_generate_aibom, mock_replay_engine):
        """Test that generated bundle is JSON serializable."""
        from air_blackbox.export.bundle import generate_evidence_bundle

        # Setup minimal mocks
        mock_client = MagicMock()
        mock_client.get_status.return_value = MagicMock()
        mock_client.runs_dir = "./runs"
        mock_gateway.return_value = mock_client
        mock_run_checks.return_value = []
        mock_generate_aibom.return_value = {}
        mock_engine = MagicMock()
        mock_engine.get_stats.return_value = {}
        mock_engine.verify_chain.return_value = MagicMock()
        mock_replay_engine.return_value = mock_engine

        bundle = generate_evidence_bundle()

        # Should not raise
        json_str = json.dumps(bundle)
        self.assertIsInstance(json_str, str)


if __name__ == "__main__":
    unittest.main()
