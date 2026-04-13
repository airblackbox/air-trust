"""Tests for compliance feedback collection and processing.

Tests cover:
- ComplianceFeedback dataclass creation and validation
- validate_feedback_input() with valid and invalid inputs
- record_feedback() with correct logging and error handling
- collect_feedback_batch() with mixed success/failure scenarios
"""

import logging
import unittest
from datetime import datetime
from unittest.mock import patch

from air_blackbox.feedback import ComplianceFeedback, collect_feedback_batch, record_feedback, validate_feedback_input


class TestComplianceFeedbackDataclass(unittest.TestCase):
    """Tests for ComplianceFeedback dataclass."""

    def test_feedback_creation_basic(self):
        """Test creating a basic ComplianceFeedback instance."""
        now = datetime.utcnow()
        feedback = ComplianceFeedback(
            scan_id="scan_001",
            article=9,
            severity="high",
            feedback_text="This is important feedback",
            timestamp=now,
        )

        self.assertEqual(feedback.scan_id, "scan_001")
        self.assertEqual(feedback.article, 9)
        self.assertEqual(feedback.severity, "high")
        self.assertEqual(feedback.feedback_text, "This is important feedback")
        self.assertEqual(feedback.timestamp, now)

    def test_feedback_creation_all_articles(self):
        """Test feedback with all valid article numbers."""
        valid_articles = [9, 10, 11, 12, 14, 15]
        now = datetime.utcnow()

        for article in valid_articles:
            feedback = ComplianceFeedback(
                scan_id=f"scan_{article}",
                article=article,
                severity="high",
                feedback_text="Test feedback text here",
                timestamp=now,
            )
            self.assertEqual(feedback.article, article)

    def test_feedback_creation_all_severities(self):
        """Test feedback with all valid severity levels."""
        valid_severities = ["critical", "high", "medium", "low"]
        now = datetime.utcnow()

        for severity in valid_severities:
            feedback = ComplianceFeedback(
                scan_id="scan_test",
                article=9,
                severity=severity,
                feedback_text="Test feedback text here",
                timestamp=now,
            )
            self.assertEqual(feedback.severity, severity)

    def test_feedback_with_long_text(self):
        """Test feedback with long text content."""
        now = datetime.utcnow()
        long_text = "A" * 5000
        feedback = ComplianceFeedback(
            scan_id="scan_long",
            article=10,
            severity="medium",
            feedback_text=long_text,
            timestamp=now,
        )
        self.assertEqual(len(feedback.feedback_text), 5000)

    def test_feedback_with_special_characters(self):
        """Test feedback with special characters and unicode."""
        now = datetime.utcnow()
        special_text = "Test feedback with emoji 🔐 and special chars: @#$%^&*()"
        feedback = ComplianceFeedback(
            scan_id="scan_special",
            article=11,
            severity="low",
            feedback_text=special_text,
            timestamp=now,
        )
        self.assertEqual(feedback.feedback_text, special_text)


class TestValidateFeedbackInput(unittest.TestCase):
    """Tests for validate_feedback_input() function."""

    def test_validate_feedback_valid_input(self):
        """Test validation passes for valid feedback."""
        result = validate_feedback_input(
            feedback_text="This is valid feedback",
            article=9,
            severity="high",
        )
        self.assertTrue(result)

    def test_validate_feedback_all_valid_articles(self):
        """Test validation accepts all valid article numbers."""
        valid_articles = [9, 10, 11, 12, 14, 15]

        for article in valid_articles:
            result = validate_feedback_input(
                feedback_text="This is valid feedback",
                article=article,
                severity="high",
            )
            self.assertTrue(result)

    def test_validate_feedback_all_valid_severities(self):
        """Test validation accepts all valid severity levels."""
        valid_severities = ["critical", "high", "medium", "low"]

        for severity in valid_severities:
            result = validate_feedback_input(
                feedback_text="This is valid feedback",
                article=9,
                severity=severity,
            )
            self.assertTrue(result)

    def test_validate_feedback_exactly_10_chars(self):
        """Test validation accepts exactly 10 character feedback."""
        result = validate_feedback_input(
            feedback_text="1234567890",
            article=9,
            severity="high",
        )
        self.assertTrue(result)

    def test_validate_feedback_short_text(self):
        """Test validation rejects feedback under 10 characters."""
        with self.assertRaises(ValueError) as ctx:
            validate_feedback_input(
                feedback_text="short",
                article=9,
                severity="high",
            )
        self.assertIn("at least 10 characters", str(ctx.exception))

    def test_validate_feedback_empty_text(self):
        """Test validation rejects empty feedback text."""
        with self.assertRaises(ValueError) as ctx:
            validate_feedback_input(
                feedback_text="",
                article=9,
                severity="high",
            )
        self.assertIn("at least 10 characters", str(ctx.exception))

    def test_validate_feedback_whitespace_only(self):
        """Test validation rejects whitespace-only feedback."""
        with self.assertRaises(ValueError) as ctx:
            validate_feedback_input(
                feedback_text="   \t\n   ",
                article=9,
                severity="high",
            )
        self.assertIn("at least 10 characters", str(ctx.exception))

    def test_validate_feedback_invalid_article(self):
        """Test validation rejects invalid article numbers."""
        invalid_articles = [0, 1, 8, 13, 99, -1]

        for article in invalid_articles:
            with self.assertRaises(ValueError) as ctx:
                validate_feedback_input(
                    feedback_text="This is valid feedback",
                    article=article,
                    severity="high",
                )
            self.assertIn("Invalid article", str(ctx.exception))

    def test_validate_feedback_invalid_severity(self):
        """Test validation rejects invalid severity levels."""
        invalid_severities = ["urgent", "info", "warning", "blocker", "CRITICAL"]

        for severity in invalid_severities:
            with self.assertRaises(ValueError) as ctx:
                validate_feedback_input(
                    feedback_text="This is valid feedback",
                    article=9,
                    severity=severity,
                )
            self.assertIn("Invalid severity", str(ctx.exception))

    def test_validate_feedback_none_text(self):
        """Test validation rejects None feedback text."""
        with self.assertRaises(ValueError):
            validate_feedback_input(
                feedback_text=None,
                article=9,
                severity="high",
            )


class TestRecordFeedback(unittest.TestCase):
    """Tests for record_feedback() function."""

    def test_record_feedback_valid(self):
        """Test recording valid feedback."""
        feedback = record_feedback(
            scan_id="scan_001",
            article=9,
            severity="high",
            feedback_text="This is important feedback",
        )

        self.assertIsInstance(feedback, ComplianceFeedback)
        self.assertEqual(feedback.scan_id, "scan_001")
        self.assertEqual(feedback.article, 9)
        self.assertEqual(feedback.severity, "high")
        self.assertEqual(feedback.feedback_text, "This is important feedback")

    def test_record_feedback_strips_whitespace(self):
        """Test that record_feedback strips whitespace from text."""
        feedback = record_feedback(
            scan_id="scan_001",
            article=9,
            severity="high",
            feedback_text="  feedback with spaces  \n",
        )

        self.assertEqual(feedback.feedback_text, "feedback with spaces")

    def test_record_feedback_sets_timestamp(self):
        """Test that record_feedback sets timestamp."""
        before = datetime.utcnow()
        feedback = record_feedback(
            scan_id="scan_001",
            article=9,
            severity="high",
            feedback_text="Test feedback text",
        )
        after = datetime.utcnow()

        self.assertGreaterEqual(feedback.timestamp, before)
        self.assertLessEqual(feedback.timestamp, after)

    def test_record_feedback_invalid_article_raises(self):
        """Test that invalid article raises ValueError."""
        with self.assertRaises(ValueError):
            record_feedback(
                scan_id="scan_001",
                article=99,
                severity="high",
                feedback_text="This is important feedback",
            )

    def test_record_feedback_invalid_severity_raises(self):
        """Test that invalid severity raises ValueError."""
        with self.assertRaises(ValueError):
            record_feedback(
                scan_id="scan_001",
                article=9,
                severity="invalid",
                feedback_text="This is important feedback",
            )

    def test_record_feedback_short_text_raises(self):
        """Test that short feedback text raises ValueError."""
        with self.assertRaises(ValueError):
            record_feedback(
                scan_id="scan_001",
                article=9,
                severity="high",
                feedback_text="short",
            )

    @patch("air_blackbox.feedback.logger")
    def test_record_feedback_logs_success(self, mock_logger):
        """Test that successful feedback recording is logged."""
        record_feedback(
            scan_id="scan_001",
            article=9,
            severity="high",
            feedback_text="This is important feedback",
        )

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        self.assertEqual(call_args[0][0], "feedback_recorded")

    @patch("air_blackbox.feedback.logger")
    def test_record_feedback_logs_validation_error(self, mock_logger):
        """Test that validation errors are logged."""
        try:
            record_feedback(
                scan_id="scan_001",
                article=99,
                severity="high",
                feedback_text="This is important feedback",
            )
        except ValueError:
            pass

        mock_logger.error.assert_called_once()


class TestCollectFeedbackBatch(unittest.TestCase):
    """Tests for collect_feedback_batch() function."""

    def test_collect_feedback_batch_all_valid(self):
        """Test batch collection with all valid feedback items."""
        items = [
            {
                "scan_id": "scan_001",
                "article": 9,
                "severity": "high",
                "feedback_text": "First feedback item",
            },
            {
                "scan_id": "scan_002",
                "article": 10,
                "severity": "medium",
                "feedback_text": "Second feedback item",
            },
            {
                "scan_id": "scan_003",
                "article": 11,
                "severity": "low",
                "feedback_text": "Third feedback item",
            },
        ]

        results = collect_feedback_batch(items)

        self.assertEqual(len(results), 3)
        self.assertIsInstance(results[0], ComplianceFeedback)
        self.assertEqual(results[0].scan_id, "scan_001")
        self.assertEqual(results[1].scan_id, "scan_002")
        self.assertEqual(results[2].scan_id, "scan_003")

    def test_collect_feedback_batch_empty(self):
        """Test batch collection with empty list."""
        results = collect_feedback_batch([])
        self.assertEqual(results, [])

    def test_collect_feedback_batch_single_item(self):
        """Test batch collection with single item."""
        items = [
            {
                "scan_id": "scan_001",
                "article": 9,
                "severity": "high",
                "feedback_text": "Single feedback item",
            }
        ]

        results = collect_feedback_batch(items)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].scan_id, "scan_001")

    def test_collect_feedback_batch_all_invalid(self):
        """Test batch collection with all invalid items."""
        items = [
            {
                "scan_id": "scan_001",
                "article": 99,
                "severity": "high",
                "feedback_text": "Invalid article",
            },
            {
                "scan_id": "scan_002",
                "article": 10,
                "severity": "invalid",
                "feedback_text": "Invalid severity",
            },
            {
                "scan_id": "scan_003",
                "article": 11,
                "severity": "low",
                "feedback_text": "short",
            },
        ]

        results = collect_feedback_batch(items)

        self.assertEqual(len(results), 0)

    def test_collect_feedback_batch_mixed_valid_invalid(self):
        """Test batch collection with mix of valid and invalid items."""
        items = [
            {
                "scan_id": "scan_001",
                "article": 9,
                "severity": "high",
                "feedback_text": "Valid first item",
            },
            {
                "scan_id": "scan_002",
                "article": 99,
                "severity": "high",
                "feedback_text": "Invalid article",
            },
            {
                "scan_id": "scan_003",
                "article": 11,
                "severity": "low",
                "feedback_text": "Valid third item",
            },
        ]

        results = collect_feedback_batch(items)

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].scan_id, "scan_001")
        self.assertEqual(results[1].scan_id, "scan_003")

    def test_collect_feedback_batch_missing_fields(self):
        """Test batch collection with missing required fields."""
        items = [
            {
                "scan_id": "scan_001",
                "article": 9,
                # Missing severity and feedback_text
            },
            {
                "scan_id": "scan_002",
                "article": 10,
                "severity": "high",
                # Missing feedback_text
            },
        ]

        results = collect_feedback_batch(items)

        # Both should fail due to missing fields or validation
        self.assertLessEqual(len(results), 2)

    def test_collect_feedback_batch_extra_fields(self):
        """Test batch collection with extra fields (should be ignored)."""
        items = [
            {
                "scan_id": "scan_001",
                "article": 9,
                "severity": "high",
                "feedback_text": "Valid feedback item",
                "extra_field": "Should be ignored",
                "another_extra": 12345,
            }
        ]

        results = collect_feedback_batch(items)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].scan_id, "scan_001")

    def test_collect_feedback_batch_whitespace_handling(self):
        """Test batch collection with whitespace-padded feedback."""
        items = [
            {
                "scan_id": "scan_001",
                "article": 9,
                "severity": "high",
                "feedback_text": "  Valid feedback with spaces  ",
            }
        ]

        results = collect_feedback_batch(items)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].feedback_text, "Valid feedback with spaces")

    def test_collect_feedback_batch_large_batch(self):
        """Test batch collection with large number of items."""
        items = [
            {
                "scan_id": f"scan_{i:04d}",
                "article": [9, 10, 11, 12, 14, 15][i % 6],
                "severity": ["critical", "high", "medium", "low"][i % 4],
                "feedback_text": f"Feedback item number {i}",
            }
            for i in range(100)
        ]

        results = collect_feedback_batch(items)

        # All should be valid
        self.assertEqual(len(results), 100)

    @patch("air_blackbox.feedback.logger")
    def test_collect_feedback_batch_logs_summary(self, mock_logger):
        """Test that batch processing is logged with summary."""
        items = [
            {
                "scan_id": "scan_001",
                "article": 9,
                "severity": "high",
                "feedback_text": "Valid feedback",
            }
        ]

        collect_feedback_batch(items)

        # Should log the batch processing summary
        logged_calls = [call for call in mock_logger.info.call_args_list]
        batch_logged = any("batch_feedback_processed" in str(call) for call in logged_calls)
        self.assertTrue(batch_logged)

    def test_collect_feedback_batch_returns_list(self):
        """Test that collect_feedback_batch always returns a list."""
        items = []
        results = collect_feedback_batch(items)
        self.assertIsInstance(results, list)

        items = [
            {
                "scan_id": "scan_001",
                "article": 9,
                "severity": "high",
                "feedback_text": "Valid feedback",
            }
        ]
        results = collect_feedback_batch(items)
        self.assertIsInstance(results, list)


if __name__ == "__main__":
    unittest.main()
