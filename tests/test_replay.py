"""Tests for replay module and engine."""

import pytest
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

from air_blackbox.replay import validate_audit_record, replay_operation, generate_audit_summary
from air_blackbox.replay.engine import AuditRecord, ChainVerification, ReplayEngine


# ============================================================================
# Tests for replay/__init__.py functions
# ============================================================================


class TestValidateAuditRecord:
    """Test validate_audit_record function."""

    def test_validate_audit_record_valid(self):
        """Test validate_audit_record with valid record."""
        record = {
            "timestamp": "2026-01-01T12:00:00Z",
            "operation": "tool_call",
            "status": "success",
        }

        result = validate_audit_record(record)

        assert result is True

    def test_validate_audit_record_with_extra_fields(self):
        """Test validate_audit_record allows extra fields."""
        record = {
            "timestamp": "2026-01-01T12:00:00Z",
            "operation": "scan_code",
            "status": "success",
            "extra_field": "extra_value",
            "another_field": 123,
        }

        result = validate_audit_record(record)

        assert result is True

    def test_validate_audit_record_missing_timestamp(self):
        """Test validate_audit_record rejects missing timestamp."""
        record = {
            "operation": "tool_call",
            "status": "success",
        }

        with pytest.raises(ValueError, match="Missing required audit field: timestamp"):
            validate_audit_record(record)

    def test_validate_audit_record_missing_operation(self):
        """Test validate_audit_record rejects missing operation."""
        record = {
            "timestamp": "2026-01-01T12:00:00Z",
            "status": "success",
        }

        with pytest.raises(ValueError, match="Missing required audit field: operation"):
            validate_audit_record(record)

    def test_validate_audit_record_missing_status(self):
        """Test validate_audit_record rejects missing status."""
        record = {
            "timestamp": "2026-01-01T12:00:00Z",
            "operation": "tool_call",
        }

        with pytest.raises(ValueError, match="Missing required audit field: status"):
            validate_audit_record(record)

    @patch("air_blackbox.replay.logger")
    def test_validate_audit_record_logs(self, mock_logger):
        """Test validate_audit_record logs on success."""
        record = {
            "timestamp": "2026-01-01T12:00:00Z",
            "operation": "tool_call",
            "status": "success",
        }

        validate_audit_record(record)

        mock_logger.info.assert_called_once_with("audit_record_validated")


class TestReplayOperation:
    """Test replay_operation function."""

    def test_replay_operation_valid(self):
        """Test replay_operation with valid operation record."""
        operation = {
            "timestamp": "2026-01-01T12:00:00Z",
            "operation": "tool_call",
            "status": "success",
        }

        result = replay_operation(operation)

        assert result["status"] == "replayed"
        assert "replay_timestamp" in result
        assert result["original_operation"] == operation

    def test_replay_operation_returns_timestamp(self):
        """Test replay_operation includes replay_timestamp."""
        operation = {
            "timestamp": "2026-01-01T12:00:00Z",
            "operation": "scan_code",
            "status": "success",
        }

        result = replay_operation(operation)

        assert "replay_timestamp" in result
        timestamp_str = result["replay_timestamp"]
        # Verify it's a valid ISO format timestamp
        assert datetime.fromisoformat(timestamp_str)

    def test_replay_operation_preserves_original(self):
        """Test replay_operation preserves original operation."""
        operation = {
            "timestamp": "2026-01-01T12:00:00Z",
            "operation": "analyze_code",
            "status": "error",
            "error_msg": "Timeout occurred",
        }

        result = replay_operation(operation)

        assert result["original_operation"] == operation
        assert result["original_operation"]["error_msg"] == "Timeout occurred"

    def test_replay_operation_invalid_record(self):
        """Test replay_operation with invalid record raises."""
        operation = {
            "operation": "tool_call",
            "status": "success",
            # Missing timestamp
        }

        with pytest.raises(ValueError):
            replay_operation(operation)

    @patch("air_blackbox.replay.logger")
    def test_replay_operation_logs_start(self, mock_logger):
        """Test replay_operation logs operation start."""
        operation = {
            "timestamp": "2026-01-01T12:00:00Z",
            "operation": "scan_file",
            "status": "success",
        }

        replay_operation(operation)

        # Check that operation_replay_started was logged
        calls = [str(call) for call in mock_logger.info.call_args_list]
        assert any("operation_replay_started" in str(call) for call in calls)

    @patch("air_blackbox.replay.logger")
    def test_replay_operation_logs_completion(self, mock_logger):
        """Test replay_operation logs completion."""
        operation = {
            "timestamp": "2026-01-01T12:00:00Z",
            "operation": "validate_code",
            "status": "success",
        }

        replay_operation(operation)

        calls = [str(call) for call in mock_logger.info.call_args_list]
        assert any("operation_replay_completed" in str(call) for call in calls)


class TestGenerateAuditSummary:
    """Test generate_audit_summary function."""

    def test_generate_audit_summary_empty_list(self):
        """Test generate_audit_summary with empty record list."""
        summary = generate_audit_summary([])

        assert summary["total_records"] == 0
        assert summary["successful_operations"] == 0
        assert summary["failed_operations"] == 0
        assert "generated_at" in summary

    def test_generate_audit_summary_all_success(self):
        """Test generate_audit_summary with all successful operations."""
        records = [
            {"timestamp": "2026-01-01T12:00:00Z", "operation": "op1", "status": "success"},
            {"timestamp": "2026-01-01T12:01:00Z", "operation": "op2", "status": "success"},
            {"timestamp": "2026-01-01T12:02:00Z", "operation": "op3", "status": "success"},
        ]

        summary = generate_audit_summary(records)

        assert summary["total_records"] == 3
        assert summary["successful_operations"] == 3
        assert summary["failed_operations"] == 0

    def test_generate_audit_summary_mixed_status(self):
        """Test generate_audit_summary with mixed status records."""
        records = [
            {"timestamp": "2026-01-01T12:00:00Z", "operation": "op1", "status": "success"},
            {"timestamp": "2026-01-01T12:01:00Z", "operation": "op2", "status": "error"},
            {"timestamp": "2026-01-01T12:02:00Z", "operation": "op3", "status": "success"},
            {"timestamp": "2026-01-01T12:03:00Z", "operation": "op4", "status": "error"},
            {"timestamp": "2026-01-01T12:04:00Z", "operation": "op5", "status": "success"},
        ]

        summary = generate_audit_summary(records)

        assert summary["total_records"] == 5
        assert summary["successful_operations"] == 3
        assert summary["failed_operations"] == 2

    def test_generate_audit_summary_missing_status(self):
        """Test generate_audit_summary handles records without status."""
        records = [
            {"timestamp": "2026-01-01T12:00:00Z", "operation": "op1", "status": "success"},
            {"timestamp": "2026-01-01T12:01:00Z", "operation": "op2"},
            {"timestamp": "2026-01-01T12:02:00Z", "operation": "op3", "status": "error"},
        ]

        summary = generate_audit_summary(records)

        assert summary["total_records"] == 3
        assert summary["successful_operations"] == 1
        assert summary["failed_operations"] == 1

    def test_generate_audit_summary_generated_at(self):
        """Test generate_audit_summary includes valid timestamp."""
        records = [
            {"timestamp": "2026-01-01T12:00:00Z", "operation": "op1", "status": "success"},
        ]

        summary = generate_audit_summary(records)

        assert "generated_at" in summary
        # Verify it's a valid ISO format timestamp
        assert datetime.fromisoformat(summary["generated_at"])

    @patch("air_blackbox.replay.logger")
    def test_generate_audit_summary_logs(self, mock_logger):
        """Test generate_audit_summary logs summary."""
        records = [
            {"timestamp": "2026-01-01T12:00:00Z", "operation": "op1", "status": "success"},
            {"timestamp": "2026-01-01T12:01:00Z", "operation": "op2", "status": "error"},
        ]

        generate_audit_summary(records)

        calls = [str(call) for call in mock_logger.info.call_args_list]
        assert any("audit_summary_generated" in str(call) for call in calls)


# ============================================================================
# Tests for replay/engine.py dataclasses and ReplayEngine
# ============================================================================


class TestAuditRecord:
    """Test AuditRecord dataclass."""

    def test_audit_record_creation_minimal(self):
        """Test creating AuditRecord with minimal fields."""
        record = AuditRecord(
            run_id="run_001",
            timestamp="2026-01-01T12:00:00Z",
            model="claude-3-opus",
            provider="anthropic",
            tokens={"input": 100, "output": 50},
            duration_ms=1000,
            status="success",
        )

        assert record.run_id == "run_001"
        assert record.timestamp == "2026-01-01T12:00:00Z"
        assert record.model == "claude-3-opus"
        assert record.provider == "anthropic"
        assert record.duration_ms == 1000
        assert record.status == "success"
        assert record.record_type == "llm_call"

    def test_audit_record_with_tool_calls(self):
        """Test AuditRecord with tool_calls."""
        record = AuditRecord(
            run_id="run_001",
            timestamp="2026-01-01T12:00:00Z",
            model="claude-3-opus",
            provider="anthropic",
            tokens={},
            duration_ms=500,
            status="success",
            tool_calls=["tool_a", "tool_b"],
        )

        assert record.tool_calls == ["tool_a", "tool_b"]

    def test_audit_record_with_alerts(self):
        """Test AuditRecord with PII and injection alerts."""
        record = AuditRecord(
            run_id="run_001",
            timestamp="2026-01-01T12:00:00Z",
            model="claude-3-opus",
            provider="anthropic",
            tokens={},
            duration_ms=500,
            status="success",
            pii_alerts=["email_detected"],
            injection_alerts=["prompt_injection_attempt"],
        )

        assert len(record.pii_alerts) == 1
        assert len(record.injection_alerts) == 1

    def test_audit_record_with_error(self):
        """Test AuditRecord with error message."""
        record = AuditRecord(
            run_id="run_001",
            timestamp="2026-01-01T12:00:00Z",
            model="claude-3-opus",
            provider="anthropic",
            tokens={},
            duration_ms=500,
            status="error",
            error="Timeout after 30s",
        )

        assert record.error == "Timeout after 30s"
        assert record.status == "error"

    def test_audit_record_defaults(self):
        """Test AuditRecord default values."""
        record = AuditRecord(
            run_id="run_001",
            timestamp="2026-01-01T12:00:00Z",
            model="claude-3-opus",
            provider="anthropic",
            tokens={},
            duration_ms=500,
            status="success",
        )

        assert record.tool_calls == []
        assert record.pii_alerts == []
        assert record.injection_alerts == []
        assert record.error == ""
        assert record.raw == {}


class TestChainVerification:
    """Test ChainVerification dataclass."""

    def test_chain_verification_intact(self):
        """Test ChainVerification for intact chain."""
        verification = ChainVerification(
            intact=True,
            total_records=10,
            verified_records=10,
        )

        assert verification.intact is True
        assert verification.total_records == 10
        assert verification.verified_records == 10
        assert verification.first_break_at is None
        assert verification.first_break_run_id is None

    def test_chain_verification_broken(self):
        """Test ChainVerification for broken chain."""
        verification = ChainVerification(
            intact=False,
            total_records=10,
            verified_records=5,
            first_break_at=6,
            first_break_run_id="run_006",
        )

        assert verification.intact is False
        assert verification.verified_records == 5
        assert verification.first_break_at == 6
        assert verification.first_break_run_id == "run_006"


class TestReplayEngine:
    """Test ReplayEngine class."""

    def test_replay_engine_init_default(self):
        """Test ReplayEngine initialization with default runs_dir."""
        engine = ReplayEngine()

        assert engine.runs_dir == "./runs"
        assert engine.records == []
        assert engine._raw_records == []

    def test_replay_engine_init_custom_dir(self):
        """Test ReplayEngine initialization with custom runs_dir."""
        engine = ReplayEngine(runs_dir="/custom/path")

        assert engine.runs_dir == "/custom/path"

    def test_replay_engine_load_no_directory(self):
        """Test load() when runs_dir doesn't exist."""
        engine = ReplayEngine(runs_dir="/nonexistent/path")

        count = engine.load()

        assert count == 0
        assert len(engine.records) == 0

    def test_replay_engine_load_no_files(self):
        """Test load() when directory exists but no .air.json files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ReplayEngine(runs_dir=tmpdir)

            count = engine.load()

            assert count == 0

    def test_replay_engine_load_single_file(self):
        """Test load() with one .air.json file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a sample .air.json file
            record_data = {
                "run_id": "run_001",
                "timestamp": "2026-01-01T12:00:00Z",
                "model": "claude-3-opus",
                "provider": "anthropic",
                "tokens": {"input": 100, "output": 50},
                "duration_ms": 1000,
                "status": "success",
            }
            air_file = os.path.join(tmpdir, "run_001.air.json")
            with open(air_file, "w") as f:
                json.dump(record_data, f)

            engine = ReplayEngine(runs_dir=tmpdir)
            count = engine.load()

            assert count == 1
            assert len(engine.records) == 1
            assert engine.records[0].run_id == "run_001"

    def test_replay_engine_load_multiple_files(self):
        """Test load() with multiple .air.json files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple .air.json files
            for i in range(3):
                record_data = {
                    "run_id": f"run_{i:03d}",
                    "timestamp": f"2026-01-01T12:{i:02d}:00Z",
                    "model": "claude-3-opus",
                    "provider": "anthropic",
                    "tokens": {},
                    "duration_ms": 1000,
                    "status": "success",
                }
                air_file = os.path.join(tmpdir, f"run_{i:03d}.air.json")
                with open(air_file, "w") as f:
                    json.dump(record_data, f)

            engine = ReplayEngine(runs_dir=tmpdir)
            count = engine.load()

            assert count == 3
            assert len(engine.records) == 3

    def test_replay_engine_load_sorted_by_timestamp(self):
        """Test load() sorts records by timestamp."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create files in non-chronological order
            timestamps = ["2026-01-01T12:02:00Z", "2026-01-01T12:00:00Z", "2026-01-01T12:01:00Z"]
            for i, ts in enumerate(timestamps):
                record_data = {
                    "run_id": f"run_{i:03d}",
                    "timestamp": ts,
                    "model": "claude-3-opus",
                    "provider": "anthropic",
                    "tokens": {},
                    "duration_ms": 1000,
                    "status": "success",
                }
                air_file = os.path.join(tmpdir, f"run_{i:03d}.air.json")
                with open(air_file, "w") as f:
                    json.dump(record_data, f)

            engine = ReplayEngine(runs_dir=tmpdir)
            count = engine.load()

            assert count == 3
            # Check sorting by timestamp
            assert engine.records[0].timestamp == "2026-01-01T12:00:00Z"
            assert engine.records[1].timestamp == "2026-01-01T12:01:00Z"
            assert engine.records[2].timestamp == "2026-01-01T12:02:00Z"

    def test_replay_engine_load_skips_invalid_json(self):
        """Test load() skips invalid JSON files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Valid file
            record_data = {
                "run_id": "run_001",
                "timestamp": "2026-01-01T12:00:00Z",
                "model": "claude-3-opus",
                "provider": "anthropic",
                "tokens": {},
                "duration_ms": 1000,
                "status": "success",
            }
            air_file1 = os.path.join(tmpdir, "run_001.air.json")
            with open(air_file1, "w") as f:
                json.dump(record_data, f)

            # Invalid JSON file
            air_file2 = os.path.join(tmpdir, "run_002.air.json")
            with open(air_file2, "w") as f:
                f.write("{ invalid json")

            engine = ReplayEngine(runs_dir=tmpdir)
            count = engine.load()

            assert count == 1
            assert len(engine.records) == 1

    def test_replay_engine_filter_by_model(self):
        """Test filter() by model."""
        with tempfile.TemporaryDirectory() as tmpdir:
            records_data = [
                {
                    "run_id": "run_001",
                    "timestamp": "2026-01-01T12:00:00Z",
                    "model": "claude-3-opus",
                    "provider": "anthropic",
                    "tokens": {},
                    "duration_ms": 1000,
                    "status": "success",
                },
                {
                    "run_id": "run_002",
                    "timestamp": "2026-01-01T12:01:00Z",
                    "model": "claude-3-sonnet",
                    "provider": "anthropic",
                    "tokens": {},
                    "duration_ms": 1000,
                    "status": "success",
                },
                {
                    "run_id": "run_003",
                    "timestamp": "2026-01-01T12:02:00Z",
                    "model": "claude-3-opus",
                    "provider": "anthropic",
                    "tokens": {},
                    "duration_ms": 1000,
                    "status": "success",
                },
            ]
            for i, rec in enumerate(records_data):
                air_file = os.path.join(tmpdir, f"run_{i:03d}.air.json")
                with open(air_file, "w") as f:
                    json.dump(rec, f)

            engine = ReplayEngine(runs_dir=tmpdir)
            engine.load()

            results = engine.filter(model="opus")

            assert len(results) == 2
            assert all("opus" in r.model for r in results)

    def test_replay_engine_filter_by_status(self):
        """Test filter() by status."""
        with tempfile.TemporaryDirectory() as tmpdir:
            records_data = [
                {
                    "run_id": "run_001",
                    "timestamp": "2026-01-01T12:00:00Z",
                    "model": "claude-3-opus",
                    "provider": "anthropic",
                    "tokens": {},
                    "duration_ms": 1000,
                    "status": "success",
                },
                {
                    "run_id": "run_002",
                    "timestamp": "2026-01-01T12:01:00Z",
                    "model": "claude-3-opus",
                    "provider": "anthropic",
                    "tokens": {},
                    "duration_ms": 1000,
                    "status": "error",
                },
            ]
            for i, rec in enumerate(records_data):
                air_file = os.path.join(tmpdir, f"run_{i:03d}.air.json")
                with open(air_file, "w") as f:
                    json.dump(rec, f)

            engine = ReplayEngine(runs_dir=tmpdir)
            engine.load()

            results = engine.filter(status="error")

            assert len(results) == 1
            assert results[0].status == "error"

    def test_replay_engine_filter_by_time_range(self):
        """Test filter() by time range."""
        with tempfile.TemporaryDirectory() as tmpdir:
            records_data = [
                {
                    "run_id": "run_001",
                    "timestamp": "2026-01-01T12:00:00Z",
                    "model": "claude-3-opus",
                    "provider": "anthropic",
                    "tokens": {},
                    "duration_ms": 1000,
                    "status": "success",
                },
                {
                    "run_id": "run_002",
                    "timestamp": "2026-01-01T12:30:00Z",
                    "model": "claude-3-opus",
                    "provider": "anthropic",
                    "tokens": {},
                    "duration_ms": 1000,
                    "status": "success",
                },
                {
                    "run_id": "run_003",
                    "timestamp": "2026-01-01T13:00:00Z",
                    "model": "claude-3-opus",
                    "provider": "anthropic",
                    "tokens": {},
                    "duration_ms": 1000,
                    "status": "success",
                },
            ]
            for i, rec in enumerate(records_data):
                air_file = os.path.join(tmpdir, f"run_{i:03d}.air.json")
                with open(air_file, "w") as f:
                    json.dump(rec, f)

            engine = ReplayEngine(runs_dir=tmpdir)
            engine.load()

            results = engine.filter(since="2026-01-01T12:15:00Z", until="2026-01-01T12:45:00Z")

            assert len(results) == 1
            assert results[0].run_id == "run_002"

    def test_replay_engine_get_run(self):
        """Test get_run() retrieves specific run by ID."""
        with tempfile.TemporaryDirectory() as tmpdir:
            record_data = {
                "run_id": "run_abc123def",
                "timestamp": "2026-01-01T12:00:00Z",
                "model": "claude-3-opus",
                "provider": "anthropic",
                "tokens": {},
                "duration_ms": 1000,
                "status": "success",
            }
            air_file = os.path.join(tmpdir, "run_abc123def.air.json")
            with open(air_file, "w") as f:
                json.dump(record_data, f)

            engine = ReplayEngine(runs_dir=tmpdir)
            engine.load()

            result = engine.get_run("run_abc")

            assert result is not None
            assert result.run_id == "run_abc123def"

    def test_replay_engine_get_run_not_found(self):
        """Test get_run() returns None when run not found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ReplayEngine(runs_dir=tmpdir)
            engine.load()

            result = engine.get_run("nonexistent")

            assert result is None

    def test_replay_engine_verify_chain_empty(self):
        """Test verify_chain() with no records."""
        engine = ReplayEngine()

        verification = engine.verify_chain()

        assert verification.intact is True
        assert verification.total_records == 0
        assert verification.verified_records == 0

    def test_replay_engine_verify_chain_no_hashes(self):
        """Test verify_chain() with records that have no chain_hash field."""
        with tempfile.TemporaryDirectory() as tmpdir:
            records_data = [
                {
                    "run_id": "run_001",
                    "timestamp": "2026-01-01T12:00:00Z",
                    "model": "claude-3-opus",
                    "provider": "anthropic",
                    "tokens": {},
                    "duration_ms": 1000,
                    "status": "success",
                },
                {
                    "run_id": "run_002",
                    "timestamp": "2026-01-01T12:01:00Z",
                    "model": "claude-3-opus",
                    "provider": "anthropic",
                    "tokens": {},
                    "duration_ms": 1000,
                    "status": "success",
                },
            ]
            for i, rec in enumerate(records_data):
                air_file = os.path.join(tmpdir, f"run_{i:03d}.air.json")
                with open(air_file, "w") as f:
                    json.dump(rec, f)

            engine = ReplayEngine(runs_dir=tmpdir)
            engine.load()

            verification = engine.verify_chain()

            assert verification.intact is True
            assert verification.total_records == 2
            assert verification.verified_records == 2

    def test_replay_engine_get_stats_empty(self):
        """Test get_stats() with no records."""
        engine = ReplayEngine()

        stats = engine.get_stats()

        assert stats == {}

    def test_replay_engine_get_stats_with_records(self):
        """Test get_stats() computes statistics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            records_data = [
                {
                    "run_id": "run_001",
                    "timestamp": "2026-01-01T12:00:00Z",
                    "model": "claude-3-opus",
                    "provider": "anthropic",
                    "tokens": {"total": 150},
                    "duration_ms": 1000,
                    "status": "success",
                    "tool_calls": [],
                    "pii_alerts": [],
                    "injection_alerts": [],
                },
                {
                    "run_id": "run_002",
                    "timestamp": "2026-01-01T12:01:00Z",
                    "model": "claude-3-sonnet",
                    "provider": "anthropic",
                    "tokens": {"total": 200},
                    "duration_ms": 2000,
                    "status": "error",
                    "tool_calls": [],
                    "pii_alerts": ["email"],
                    "injection_alerts": [],
                },
            ]
            for i, rec in enumerate(records_data):
                air_file = os.path.join(tmpdir, f"run_{i:03d}.air.json")
                with open(air_file, "w") as f:
                    json.dump(rec, f)

            engine = ReplayEngine(runs_dir=tmpdir)
            engine.load()

            stats = engine.get_stats()

            assert stats["total_records"] == 2
            assert stats["total_tokens"] == 350
            assert stats["total_duration_ms"] == 3000
            assert stats["avg_duration_ms"] == 1500
            assert stats["pii_alerts"] == 1
            assert stats["injection_alerts"] == 0
            assert "claude-3-opus" in stats["models"]
            assert "claude-3-sonnet" in stats["models"]
            assert stats["statuses"]["success"] == 1
            assert stats["statuses"]["error"] == 1

    def test_replay_engine_get_stats_date_range(self):
        """Test get_stats() includes date range."""
        with tempfile.TemporaryDirectory() as tmpdir:
            records_data = [
                {
                    "run_id": "run_001",
                    "timestamp": "2026-01-01T12:00:00Z",
                    "model": "claude-3-opus",
                    "provider": "anthropic",
                    "tokens": {},
                    "duration_ms": 1000,
                    "status": "success",
                },
                {
                    "run_id": "run_002",
                    "timestamp": "2026-01-01T13:00:00Z",
                    "model": "claude-3-opus",
                    "provider": "anthropic",
                    "tokens": {},
                    "duration_ms": 1000,
                    "status": "success",
                },
            ]
            for i, rec in enumerate(records_data):
                air_file = os.path.join(tmpdir, f"run_{i:03d}.air.json")
                with open(air_file, "w") as f:
                    json.dump(rec, f)

            engine = ReplayEngine(runs_dir=tmpdir)
            engine.load()

            stats = engine.get_stats()

            assert stats["date_range"] == ("2026-01-01T12:00:00Z", "2026-01-01T13:00:00Z")

    def test_replay_engine_parse_with_tool_calls(self):
        """Test _parse() correctly extracts tool_calls."""
        with tempfile.TemporaryDirectory() as tmpdir:
            record_data = {
                "run_id": "run_001",
                "timestamp": "2026-01-01T12:00:00Z",
                "model": "claude-3-opus",
                "provider": "anthropic",
                "tokens": {},
                "duration_ms": 1000,
                "status": "success",
                "tool_calls": ["tool_a", "tool_b"],
            }
            air_file = os.path.join(tmpdir, "run_001.air.json")
            with open(air_file, "w") as f:
                json.dump(record_data, f)

            engine = ReplayEngine(runs_dir=tmpdir)
            engine.load()

            assert engine.records[0].tool_calls == ["tool_a", "tool_b"]

    def test_replay_engine_parse_missing_optional_fields(self):
        """Test _parse() handles missing optional fields with defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            record_data = {
                "run_id": "run_001",
                "timestamp": "2026-01-01T12:00:00Z",
                "model": "claude-3-opus",
                "provider": "anthropic",
                "tokens": {},
                "duration_ms": 1000,
                "status": "success",
            }
            air_file = os.path.join(tmpdir, "run_001.air.json")
            with open(air_file, "w") as f:
                json.dump(record_data, f)

            engine = ReplayEngine(runs_dir=tmpdir)
            engine.load()

            record = engine.records[0]
            assert record.tool_calls == []
            assert record.pii_alerts == []
            assert record.injection_alerts == []
            assert record.error == ""
