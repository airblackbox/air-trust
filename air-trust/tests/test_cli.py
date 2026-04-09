"""Tests for the CLI interface."""

import json
import csv
import os
import subprocess
import sys
from pathlib import Path
import pytest
import io

from air_trust.chain import AuditChain
from air_trust.events import Event


@pytest.fixture
def temp_dir(tmp_path):
    """Use pytest's built-in tmp_path which handles cleanup."""
    return str(tmp_path)


@pytest.fixture
def populated_chain(temp_dir, monkeypatch):
    """Create a chain with test data."""
    db_path = os.path.join(temp_dir, "events.db")

    # Set the signing key via environment variable so CLI uses the same key
    signing_key = "test-cli-key-fixed-for-verification"
    monkeypatch.setenv("AIR_TRUST_KEY", signing_key)

    # Create chain with the fixed key
    chain = AuditChain(db_path=db_path, signing_key=signing_key)

    # Add some events
    for i in range(5):
        event = Event(
            type="llm_call",
            framework="openai",
            model="gpt-4o",
            description=f"Test event {i}",
            tokens={"prompt": 100, "completion": 50, "total": 150},
        )
        chain.write(event)

    return db_path


class TestCLIVerify:
    """Test the verify command."""

    def test_verify_default_nonexistent(self):
        """Verify should exit 1 if database doesn't exist."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "verify", "--db", "/tmp/nonexistent_air_trust_db.db"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "not found" in result.stdout.lower() or "error" in result.stdout.lower()

    def test_verify_valid_chain(self, populated_chain):
        """Verify should exit 0 for a valid chain."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "verify", "--db", populated_chain],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "PASS" in result.stdout
        assert "intact" in result.stdout.lower()
        assert "5" in result.stdout  # 5 records

    def test_verify_broken_chain(self, temp_dir):
        """Verify should detect tampering."""
        db_path = os.path.join(temp_dir, "tampered.db")
        chain = AuditChain(db_path=db_path, signing_key="tamper-key")

        for i in range(3):
            chain.write(Event(type="llm_call", framework="openai"))

        # Tamper with the database
        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE events SET data = REPLACE(data, 'llm_call', 'tampered') WHERE rowid = 2")
        conn.commit()
        conn.close()

        # Verify should detect it
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "verify", "--db", db_path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "FAIL" in result.stdout
        assert "broken" in result.stdout.lower()

    def test_verify_empty_chain(self, temp_dir):
        """Verify should handle empty chain."""
        db_path = os.path.join(temp_dir, "empty.db")
        chain = AuditChain(db_path=db_path, signing_key="empty-key")
        # Don't write anything

        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "verify", "--db", db_path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "PASS" in result.stdout
        assert "0" in result.stdout


class TestCLIStats:
    """Test the stats command."""

    def test_stats_nonexistent_db(self):
        """Stats should handle missing database."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "stats", "--db", "/tmp/nonexistent_air_trust_stats.db"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1

    def test_stats_populated_chain(self, populated_chain):
        """Stats should show chain information."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "stats", "--db", populated_chain],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Total Events" in result.stdout or "total" in result.stdout.lower()
        assert "5" in result.stdout
        assert "openai" in result.stdout.lower()
        assert "VALID" in result.stdout or "valid" in result.stdout.lower()

    def test_stats_empty_chain(self, temp_dir):
        """Stats should handle empty chain."""
        db_path = os.path.join(temp_dir, "empty.db")
        chain = AuditChain(db_path=db_path, signing_key="empty-key")

        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "stats", "--db", db_path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "0" in result.stdout


class TestCLIExport:
    """Test the export command."""

    def test_export_json_default(self, populated_chain):
        """Export should produce valid JSON by default."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "export", "--db", populated_chain],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0

        # Parse as JSON
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) == 5

        # Check record structure
        for record in data:
            assert "id" in record or "type" in record
            assert "chain_hash" in record or "data" in record

    def test_export_json_explicit(self, populated_chain):
        """Export with --format json should work."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "export", "--db", populated_chain, "--format", "json"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) == 5

    def test_export_csv(self, populated_chain):
        """Export as CSV should work."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "export", "--db", populated_chain, "--format", "csv"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0

        # Parse as CSV
        reader = csv.DictReader(io.StringIO(result.stdout))
        rows = list(reader)
        assert len(rows) == 5

        # Check headers exist
        assert reader.fieldnames is not None
        assert len(reader.fieldnames) > 0

    def test_export_csv_has_chain_hash(self, populated_chain):
        """Exported CSV should include chain_hash."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "export", "--db", populated_chain, "--format", "csv"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        # Chain hash should be in output
        assert "chain_hash" in result.stdout or result.stdout.count("-") > 10  # hex digits

    def test_export_empty_chain(self, temp_dir):
        """Export should handle empty chain."""
        db_path = os.path.join(temp_dir, "empty.db")
        chain = AuditChain(db_path=db_path, signing_key="empty-key")

        # JSON export
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "export", "--db", db_path, "--format", "json"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data == []

        # CSV export
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "export", "--db", db_path, "--format", "csv"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert result.stdout.strip() == ""

    def test_export_nonexistent_db(self):
        """Export should handle missing database."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "export", "--db", "/tmp/nonexistent_air_trust_export.db"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1

    def test_export_invalid_format(self, populated_chain):
        """Export should reject invalid formats."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "export", "--db", populated_chain, "--format", "xml"],
            capture_output=True,
            text=True,
        )
        # argparse returns 2 for argument errors
        assert result.returncode == 2
        assert "invalid choice" in result.stderr or "Unknown format" in result.stderr


class TestCLINoCommand:
    """Test CLI with no command."""

    def test_help_with_no_command(self):
        """Running with no command should show help."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust"],
            capture_output=True,
            text=True,
        )
        assert "usage" in result.stdout.lower() or "help" in result.stdout.lower()

    def test_help_flag(self):
        """--help should show help."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "usage" in result.stdout.lower() or "verify" in result.stdout.lower()


class TestCLIIntegration:
    """Integration tests combining multiple commands."""

    def test_verify_then_export(self, populated_chain):
        """Should be able to verify and export the same chain."""
        # Verify
        verify_result = subprocess.run(
            [sys.executable, "-m", "air_trust", "verify", "--db", populated_chain],
            capture_output=True,
            text=True,
        )
        assert verify_result.returncode == 0

        # Export
        export_result = subprocess.run(
            [sys.executable, "-m", "air_trust", "export", "--db", populated_chain, "--format", "json"],
            capture_output=True,
            text=True,
        )
        assert export_result.returncode == 0
        data = json.loads(export_result.stdout)
        assert len(data) == 5

    def test_stats_matches_export_count(self, populated_chain):
        """Stats and export should report same record count."""
        # Get stats
        stats_result = subprocess.run(
            [sys.executable, "-m", "air_trust", "stats", "--db", populated_chain],
            capture_output=True,
            text=True,
        )
        assert "5" in stats_result.stdout

        # Get export
        export_result = subprocess.run(
            [sys.executable, "-m", "air_trust", "export", "--db", populated_chain],
            capture_output=True,
            text=True,
        )
        data = json.loads(export_result.stdout)
        assert len(data) == 5


class TestCLIRegister:
    """Test the register command."""

    def test_register_command_exists(self):
        """Register command should be in help output."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "register" in result.stdout.lower()

    def test_register_help(self):
        """Register command should have help text."""
        result = subprocess.run(
            [sys.executable, "-m", "air_trust", "register", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "register" in result.stdout.lower() or "Registration" in result.stdout
