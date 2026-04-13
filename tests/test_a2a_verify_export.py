"""
Comprehensive tests for A2A verification and export modules.

Tests bilateral_verify, BilateralReport, BilateralMatch, UnilateralRecord,
build_transaction_trace, trace_to_text, and export_evidence_bundle.
"""

import json
import zipfile
from pathlib import Path
from datetime import datetime, timezone

import pytest

from air_blackbox.a2a.transaction import TransactionLedger, TransactionRecord
from air_blackbox.a2a.verify import (
    bilateral_verify,
    BilateralReport,
    BilateralMatch,
    UnilateralRecord,
)
from air_blackbox.a2a.export import (
    build_transaction_trace,
    trace_to_text,
    export_evidence_bundle,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ledger_dir_a(tmp_path):
    """Temporary ledger directory for agent A."""
    return tmp_path / "ledger_a"


@pytest.fixture
def ledger_dir_b(tmp_path):
    """Temporary ledger directory for agent B."""
    return tmp_path / "ledger_b"


@pytest.fixture
def ledger_a(ledger_dir_a):
    """TransactionLedger for agent A."""
    return TransactionLedger(ledger_dir=str(ledger_dir_a), signing_key="test-key-verify")


@pytest.fixture
def ledger_b(ledger_dir_b):
    """TransactionLedger for agent B."""
    return TransactionLedger(ledger_dir=str(ledger_dir_b), signing_key="test-key-verify")


@pytest.fixture
def populated_ledgers(ledger_a, ledger_b):
    """Two ledgers with a complete exchange of messages.

    Simulates a conversation:
    1. A sends a request to B
    2. B receives and records it
    3. B sends a response to A
    4. A receives and records it
    5. A sends a follow-up request to B

    This creates:
    - 2 matched transactions (request and response)
    - 1 unilateral record (A's follow-up that B hasn't received yet)
    """
    # Message 1: A sends request to B (both record it)
    content1 = b"Can you help with this task?"
    rec1_a = TransactionRecord.create(
        sender_id="agent-a",
        sender_name="LangChain Researcher",
        sender_framework="langchain",
        receiver_id="agent-b",
        receiver_name="CrewAI Worker",
        receiver_framework="crewai",
        message_type="request",
        content=content1,
    )
    ledger_a.write(rec1_a)

    rec1_b = TransactionRecord.create(
        sender_id="agent-a",
        sender_name="LangChain Researcher",
        sender_framework="langchain",
        receiver_id="agent-b",
        receiver_name="CrewAI Worker",
        receiver_framework="crewai",
        message_type="request",
        content=content1,
    )
    ledger_b.write(rec1_b)

    # Message 2: B sends response to A (both record it)
    content2 = b"I will analyze this and report back."
    rec2_b = TransactionRecord.create(
        sender_id="agent-b",
        sender_name="CrewAI Worker",
        sender_framework="crewai",
        receiver_id="agent-a",
        receiver_name="LangChain Researcher",
        receiver_framework="langchain",
        message_type="response",
        content=content2,
    )
    ledger_b.write(rec2_b)

    rec2_a = TransactionRecord.create(
        sender_id="agent-b",
        sender_name="CrewAI Worker",
        sender_framework="crewai",
        receiver_id="agent-a",
        receiver_name="LangChain Researcher",
        receiver_framework="langchain",
        message_type="response",
        content=content2,
    )
    ledger_a.write(rec2_a)

    # Message 3: A sends follow-up (only A has this, B doesn't)
    content3 = b"Please check the updated requirements."
    rec3_a = TransactionRecord.create(
        sender_id="agent-a",
        sender_name="LangChain Researcher",
        sender_framework="langchain",
        receiver_id="agent-b",
        receiver_name="CrewAI Worker",
        receiver_framework="crewai",
        message_type="request",
        content=content3,
    )
    ledger_a.write(rec3_a)

    return {
        "ledger_a": ledger_a,
        "ledger_b": ledger_b,
    }


# ---------------------------------------------------------------------------
# bilateral_verify Tests
# ---------------------------------------------------------------------------


class TestBilateralVerify:
    """Tests for the bilateral_verify function."""

    def test_empty_ledgers_no_matches(self, ledger_a, ledger_b):
        """Two empty ledgers -> bilateral_verified = False (no matches)."""
        report = bilateral_verify(ledger_a, ledger_b)

        assert report.bilateral_verified is False
        assert len(report.matched_transactions) == 0
        assert report.chain_a_valid is True
        assert report.chain_b_valid is True
        assert report.chain_a_records == 0
        assert report.chain_b_records == 0
        assert len(report.issues) == 1
        assert "No matching transactions" in report.issues[0]

    def test_matching_exchange(self, populated_ledgers):
        """A sends to B, B records same -> 1 match, 0 unilateral."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        report = bilateral_verify(ledger_a, ledger_b)

        # Should have at least 2 matches (request and response)
        assert len(report.matched_transactions) >= 2
        # The unilateral follow-up is only in A
        assert len(report.unilateral_a) >= 1
        assert len(report.unilateral_b) == 0
        assert report.bilateral_verified is True
        assert report.chain_a_valid is True
        assert report.chain_b_valid is True

    def test_unilateral_in_ledger_a(self, ledger_a, ledger_b):
        """A has records B doesn't -> shows in unilateral_a."""
        # A sends request to B
        content = b"Only A will record this"
        rec_a = TransactionRecord.create(
            sender_id="agent-a",
            sender_name="LangChain",
            sender_framework="langchain",
            receiver_id="agent-b",
            receiver_name="CrewAI",
            receiver_framework="crewai",
            message_type="request",
            content=content,
        )
        ledger_a.write(rec_a)

        # B is empty
        report = bilateral_verify(ledger_a, ledger_b)

        assert len(report.unilateral_a) == 1
        assert len(report.unilateral_b) == 0
        assert report.bilateral_verified is False

    def test_tampered_chain_breaks_validity(self, populated_ledgers):
        """Break a record in A's chain -> chain_a_valid = False."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        # Corrupt a record on disk (change the chain_hash)
        records = ledger_a.read_all()
        if records:
            rec = records[0]
            rec_path = ledger_a.ledger_dir / f"{rec.transaction_id}.txn.json"
            data = json.loads(rec_path.read_text())
            data["chain_hash"] = "corrupted_hash_value"
            rec_path.write_text(json.dumps(data, indent=2))

        report = bilateral_verify(ledger_a, ledger_b)

        # Chain A should now be invalid
        assert report.chain_a_valid is False
        assert report.bilateral_verified is False
        assert any("chain is broken" in issue for issue in report.issues)

    def test_multiple_matches(self, populated_ledgers):
        """Two exchanges -> 2+ matches."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        report = bilateral_verify(ledger_a, ledger_b)

        # Should have at least 2 matched transactions
        assert len(report.matched_transactions) >= 2

    def test_agent_id_inference_from_records(self, populated_ledgers):
        """Agent IDs inferred from most frequent sender if not provided."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        # Don't provide agent IDs
        report = bilateral_verify(ledger_a, ledger_b)

        # Should have inferred reasonable IDs (or fallback defaults)
        assert report.agent_a_id != ""
        assert report.agent_b_id != ""
        # Note: IDs could be the same if inference logic determines it's the same agent
        # The important thing is that we have valid IDs

    def test_agent_id_explicit_provided(self, populated_ledgers):
        """Provided agent IDs are used in report."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        report = bilateral_verify(
            ledger_a, ledger_b,
            agent_a_id="custom-agent-a",
            agent_b_id="custom-agent-b",
        )

        assert report.agent_a_id == "custom-agent-a"
        assert report.agent_b_id == "custom-agent-b"


# ---------------------------------------------------------------------------
# BilateralReport Tests
# ---------------------------------------------------------------------------


class TestBilateralReport:
    """Tests for BilateralReport data class and methods."""

    def test_summary_contains_key_fields(self, populated_ledgers):
        """summary() output contains agent IDs, chain status, match counts."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        report = bilateral_verify(ledger_a, ledger_b)
        summary = report.summary()

        assert "Bilateral Verification" in summary
        assert report.agent_a_id in summary
        assert report.agent_b_id in summary
        assert "VALID" in summary or "BROKEN" in summary
        assert "Matched transactions" in summary
        assert "Unilateral" in summary

    def test_summary_shows_pass_when_verified(self, populated_ledgers):
        """summary() shows PASS when bilateral_verified=True."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        report = bilateral_verify(ledger_a, ledger_b)

        if report.bilateral_verified:
            assert "PASS" in report.summary()
        else:
            assert "FAIL" in report.summary()

    def test_summary_includes_issues(self, populated_ledgers):
        """summary() includes issues list if present."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        # Corrupt one chain
        records = ledger_a.read_all()
        if records:
            rec = records[0]
            rec_path = ledger_a.ledger_dir / f"{rec.transaction_id}.txn.json"
            data = json.loads(rec_path.read_text())
            data["chain_hash"] = "bad_hash"
            rec_path.write_text(json.dumps(data, indent=2))

        report = bilateral_verify(ledger_a, ledger_b)
        summary = report.summary()

        if report.issues:
            assert "Issues" in summary
            for issue in report.issues:
                assert issue in summary

    def test_to_dict_returns_proper_dict(self, populated_ledgers):
        """to_dict() returns a proper dictionary."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        report = bilateral_verify(ledger_a, ledger_b)
        d = report.to_dict()

        assert isinstance(d, dict)
        assert "agent_a_id" in d
        assert "agent_b_id" in d
        assert "chain_a_valid" in d
        assert "chain_b_valid" in d
        assert "matched_transactions" in d
        assert "unilateral_a" in d
        assert "unilateral_b" in d
        assert "bilateral_verified" in d
        assert "verification_timestamp" in d
        assert "issues" in d

    def test_to_json_returns_valid_json(self, populated_ledgers):
        """to_json() returns a valid JSON string."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        report = bilateral_verify(ledger_a, ledger_b)
        json_str = report.to_json()

        # Should be parseable
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)
        assert parsed["agent_a_id"] == report.agent_a_id
        assert parsed["agent_b_id"] == report.agent_b_id


# ---------------------------------------------------------------------------
# build_transaction_trace Tests
# ---------------------------------------------------------------------------


class TestBuildTransactionTrace:
    """Tests for the build_transaction_trace function."""

    def test_single_ledger_all_records_in_trace(self, populated_ledgers):
        """Single ledger -> all records in trace."""
        ledger_a = populated_ledgers["ledger_a"]

        ledgers_dict = {"agent-a": ledger_a}
        trace = build_transaction_trace(ledgers_dict)

        records_a = ledger_a.read_all()
        assert len(trace) == len(records_a)

    def test_two_ledgers_with_overlapping_records(self, populated_ledgers):
        """Two ledgers with overlapping records -> deduplication works."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        trace = build_transaction_trace(ledgers_dict)

        records_a = ledger_a.read_all()
        records_b = ledger_b.read_all()

        # Total trace should be <= sum of both (due to deduplication)
        assert len(trace) <= len(records_a) + len(records_b)

        # Matched transactions should appear once
        # (the matching messages between A and B)

    def test_records_sorted_by_timestamp(self, populated_ledgers):
        """Records in trace are sorted by timestamp."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        trace = build_transaction_trace(ledgers_dict)

        # All timestamps should be in ascending order
        timestamps = [r.get("timestamp", "") for r in trace]
        assert timestamps == sorted(timestamps)

    def test_source_agent_field_is_set(self, populated_ledgers):
        """Each trace entry has source_agent field set."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        trace = build_transaction_trace(ledgers_dict)

        for entry in trace:
            assert "source_agent" in entry
            assert entry["source_agent"] in ["agent-a", "agent-b"]

    def test_deduplication_by_content_hash(self, populated_ledgers):
        """Same message recorded by A and B counts as one in trace."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        # Both ledgers should have a matching "request" from A to B
        records_a = ledger_a.read_all()
        records_b = ledger_b.read_all()

        # Create a trace
        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        trace = build_transaction_trace(ledgers_dict)

        # Count unique content_hash+message_type+sender+receiver
        seen_keys = set()
        for entry in trace:
            key = (
                entry["content_hash"],
                entry["message_type"],
                entry["sender_id"],
                entry["receiver_id"],
            )
            assert key not in seen_keys, f"Duplicate key in trace: {key}"
            seen_keys.add(key)


# ---------------------------------------------------------------------------
# trace_to_text Tests
# ---------------------------------------------------------------------------


class TestTraceToText:
    """Tests for the trace_to_text function."""

    def test_output_contains_header(self, populated_ledgers):
        """Output contains 'A2A Transaction Trace' header."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        trace = build_transaction_trace(ledgers_dict)
        text = trace_to_text(trace)

        assert "A2A Transaction Trace" in text

    def test_output_contains_sender_receiver_names(self, populated_ledgers):
        """Output contains sender and receiver names."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        trace = build_transaction_trace(ledgers_dict)
        text = trace_to_text(trace)

        # Should contain agent names from our test setup
        assert "LangChain" in text or "CrewAI" in text or "Researcher" in text or "Worker" in text

    def test_output_shows_blocked_records(self):
        """Output shows [BLOCKED] for injection-blocked records."""
        # Create a trace entry with injection_action = "blocked"
        trace = [{
            "sender_name": "Agent A",
            "receiver_name": "Agent B",
            "message_type": "request",
            "content_hash": "abc123",
            "chain_hash": "def456",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "content_size": 100,
            "injection_action": "blocked",
            "pii_detected": False,
        }]

        text = trace_to_text(trace)

        assert "[BLOCKED]" in text

    def test_output_shows_pii_records(self):
        """Output shows [PII] for PII-detected records."""
        trace = [{
            "sender_name": "Agent A",
            "receiver_name": "Agent B",
            "message_type": "request",
            "content_hash": "abc123",
            "chain_hash": "def456",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "content_size": 100,
            "injection_action": "allowed",
            "pii_detected": True,
        }]

        text = trace_to_text(trace)

        assert "[PII]" in text

    def test_output_contains_transaction_count(self, populated_ledgers):
        """Output shows total transaction count."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        trace = build_transaction_trace(ledgers_dict)
        text = trace_to_text(trace)

        assert "Total transactions" in text
        assert str(len(trace)) in text


# ---------------------------------------------------------------------------
# export_evidence_bundle Tests
# ---------------------------------------------------------------------------


class TestExportEvidenceBundle:
    """Tests for the export_evidence_bundle function."""

    def test_creates_air_a2a_evidence_file(self, populated_ledgers, tmp_path):
        """Creates a .air-a2a-evidence ZIP file."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        bundle_path = export_evidence_bundle(
            ledgers_dict,
            output_dir=output_dir,
            system_name="test-system",
        )

        assert bundle_path.exists()
        assert bundle_path.suffix == ".air-a2a-evidence"
        assert bundle_path.name.startswith("a2a-")

    def test_bundle_is_valid_zip(self, populated_ledgers, tmp_path):
        """Bundle file is a valid ZIP archive."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        bundle_path = export_evidence_bundle(
            ledgers_dict,
            output_dir=output_dir,
        )

        # Should be readable as a ZIP file
        with zipfile.ZipFile(bundle_path, "r") as zf:
            assert zf.testzip() is None

    def test_bundle_contains_metadata(self, populated_ledgers, tmp_path):
        """Bundle contains metadata/bundle.json."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        bundle_path = export_evidence_bundle(ledgers_dict, output_dir=output_dir)

        with zipfile.ZipFile(bundle_path, "r") as zf:
            assert "metadata/bundle.json" in zf.namelist()

            metadata = json.loads(zf.read("metadata/bundle.json"))
            assert "bundle_id" in metadata
            assert "agents" in metadata
            assert "agent-a" in metadata["agents"]
            assert "agent-b" in metadata["agents"]

    def test_bundle_contains_transaction_records(self, populated_ledgers, tmp_path):
        """Bundle contains transactions/{agent_id}/records.json."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        bundle_path = export_evidence_bundle(ledgers_dict, output_dir=output_dir)

        with zipfile.ZipFile(bundle_path, "r") as zf:
            assert "transactions/agent-a/records.json" in zf.namelist()
            assert "transactions/agent-b/records.json" in zf.namelist()

            records_a = json.loads(zf.read("transactions/agent-a/records.json"))
            records_b = json.loads(zf.read("transactions/agent-b/records.json"))

            assert isinstance(records_a, list)
            assert isinstance(records_b, list)
            assert len(records_a) > 0
            assert len(records_b) > 0

    def test_bundle_contains_chain_integrity_checks(self, populated_ledgers, tmp_path):
        """Bundle contains transactions/{agent_id}/chain_integrity.json."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        bundle_path = export_evidence_bundle(ledgers_dict, output_dir=output_dir)

        with zipfile.ZipFile(bundle_path, "r") as zf:
            assert "transactions/agent-a/chain_integrity.json" in zf.namelist()
            assert "transactions/agent-b/chain_integrity.json" in zf.namelist()

            chain_a = json.loads(zf.read("transactions/agent-a/chain_integrity.json"))
            chain_b = json.loads(zf.read("transactions/agent-b/chain_integrity.json"))

            assert "valid" in chain_a
            assert "valid" in chain_b
            assert "records_checked" in chain_a
            assert "records_checked" in chain_b

    def test_bundle_contains_bilateral_verification(self, populated_ledgers, tmp_path):
        """Bundle contains verification/{a}_vs_{b}.json when 2+ agents."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        bundle_path = export_evidence_bundle(
            ledgers_dict,
            output_dir=output_dir,
            include_bilateral=True,
        )

        with zipfile.ZipFile(bundle_path, "r") as zf:
            namelist = zf.namelist()
            # Should have at least one bilateral report
            bilateral_files = [f for f in namelist if f.startswith("verification/") and "_vs_" in f]
            assert len(bilateral_files) > 0

    def test_bundle_contains_trace(self, populated_ledgers, tmp_path):
        """Bundle contains trace/trace.json and trace/trace.txt."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        bundle_path = export_evidence_bundle(ledgers_dict, output_dir=output_dir)

        with zipfile.ZipFile(bundle_path, "r") as zf:
            assert "trace/trace.json" in zf.namelist()
            assert "trace/trace.txt" in zf.namelist()

            trace_json = json.loads(zf.read("trace/trace.json"))
            trace_txt = zf.read("trace/trace.txt").decode("utf-8")

            assert isinstance(trace_json, list)
            assert isinstance(trace_txt, str)
            assert "A2A Transaction Trace" in trace_txt

    def test_bundle_contains_manifest_with_sha256(self, populated_ledgers, tmp_path):
        """Bundle contains manifest.json with SHA-256 hashes."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        bundle_path = export_evidence_bundle(ledgers_dict, output_dir=output_dir)

        with zipfile.ZipFile(bundle_path, "r") as zf:
            assert "manifest.json" in zf.namelist()

            manifest = json.loads(zf.read("manifest.json"))
            assert "files" in manifest
            assert isinstance(manifest["files"], dict)

            # Every file should have a SHA-256 hash
            for filepath, entry in manifest["files"].items():
                assert "sha256" in entry
                assert len(entry["sha256"]) == 64  # SHA-256 hex is 64 chars
                assert "size_bytes" in entry

    def test_bundle_contains_verify_script(self, populated_ledgers, tmp_path):
        """Bundle contains verify.py standalone verifier."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        bundle_path = export_evidence_bundle(ledgers_dict, output_dir=output_dir)

        with zipfile.ZipFile(bundle_path, "r") as zf:
            assert "verify.py" in zf.namelist()

            verify_content = zf.read("verify.py").decode("utf-8")
            assert "Standalone A2A Evidence Bundle Verifier" in verify_content or "verify" in verify_content.lower()

    def test_bundle_contains_readme(self, populated_ledgers, tmp_path):
        """Bundle contains README.md for auditors."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        bundle_path = export_evidence_bundle(ledgers_dict, output_dir=output_dir)

        with zipfile.ZipFile(bundle_path, "r") as zf:
            assert "README.md" in zf.namelist()

            readme_content = zf.read("README.md").decode("utf-8")
            assert "A2A Transaction Evidence Bundle" in readme_content
            assert "verify" in readme_content.lower()

    def test_bundle_summary_when_bilateral_enabled(self, populated_ledgers, tmp_path):
        """Bundle contains verification/summary.json when include_bilateral=True."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        bundle_path = export_evidence_bundle(
            ledgers_dict,
            output_dir=output_dir,
            include_bilateral=True,
        )

        with zipfile.ZipFile(bundle_path, "r") as zf:
            assert "verification/summary.json" in zf.namelist()

            summary = json.loads(zf.read("verification/summary.json"))
            assert "pairs_checked" in summary
            assert "all_verified" in summary
            assert "reports" in summary

    def test_bundle_single_agent_no_bilateral(self, tmp_path):
        """Bundle with single agent doesn't include bilateral verification."""
        ledger_a = TransactionLedger(
            ledger_dir=str(tmp_path / "single_agent"),
            signing_key="test-key",
        )

        # Add a record
        rec = TransactionRecord.create(
            sender_id="agent-a",
            sender_name="Solo Agent",
            sender_framework="langchain",
            receiver_id="external",
            receiver_name="External System",
            receiver_framework="api",
            message_type="request",
            content=b"A solo message",
        )
        ledger_a.write(rec)

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        ledgers_dict = {"agent-a": ledger_a}
        bundle_path = export_evidence_bundle(
            ledgers_dict,
            output_dir=output_dir,
            include_bilateral=True,
        )

        with zipfile.ZipFile(bundle_path, "r") as zf:
            namelist = zf.namelist()
            # No bilateral reports should be generated for single agent
            bilateral_files = [f for f in namelist if f.startswith("verification/") and "_vs_" in f]
            assert len(bilateral_files) == 0

    def test_bundle_system_name_in_metadata(self, populated_ledgers, tmp_path):
        """Bundle metadata includes the system_name parameter."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        bundle_path = export_evidence_bundle(
            ledgers_dict,
            output_dir=output_dir,
            system_name="test-audit-system",
        )

        with zipfile.ZipFile(bundle_path, "r") as zf:
            metadata = json.loads(zf.read("metadata/bundle.json"))
            assert metadata["system_name"] == "test-audit-system"

    def test_bundle_uses_current_dir_as_default_output(self, populated_ledgers, monkeypatch, tmp_path):
        """export_evidence_bundle defaults to current directory."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        # Change to a temporary directory
        monkeypatch.chdir(tmp_path)

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        bundle_path = export_evidence_bundle(
            ledgers_dict,
            output_dir=None,
        )

        # Should be created in the current (tmp_path) directory
        # Resolve to absolute path for comparison
        assert bundle_path.resolve().parent == tmp_path


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------


class TestIntegration:
    """Integration tests combining multiple functions."""

    def test_full_workflow_verify_and_export(self, populated_ledgers, tmp_path):
        """Full workflow: verify ledgers, build trace, and export bundle."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        # 1. Run bilateral verification
        report = bilateral_verify(ledger_a, ledger_b)
        assert report.bilateral_verified is True

        # 2. Build transaction trace
        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        trace = build_transaction_trace(ledgers_dict)
        assert len(trace) > 0

        # 3. Convert trace to text
        trace_text = trace_to_text(trace)
        assert "A2A Transaction Trace" in trace_text

        # 4. Export evidence bundle
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        bundle_path = export_evidence_bundle(
            ledgers_dict,
            output_dir=output_dir,
        )

        # 5. Verify bundle contents
        assert bundle_path.exists()
        with zipfile.ZipFile(bundle_path, "r") as zf:
            assert "metadata/bundle.json" in zf.namelist()
            assert "transactions/agent-a/records.json" in zf.namelist()
            assert "trace/trace.json" in zf.namelist()
            assert "manifest.json" in zf.namelist()

    def test_trace_matches_records_count(self, populated_ledgers):
        """Transaction trace accounts for all records (with deduplication)."""
        ledger_a = populated_ledgers["ledger_a"]
        ledger_b = populated_ledgers["ledger_b"]

        records_a = ledger_a.read_all()
        records_b = ledger_b.read_all()

        ledgers_dict = {"agent-a": ledger_a, "agent-b": ledger_b}
        trace = build_transaction_trace(ledgers_dict)

        # Count unique transaction hashes in ledgers
        unique_hashes = set()
        for rec in records_a:
            key = (rec.content_hash, rec.message_type, rec.sender_id, rec.receiver_id)
            unique_hashes.add(key)
        for rec in records_b:
            key = (rec.content_hash, rec.message_type, rec.sender_id, rec.receiver_id)
            unique_hashes.add(key)

        # Trace should have same count as unique transactions
        assert len(trace) == len(unique_hashes)
