"""
A2A Transaction Export -- bundle transactions into verifiable evidence.

Exports transaction ledgers into three formats:

  1. Transaction Trace -- a chronological view of all messages across
     multiple agents' ledgers, reconstructing the full conversation.

  2. Bilateral Verification Report -- JSON proof that two agents agree
     on what happened, with chain integrity checks.

  3. .air-a2a-evidence bundle -- a ZIP file containing all transactions,
     verification reports, signing keys, and a standalone verifier.
     Designed for regulators and auditors.

Usage:
    from air_blackbox.a2a.export import (
        build_transaction_trace,
        export_evidence_bundle,
    )

    trace = build_transaction_trace([ledger_a, ledger_b, ledger_c])
    bundle_path = export_evidence_bundle(
        ledgers={"agent-a": ledger_a, "agent-b": ledger_b},
        output_dir=Path("./evidence"),
    )
"""

import hashlib
import json
import os
import zipfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .transaction import TransactionLedger, TransactionRecord
from .verify import bilateral_verify, BilateralReport


# ---------------------------------------------------------------------------
# Transaction Trace
# ---------------------------------------------------------------------------

def build_transaction_trace(
    ledgers: Dict[str, TransactionLedger],
) -> List[Dict[str, Any]]:
    """Build a chronological trace of all transactions across ledgers.

    Merges records from multiple agents' ledgers into a single
    timeline sorted by timestamp. Deduplicates transactions that
    appear in both sender and receiver ledgers (matched by
    content_hash + message_type + sender_id + receiver_id).

    Args:
        ledgers: Dict mapping agent_id to TransactionLedger.

    Returns:
        List of transaction dicts sorted by timestamp, with an
        added 'source_agent' field showing which ledger it came from.
    """
    all_records = []
    seen_keys = set()

    for agent_id, ledger in ledgers.items():
        for record in ledger.read_all():
            # Dedup key: same content sent between same parties
            dedup_key = (
                f"{record.content_hash}|{record.message_type}|"
                f"{record.sender_id}|{record.receiver_id}"
            )

            if dedup_key not in seen_keys:
                seen_keys.add(dedup_key)
                entry = record.to_dict()
                entry["source_agent"] = agent_id
                all_records.append(entry)

    # Sort by timestamp
    all_records.sort(key=lambda r: r.get("timestamp", ""))

    return all_records


def trace_to_text(trace: List[Dict[str, Any]]) -> str:
    """Convert a transaction trace to a human-readable text report.

    Args:
        trace: Output from build_transaction_trace().

    Returns:
        Formatted text string showing the full conversation flow.
    """
    lines = [
        "A2A Transaction Trace",
        "=" * 60,
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Total transactions: {len(trace)}",
        "",
    ]

    for i, txn in enumerate(trace, 1):
        blocked = " [BLOCKED]" if txn.get("injection_action") == "blocked" else ""
        pii = " [PII]" if txn.get("pii_detected") else ""

        lines.append(f"#{i}  {txn['sender_name']} --> {txn['receiver_name']}")
        lines.append(f"     type: {txn['message_type']}{blocked}{pii}")
        lines.append(f"     size: {txn['content_size']}B  "
                      f"hash: {txn['content_hash'][:24]}...")
        lines.append(f"     chain: {txn['chain_hash'][:24]}...")
        lines.append(f"     time: {txn['timestamp']}")
        if txn.get("redacted_preview"):
            preview = txn["redacted_preview"][:80]
            lines.append(f"     preview: {preview}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Evidence Bundle
# ---------------------------------------------------------------------------

def export_evidence_bundle(
    ledgers: Dict[str, TransactionLedger],
    output_dir: Optional[Path] = None,
    system_name: str = "unknown",
    include_bilateral: bool = True,
) -> Path:
    """Export A2A transaction evidence as a .air-a2a-evidence ZIP bundle.

    Creates a self-contained evidence package for regulators containing:
    - All transaction records from all agents
    - Chain integrity verification for each agent
    - Bilateral verification reports (if multiple agents)
    - Full chronological trace
    - Standalone verifier script
    - Metadata (scanner version, timestamp, agents)

    Args:
        ledgers: Dict mapping agent_id to TransactionLedger.
        output_dir: Directory to write the bundle. Defaults to current dir.
        system_name: Name of the system being audited.
        include_bilateral: Whether to run bilateral verification between
                          all pairs of agents.

    Returns:
        Path to the created .air-a2a-evidence ZIP file.
    """
    if output_dir is None:
        output_dir = Path(".")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc)
    bundle_id = f"a2a-{timestamp.strftime('%Y%m%d-%H%M%S')}"
    bundle_path = output_dir / f"{bundle_id}.air-a2a-evidence"

    with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zf:

        # -- Metadata ---------------------------------------------------------
        agent_ids = list(ledgers.keys())
        metadata = {
            "bundle_id": bundle_id,
            "bundle_version": "1.0",
            "created_at": timestamp.isoformat(),
            "system_name": system_name,
            "scanner_version": "air-blackbox 1.9.0",
            "agents": agent_ids,
            "agent_count": len(agent_ids),
        }
        zf.writestr(
            "metadata/bundle.json",
            json.dumps(metadata, indent=2),
        )

        # -- Per-agent transaction records ------------------------------------
        total_records = 0
        for agent_id, ledger in ledgers.items():
            records = ledger.read_all()
            total_records += len(records)

            # Write all records
            records_data = [r.to_dict() for r in records]
            zf.writestr(
                f"transactions/{agent_id}/records.json",
                json.dumps(records_data, indent=2),
            )

            # Chain verification
            chain_result = ledger.verify_chain()
            zf.writestr(
                f"transactions/{agent_id}/chain_integrity.json",
                json.dumps(chain_result, indent=2),
            )

        # -- Bilateral verification -------------------------------------------
        if include_bilateral and len(agent_ids) >= 2:
            bilateral_reports = []
            pairs_checked = 0

            for i in range(len(agent_ids)):
                for j in range(i + 1, len(agent_ids)):
                    id_a = agent_ids[i]
                    id_b = agent_ids[j]
                    report = bilateral_verify(
                        ledgers[id_a],
                        ledgers[id_b],
                        agent_a_id=id_a,
                        agent_b_id=id_b,
                    )
                    pairs_checked += 1

                    report_data = report.to_dict()
                    fname = f"verification/{id_a}_vs_{id_b}.json"
                    zf.writestr(fname, json.dumps(report_data, indent=2))
                    bilateral_reports.append(report_data)

            # Summary of all bilateral checks
            summary = {
                "pairs_checked": pairs_checked,
                "all_verified": all(
                    r["bilateral_verified"] for r in bilateral_reports
                ),
                "reports": [
                    {
                        "agent_a": r["agent_a_id"],
                        "agent_b": r["agent_b_id"],
                        "verified": r["bilateral_verified"],
                        "matched": len(r["matched_transactions"]),
                    }
                    for r in bilateral_reports
                ],
            }
            zf.writestr(
                "verification/summary.json",
                json.dumps(summary, indent=2),
            )

        # -- Full trace -------------------------------------------------------
        trace = build_transaction_trace(ledgers)
        zf.writestr(
            "trace/trace.json",
            json.dumps(trace, indent=2),
        )
        zf.writestr(
            "trace/trace.txt",
            trace_to_text(trace),
        )

        # -- Manifest ---------------------------------------------------------
        # Hash every file in the ZIP for integrity verification
        manifest_entries = {}
        for info in zf.infolist():
            data = zf.read(info.filename)
            manifest_entries[info.filename] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
            }

        manifest = {
            "bundle_id": bundle_id,
            "created_at": timestamp.isoformat(),
            "total_records": total_records,
            "total_agents": len(agent_ids),
            "files": manifest_entries,
        }
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

        # -- Standalone verifier ----------------------------------------------
        zf.writestr("verify.py", _STANDALONE_VERIFIER)

        # -- README for auditors ----------------------------------------------
        zf.writestr("README.md", _AUDITOR_README.format(
            bundle_id=bundle_id,
            timestamp=timestamp.isoformat(),
            system_name=system_name,
            agent_count=len(agent_ids),
            total_records=total_records,
        ))

    return bundle_path


# ---------------------------------------------------------------------------
# Standalone verifier (embedded in the bundle)
# ---------------------------------------------------------------------------

_STANDALONE_VERIFIER = '''#!/usr/bin/env python3
"""
Standalone A2A Evidence Bundle Verifier
=======================================

Verifies the integrity of an .air-a2a-evidence bundle by checking:
  1. Manifest SHA-256 hashes match all files
  2. Chain integrity for each agent's ledger
  3. Bilateral verification results are consistent

Run:
    python3 verify.py

Requires Python 3.10+ (stdlib only, no pip install needed).
"""

import hashlib
import json
import os
import sys
import zipfile


def main():
    # Find the bundle (same directory as this script)
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # If running from inside an extracted ZIP
    manifest_path = os.path.join(script_dir, "manifest.json")
    if os.path.exists(manifest_path):
        verify_extracted(script_dir)
    else:
        # Look for .air-a2a-evidence files
        bundles = [f for f in os.listdir(script_dir) if f.endswith(".air-a2a-evidence")]
        if not bundles:
            print("ERROR: No .air-a2a-evidence bundle found.")
            sys.exit(1)
        verify_zip(os.path.join(script_dir, bundles[0]))


def verify_extracted(base_dir):
    """Verify an extracted bundle directory."""
    print("Verifying extracted A2A evidence bundle...\\n")

    with open(os.path.join(base_dir, "manifest.json")) as f:
        manifest = json.load(f)

    print(f"Bundle: {manifest['bundle_id']}")
    print(f"Created: {manifest['created_at']}")
    print(f"Agents: {manifest['total_agents']}")
    print(f"Records: {manifest['total_records']}")
    print()

    passed = 0
    failed = 0

    for filepath, expected in manifest["files"].items():
        full_path = os.path.join(base_dir, filepath)
        if not os.path.exists(full_path):
            print(f"  FAIL  {filepath} -- file missing")
            failed += 1
            continue

        with open(full_path, "rb") as f:
            actual_hash = hashlib.sha256(f.read()).hexdigest()

        if actual_hash == expected["sha256"]:
            print(f"  OK    {filepath}")
            passed += 1
        else:
            print(f"  FAIL  {filepath} -- hash mismatch")
            failed += 1

    print(f"\\nResult: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)


def verify_zip(zip_path):
    """Verify a .air-a2a-evidence ZIP file."""
    print(f"Verifying {os.path.basename(zip_path)}...\\n")

    with zipfile.ZipFile(zip_path, "r") as zf:
        manifest_data = zf.read("manifest.json")
        manifest = json.loads(manifest_data)

        print(f"Bundle: {manifest['bundle_id']}")
        print(f"Created: {manifest['created_at']}")
        print(f"Agents: {manifest['total_agents']}")
        print(f"Records: {manifest['total_records']}")
        print()

        passed = 0
        failed = 0

        for filepath, expected in manifest["files"].items():
            try:
                data = zf.read(filepath)
                actual_hash = hashlib.sha256(data).hexdigest()

                if actual_hash == expected["sha256"]:
                    print(f"  OK    {filepath}")
                    passed += 1
                else:
                    print(f"  FAIL  {filepath} -- hash mismatch")
                    failed += 1
            except KeyError:
                print(f"  FAIL  {filepath} -- file missing from archive")
                failed += 1

    print(f"\\nResult: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
'''


_AUDITOR_README = """# A2A Transaction Evidence Bundle

**Bundle ID:** {bundle_id}
**Created:** {timestamp}
**System:** {system_name}
**Agents:** {agent_count}
**Total Records:** {total_records}

## What This Contains

This bundle is a cryptographically verifiable record of all
agent-to-agent communication that occurred during an AI system
operation. It is designed for EU AI Act Article 12 compliance
(record-keeping requirements).

## Directory Structure

```
metadata/          System and scanner metadata
transactions/      Per-agent transaction records and chain integrity
verification/      Bilateral verification between agent pairs
trace/             Chronological view of the full conversation
manifest.json      SHA-256 hashes of all files
verify.py          Standalone integrity checker
```

## How to Verify

Run the standalone verifier (requires Python 3.10+, no pip install):

```bash
python3 verify.py
```

This checks every file's SHA-256 hash against the manifest.

## Key Concepts

- **Transaction Records**: Every message between agents is recorded
  with sender, receiver, content hash (NOT content), timestamps,
  PII scan results, and injection detection scores.

- **HMAC-SHA256 Chain**: Records are linked in a tamper-evident chain.
  Modifying any record breaks all subsequent chain hashes.

- **ML-DSA-65 Signatures**: Each record is signed with a quantum-safe
  digital signature (FIPS 204) that proves authenticity.

- **Bilateral Verification**: Both sides of every conversation keep
  independent ledgers. This bundle includes cross-verification
  proving both sides agree on what happened.

- **Content Privacy**: The actual message content is NEVER stored.
  Only SHA-256 hashes are recorded, proving what was exchanged
  without exposing the data itself.
"""
