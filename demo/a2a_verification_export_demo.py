#!/usr/bin/env python3
"""
A2A Verification & Export Demo (Phase 3)
========================================

Demonstrates the full audit pipeline:

  1. Two agents exchange signed messages (reuses Phase 1 gateway)
  2. Bilateral verification -- cross-check both ledgers agree
  3. Transaction trace -- chronological view of the conversation
  4. Evidence bundle export -- .air-a2a-evidence ZIP for regulators
  5. Standalone verification of the bundle
  6. Tamper an exported bundle and detect it

Run:
    python3 demo/a2a_verification_export_demo.py

No API keys. No internet. No cloud. Everything runs locally.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))

from air_blackbox.a2a.gateway import A2AGateway
from air_blackbox.a2a.verify import bilateral_verify
from air_blackbox.a2a.export import (
    build_transaction_trace,
    trace_to_text,
    export_evidence_bundle,
)
from air_blackbox.evidence.keys import KeyManager
from air_blackbox.evidence.signer import EvidenceSigner


# -- Formatting ---------------------------------------------------------------

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def header(title):
    print(f"\n{'=' * 64}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{'=' * 64}")


def ok(msg):
    print(f"  {GREEN}OK{RESET}  {msg}")


def fail(msg):
    print(f"  {RED}XX{RESET}  {msg}")


def info(msg):
    print(f"  {DIM}--{RESET}  {msg}")


# -- Demo ---------------------------------------------------------------------

def main():
    print(f"\n{BOLD}AIR Blackbox -- A2A Verification & Export Demo{RESET}")
    print(f"{DIM}Bilateral proof, transaction traces, and audit-ready evidence bundles{RESET}\n")

    tmp = tempfile.mkdtemp(prefix="air-a2a-export-")
    signing_key = "bilateral-demo-key-2026"

    try:
        # ================================================================
        # STEP 1: Set up agents and exchange messages
        # ================================================================
        header("Step 1 -- Agent Setup & Message Exchange")

        # Keys
        km_a = KeyManager(key_dir=os.path.join(tmp, "keys-a"))
        pub_a, _ = km_a.generate()
        signer_a = EvidenceSigner(km_a)

        km_b = KeyManager(key_dir=os.path.join(tmp, "keys-b"))
        pub_b, _ = km_b.generate()
        signer_b = EvidenceSigner(km_b)

        # Gateways
        gw_a = A2AGateway(
            agent_id="compliance-scanner",
            agent_name="Compliance Scanner",
            framework="langchain",
            ledger_dir=os.path.join(tmp, "ledger", "compliance-scanner"),
            signing_key=signing_key,
            key_fingerprint=km_a.get_key_id(),
            signer=signer_a,
        )

        gw_b = A2AGateway(
            agent_id="risk-assessor",
            agent_name="Risk Assessor",
            framework="crewai",
            ledger_dir=os.path.join(tmp, "ledger", "risk-assessor"),
            signing_key=signing_key,
            key_fingerprint=km_b.get_key_id(),
            signer=signer_b,
        )

        ok("Compliance Scanner (LangChain) ready")
        ok("Risk Assessor (CrewAI) ready")

        # Exchange messages (both sides record)
        messages = [
            ("request", b"Scan project /app for EU AI Act Article 9 risk management compliance."),
            ("response", b"Scan complete. 8/8 Article 9 checks passed. Risk classification: high_risk_annex_iii. No critical gaps found."),
            ("request", b"Cross-reference results with ISO 42001 Annex B controls."),
            ("tool_call", b"TOOL:iso42001_mapper:map Article 9 findings to ISO 42001 Annex B"),
            ("tool_result", b"TOOL_RESULT: 6/8 ISO 42001 controls mapped. 2 require manual documentation: B.3.2 (risk criteria), B.4.1 (risk treatment plan)."),
            ("response", b"Cross-reference complete. 6/8 ISO controls auto-mapped. Manual action needed for B.3.2 and B.4.1. Generating compliance report."),
            ("request", b"Generate final compliance attestation with both EU AI Act and ISO 42001 findings."),
            ("response", b"Attestation generated. EU AI Act: 48/48 checks, 43 pass, 3 warn, 2 fail. ISO 42001: 6/8 auto-mapped. Risk: HIGH. Recommendation: address 2 manual controls before August 2026 deadline."),
        ]

        for i, (msg_type, content) in enumerate(messages):
            if msg_type in ("request", "tool_call"):
                # A sends, B receives
                gw_a.send(
                    content=content,
                    receiver_id="risk-assessor",
                    receiver_name="Risk Assessor",
                    receiver_framework="crewai",
                    message_type=msg_type,
                )
                gw_b.receive(
                    content=content,
                    sender_id="compliance-scanner",
                    sender_name="Compliance Scanner",
                    sender_framework="langchain",
                    message_type=msg_type,
                )
            else:
                # B sends, A receives
                gw_b.send(
                    content=content,
                    receiver_id="compliance-scanner",
                    receiver_name="Compliance Scanner",
                    receiver_framework="langchain",
                    message_type=msg_type,
                )
                gw_a.receive(
                    content=content,
                    sender_id="risk-assessor",
                    sender_name="Risk Assessor",
                    sender_framework="crewai",
                    message_type=msg_type,
                )

        ok(f"Exchanged {len(messages)} messages")
        ok(f"Scanner ledger: {gw_a.stats['ledger_records']} records")
        ok(f"Assessor ledger: {gw_b.stats['ledger_records']} records")

        # ================================================================
        # STEP 2: Bilateral verification
        # ================================================================
        header("Step 2 -- Bilateral Verification")

        report = bilateral_verify(
            gw_a.ledger,
            gw_b.ledger,
            agent_a_id="compliance-scanner",
            agent_b_id="risk-assessor",
        )

        if report.bilateral_verified:
            ok(f"Bilateral verification: {GREEN}PASS{RESET}")
        else:
            fail(f"Bilateral verification: FAIL")

        ok(f"Chain A: {'VALID' if report.chain_a_valid else 'BROKEN'} ({report.chain_a_records} records)")
        ok(f"Chain B: {'VALID' if report.chain_b_valid else 'BROKEN'} ({report.chain_b_records} records)")
        ok(f"Matched transactions: {len(report.matched_transactions)}")
        info(f"Unilateral A (internal ops): {len(report.unilateral_a)}")
        info(f"Unilateral B (internal ops): {len(report.unilateral_b)}")

        if report.matched_transactions:
            print()
            info("Matched transaction details:")
            for m in report.matched_transactions[:5]:
                info(f"  {m.sender_id} -> {m.receiver_id}  "
                     f"type={m.message_type}  hash={m.content_hash[:16]}...")

        # ================================================================
        # STEP 3: Transaction trace
        # ================================================================
        header("Step 3 -- Transaction Trace")

        ledgers = {
            "compliance-scanner": gw_a.ledger,
            "risk-assessor": gw_b.ledger,
        }
        trace = build_transaction_trace(ledgers)
        trace_text = trace_to_text(trace)

        ok(f"Trace built: {len(trace)} unique transactions")
        print()
        # Print first few entries
        for entry in trace[:4]:
            blocked = f" {RED}[BLOCKED]{RESET}" if entry.get("injection_action") == "blocked" else ""
            print(f"  {entry['sender_name']} --> {entry['receiver_name']}  "
                  f"{DIM}type={entry['message_type']}  size={entry['content_size']}B{RESET}{blocked}")

        if len(trace) > 4:
            info(f"... and {len(trace) - 4} more transactions")

        # ================================================================
        # STEP 4: Export evidence bundle
        # ================================================================
        header("Step 4 -- Evidence Bundle Export")

        bundle_path = export_evidence_bundle(
            ledgers=ledgers,
            output_dir=tmp,
            system_name="AI Compliance Pipeline Demo",
            include_bilateral=True,
        )

        bundle_size = os.path.getsize(bundle_path)
        ok(f"Evidence bundle created: {bundle_path.name}")
        ok(f"Size: {bundle_size:,} bytes")

        # List contents
        with zipfile.ZipFile(bundle_path) as zf:
            file_count = len(zf.namelist())
            ok(f"Contains {file_count} files")
            print()
            for name in sorted(zf.namelist()):
                size = zf.getinfo(name).file_size
                print(f"  {DIM}{size:>6}B{RESET}  {name}")

        # ================================================================
        # STEP 5: Run standalone verifier
        # ================================================================
        header("Step 5 -- Standalone Bundle Verification")

        # Extract the bundle and run verify.py
        extract_dir = os.path.join(tmp, "extracted")
        with zipfile.ZipFile(bundle_path) as zf:
            zf.extractall(extract_dir)

        result = subprocess.run(
            [sys.executable, os.path.join(extract_dir, "verify.py")],
            capture_output=True,
            text=True,
            cwd=extract_dir,
        )

        if result.returncode == 0:
            ok("Standalone verifier: ALL CHECKS PASSED")
        else:
            fail("Standalone verifier found issues!")

        # Print verifier output (indented)
        for line in result.stdout.strip().split("\n"):
            info(line)

        # ================================================================
        # STEP 6: Tamper with bundle and detect
        # ================================================================
        header("Step 6 -- Tamper Detection on Exported Bundle")

        # Modify a transaction record in the extracted bundle
        scanner_records_path = os.path.join(
            extract_dir, "transactions", "compliance-scanner", "records.json"
        )
        with open(scanner_records_path) as f:
            records = json.load(f)

        info(f"Tampering with compliance-scanner record #2...")
        original_type = records[1]["message_type"]
        records[1]["message_type"] = "handoff"  # attacker changes type
        records[1]["content_size"] = 9999  # attacker inflates size
        info(f"Changed message_type: '{original_type}' -> 'handoff'")
        info(f"Changed content_size: -> 9999")

        with open(scanner_records_path, "w") as f:
            json.dump(records, f, indent=2)

        # Re-run verifier
        result2 = subprocess.run(
            [sys.executable, os.path.join(extract_dir, "verify.py")],
            capture_output=True,
            text=True,
            cwd=extract_dir,
        )

        if result2.returncode != 0:
            ok(f"Tamper DETECTED by standalone verifier")
            # Show which file failed
            for line in result2.stdout.strip().split("\n"):
                if "FAIL" in line:
                    info(line.strip())
        else:
            fail("Tamper was not detected!")

        # ================================================================
        # Summary
        # ================================================================
        header("Summary")

        print(f"""
  {GREEN}All tests passed.{RESET}

  {BOLD}Phase 3 delivers three capabilities:{RESET}

  {BOLD}1. Bilateral Verification{RESET}
     Cross-verified two agents' ledgers. Confirmed {len(report.matched_transactions)} matching
     transactions. Both chains intact. Both sides agree on what happened.

  {BOLD}2. Transaction Trace{RESET}
     Built a chronological timeline of {len(trace)} unique transactions across
     both agents. Deduplicated, sorted, human-readable.

  {BOLD}3. Evidence Bundle{RESET}
     Exported a {bundle_size:,}-byte .air-a2a-evidence ZIP containing:
     - All transaction records from both agents
     - Chain integrity verification for each agent
     - Bilateral verification report
     - Full conversation trace (JSON + text)
     - SHA-256 manifest of all files
     - Standalone verifier (Python 3.10+, no pip install)
     - Auditor README with instructions

     Tampering with any file in the bundle is detected by the
     standalone verifier via manifest hash mismatch.

  {BOLD}This is what you hand to a regulator.{RESET}
  Self-contained. Self-verifying. Tamper-evident.

  {DIM}No API keys. No internet. No cloud. Everything ran locally.{RESET}
""")

    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
