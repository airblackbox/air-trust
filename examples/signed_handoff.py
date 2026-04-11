#!/usr/bin/env python3
"""
Signed Handoff Demo — Two agents doing a research → write handoff.

This demonstrates AIR Trust v1.2 signed handoffs:
  1. Agent A (researcher) generates an Ed25519 keypair
  2. Agent B (writer) generates an Ed25519 keypair
  3. Agent A sends a handoff_request (signed with A's key)
  4. Agent B sends a handoff_ack (signed with B's key)
  5. Agent B sends a handoff_result (signed with B's key)
  6. The verifier checks integrity, completeness, AND handoff signatures

Run:
    python3 examples/signed_handoff.py

Requires: pip install air-trust cryptography
"""

import os
import sys
import json
import uuid
import tempfile

# Add parent dir to path so we can import air_trust from the repo
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "air-trust"))

from air_trust.events import Event, AgentIdentity
from air_trust.chain import AuditChain


def main():
    print("=" * 60)
    print("  AIR Trust v1.2 — Signed Handoff Demo")
    print("=" * 60)
    print()

    # Use a temp directory for keys and database so the demo is self-contained
    demo_dir = tempfile.mkdtemp(prefix="air-trust-demo-")
    keys_dir = os.path.join(demo_dir, "keys")
    os.makedirs(keys_dir)
    db_path = os.path.join(demo_dir, "demo.db")

    # Monkeypatch keys directory for the demo
    from pathlib import Path
    from air_trust import keys as keys_module
    original_keys_dir = keys_module._keys_dir
    keys_module._keys_dir = lambda: Path(keys_dir)

    # ── Step 1: Create agent identities ──────────────────────────
    print("[1/6] Creating agent identities...")

    agent_a = AgentIdentity(
        agent_name="research-agent",
        owner="jason@airblackbox.ai",
        agent_version="1.0.0",
        purpose="Research AI governance trends and regulations",
        capabilities=["search:web", "search:papers", "summarize"],
    )
    print(f"  Agent A: {agent_a.agent_name} (fingerprint: {agent_a.fingerprint[:12]}...)")

    agent_b = AgentIdentity(
        agent_name="writer-agent",
        owner="jason@airblackbox.ai",
        agent_version="1.0.0",
        purpose="Write technical blog posts from research material",
        capabilities=["write:markdown", "edit:prose"],
    )
    print(f"  Agent B: {agent_b.agent_name} (fingerprint: {agent_b.fingerprint[:12]}...)")

    # ── Step 2: Generate Ed25519 keypairs ─────────────────────────
    print("\n[2/6] Generating Ed25519 keypairs...")

    pub_a = keys_module.generate_keypair(agent_a.fingerprint)
    print(f"  Agent A public key: {pub_a[:20]}...")

    pub_b = keys_module.generate_keypair(agent_b.fingerprint)
    print(f"  Agent B public key: {pub_b[:20]}...")

    # ── Step 3: Create audit chain and start a session ────────────
    print("\n[3/6] Starting audit chain and session...")

    chain = AuditChain(db_path=db_path, signing_key="demo-signing-key")
    session_id = uuid.uuid4().hex

    # Session start
    chain.write(Event(
        type="session_start",
        framework="raw_python",
        session_id=session_id,
        status="running",
        description="Multi-agent blog writing session",
    ))
    print(f"  Session started: {session_id[:12]}...")

    # Agent A does some research
    chain.write(Event(
        type="llm_call",
        framework="raw_python",
        session_id=session_id,
        identity=agent_a,
        model="gpt-4o",
        description="Researching EU AI Act Article 12 record-keeping requirements",
        status="success",
    ))
    print("  Agent A: researching...")

    # ── Step 4: Agent A hands off to Agent B ──────────────────────
    print("\n[4/6] Agent A sending handoff request (Ed25519 signed)...")

    interaction_id = uuid.uuid4().hex
    research_payload = "EU AI Act Article 12 requires tamper-evident logging for all high-risk AI systems. Key requirements include: completeness of records, integrity verification, and cross-agent audit trails."
    task_hash = keys_module.compute_payload_hash(research_payload)

    request_event = Event(
        type="handoff_request",
        framework="raw_python",
        session_id=session_id,
        identity=agent_a,
        interaction_id=interaction_id,
        counterparty_id=agent_b.fingerprint,
        payload_hash=task_hash,
        nonce=keys_module.generate_nonce(),
        description="Handing research to writer agent",
    )
    chain.write(request_event)
    print(f"  Request signed: {request_event.signature[:30]}...")
    print(f"  Payload hash:   {task_hash[:30]}...")

    # ── Step 5: Agent B acknowledges and produces result ──────────
    print("\n[5/6] Agent B acknowledging and writing result (Ed25519 signed)...")

    ack_event = Event(
        type="handoff_ack",
        framework="raw_python",
        session_id=session_id,
        identity=agent_b,
        interaction_id=interaction_id,
        counterparty_id=agent_a.fingerprint,
        payload_hash=task_hash,  # Same hash = "I received the same data"
        nonce=keys_module.generate_nonce(),
        description="Writer agent acknowledges research receipt",
    )
    chain.write(ack_event)
    print(f"  Ack signed:     {ack_event.signature[:30]}...")

    # Agent B does some writing
    chain.write(Event(
        type="llm_call",
        framework="raw_python",
        session_id=session_id,
        identity=agent_b,
        model="claude-sonnet-4-20250514",
        description="Writing blog post from research material",
        status="success",
    ))

    # Agent B delivers the result
    result_payload = "Blog post: 'Why Tamper-Evident Audit Chains Matter for EU AI Act Compliance' — 1,200 words covering Article 12 requirements with practical implementation guidance."
    result_hash = keys_module.compute_payload_hash(result_payload)

    result_event = Event(
        type="handoff_result",
        framework="raw_python",
        session_id=session_id,
        identity=agent_b,
        interaction_id=interaction_id,
        counterparty_id=agent_a.fingerprint,
        payload_hash=result_hash,
        nonce=keys_module.generate_nonce(),
        description="Writer agent delivers completed blog post",
    )
    chain.write(result_event)
    print(f"  Result signed:  {result_event.signature[:30]}...")
    print(f"  Result hash:    {result_hash[:30]}...")

    # Session end
    chain.write(Event(
        type="session_end",
        framework="raw_python",
        session_id=session_id,
        status="success",
        description="Multi-agent session completed successfully",
    ))

    # ── Step 6: Verify everything ─────────────────────────────────
    print("\n[6/6] Verifying audit chain...")
    print("-" * 60)

    result = chain.verify()

    # Integrity
    integrity = result["integrity"]
    if integrity["valid"]:
        print(f"  \033[32m✓ PASS\033[0m: Integrity — {integrity['records']} records, chain intact (HMAC-SHA256)")
    else:
        print(f"  \033[31m✗ FAIL\033[0m: Integrity — chain broken at record {integrity['broken_at']}")

    # Completeness
    completeness = result["completeness"]
    print(f"  \033[32m✓ PASS\033[0m: Completeness — {completeness['sessions_checked']} session(s), {completeness['sessions_complete']} complete")

    # Handoffs
    handoffs = result["handoffs"]
    if handoffs["interactions_complete"] == handoffs["interactions_checked"]:
        print(f"  \033[32m✓ PASS\033[0m: Handoffs — {handoffs['interactions_checked']} handoff(s), all Ed25519 signatures valid")
    else:
        print(f"  \033[33m⚠ WARN\033[0m: Handoffs — {handoffs['interactions_incomplete']} incomplete")
        for issue in handoffs["issues"]:
            print(f"    {issue['issue']}: {issue.get('detail', '')}")

    if handoffs["issues"]:
        print(f"\n  Issues: {json.dumps(handoffs['issues'], indent=4)}")

    print("-" * 60)
    print()

    # JSON output for reference
    print("Full verification report (JSON):")
    print(json.dumps({
        "integrity": result["integrity"],
        "completeness": result["completeness"],
        "handoffs": result["handoffs"],
    }, indent=2))

    print(f"\nDemo database: {db_path}")
    print(f"Demo keys:     {keys_dir}/")
    print()

    # Restore original keys dir
    keys_module._keys_dir = original_keys_dir

    return 0 if integrity["valid"] and handoffs["interactions_complete"] == handoffs["interactions_checked"] else 1


if __name__ == "__main__":
    sys.exit(main())
