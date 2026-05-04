# AIR Blackbox Product Roadmap

**Last updated:** 2026-04-10
**Horizon:** 30 days of committed build work (Phase 2), plus a vision section for what comes after
**Author:** Jason Shotwell

---

## TL;DR

Phase 1 (Session Completeness) shipped on April 10, 2026 as `air-trust` v0.5.0 - spec v1.1, 254 tests, PyPI live, RFC blog post published. The next 30 days are focused on exactly one thing: **signed handoffs between cooperating agents**, shipped as `air-trust` v0.6.0 (spec v1.2). This adds Ed25519 asymmetric signatures on top of the existing HMAC-SHA256 chain so two agents can cryptographically prove a task was handed off, acknowledged, and completed. Everything beyond that - federated trust, policy engine, evidence graphs - stays in the vision section.

---

## Product vision (north star, unchanged)

AIR Blackbox is evolving from a **tamper-evident recorder** into a **tamper-evident witness layer for AI workflows**.

The one-liner:

> AIR Blackbox started by proving records weren't changed (v1.0). Then it proved records weren't dropped (v1.1). Now it proves the handoff happened (v1.2).

The wedge is single-agent tamper-evident logging (shipped). The expansion is cross-agent signed witnessing (Phase 2, building now). The moat is standardized attestation across frameworks and organizational boundaries (Phase 3+, vision).

---

## What we've shipped

### Phase 1 - Session Completeness ✅ SHIPPED

**Shipped:** April 10, 2026 as `air-trust` v0.5.0

- Spec v1.1 with `session_seq` / `prev_session_seq` for gap detection
- ContextVar-based `session_id` propagation - zero adapter changes needed
- Completeness verifier: gaps, duplicates, rewinds, missing lifecycle records
- CLI upgrade with PASS/WARN/FAIL tiers, `--json` and `--key` flags
- 31 new tests (254 total), SPEC.md, CHANGELOG.md published
- RFC blog post: "Integrity Is Not Completeness" live on airblackbox.ai
- PyPI: https://pypi.org/project/air-trust/0.5.0/

### Previously shipped

- `air-trust` v0.4.0 - CSA Agentic Trust Framework v0.9.1 conformant
- `gateway` - HTTP proxy with HMAC-SHA256 audit chain
- `air-gate` - Human-in-the-loop tool approval checkpoint
- `air-platform` - Full-stack Docker bundle
- `air-blackbox-mcp` - MCP server
- `air-controls` / `air-controls-mcp` - Runtime visibility
- `compliance-action` - GitHub Action
- `airblackbox-site` - Marketing site with `/which-product` decision tree

### Standards pegs

- CSA Agentic Trust Framework v0.9.1 - air-trust conforms
- EU AI Act Articles 11 (Technical Documentation) and 12 (Record-Keeping) - targeted
- ISO 42001 and NIST AI RMF - mapping docs in progress

**The deadline that matters:** August 2, 2026 - roughly **16 weeks** from today for EU AI Act high-risk AI system obligations.

---

## Phase 2 - Signed Handoffs ✅ SHIPPED

**Shipped:** April 10, 2026 as `air-trust` v0.6.1 (28 days ahead of schedule)

### The problem Phase 2 solves

Phase 1 proves records weren't dropped *within a single session*. But modern AI workflows involve multiple agents cooperating - Agent A researches, then hands context to Agent B for writing, then Agent C reviews. Today, the audit chain can prove each agent's individual records are intact, but it cannot prove:

1. That Agent A actually sent the handoff to Agent B (not spoofed)
2. That Agent B acknowledged receiving it (not dropped silently)
3. That Agent B's result corresponds to Agent A's request (not swapped)

This matters for EU AI Act Article 12 because record-keeping must cover the *entire decision chain*, not just individual agent sessions. If an auditor asks "how did this decision get made?", you need proof that the handoff between agents actually happened and wasn't tampered with.

### How it works (the design)

**Keep HMAC for chain integrity. Add Ed25519 for cross-agent identity.**

HMAC-SHA256 is perfect for "records in this chain haven't been tampered with" - a shared secret between writer and verifier. But HMAC can't prove *who* wrote a record because any party with the key can sign. For cross-agent handoffs, you need asymmetric signatures: Agent A signs with its private key, Agent B (and auditors) verify with Agent A's public key.

**The handoff protocol (three records):**

```
Agent A writes:  handoff_request  (signed by A's Ed25519 private key)
                 → "Here's the task, here's the payload hash, here's my identity"

Agent B writes:  handoff_ack      (signed by B's Ed25519 private key)
                 → "I received the request, I accept it, here's my identity"

Agent B writes:  handoff_result   (signed by B's Ed25519 private key)
                 → "Here's my output, here's the hash of what I produced"
```

The verifier checks: (1) signatures are valid, (2) the `interaction_id` links all three records, (3) payload hashes match, (4) both agents' identities are bound to their keys.

**New fields on Event (additive, backward compatible):**

```json
{
  "interaction_id": "uuid",
  "counterparty_id": "agent-b-fingerprint",
  "payload_hash": "sha256-of-handoff-payload",
  "nonce": "random-bytes-hex",
  "signature": "ed25519-signature-hex",
  "signature_alg": "ed25519",
  "public_key": "ed25519-public-key-hex"
}
```

**What stays the same:**

- HMAC-SHA256 chain integrity (untouched - still the backbone)
- Session completeness (v1.1 - still works, handoff records get session_seq too)
- All existing adapters (zero changes needed - handoffs are opt-in)
- SQLite storage (new columns, migration on first access)
- CLI backward compat (v1.0 and v1.1 records still verify)

### Owner product

**`air-trust`** owns Phase 2 record shapes, key generation, signing, and verification. Rationale:

- Handoff records are Events with new fields - same dataclass, same chain
- Ed25519 key generation is a library function, not a transport concern
- The verifier already lives in air-trust - handoff verification extends it
- `gateway` will inherit handoff support by bumping its air-trust dependency (Phase 2 scope does NOT include Go-side changes)

### Deliverables

1. **Spec v1.2** - published as update to `SPEC.md`, covering handoff record types, Ed25519 signing rules, verification rules, and threat model
2. **Ed25519 key management** - `air_trust.keys` module: generate keypair, store in `~/.air-trust/keys/`, load by agent fingerprint
3. **Handoff record types** - `handoff_request`, `handoff_ack`, `handoff_result` with new fields on Event
4. **Handoff signing** - `AuditChain.write()` auto-signs handoff records with agent's Ed25519 private key
5. **Handoff verification** - `verify()` returns `integrity` + `completeness` + `handoffs` section: checks signatures, interaction linking, payload hash matching
6. **CLI output** - `air-trust verify` adds HANDOFF tier alongside PASS/WARN/FAIL
7. **End-to-end demo** - `examples/signed-handoff/` with two agents doing a research→write handoff
8. **Public RFC** - blog post: "Proving the Handoff: Adding Cross-Agent Signatures to Tamper-Evident Audit Chains"

### Spec changes (v1.2)

New fields on handoff Event records (optional on non-handoff records):

```json
{
  "interaction_id": "a1b2c3d4",
  "counterparty_id": "agent-b-fp",
  "payload_hash": "sha256:abcdef...",
  "nonce": "random16hex",
  "signature": "ed25519:hexstring",
  "signature_alg": "ed25519",
  "public_key": "ed25519:hexstring"
}
```

New record types:

```json
"handoff_request"   // Agent A → "I'm handing off this task"
"handoff_ack"       // Agent B → "I accept the handoff"
"handoff_result"    // Agent B → "Here's my result"
```

Verification rules:

- Every `handoff_request` must have a matching `handoff_ack` with the same `interaction_id`
- Every `handoff_ack` should have a matching `handoff_result` (missing = incomplete handoff, warning)
- `signature` must verify against `public_key` using Ed25519
- `payload_hash` in `handoff_ack` must match `payload_hash` in `handoff_request`
- `counterparty_id` in request must match the signing agent's fingerprint in ack
- Handoff records still participate in HMAC chain integrity and session completeness

### 30-day timeline

**Week 1 (Apr 11-17): Spec + Key Management**

- Write SPEC.md v1.2 draft with threat model and scope statement
- Implement `air_trust/keys.py`: Ed25519 keypair generation, storage in `~/.air-trust/keys/{fingerprint}.pub` and `{fingerprint}.key`, key loading by fingerprint
- Add `public_key` field to `AgentIdentity` (auto-populated on key generation)
- Write acceptance tests: key generation, key storage permissions (0o600), key loading, key-not-found errors
- Decide: does `AgentIdentity` auto-generate a keypair on first use, or require explicit `air_trust.keys.generate()`?

**Week 2 (Apr 18-24): Record Types + Signing**

- Add handoff fields to Event dataclass (all Optional, backward compat)
- Add `handoff_request`, `handoff_ack`, `handoff_result` to recognized event types
- Implement signing in `AuditChain.write()`: if event type is `handoff_*`, compute Ed25519 signature over `interaction_id + counterparty_id + payload_hash + nonce`
- Add SQLite migration for new columns + `idx_interaction_id` index
- Implement `air_trust.handoff()` context manager or helper:
  ```python
  async with air_trust.handoff(chain, from_agent=identity_a, to_agent=identity_b) as h:
      h.request(payload="research these topics")
      # ... Agent B does work ...
      h.ack()
      h.result(payload="here are the results")
  ```
- Write tests: signing produces valid signature, wrong key fails verification, nonce uniqueness, payload hash computation

**Week 3 (Apr 25-May 1): Verification + CLI**

- Extend `verify()` to return `handoffs` section alongside `integrity` and `completeness`
- Implement `_check_handoffs(records)`: groups by `interaction_id`, checks request/ack/result completeness, verifies Ed25519 signatures, checks payload hash matching
- Handoff issues: `missing_ack`, `missing_result`, `signature_invalid`, `payload_mismatch`, `counterparty_mismatch`
- CLI upgrade: `air-trust verify` shows handoff verification results with pass/warn/fail
- All existing tests still pass (v1.0 and v1.1 records unaffected)
- Write comprehensive handoff test suite: clean handoff, missing ack, bad signature, payload tamper, multi-handoff chain

**Week 4 (May 2-8): Demo + Blog + Ship**

- Build `examples/signed-handoff/` - two-agent demo (Agent A = researcher, Agent B = writer)
- Demo generates a complete audit chain with handoff records, then verifies it
- Write RFC blog post for airblackbox.ai
- Update CHANGELOG.md
- Version bump to v0.6.0
- Tag `air-trust-v0.6.0`, push, publish to PyPI
- Bump downstream `gateway`, `air-gate`, `air-platform` dependencies

### Acceptance criteria

- `air-trust` v0.6.0 on PyPI
- Ed25519 keypair generation and storage working
- Handoff protocol: request → ack → result with valid signatures
- Verifier detects: missing ack, missing result, bad signature, payload hash mismatch, counterparty mismatch
- All existing tests pass (v1.0, v1.1 backward compat preserved)
- `examples/signed-handoff/` runs end-to-end and verifies clean
- SPEC.md v1.2 published
- RFC blog post live on airblackbox.ai
- At least 30 new handoff-specific tests

---

## Product ownership map

| Capability | Owner product | Reason |
|---|---|---|
| HMAC-SHA256 audit chain | `air-trust` | Core primitive, already shipped |
| Session sequence + completeness (v1.1) | `air-trust` | ✅ Shipped in v0.5.0 |
| CSA ATF conformance checks | `air-trust` | ✅ Shipped in v0.4.0 |
| **Ed25519 key management (v1.2)** | **`air-trust`** | **Keys are per-agent-identity, library concern** |
| **Handoff record types (v1.2)** | **`air-trust`** | **Record shapes live in the core library** |
| **Handoff signing + verification (v1.2)** | **`air-trust`** | **Extends existing verify()** |
| HTTP proxy audit logging | `gateway` | Transport layer for non-Python callers |
| Human-in-the-loop tool approval | `air-gate` | Approval is a runtime workflow |
| Cross-process handoff transport (future) | `gateway` | When Go side needs handoff awareness |
| Policy engine (vision) | `air-gate` | Policy is already air-gate's job |
| Docker bundle + reference deployment | `air-platform` | The full stack SKU |
| Evidence explorer UI (vision) | TBD | User-facing, probably air-platform |
| Federated trust / PKI (vision only) | Unassigned | Not building this |

**Key principle unchanged:** `air-trust` owns record shapes and verification logic; `gateway` owns cross-process transport and signing; `air-gate` owns approval and policy; `air-platform` owns packaging.

---

## Spec evolution plan

| Version | Status | Focus | Target date |
|---|---|---|---|
| v1.0 | ✅ Shipped | Integrity only (HMAC chain) | Live |
| v0.9.1 ATF | ✅ Shipped in v0.4.0 | CSA Agentic Trust Framework | Live |
| v1.1 | ✅ Shipped in v0.5.0 | Session completeness | April 10, 2026 |
| **v1.2** | **✅ Shipped in v0.6.1** | **Signed handoffs (Ed25519)** | **April 10, 2026** |
| v1.3-alpha | Vision (demo only) | Co-attestation / bilateral proof | Unscheduled |

---

## Phase 3+ - Trust Infrastructure (vision whitepaper only)

Everything below is **not on any build timeline**. It exists so the story has a horizon.

- Co-attestation as a first-class record type (bilateral proof, not just unilateral signing)
- Evidence graph visualization
- Policy engine ("critical actions require bilateral attestation")
- Dispute detection and resolution records
- Federated PKI and key rotation
- Trust registry across orgs
- Attestation profiles (lightweight / strict / partner federation)
- Signed evidence bundles for audit export
- Enterprise SKU tier

These will be written up as a `VISION.md` whitepaper after Phase 2 ships.

---

## What we are explicitly NOT doing in the next 30 days

- Building federated PKI or key rotation infrastructure
- Building bilateral co-attestation (Phase 2 is unilateral signing - A signs for A, B signs for B)
- Building a policy engine around handoffs
- Building an evidence graph visualizer
- Making Go-side gateway changes (air-trust only)
- Changing any existing adapter code (handoffs are opt-in, new API surface)
- Rewriting the brand around "Verified Agent Interactions"
- Adding a new SKU tier
- Competing with observability platforms

If any of the above starts to feel urgent during the next 30 days, write it in `VISION.md` instead.

---

## Success criteria for this roadmap

By May 8, 2026:

1. `air-trust` v0.6.0 is on PyPI with Ed25519 handoff signing
2. Spec v1.2 is published and linked from the marketing site
3. The RFC blog post is live and shared in at least 3 places
4. `examples/signed-handoff/` is a working, runnable demo
5. At least one downstream product has consumed v0.6.0
6. The "what are we NOT doing" list above is intact and unmodified
7. We can show an auditor: "here's cryptographic proof that Agent A handed off to Agent B, and Agent B acknowledged it"

---

## Open questions for Jason

1. **Key storage location**: `~/.air-trust/keys/` alongside the existing `signing.key`? Or a separate `~/.air-trust/identities/` directory that bundles identity + keypair?
2. **Auto-generate keys?** Should `AgentIdentity` auto-generate an Ed25519 keypair on first use, or require explicit `air_trust.keys.generate(identity)`? Auto is simpler for devs, explicit is safer for enterprise.
3. **Handoff API shape**: Context manager (`async with air_trust.handoff(...)`) vs. explicit calls (`chain.write_handoff_request(...)`)? Context manager is cleaner but limits flexibility.
4. **Sync vs async**: The existing codebase is sync. Should handoffs stay sync or move to async? Most multi-agent frameworks (CrewAI, AutoGen) are async.
5. **Version number**: v0.6.0 or jump to v1.0.0? Adding cross-agent attestation might be the feature that justifies a 1.0 signal.

---

*This roadmap replaces the previous Phase 2 vision section. Phase 1 (Session Completeness) shipped on April 10, 2026 as air-trust v0.5.0. Phase 2 is committed build work starting April 11, 2026, shipping no later than May 8, 2026.*
