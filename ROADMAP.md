# AIR Blackbox Product Roadmap

**Last updated:** 2026-04-09
**Horizon:** 30 days of committed build work, plus a vision section for what comes after
**Author:** Jason Shotwell

---

## TL;DR

AIR Blackbox today is four shipped products (`air-trust`, `gateway`, `air-gate`, `air-platform`) that share a tamper-evident HMAC-SHA256 audit chain and conform to the CSA Agentic Trust Framework v0.9.1. The next 30 days are focused on exactly one thing: **closing the completeness gap inside a single session**, shipped as `air-trust` v0.5.0 (spec v1.1). Everything beyond that — signed handoffs, bilateral attestation, federated trust — stays in the vision section until Phase 1 is live and we have real user pull signal.

---

## Product vision (north star, unchanged)

AIR Blackbox is evolving from a **tamper-evident recorder** into a **tamper-evident witness layer for AI workflows**.

The one-liner:

> AIR Blackbox started by proving records weren't changed. Next, it will prove the handoff happened.

The wedge is single-agent tamper-evident logging (shipped). The expansion is cross-agent signed witnessing (Phase 2, vision). The moat is standardized attestation across frameworks and organizational boundaries (Phase 3+, vision).

---

## Where we actually are today (April 9, 2026)

This is the section the old roadmap got wrong. It assumed we were at "v1.0, integrity only." We are not.

**Shipped:**

- `air-trust` v0.4.0 on PyPI — Universal compliance trust layer, CSA Agentic Trust Framework v0.9.1 conformant
- `gateway` — HTTP proxy with HMAC-SHA256 audit chain
- `air-gate` — Human-in-the-loop tool approval checkpoint
- `air-platform` — Full-stack Docker bundle that packages all three together
- `air-blackbox-mcp` — MCP server
- `air-controls` / `air-controls-mcp` — Runtime visibility
- `compliance-action` — GitHub Action
- `airblackbox-site` — Marketing site with the new `/which-product` decision tree page

**Standards pegs:**

- CSA Agentic Trust Framework v0.9.1 — air-trust conforms
- EU AI Act Articles 11 (Technical Documentation) and 12 (Record-Keeping) — targeted
- ISO 42001 and NIST AI RMF — mapping docs in progress

**The deadline that matters:** August 2, 2026. That is roughly **16 weeks** from today for the EU AI Act high-risk AI system obligations. Any work that can't realistically ship usable-and-documented before late July is not on this roadmap.

**What we do not have yet:**

- Sequence numbering on audit records
- Gap detection in the verifier
- Session lifecycle records (`session_start`, `checkpoint`, `session_end`)
- Any cross-system attestation primitives
- A public RFC for the completeness spec

---

## Scope discipline

This roadmap intentionally commits to less than the previous version. That is the whole point of this rewrite.

**What we are building now (the next 30 days):** Phase 1 only — Session Completeness inside `air-trust`. Shipped as v0.5.0 with spec v1.1. This is one person's work for 30 days, and it has to be shippable without a team.

**What we are sketching but not building yet (Phase 2, vision):** A single end-to-end demo of signed handoffs between two cooperating agents, as a blog post and a reference integration. Not a product. Not a protocol. Not in any SKU. Purpose: validate whether anyone actually cares about cross-agent attestation before we invest engineering weeks in building the full protocol.

**What we are explicitly NOT building yet (Phase 3+, vision only):** Co-attestation as a first-class record type, policy engine, evidence graph, federated PKI, trust registry, dispute workflows, attestation profiles, federated trust infrastructure. These live in a whitepaper. Zero engineering hours committed.

The strategic reason for this discipline: we are a solo founder with ~16 weeks until the EU AI Act deadline, four shipped products to maintain, and active contract work that pays the bills. Scope creep is the biggest risk, not slow execution.

---

## Phase 1 — Session Completeness (Days 1–30)

### Objective

Answer Tim's challenge concretely: the chain proves records weren't changed, now it also proves records weren't dropped from a session.

### Owner product

**`air-trust`** owns Phase 1. Rationale:

- Completeness is a property of the audit chain itself, not the transport layer
- `air-trust` already owns the HMAC chain + CSA ATF conformance logic
- Ships as the Python library that every other product depends on, so fixing it here propagates to `gateway`, `air-gate`, and `air-platform` for free
- Downstream: `gateway` inherits the new record types by bumping its `air-trust` dependency; no net-new Go work in Phase 1

### Deliverables

1. **Spec v1.1** — published as `SPEC.md` in the `air-trust` repo, covering required fields, new record types, verification rules, and a threat model for session-scoped completeness claims
2. **Record field additions** — every audit record gains `session_seq` (monotonic int, starts at 0) and `prev_session_seq` (int, `-1` for first record in session)
3. **New record types** — `session_start`, `checkpoint`, `session_end`
4. **Verifier upgrade** — `air_trust.verify.verify_chain()` detects gaps, duplicates, rewinds, missing lifecycle records, and returns a structured completeness report
5. **Backward compatibility** — v1.0 records still verify (integrity-only mode); v1.1 records get both integrity and completeness checks
6. **CLI output** — `air-trust verify` shows pass/warn/fail tiers with human-readable and JSON output
7. **Public RFC** — a blog post on `airblackbox.ai` titled something like "Integrity is not completeness: adding session-level gap detection to tamper-evident audit chains"

### Spec changes (v1.1)

New required fields on every audit record:

```json
{
  "session_seq": 14,
  "prev_session_seq": 13
}
```

New record types:

```json
"session_start"
"checkpoint"
"session_end"
```

Verification rules:

- `session_seq` must increase by exactly 1 within a session
- `prev_session_seq` must match the previous record's `session_seq`
- First record of a session must be `session_start`
- Last record of a session should be `session_end`
- Missing `session_end` → session marked as incomplete (warning, not failure)
- Verifier flags: gaps, duplicates, rewinds, broken lifecycle

### 30-day timeline

**Week 1 (Apr 10–16):**

- Finalize `SPEC.md` v1.1 draft including threat model and scope statement
- Decide backward-compat strategy: additive-only fields, v1.0 records still verify cleanly
- Update the JSON schema in `air-trust/air_trust/schema/`
- Write acceptance tests before implementation (bad-chain fixtures: gap, duplicate, rewind, missing session_end)

**Week 2 (Apr 17–23):**

- Implement `session_seq` and `prev_session_seq` on the `AuditRecord` dataclass
- Implement `session_start`, `checkpoint`, `session_end` record emitters
- Wire session lifecycle into the existing `TrustChain` context manager
- All existing tests still pass

**Week 3 (Apr 24–30):**

- Upgrade `verify_chain()` to return a `CompletenessReport` alongside the existing `IntegrityReport`
- Implement gap / duplicate / rewind / lifecycle detection
- Ship CLI output with PASS / WARN / FAIL tiers and JSON-mode output for CI/CD consumption
- Update the 6 adapter integrations (LangChain, CrewAI, AutoGen, etc.) to emit lifecycle records

**Week 4 (May 1–7):**

- End-to-end smoke test across every adapter
- Produce broken-chain fixtures and document them in `tests/fixtures/`
- Publish `SPEC.md` v1.1 in the air-trust repo
- Tag and publish `air-trust` v0.5.0 to PyPI
- Publish the RFC blog post on `airblackbox.ai`
- Bump `gateway`, `air-gate`, and `air-platform` to depend on v0.5.0 (dependency bump PRs only, no logic changes)

### Acceptance criteria

- `air-trust` v0.5.0 on PyPI
- Verifier reliably detects: sequence gaps, duplicate sequence numbers, rewinds, incomplete lifecycles
- Verifier returns exact missing index ranges for gaps
- All existing adapter tests pass; all new completeness tests pass
- `gateway`, `air-gate`, `air-platform` all consume v0.5.0 without code changes beyond dependency bump
- `SPEC.md` v1.1 published in repo and linked from `airblackbox.ai/which-product`
- Public RFC post live

---

## Product ownership map (Section B)

When Phase 2 and Phase 3 eventually become real work (not yet), here's where the work lives:

| Capability | Owner product | Reason |
|---|---|---|
| HMAC-SHA256 audit chain | `air-trust` | Core primitive, Python library, already shipped |
| Session sequence + completeness (v1.1) | `air-trust` | Property of the chain itself |
| CSA ATF conformance checks | `air-trust` | Already shipped as of v0.4.0 |
| HTTP proxy audit logging | `gateway` | Transport layer for non-Python callers |
| Human-in-the-loop tool approval | `air-gate` | Approval is a runtime workflow, not a chain property |
| Signed handoff envelopes (v1.2, vision) | `gateway` | Handoffs are cross-process; the proxy already sits at the boundary |
| Ed25519 key management (vision) | `gateway` | Keys live where signing happens |
| Co-attestation records (v1.2b, vision) | `air-trust` | Record shape lives in the core library |
| Policy engine (vision) | `air-gate` | Policy is already `air-gate`'s job |
| OTel trace correlation (vision) | `air-trust` + `gateway` | Need both sides |
| Docker bundle + reference deployment | `air-platform` | The full stack SKU |
| Evidence explorer UI (vision) | TBD — probably `air-platform` | User-facing, lives in the bundle |
| Federated trust / PKI (vision only) | Unassigned | Not building this |

The key principle: **`air-trust` owns record shapes and verification logic; `gateway` owns cross-process transport and signing; `air-gate` owns approval and policy; `air-platform` owns packaging.** No single product needs to do all four things.

---

## Phase 2 — Signed Handoff Demo (vision, NOT committed)

**This is not on the 30-day plan.** It lives here to keep the north star visible and to give us something to validate demand against before committing engineering time.

### What it would be

A single end-to-end demo of two cooperating agents signing a handoff, published as:

- One blog post walking through the demo
- One reference integration in the `gateway` repo under `examples/signed-handoff/`
- One spec draft called v1.2-alpha, clearly marked as experimental

### What it would NOT be

- A shipped product SKU
- A stable spec
- A required feature of any product
- Available in `air-platform`
- Marketed as "verified agent interactions"

### Trigger to actually build it

Phase 2 becomes real work only if **at least two of** the following are true after Phase 1 ships:

1. A paying customer or serious enterprise lead asks for cross-agent attestation by name
2. At least three GitHub issues or discussion threads request the feature
3. A framework maintainer (LangChain, CrewAI, AutoGen) expresses interest in integrating
4. An analyst or compliance firm cites the lack of cross-agent proof as a gap

Without two of those four signals, Phase 2 stays a demo, not a product.

### Rough shape if it does become real

- Ed25519 signatures for cross-party attestation (keep HMAC for internal chain integrity)
- New record types: `handoff_request`, `handoff_ack`, `handoff_result`
- New fields: `interaction_id`, `counterparty_id`, `payload_hash`, `nonce`, `signature`, `signature_alg`
- Owner: `gateway` for transport and signing, `air-trust` for record shapes
- OTel `trace_id` / `span_id` correlation

---

## Phase 3+ — Trust Infrastructure (vision whitepaper only)

Everything below is **not on any build timeline**. It exists so the story has a horizon and so enterprise conversations have somewhere to point.

- Evidence graph visualization
- Policy engine ("critical actions require bilateral attestation")
- Dispute detection
- Federated PKI and key rotation
- Trust registry across orgs
- Attestation profiles (lightweight / strict / partner federation)
- Signed evidence bundles for audit export
- Enterprise SKU tier

These will be written up as a `VISION.md` whitepaper after Phase 1 ships. Not before.

---

## Spec evolution plan

| Version | Status | Focus | Target date |
|---|---|---|---|
| v1.0 | Shipped | Integrity only (HMAC chain) | Already live |
| v0.9.1 ATF conformance | Shipped in `air-trust` v0.4.0 | CSA Agentic Trust Framework | Already live |
| **v1.1** | **Building** | **Session completeness** | **May 7, 2026 (Day 30)** |
| v1.2-alpha | Vision (demo only) | Signed handoff primitives | Unscheduled |
| v1.2-beta | Vision (whitepaper only) | Co-attestation | Unscheduled |

---

## What we are explicitly NOT doing in the next 30 days

This list exists so future-Jason can't quietly slip any of it back into the plan.

- Building a policy engine
- Building an evidence graph visualizer
- Writing a federated trust / PKI system
- Writing key rotation infrastructure
- Shipping any cross-org attestation features
- Rewriting the brand around "Verified Agent Interactions"
- Competing with observability platforms
- Adding a new SKU tier
- Repositioning `air-trust` as anything other than "the open-source EU AI Act compliance trust layer"
- Changing the four-product split described in `which-product.html`

If any of the above starts to feel urgent during the next 30 days, write it in `VISION.md` instead.

---

## Success criteria for this roadmap (not for Phase 1 itself)

By May 7, 2026:

1. `air-trust` v0.5.0 is on PyPI
2. Spec v1.1 is published and linked from the marketing site
3. The RFC blog post is live and has been shared in at least 3 places (Hacker News, r/LocalLLaMA or similar, LinkedIn)
4. At least one downstream product (`gateway`, `air-gate`, or `air-platform`) has consumed v0.5.0
5. The "what are we NOT doing" list above is intact and unmodified
6. We have a public answer to Tim's challenge that we can point to

If items 1–4 are shipped but we have not collected any Phase 2 signal, that is **success**, not failure. The point of Phase 1 is to ship Phase 1, not to justify Phase 2.

---

## Open questions for Jason

Questions this rewrite didn't answer. Worth thinking through before Week 1 starts.

1. **Versioning choice**: Is `air-trust` v0.5.0 the right number for "spec v1.1"? Or should we bump to v1.0.0 to signal production readiness? A 0.x version number may be hurting adoption for compliance buyers.
2. **Where does `SPEC.md` live?** In `air-trust/SPEC.md`? In a separate `airblackbox/spec` repo? On the marketing site? All three?
3. **RFC format**: Public blog post, GitHub Discussion, or a formal RFC repo with comment periods? The first is fastest; the third builds more credibility with compliance audiences.
4. **Who reviews the threat model?** The completeness claim needs at least one external reviewer who will push back hard. Tim? A CSA ATF contributor? A friendly academic?
5. **Phase 2 demand-signal tracker**: Do we add an issue template to every repo ("Cross-agent attestation interest") to systematically collect the signal, or just watch organically?

---

*This roadmap replaces the previous 90-day version dated March 2026. The previous version committed to building Phase 2 and Phase 3 as shipped features; this version builds Phase 1 only and keeps the rest in the vision section until we have real pull signal.*
