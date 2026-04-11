# AIR Trust Audit Chain Specification v1.2

**Status:** Draft
**Date:** 2026-04-10
**Author:** Jason Shotwell (jason@airblackbox.ai)
**Supersedes:** v1.1 (session completeness)

---

## 1. Overview

This specification defines the tamper-evident audit chain format for AIR Trust, the universal compliance trust layer for AI systems.

**v1.0** established the HMAC-SHA256 chain that proves records were not modified after being written. **v1.1** added session-scoped sequence numbering and lifecycle records that prove records were not *dropped* within a session. **v1.2** adds Ed25519 asymmetric signatures and handoff records that prove a task was transferred between agents and acknowledged.

Together, these provide three guarantees:

- **Integrity:** no record was changed after it was written (v1.0, unchanged)
- **Completeness:** no record was silently dropped within a session (v1.1, unchanged)
- **Handoff provenance:** a task transfer between agents was signed, acknowledged, and completed (v1.2, new)

### 1.1 Scope

v1.2 covers **unilateral signed handoffs** between two cooperating agents within the same audit chain. It answers the question:

> "Can we prove that Agent A requested a handoff to Agent B, that Agent B acknowledged it, and that Agent B's result corresponds to Agent A's request?"

It does NOT cover:

- **Bilateral co-attestation** (both parties signing a single shared record)
- **Cross-chain handoffs** (agents writing to different databases)
- **Federated trust** (agents in different organizations with separate PKI)
- **Key rotation or revocation** (keys are static per agent identity for now)
- **Non-repudiation in a legal sense** (Ed25519 proves key-holder signed, not that a specific human authorized it)

These limitations are intentional. v1.2 proves "the right keys signed the right records in the right order." It does not prove "the right humans authorized the right agents." That belongs in a policy layer (air-gate), not the audit chain.

### 1.2 Backward Compatibility

v1.2 is **additive-only**:

- v1.0 records (integrity only) remain valid and verify successfully
- v1.1 records (session completeness) remain valid and verify successfully
- Handoff fields are `Optional` — only present on handoff record types
- Non-handoff records are completely unaffected
- The verifier runs handoff checks only on records with `interaction_id`
- Mixed chains (v1.0 + v1.1 + v1.2 records) are explicitly supported

### 1.3 Standards Alignment

- **CSA Agentic Trust Framework v0.9.1** — signed handoffs strengthen ATF Interaction Logging (Section 4.3) by providing cryptographic proof of agent-to-agent communication
- **EU AI Act Article 12 (Record-Keeping)** — handoff provenance supports the requirement that logs cover "the entire lifecycle of the system," including multi-agent decision chains
- **EU AI Act Article 14 (Human Oversight)** — binding agent identities to Ed25519 keys creates a verifiable link between the authorizing human (via AgentIdentity.owner) and the agent's actions
- **ISO 42001 Clause 8** — handoff records provide operational evidence of controlled AI interactions

---

## 2. Chain Formula (unchanged from v1.0)

Every record is signed with HMAC-SHA256 and linked to the previous record:

```
chain_hash = HMAC-SHA256(
    key = signing_key,
    message = previous_hash_bytes || JSON(record, sort_keys=True)
)
```

Where:

- `signing_key` is a persistent hex-encoded key stored at `~/.air-trust/signing.key`
- `previous_hash_bytes` is the raw bytes of the preceding record's `chain_hash` (or `b"genesis"` for the first record)
- `JSON(record, sort_keys=True)` is the deterministic JSON serialization of the record with `chain_hash` excluded

**This formula is identical to v1.0 and v1.1. No changes.**

The HMAC chain proves integrity (no record was modified). Ed25519 signatures (Section 5) prove identity (which agent wrote the record). These are independent, complementary mechanisms.

---

## 3. Session Completeness Fields (unchanged from v1.1)

### 3.1 `session_seq` (integer)

A monotonically increasing sequence number scoped to a single session.

- Starts at `0` for the first record in a session (the `session_start` record)
- Increments by exactly `1` for each subsequent record in the same session
- Scoped by `session_id` — different sessions have independent counters
- MUST be present on every record that has a `session_id`

### 3.2 `prev_session_seq` (integer)

The `session_seq` of the immediately preceding record in the same session.

- Set to `-1` for the first record in a session (there is no predecessor)
- For all other records: MUST equal the `session_seq` of the previous record with the same `session_id`

### 3.3 `session_id` (string)

A unique identifier for the session. Format: UUID v4 (hex string, no dashes).

- MUST be present on every record emitted within a `session()` context
- Records without a `session_id` are "unscoped" and exempt from completeness checking

### 3.4 Lifecycle Record Types (unchanged from v1.1)

- `session_start` — first record in a session (`session_seq: 0`, `prev_session_seq: -1`)
- `checkpoint` — developer-defined intermediate record (optional)
- `session_end` — final record in a session (`status: "success"` or `"error"`)

---

## 4. Ed25519 Key Management (new in v1.2)

### 4.1 Key Generation

Each `AgentIdentity` MAY have an associated Ed25519 keypair. Keys are generated using the standard Ed25519 algorithm (RFC 8032).

- **Private key:** 32 bytes, stored as hex string
- **Public key:** 32 bytes, stored as hex string
- **Keypair generation:** deterministic from seed or random

### 4.2 Key Storage

Keys are stored in the local filesystem at `~/.air-trust/keys/`:

```
~/.air-trust/keys/
├── {fingerprint}.key      # Ed25519 private key (hex), permissions 0o600
└── {fingerprint}.pub      # Ed25519 public key (hex), permissions 0o644
```

Where `{fingerprint}` is the `AgentIdentity.fingerprint` (SHA256[:16] of identity fields).

File permissions:

- Private key files MUST be created with mode `0o600` (owner read/write only)
- Public key files SHOULD be created with mode `0o644` (world readable)

### 4.3 Key Binding

An agent's public key is bound to its identity via the `public_key` field on `AgentIdentity`:

```json
{
    "agent_name": "research-agent",
    "owner": "jason@airblackbox.ai",
    "fingerprint": "a1b2c3d4e5f67890",
    "public_key": "ed25519:3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
}
```

The `ed25519:` prefix on the public key distinguishes it from future signature algorithms.

### 4.4 No Key Rotation (v1.2 limitation)

v1.2 does not support key rotation or revocation. A keypair is bound to an agent identity for its lifetime. Key rotation infrastructure is deferred to a future spec version.

If a key is compromised, the agent identity must be retired and a new identity (with new fingerprint and keypair) must be created.

---

## 5. Handoff Record Types (new in v1.2)

### 5.1 New Fields

Handoff records carry the following additional fields. These fields are REQUIRED on handoff record types and MUST NOT be present on non-handoff records.

| Field | Type | Description |
|---|---|---|
| `interaction_id` | string (UUID hex) | Links all records in a single handoff exchange |
| `counterparty_id` | string | Fingerprint of the other agent in the handoff |
| `payload_hash` | string | `sha256:{hex}` hash of the handoff payload |
| `nonce` | string | Random 16-byte hex string, unique per record |
| `signature` | string | `ed25519:{hex}` signature over the signing payload |
| `signature_alg` | string | Always `"ed25519"` in v1.2 |
| `public_key` | string | `ed25519:{hex}` public key of the signing agent |

### 5.2 Signing Payload

The Ed25519 signature is computed over the following concatenated fields, in this order:

```
signing_payload = interaction_id || counterparty_id || payload_hash || nonce || type || timestamp
```

All fields are UTF-8 encoded strings concatenated with `|` as a delimiter:

```
"a1b2c3d4|agent-b-fp|sha256:abcdef...|random16hex|handoff_request|2026-04-10T14:30:00Z"
```

The signature is then:

```
signature = Ed25519.sign(private_key, signing_payload)
```

### 5.3 `handoff_request`

Emitted by the **sending agent** (Agent A) to initiate a handoff.

Required properties:

- `type`: `"handoff_request"`
- `interaction_id`: new UUID for this handoff exchange
- `counterparty_id`: fingerprint of the receiving agent (Agent B)
- `payload_hash`: SHA-256 hash of the task/payload being handed off
- `nonce`: random 16-byte hex
- `signature`: Ed25519 signature by Agent A
- `signature_alg`: `"ed25519"`
- `public_key`: Agent A's public key

The `payload_hash` is computed as:

```
payload_hash = "sha256:" + SHA256(payload_bytes)
```

Where `payload_bytes` is the UTF-8 encoding of whatever data is being handed off (task description, context, documents, etc.). The actual payload is NOT stored in the audit chain — only its hash.

### 5.4 `handoff_ack`

Emitted by the **receiving agent** (Agent B) to acknowledge receipt.

Required properties:

- `type`: `"handoff_ack"`
- `interaction_id`: MUST match the `handoff_request`'s `interaction_id`
- `counterparty_id`: fingerprint of the sending agent (Agent A)
- `payload_hash`: MUST match the `handoff_request`'s `payload_hash`
- `nonce`: random 16-byte hex (different from request's nonce)
- `signature`: Ed25519 signature by Agent B
- `signature_alg`: `"ed25519"`
- `public_key`: Agent B's public key

The matching `payload_hash` proves Agent B received the same payload Agent A sent.

### 5.5 `handoff_result`

Emitted by the **receiving agent** (Agent B) when work is complete.

Required properties:

- `type`: `"handoff_result"`
- `interaction_id`: MUST match the original `handoff_request`'s `interaction_id`
- `counterparty_id`: fingerprint of the sending agent (Agent A)
- `payload_hash`: SHA-256 hash of the result payload (NOT the original request payload)
- `nonce`: random 16-byte hex (different from previous nonces)
- `signature`: Ed25519 signature by Agent B
- `signature_alg`: `"ed25519"`
- `public_key`: Agent B's public key

### 5.6 Example Handoff Exchange

```json
// Record 1: Agent A requests handoff
{
    "type": "handoff_request",
    "interaction_id": "a1b2c3d4e5f6789012345678abcdef01",
    "counterparty_id": "b2c3d4e5f6a17890",
    "payload_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "nonce": "f47ac10b58cc4372",
    "signature": "ed25519:3b6a27bcceb6a42d62a3...",
    "signature_alg": "ed25519",
    "public_key": "ed25519:a1b2c3d4...",
    "session_id": "d4e5f6a1b2c3789012345678abcdef01",
    "session_seq": 5,
    "prev_session_seq": 4,
    "timestamp": "2026-04-10T14:30:00Z",
    "version": "1.2.0"
}

// Record 2: Agent B acknowledges
{
    "type": "handoff_ack",
    "interaction_id": "a1b2c3d4e5f6789012345678abcdef01",
    "counterparty_id": "a1b2c3d4e5f67890",
    "payload_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "nonce": "8b4f92e71a3c5d60",
    "signature": "ed25519:7d2f4e8b1c9a3f05...",
    "signature_alg": "ed25519",
    "public_key": "ed25519:b2c3d4e5...",
    "session_id": "d4e5f6a1b2c3789012345678abcdef01",
    "session_seq": 6,
    "prev_session_seq": 5,
    "timestamp": "2026-04-10T14:30:01Z",
    "version": "1.2.0"
}

// Record 3: Agent B delivers result
{
    "type": "handoff_result",
    "interaction_id": "a1b2c3d4e5f6789012345678abcdef01",
    "counterparty_id": "a1b2c3d4e5f67890",
    "payload_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "nonce": "2c7e9b4d1f8a6053",
    "signature": "ed25519:4e8c2a1f7b3d9e06...",
    "signature_alg": "ed25519",
    "public_key": "ed25519:b2c3d4e5...",
    "session_id": "d4e5f6a1b2c3789012345678abcdef01",
    "session_seq": 7,
    "prev_session_seq": 6,
    "timestamp": "2026-04-10T14:31:00Z",
    "version": "1.2.0"
}
```

---

## 6. Verification Rules

The verifier performs three independent checks on a chain:

### 6.1 Integrity Check (unchanged from v1.0)

Replays the chain from genesis, recomputing every HMAC. If any recomputed hash does not match the stored `chain_hash`, the chain has been tampered with.

Result: `PASS` or `FAIL` (with the index of the broken record).

### 6.2 Completeness Check (unchanged from v1.1)

Groups records by `session_id` and checks each session for: sequence gaps, duplicates, rewinds, and lifecycle boundary violations.

Result: per-session `PASS`, `WARN`, or `INFO` (see v1.1 spec for details).

### 6.3 Handoff Check (new in v1.2)

Groups records by `interaction_id` and checks each handoff exchange for:

#### 6.3.1 Structural Completeness

For each `interaction_id`, the verifier expects:

- Exactly one `handoff_request`
- Exactly one `handoff_ack`
- At most one `handoff_result`

Missing records:

| Present | Missing | Severity |
|---|---|---|
| request only | ack + result | **WARN** — handoff was never acknowledged |
| request + ack | result | **INFO** — handoff in progress or agent crashed |
| request + ack + result | nothing | **PASS** — complete handoff |
| ack or result without request | request | **WARN** — orphaned handoff response |

#### 6.3.2 Signature Verification

For each handoff record:

1. Extract the `signing_payload` (Section 5.2) from the record fields
2. Verify `Ed25519.verify(public_key, signature, signing_payload)`
3. If verification fails: **FAIL** — the signature does not match

#### 6.3.3 Payload Hash Matching

- The `payload_hash` in `handoff_ack` MUST equal the `payload_hash` in `handoff_request`
- If they differ: **WARN** — Agent B received different data than Agent A sent

The `payload_hash` in `handoff_result` is allowed to differ (it hashes the *result*, not the original request).

#### 6.3.4 Counterparty Matching

- In `handoff_request`: `counterparty_id` MUST match `handoff_ack.public_key`'s agent fingerprint
- In `handoff_ack`: `counterparty_id` MUST match `handoff_request.public_key`'s agent fingerprint
- If they differ: **WARN** — the handoff was acknowledged by a different agent than intended

#### 6.3.5 Nonce Uniqueness

- Every `nonce` in handoff records MUST be unique within the chain
- Duplicate nonces: **WARN** — possible replay attack

### 6.4 Verification Output

The verifier returns a structured report with all three sections:

```json
{
    "integrity": {
        "valid": true,
        "records": 47,
        "broken_at": null
    },
    "completeness": {
        "sessions_checked": 3,
        "sessions_complete": 2,
        "sessions_incomplete": 1,
        "issues": []
    },
    "handoffs": {
        "interactions_checked": 2,
        "interactions_complete": 1,
        "interactions_incomplete": 1,
        "issues": [
            {
                "interaction_id": "a1b2c3d4...",
                "issue": "missing_result",
                "severity": "info"
            }
        ]
    },
    "valid": true,
    "records": 47,
    "broken_at": null
}
```

Top-level `valid`, `records`, and `broken_at` remain for backward compatibility (reflect integrity check only).

### 6.5 Severity Tiers (updated)

| Issue | Severity | Meaning |
|---|---|---|
| Chain hash mismatch | **FAIL** | A record was modified after writing. Trust is broken. |
| Signature invalid | **FAIL** | An Ed25519 signature does not verify. Record is forged or corrupted. |
| Sequence gap | **WARN** | A record appears to be missing from the session. |
| Duplicate sequence | **WARN** | Two records claim the same position. |
| Sequence rewind | **WARN** | The counter went backward. |
| Missing handoff ack | **WARN** | Handoff was never acknowledged. |
| Payload hash mismatch | **WARN** | Agent B received different data than Agent A sent. |
| Counterparty mismatch | **WARN** | Wrong agent acknowledged the handoff. |
| Duplicate nonce | **WARN** | Possible replay attack. |
| Orphaned handoff response | **WARN** | Ack or result without a matching request. |
| Missing `session_end` | **INFO** | Session may have crashed or still running. |
| Missing handoff result | **INFO** | Handoff in progress or agent crashed. |
| Missing `session_start` | **WARN** | First record is not a lifecycle boundary. |

Integrity and signature failures are always **FAIL** (cryptographic proof of tampering or forgery). Structural issues are **WARN** or **INFO** (suspicious conditions, not proof of malice).

---

## 7. Threat Model

### 7.1 What Signed Handoffs Detect

- **Handoff forgery:** someone creates a fake `handoff_request` claiming to be Agent A. The Ed25519 signature will not verify against Agent A's public key.
- **Handoff tampering:** someone modifies the payload hash after Agent A signed the request. The signature verification fails.
- **Acknowledgment forgery:** someone fakes an ack from Agent B. The Ed25519 signature will not verify against Agent B's public key.
- **Payload substitution:** Agent B receives different data than Agent A sent. The mismatched `payload_hash` between request and ack reveals it.
- **Dropped handoffs:** Agent A sends a request but Agent B never acknowledges. The missing `handoff_ack` is flagged.
- **Replay attacks:** someone replays an old handoff record. The duplicate `nonce` detection catches it.

### 7.2 What Signed Handoffs Do NOT Detect

- **Key compromise:** if Agent A's private key is stolen, the attacker can forge valid signatures. Ed25519 proves key-holder signed, not that the legitimate agent signed.
- **Colluding agents:** if both agents cooperate to fabricate a handoff exchange, the signatures will be valid. The chain proves the protocol was followed, not that it was honest.
- **Off-chain handoffs:** if agents communicate outside the audit chain (direct API call, shared memory), there is no record to verify. The chain only witnesses what it participates in.
- **Payload content quality:** the hash proves the payload wasn't tampered with, but says nothing about whether the payload was correct, complete, or useful.
- **Authorization:** Ed25519 proves identity (which key signed). It does not prove authorization (whether that agent was allowed to participate in this handoff). Authorization belongs in the policy layer (air-gate).

### 7.3 Honest Handoff Claim

> "For handoffs that were recorded in the audit chain, AIR Trust v1.2 can prove which agent initiated the handoff, which agent acknowledged it, whether the payload was tampered with in transit, and whether the exchange completed. It cannot prove that all handoffs were recorded, that the agents were authorized, or that the payload content was correct."

### 7.4 Relationship Between HMAC and Ed25519

| Mechanism | Proves | Scope | Key type |
|---|---|---|---|
| HMAC-SHA256 | Record integrity (not modified) | Entire chain | Shared secret |
| Ed25519 | Record identity (who wrote it) | Handoff records | Asymmetric keypair |

Both mechanisms operate on every handoff record. HMAC proves the record is part of the chain and hasn't been tampered with. Ed25519 proves which agent wrote it.

A record with valid HMAC but invalid Ed25519 signature means: "the record is in the chain and wasn't modified, but the claimed signer didn't actually sign it." This is a **FAIL** — the record is authentic (HMAC) but forged (identity).

---

## 8. Implementation Notes

### 8.1 Dependency: Ed25519

The reference implementation uses Python's `cryptography` library for Ed25519 operations. This is the first external dependency added to air-trust (previously zero-dependency).

Alternative: Python 3.13's `hashlib` does not include Ed25519. The `PyNaCl` library is another option but `cryptography` is more widely deployed.

If zero-dependency is critical, a future version may include a pure-Python Ed25519 implementation, but this is not recommended for production use.

### 8.2 Handoff Records and Session Completeness

Handoff records participate in session completeness just like any other record:

- They receive `session_seq` and `prev_session_seq` if written within a session
- They are counted in sequence gap detection
- A `handoff_request` followed by a `handoff_ack` with no gap is two consecutive records

This means the completeness and handoff checks are independent but complementary. A chain can pass completeness (no gaps) but fail handoffs (bad signature). Or pass handoffs but fail completeness (gap between request and ack).

### 8.3 Storage

The existing SQLite schema gains new columns for handoff fields:

```sql
ALTER TABLE events ADD COLUMN interaction_id TEXT;
ALTER TABLE events ADD COLUMN counterparty_id TEXT;
ALTER TABLE events ADD COLUMN payload_hash TEXT;
ALTER TABLE events ADD COLUMN nonce TEXT;
ALTER TABLE events ADD COLUMN signature TEXT;
ALTER TABLE events ADD COLUMN signature_alg TEXT;
ALTER TABLE events ADD COLUMN public_key TEXT;
CREATE INDEX idx_interaction_id ON events(interaction_id);
```

These are nullable for backward compatibility with v1.0 and v1.1 records.

### 8.4 Performance

Ed25519 signature generation takes ~0.1ms on modern hardware. Ed25519 verification takes ~0.3ms. For a chain with 1,000 handoff records, handoff verification adds ~300ms to the total verification time. This is negligible compared to HMAC recomputation for the full chain.

---

## 9. Version History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-01 | Initial spec. HMAC-SHA256 chain, integrity verification. |
| 1.1 | 2026-04-10 | Session completeness: `session_seq`, `prev_session_seq`, lifecycle records, completeness verifier. |
| 1.2 | 2026-04-10 | Signed handoffs: Ed25519 key management, `handoff_request`/`handoff_ack`/`handoff_result` record types, handoff verification. |
