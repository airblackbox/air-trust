# AIR Trust Audit Chain Specification v1.1

**Status:** Draft
**Date:** 2026-04-10
**Author:** Jason Shotwell (jason@airblackbox.ai)
**Supersedes:** v1.0 (integrity-only chain)

---

## 1. Overview

This specification defines the tamper-evident audit chain format for AIR Trust, the universal compliance trust layer for AI systems.

**v1.0** established the HMAC-SHA256 chain that proves records were not modified after being written. **v1.1** adds session-scoped sequence numbering and lifecycle records that prove records were not *dropped* within a session.

Together, these provide two guarantees:

- **Integrity:** no record was changed after it was written (v1.0, unchanged)
- **Completeness:** no record was silently dropped within a session (v1.1, new)

### 1.1 Scope

This specification covers **single-session completeness** only. It answers the question:

> "Within one continuous session of one agent runtime, can we detect if a record is missing?"

It does NOT cover:

- Cross-session completeness (did every session that should have started actually start?)
- Cross-agent attestation (did Agent A honestly report what Agent B said?)
- Universal completeness (did every important event get recorded, including ones the system chose not to log?)
- Off-ledger activity (did something happen that was never submitted to the chain at all?)

These are real limitations, not future work items. They are intentionally out of scope because they require fundamentally different mechanisms (bilateral signing, external witnesses) that belong in a separate spec.

### 1.2 Backward Compatibility

v1.1 is **additive-only**:

- v1.0 records (without `session_seq` or `prev_session_seq`) remain valid and verify successfully for integrity
- The verifier runs completeness checks only on records that carry v1.1 fields
- Mixed chains (some v1.0 records, some v1.1 records) are explicitly supported
- No existing field meanings change

### 1.3 Standards Alignment

- **CSA Agentic Trust Framework v0.9.1** — air-trust already conforms (as of v0.4.0). Session completeness strengthens the ATF Identity and Logging requirements.
- **EU AI Act Article 12 (Record-Keeping)** — completeness detection directly supports the requirement that logs be "designed to enable the monitoring of the operation of the high-risk AI system."
- **ISO 42001** — the gap detection report maps to Clause 9 (Performance evaluation).

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

This formula is identical to v1.0. No changes.

---

## 3. New Required Fields (v1.1)

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
- Enables the verifier to detect gaps, duplicates, and rewinds without replaying the entire chain

### 3.3 `session_id` (string)

A unique identifier for the session. Already existed in v1.0 as an optional field. In v1.1:

- MUST be present on every record emitted within a `session()` context
- Format: UUID v4 (hex string, no dashes) — e.g. `"a1b2c3d4e5f6789012345678abcdef01"`
- All records in the same session share the same `session_id`
- Records without a `session_id` are "unscoped" and are exempt from completeness checking

### 3.4 Example Record (v1.1)

```json
{
    "type": "tool_call",
    "framework": "langchain",
    "run_id": "550e8400-e29b-41d4-a716-446655440000",
    "trace_id": "a1b2c3d4e5f67890",
    "session_id": "d4e5f6a1b2c3789012345678abcdef01",
    "session_seq": 3,
    "prev_session_seq": 2,
    "timestamp": "2026-04-10T14:30:00Z",
    "tool_name": "search_documents",
    "status": "success",
    "version": "1.1.0"
}
```

---

## 4. Lifecycle Record Types

v1.1 formalizes three record types that mark session boundaries. These already existed informally in v1.0; v1.1 makes them required for completeness detection.

### 4.1 `session_start`

Emitted as the FIRST record in any session.

Required properties:

- `type`: `"session_start"`
- `session_seq`: `0`
- `prev_session_seq`: `-1`
- `session_id`: the session's unique ID
- `status`: `"running"`

### 4.2 `checkpoint`

Emitted at developer-defined points within a session (via `session.log()`). Optional but recommended for long-running sessions.

Required properties:

- `type`: `"checkpoint"`
- `session_seq`: current sequence number
- `prev_session_seq`: previous sequence number
- `session_id`: the session's unique ID

### 4.3 `session_end`

Emitted as the LAST record in a session when the session closes normally or with an error.

Required properties:

- `type`: `"session_end"`
- `session_seq`: final sequence number
- `prev_session_seq`: previous sequence number
- `session_id`: the session's unique ID
- `status`: `"success"` or `"error"`

---

## 5. Verification Rules

The verifier performs two independent checks on a chain:

### 5.1 Integrity Check (unchanged from v1.0)

Replays the chain from genesis, recomputing every HMAC. If any recomputed hash does not match the stored `chain_hash`, the chain has been tampered with.

Result: `PASS` or `FAIL` (with the index of the broken record).

### 5.2 Completeness Check (new in v1.1)

Groups records by `session_id` and checks each session for:

#### 5.2.1 Sequence Gap Detection

For consecutive records `R[i]` and `R[i+1]` in the same session:

- `R[i+1].session_seq` MUST equal `R[i].session_seq + 1`
- `R[i+1].prev_session_seq` MUST equal `R[i].session_seq`

If either condition fails, the verifier reports a **gap** with the expected and actual values.

#### 5.2.2 Duplicate Detection

If two records in the same session share the same `session_seq`, the verifier reports a **duplicate**.

#### 5.2.3 Rewind Detection

If `R[i+1].session_seq < R[i].session_seq` for consecutive records, the verifier reports a **rewind** (the sequence counter went backward).

#### 5.2.4 Lifecycle Validation

- The first record in every session MUST have `type: "session_start"` and `session_seq: 0`
- The last record in every session SHOULD have `type: "session_end"`
- A session without a `session_end` is flagged as **incomplete** (warning, not failure)
- A `session_start` followed immediately by another `session_start` with the same `session_id` is flagged as **duplicate start**

### 5.3 Verification Output

The verifier returns a structured report:

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
        "issues": [
            {
                "session_id": "d4e5f6...",
                "issue": "gap",
                "expected_seq": 5,
                "actual_seq": 7,
                "record_index": 23
            },
            {
                "session_id": "a1b2c3...",
                "issue": "missing_session_end",
                "last_seq": 12
            }
        ]
    }
}
```

### 5.4 Severity Tiers

| Issue | Severity | Meaning |
|---|---|---|
| Chain hash mismatch | **FAIL** | A record was modified after writing. Trust is broken. |
| Sequence gap | **WARN** | A record appears to be missing from the session. |
| Duplicate sequence | **WARN** | Two records claim the same position. Possible replay. |
| Sequence rewind | **WARN** | The counter went backward. Possible replay or corruption. |
| Missing `session_end` | **INFO** | Session may have crashed or be still running. |
| Missing `session_start` | **WARN** | First record is not a lifecycle boundary. Possible truncation. |

Integrity failures are always FAIL. Completeness issues are WARN or INFO because they indicate *suspicious conditions*, not proof of tampering.

---

## 6. Threat Model

### 6.1 What Session Completeness Detects

- **Accidental drops:** a bug in the adapter, a crashed process, a lost database write. The sequence gap makes it visible.
- **Selective deletion:** someone removes inconvenient records from the database. The gap in `session_seq` reveals the hole.
- **Truncation:** someone deletes the end of a session. The missing `session_end` flags it.
- **Replay attacks:** someone duplicates or rewinds records. Duplicate/rewind detection catches it.

### 6.2 What Session Completeness Does NOT Detect

- **Omission by the recording system itself:** if the code never calls `chain.write()` for a particular action, there is no record to be missing. Completeness proves the chain is gap-free, not that the chain is *sufficient*.
- **Entire session suppression:** if a session never starts (no `session_start` emitted), there is nothing to check. Completeness is scoped to sessions that exist.
- **Off-ledger activity:** actions taken outside the audited code path leave no trace. The chain can only witness what it participates in.
- **Collusion:** if the recording system and the verifier are both compromised, sequence numbers provide no protection. The signing key must remain secret.

### 6.3 Honest Completeness Claim

> "For sessions that were started and recorded, AIR Trust v1.1 can detect if records were dropped, duplicated, reordered, or if the session ended abnormally. It cannot prove that all sessions that should have existed do exist, or that all important actions were submitted to the chain."

This is a **session-scoped** completeness guarantee, not a universal one. It is meaningful for compliance (EU AI Act Article 12) because it proves the logging system itself is functioning correctly for the sessions it monitors.

---

## 7. Implementation Notes

### 7.1 Sequence Counter Location

The session sequence counter lives in the `AuditChain` instance, keyed by `session_id`. When `AuditChain.write()` receives an event with a `session_id`:

1. Look up the current sequence for that `session_id`
2. Assign `session_seq` and `prev_session_seq` to the event
3. Increment the counter
4. The sequence fields are included in the HMAC payload (they are part of the record)

This means the sequence numbers are **tamper-evident** — changing them breaks the HMAC chain, just like changing any other field.

### 7.2 Session ID Propagation

When code runs inside an `air_trust.session()` context, the session ID must propagate to all events written by adapters within that block. This is achieved via a thread-local (or context-variable) `_current_session_id` that `AuditChain.write()` checks.

### 7.3 Storage

The existing SQLite schema gains two new indexed columns:

```sql
ALTER TABLE events ADD COLUMN session_seq INTEGER;
ALTER TABLE events ADD COLUMN prev_session_seq INTEGER;
CREATE INDEX idx_session_id ON events(session_id);
```

These are nullable for backward compatibility with v1.0 records.

---

## 8. Version History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-01 | Initial spec. HMAC-SHA256 chain, integrity verification. |
| 1.1 | 2026-04 | Session completeness: `session_seq`, `prev_session_seq`, lifecycle records, completeness verifier. |
