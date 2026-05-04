# AIR Blackbox - Article 12 Compliance Layer

> One chain. One signer. One bundle. Tamper-evident logging for the EU AI Act.

## The Problem

EU AI Act **Article 12** requires high-risk AI systems to produce automatic logs that are tamper-evident, retained for an appropriate period, and available for audit. Most compliance tools stop at "we check if you have logging." AIR Blackbox goes further: it *is* the logging infrastructure, and it proves the logs haven't been touched.

## The Three Components

AIR Blackbox's Article 12 compliance layer is three components that work together as a single pipeline:

```
Agent Action
    |
    v
+---------------------------+
|   1. HMAC-SHA256 Chain    |   Every action gets a chained hash.
|   (trust/chain.py)        |   Tamper with one record, every
|                            |   record after it breaks.
+---------------------------+
    |
    v
+---------------------------+
|   2. ML-DSA-65 Signer     |   The chain gets signed with a
|   (evidence/signer.py)    |   quantum-safe digital signature.
|                            |   FIPS 204. Post-quantum secure.
+---------------------------+
    |
    v
+---------------------------+
|   3. Evidence Bundle       |   Everything gets packaged into
|   (evidence/bundle.py)    |   a self-verifying .air-evidence
|                            |   ZIP. Auditor runs verify.py
|                            |   inside - no pip install needed.
+---------------------------+
    |
    v
  Auditor opens ZIP, runs verify.py,
  gets PASS/FAIL in 2 seconds.
```

## How It Works

### Step 1: The Chain

Every AI agent action - tool call, LLM response, human override - is written as a JSON record to the HMAC-SHA256 audit chain. Each record's hash is computed as:

```
chain_hash = HMAC-SHA256(key, previous_hash || canonical_json(record))
```

The first record links to a genesis value. Every subsequent record links to the one before it. Delete a record, change a timestamp, alter a field - the chain breaks and verification fails. This is the same hash-chain principle used in blockchain and certificate transparency logs, but purpose-built for AI audit trails.

The chain is specified formally in `docs/spec/audit-chain-v1.md` (RFC 2119 language, normative).

### Step 2: The Signature

The completed chain gets signed with **ML-DSA-65** (FIPS 204), formerly known as Dilithium3. This is a quantum-safe digital signature algorithm - it remains secure even against future quantum computers. The signature proves:

- **Who** generated the evidence (key identity)
- **When** it was signed (timestamp in envelope)
- **What** was signed (SHA-256 content hash)
- **Integrity** - any modification after signing invalidates the signature

Keys are generated locally (`~/.air-blackbox/keys/`), never leave the machine, and private keys are stored with owner-only permissions (chmod 600).

### Step 3: The Bundle

The chain records, signature envelopes, compliance scan results, and a standalone `verify.py` script are packaged into a `.air-evidence` ZIP file. This bundle is **self-verifying**: an auditor extracts it, runs `python verify.py`, and gets a pass/fail result without installing anything.

The bundle includes:

- `manifest.json` - SHA-256 hashes of every file in the bundle
- `signature.json` - ML-DSA-65 signature over the manifest
- `verify.py` - standalone verification script (Python 3.10+, no dependencies)
- `chain/` - the raw audit chain records
- `scan_results.json` - compliance scan output
- `standards_mapping.json` - EU AI Act / ISO 42001 / NIST AI RMF crosswalk

Directory paths inside the bundle are anonymized (hashed) so internal project structure is never leaked to auditors.

## The Scanner

AIR Blackbox doesn't just *produce* Article 12 evidence - it also *scans your codebase* to verify you have the right logging infrastructure in place. The Article 12 scanner (`compliance/engine.py`) uses hybrid static + runtime analysis:

**Static analysis detects:**

- Logging infrastructure - Python `logging`, `structlog`, `loguru`, OpenTelemetry spans and traces
- Tamper-evident patterns - HMAC usage, hash chain implementations, merkle tree references
- Retention configuration - log retention settings in `.py`, `.yaml`, `.json`, and `.toml` files
- Audit trail implementations - dedicated audit modules, event sourcing patterns

**Runtime analysis verifies:**

- The HMAC-SHA256 chain is active and producing records
- Chain integrity passes verification (no gaps, no tampering)
- Records contain required fields (timestamps, action types, chain hashes)

When runtime data isn't available (first scan, CI pipeline, external audit), the scanner falls back gracefully to static-only analysis and reports what it found.

## Comparison to Article 12 Requirements

| Article 12 Requirement | AIR Blackbox Implementation |
|---|---|
| Automatic logging | HMAC-SHA256 chain writes on every agent action - no manual intervention |
| Tamper-evident | Hash chain + ML-DSA-65 signature - modification breaks verification |
| Appropriate retention | Configurable retention, scanner detects retention config in codebase |
| Available for audit | Self-verifying `.air-evidence` bundle - auditor needs only Python |
| Traceability | Every record links to previous via chain hash - full causal ordering |

## Quick Start

```bash
# Install
pip install air-blackbox[evidence]

# Generate signing keys (one time)
air-blackbox sign --keygen

# Run a compliance scan (includes Article 12 checks)
air-blackbox comply ./my-ai-project

# Generate a signed evidence bundle
air-blackbox evidence ./my-ai-project --output report.air-evidence

# Verify a bundle (auditor side)
unzip report.air-evidence -d evidence/
cd evidence/ && python verify.py
```

## Architecture Diagram

```
+------------------------------------------------------------------+
|                        Your AI System                             |
|                                                                   |
|   +------------+    +------------+    +------------+              |
|   | LangChain  |    |  CrewAI    |    |  OpenAI    |   ...       |
|   +-----+------+    +-----+------+    +-----+------+             |
|         |                  |                  |                    |
|         v                  v                  v                    |
|   +----------------------------------------------------+         |
|   |           AIR Blackbox Trust Layer                  |         |
|   |                                                     |         |
|   |  Pre-hook: validate action before execution         |         |
|   |  Post-hook: record action to audit chain            |         |
|   |                                                     |         |
|   +------------------------+----------------------------+         |
|                            |                                      |
+----------------------------|--------------------------------------+
                             |
                             v
              +------------------------------+
              |    HMAC-SHA256 Audit Chain    |
              |    (chained .air.json files)  |
              +-------------+----------------+
                            |
                            v
              +------------------------------+
              |     ML-DSA-65 Signer         |
              |     (quantum-safe FIPS 204)  |
              +-------------+----------------+
                            |
                            v
              +------------------------------+
              |   .air-evidence Bundle       |
              |   manifest + signature +     |
              |   verify.py + chain +        |
              |   scan results               |
              +------------------------------+
                            |
                            v
                     Auditor verifies
```

## Files

| File | Purpose |
|---|---|
| `sdk/air_blackbox/trust/chain.py` | HMAC-SHA256 audit chain writer/verifier |
| `sdk/air_blackbox/evidence/signer.py` | ML-DSA-65 signing and verification |
| `sdk/air_blackbox/evidence/keys.py` | Key generation and storage |
| `sdk/air_blackbox/evidence/bundle.py` | Self-verifying evidence bundle creator |
| `sdk/air_blackbox/validate/engine.py` | Runtime pre-execution validation |
| `sdk/air_blackbox/compliance/engine.py` | Article 12 scanner (static + runtime) |
| `docs/spec/audit-chain-v1.md` | Formal chain specification (RFC 2119) |
