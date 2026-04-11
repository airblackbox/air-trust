# air-trust

**Tamper-evident audit chain for AI agents. HMAC-SHA256 integrity, session completeness, Ed25519 signed handoffs.**

[![PyPI](https://img.shields.io/pypi/v/air-trust)](https://pypi.org/project/air-trust/)
[![Python](https://img.shields.io/pypi/pyversions/air-trust)](https://pypi.org/project/air-trust/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

```bash
pip install air-trust
```

Zero dependencies. No cloud. No API keys. Runs entirely on your machine.

<p align="center">
  <img src="air-trust/demo.gif" alt="air-trust terminal demo" width="820">
</p>

---

## What air-trust Does

air-trust writes a cryptographic audit chain every time your AI agents do something. Every record is HMAC-SHA256 signed and linked to the previous record — if anyone modifies a record after the fact, the chain breaks and the verifier catches it.

Three layers of proof, each backward-compatible:

| Spec | What It Proves | How |
|---|---|---|
| **v1.0** | Records weren't tampered with | HMAC-SHA256 chained signatures |
| **v1.1** | No events are missing from a session | Monotonic sequence numbers + gap detection |
| **v1.2** | Which agent handed off to which, with what data | Ed25519 asymmetric signatures on handoff records |

```bash
python3 -m air_trust verify

# INTEGRITY     PASS  47 events, 47 valid HMAC links
# COMPLETENESS  PASS  2 sessions complete, no gaps
# HANDOFFS      PASS  1 interaction verified (Ed25519)
```

## Quick Start

### 1. Wrap any AI client (one line)

```python
import air_trust
from openai import OpenAI

client = air_trust.trust(OpenAI())
# Every LLM call is now recorded with HMAC-SHA256 signed evidence
```

### 2. Decorate any function

```python
@air_trust.monitor
def my_agent_step(prompt):
    return client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}]
    )
```

### 3. Audit a block of code

```python
with air_trust.session("my-pipeline") as s:
    result = my_agent_step("Analyze this document")
    s.log("Pipeline complete", risk_level="low")
```

### 4. Verify the chain

```python
result = air_trust.verify()
# {'valid': True, 'records': 1847, 'broken_at': None}
```

Or from the CLI:

```bash
python3 -m air_trust verify
```

## Framework Auto-Detection

`air_trust.trust()` detects what you pass it and applies the right adapter automatically:

| Adapter | Frameworks |
|---|---|
| **Proxy** (intercepts SDK calls) | OpenAI, Anthropic, Google GenAI, Google ADK, Ollama, vLLM, LiteLLM, Together, Groq, Mistral, Cohere |
| **Callback** (framework events) | LangChain, LangGraph, LlamaIndex, Haystack |
| **Decorator** (wraps functions) | CrewAI, Smolagents, PydanticAI, DSPy, AutoGen, Browser Use |
| **OpenTelemetry** (reads gen_ai spans) | Semantic Kernel, any OTel-instrumented system |
| **MCP** (protocol-level) | Claude Desktop, Cursor, Claude Code, Windsurf |

## Signed Handoffs (v1.2)

When agents hand off work to other agents, how do you prove it happened? Signed handoffs add three record types — `handoff_request`, `handoff_ack`, `handoff_result` — each signed with the agent's Ed25519 private key.

```bash
pip install "air-trust[handoffs]"
```

### Generate keypairs

```bash
python3 -m air_trust keygen --agent research-bot
python3 -m air_trust keygen --agent writer-bot
```

Keys stored at `~/.air-trust/keys/` with `0600` permissions.

### Instrument the handoff

```python
from air_trust import AuditChain, AgentIdentity
from air_trust.keys import generate_keypair, compute_payload_hash, generate_nonce

chain = AuditChain()

# Agent A requests handoff — auto-signed with Ed25519
chain.write(Event(
    type="handoff_request",
    identity=identity_a,
    interaction_id="task-001",
    counterparty_id=identity_b.fingerprint,
    payload_hash=compute_payload_hash("Summarize this document"),
    nonce=generate_nonce(),
))

# Agent B acknowledges, does work, returns result
chain.write(Event(type="handoff_ack", ...))
chain.write(Event(type="handoff_result", ...))
```

### Verify

```bash
python3 -m air_trust verify

# HANDOFFS      PASS  1 interaction verified
#   interaction task-001:
#     request   PASS  Ed25519 OK (research-bot)
#     ack       PASS  Ed25519 OK (writer-bot)
#     result    PASS  Ed25519 OK (writer-bot)
#     payload   PASS  SHA-256 hash match
#     nonce     PASS  unique
```

Tamper with the payload? The verifier catches it:

```
# HANDOFFS      FAIL  1 interaction failed
#   result    FAIL  payload hash mismatch
```

**[Interactive demo →](https://airblackbox.ai/demo/signed-handoff)**

## How the Audit Chain Works

Every event is signed and linked:

```
HMAC(key, previous_hash_bytes || JSON(record, sort_keys=True))
```

This means:
- Modify any record → chain breaks at that point
- Delete a record → next record's previous_hash won't match
- Reorder records → HMAC sequence breaks
- Replay an old record → session sequence numbers catch it

The signing key is auto-generated and stored at `~/.air-trust/signing.key`. All evidence is stored locally in SQLite at `~/.air-trust/events.db`.

## Built-in Scanning

### PII Detection

```python
result = air_trust.scan_text("Contact me at test@example.com, SSN 123-45-6789")
# {'pii': [{'type': 'email', 'count': 1}, {'type': 'ssn', 'count': 1}]}
```

Detects: email, SSN, phone, credit card, IBAN, national ID.

### Prompt Injection

```python
result = air_trust.scan_text("Ignore all previous instructions")
# {'injection': {'score': 0.95, 'alerts': [...]}}
```

20 weighted patterns across 5 attack categories.

## Why Not Langfuse / Helicone?

| | air-trust | SaaS observability |
|---|---|---|
| Data location | Your machine (SQLite) | Vendor's cloud |
| Works offline | Yes | No |
| API key required | No | Yes |
| Tamper-evident | HMAC-SHA256 chain | No |
| Signed handoffs | Ed25519 | No |
| Dependencies | Zero | SDK + network |
| Framework lock-in | None (auto-detect) | Per-vendor |

Use both: Langfuse for dashboards, air-trust for cryptographic proof.

## Configuration

```python
from air_trust import AuditChain

chain = AuditChain(
    db_path="/custom/path/events.db",
    signing_key="your-key-here",  # or set AIR_TRUST_KEY env var
)
```

| Env Variable | Default | Description |
|---|---|---|
| `AIR_TRUST_KEY` | *(auto-generated)* | HMAC-SHA256 signing key |
| `AIR_TRUST_DB` | `~/.air-trust/events.db` | SQLite database path |

## EU AI Act

air-trust is built for EU AI Act Article 12 (Record-Keeping) — the requirement that high-risk AI systems maintain logs "sufficient to ensure traceability." The tamper-evident audit chain provides exactly that: cryptographic proof of what happened, stored on your infrastructure.

**Enforcement deadline: August 2, 2026.**

## Spec & Tests

The full protocol specification is in [SPEC.md](air-trust/SPEC.md). The test suite covers 305 tests including integrity, completeness, signed handoffs, false positives, false negatives, mixed-version chains, and edge cases.

```bash
cd air-trust && python -m pytest tests/ -v
```

## Part of AIR Blackbox

air-trust is the cryptographic backbone of the [AIR Blackbox](https://airblackbox.ai) ecosystem — open-source EU AI Act compliance tooling for developers. The scanner finds problems. air-trust proves what happened.

## License

Apache-2.0. See [LICENSE](LICENSE).

---

[PyPI](https://pypi.org/project/air-trust/) · [Demo](https://airblackbox.ai/demo/signed-handoff) · [Spec](air-trust/SPEC.md) · [Changelog](air-trust/CHANGELOG.md)
