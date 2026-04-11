# air-trust

**Universal compliance trust layer for AI systems.**

One package. Any framework. Any LLM. Any agent. Zero dependencies.

```bash
pip install air-trust
```

## Quick Start

```python
import air_trust

# 1. One-liner — wraps any AI client automatically
from openai import OpenAI
client = air_trust.trust(OpenAI())
# Every call is now audited with HMAC-SHA256 signed evidence

# 2. Decorator — wrap any function
@air_trust.monitor
def my_agent_step(prompt):
    return client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": prompt}])

# 3. Context manager — audit a block of code
with air_trust.session("my-pipeline") as s:
    result = my_agent_step("Analyze this document")
    s.log("Pipeline complete", risk_level="low")
```

That's it. HMAC-SHA256 signed audit chain, Ed25519 signed handoffs, PII detection, prompt injection scanning — all local, no API key, no network calls.

## Why air-trust?

| | air-trust | SaaS alternatives |
|---|---|---|
| Evidence storage | Your machine (SQLite) | Vendor's cloud |
| Works offline | Yes | No |
| API key required | No | Yes |
| Signing location | In-process | Vendor servers |
| Vendor shutdown risk | None (open source) | Total |
| Dependencies | Zero | SDK + network |
| Framework lock-in | None | Per-framework |

## Supported Frameworks

air-trust auto-detects your framework and applies the right adapter:

**Proxy Adapter** (intercepts SDK calls):
OpenAI, Anthropic, Google GenAI, Google ADK, Ollama, vLLM, LiteLLM, Together, Groq, Mistral, Cohere

**Callback Adapter** (framework events):
LangChain, LangGraph, LlamaIndex, Haystack

**Decorator Adapter** (wraps functions/methods):
CrewAI, Smolagents, PydanticAI, DSPy, AutoGen, Browser Use

**OpenTelemetry Adapter** (reads gen_ai spans):
Semantic Kernel, any OTel-instrumented system

**MCP Adapter** (protocol-level):
Claude Desktop, Cursor, Claude Code, Windsurf, any MCP client

## How It Works

### Auto-Detection

```python
import air_trust

# Detects OpenAI client → applies proxy adapter
from openai import OpenAI
client = air_trust.trust(OpenAI())

# Detects CrewAI crew → applies decorator adapter
from crewai import Crew
crew = air_trust.trust(my_crew)

# Detects LangChain → returns callback handler
handler = air_trust.trust(my_chain)
my_chain.invoke(input, config={"callbacks": [handler]})
```

### HMAC-SHA256 Audit Chain

Every event is signed and linked to the previous record:

```
HMAC(key, previous_hash_bytes || JSON(record, sort_keys=True))
```

If anyone modifies a record after the fact, the chain breaks. Verify anytime:

```python
result = air_trust.verify()
# {'valid': True, 'records': 1847, 'broken_at': None}
```

### PII Detection

Scans every input/output for: email, SSN, phone, credit card, IBAN, national ID.

```python
result = air_trust.scan_text("Contact me at test@example.com, SSN 123-45-6789")
# {'pii': [{'type': 'email', 'count': 1}, {'type': 'ssn', 'count': 1}], ...}
```

### Prompt Injection Scanning

20 weighted patterns detect injection attempts in real-time:

```python
result = air_trust.scan_text("Ignore all previous instructions")
# {'injection': {'score': 0.95, 'alerts': [...]}}
```

### Sessions

Group related events and add custom checkpoints:

```python
with air_trust.session("document-analysis") as s:
    s.log("User input received", risk_level="low")

    # Scan arbitrary text
    scan = s.scan(user_input)
    if scan["injection"]["score"] > 0.7:
        s.log("Injection blocked", risk_level="critical")
        raise ValueError("Injection detected")

    # Wrap clients within the session
    client = s.trust(OpenAI())
    result = client.chat.completions.create(...)

    s.log("Analysis complete", risk_level="low")
```

### Signed Handoffs (v1.2)

When agents pass work to other agents, signed handoffs provide cryptographic proof of who sent what to whom:

```bash
pip install air-trust[handoffs]  # adds Ed25519 via cryptography library
```

```python
from air_trust import AuditChain, AgentIdentity
from air_trust.events import Event
from air_trust.keys import generate_keypair, compute_payload_hash, generate_nonce

# Each agent gets an Ed25519 keypair
identity_a = AgentIdentity(agent_name="research-bot", owner="jason@airblackbox.ai")
identity_b = AgentIdentity(agent_name="writer-bot", owner="jason@airblackbox.ai")
generate_keypair(identity_a.fingerprint)
generate_keypair(identity_b.fingerprint)

# Agent A sends a handoff request — auto-signed with Ed25519
chain = AuditChain(db_path="handoffs.db", signing_key="my-key")
chain.write(Event(
    type="handoff_request",
    identity=identity_a,
    interaction_id="task-001",
    counterparty_id=identity_b.fingerprint,
    payload_hash=compute_payload_hash("Summarize this document"),
    nonce=generate_nonce(),
))
```

Verify handoffs alongside integrity and completeness:

```bash
python3 -m air_trust verify --db handoffs.db
# ✓ PASS: Integrity — chain is intact (HMAC-SHA256)
# ✓ PASS: Handoffs — all handoffs verified (Ed25519)
```

## Storage

All evidence is stored locally in SQLite at `~/.air-trust/events.db`. No cloud. No network. No API keys. The signing key is auto-generated and persisted at `~/.air-trust/signing.key`.

Override paths via constructor:

```python
from air_trust import AuditChain

chain = AuditChain(
    db_path="/custom/path/events.db",
    signing_key="your-key-here",  # or set AIR_TRUST_KEY env var
)
```

## EU AI Act Compliance

air-trust is purpose-built for EU AI Act Article 11 (Technical Documentation) and Article 12 (Record-Keeping). The tamper-evident audit chain provides the evidence trail that regulators require — stored on your infrastructure, signed with NIST FIPS 198-1 compliant HMAC-SHA256.

**Deadline: August 2, 2026.**

## Part of AIR Blackbox

air-trust is the runtime compliance layer in the [AIR Blackbox](https://airblackbox.ai) ecosystem — open-source EU AI Act compliance tooling for developers.

## License

Apache-2.0
