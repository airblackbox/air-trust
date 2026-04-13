# AIR Blackbox Architecture

**How the pieces fit together — and when to use each one.**

Last updated: April 10, 2026

---

## The Stack at a Glance

AIR Blackbox is not one tool — it's a modular trust infrastructure stack. Each layer handles a different concern:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your AI System                           │
│   (LangChain, CrewAI, AutoGen, OpenAI, Anthropic, custom...)   │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                ┌───────────────┼───────────────┐
                ▼               ▼               ▼
        ┌──────────────┐ ┌──────────┐ ┌────────────────┐
        │  air-trust   │ │ air-gate │ │  air-blackbox  │
        │  (runtime)   │ │ (gates)  │ │   (scanner)    │
        │              │ │          │ │                │
        │ HMAC chain   │ │ Human    │ │ 39 compliance  │
        │ Ed25519 sigs │ │ approval │ │ checks, PII,   │
        │ Sessions     │ │ Tool     │ │ injection,     │
        │ Handoffs     │ │ gating   │ │ GDPR, bias     │
        └──────┬───────┘ └────┬─────┘ └───────┬────────┘
               │              │                │
               └──────────────┼────────────────┘
                              ▼
                    ┌──────────────────┐
                    │   air-platform   │
                    │   (deployment)   │
                    │                  │
                    │ Docker Compose   │
                    │ Gateway proxy    │
                    │ Jaeger + OTel    │
                    │ MinIO storage    │
                    └──────────────────┘
```

## When to Use What

| You want to... | Use this | Install |
|---|---|---|
| Add a tamper-evident audit trail to any Python AI system | **air-trust** | `pip install air-trust` |
| Prove cross-agent handoffs with Ed25519 signatures | **air-trust[handoffs]** | `pip install air-trust[handoffs]` |
| Require human approval before agents use dangerous tools | **air-gate** | `pip install air-gate` |
| Scan code for EU AI Act / GDPR / bias compliance gaps | **air-blackbox** | `pip install air-blackbox` |
| Detect prompt injection attempts | **air-blackbox** | `pip install air-blackbox` |
| Run compliance checks in CI/CD (GitHub Actions) | **compliance-action** | Add to `.github/workflows/` |
| Add compliance tools to Claude Desktop / Cursor / Claude Code | **air-blackbox-mcp** | `pip install air-blackbox-mcp` |
| Deploy the full stack with Docker (proxy + storage + tracing) | **air-platform** | `docker compose up` |
| Get runtime visibility into LangChain / CrewAI agent behavior | **air-controls** | `pip install air-controls` |

## The Five Layers

### Layer 1: air-trust (Runtime Evidence)

**What it does:** Sits inside every AI call and creates a cryptographic evidence trail. Every event is HMAC-SHA256 signed and linked to the previous one — if anyone tampers with a record, the chain breaks.

**Three capabilities, each building on the last:**

| Spec Version | Capability | What It Proves |
|---|---|---|
| v1.0 | HMAC-SHA256 integrity chain | Records weren't tampered with |
| v1.1 | Session completeness | Records weren't dropped or reordered |
| v1.2 | Ed25519 signed handoffs | Agent A actually handed off to Agent B |

**Key design decisions:**
- Zero dependencies for the core (pure Python + stdlib)
- `cryptography` library only needed for Ed25519 handoffs (optional extra)
- SQLite storage — local-first, no cloud, no API keys
- 15 framework adapters via auto-detection (proxy, callback, decorator, OTel, MCP)
- Thread-safe with per-session ContextVar propagation

**Current version:** v0.6.1 on PyPI (spec v1.2)

**Repository:** [github.com/airblackbox/air-trust](https://github.com/airblackbox/air-trust)

---

### Layer 2: air-gate (Approval Gates)

**What it does:** Human-in-the-loop tool approval checkpoint. When an agent wants to use a dangerous tool (delete files, send emails, make payments), air-gate pauses execution and waits for human approval.

**Key design decisions:**
- HMAC-SHA256 audit chain (shared with air-trust)
- Approval/denial decisions are themselves audited
- Configurable gating policies (block, warn, log)
- Works as middleware in any agent framework

**Repository:** [github.com/airblackbox/air-gate](https://github.com/airblackbox/air-gate)

---

### Layer 3: air-blackbox (Compliance Scanner)

**What it does:** Static and runtime compliance scanning across multiple frameworks. This is the scanner — it analyzes code and agent behavior for compliance gaps.

**Scanning capabilities:**
- 39 EU AI Act checks across Articles 9-15
- 8 GDPR compliance checks
- 6 bias/fairness checks
- 20 prompt injection detection patterns
- Standards crosswalk: EU AI Act + ISO 42001 + NIST AI RMF
- A2A compliance cards for agent-to-agent verification
- Evidence bundle export (signed ZIP for auditors)

**Key design decisions:**
- CLI-first (`air-blackbox scan`, `air-blackbox comply`)
- Optional fine-tuned model for deeper analysis (regex fallback if no model)
- 7 framework trust layers (LangChain, CrewAI, AutoGen, OpenAI, Google ADK, Haystack, Claude)
- Pre-commit hooks for CI/CD integration

**Current version:** v1.10.0 on PyPI

**Repository:** [github.com/airblackbox/gateway](https://github.com/airblackbox/gateway) (sdk/ directory)

---

### Layer 4: air-platform (Deployment)

**What it does:** Full-stack Docker deployment that bundles everything together with observability infrastructure.

**Services:**
- Gateway HTTP proxy (for non-Python callers)
- Jaeger distributed tracing
- OpenTelemetry collector
- MinIO object storage (for audit records)
- Prometheus metrics

**When to use it:** Multi-team environments where you need a shared compliance infrastructure, or when you want the full stack running in Docker instead of pip-installed libraries.

**Repository:** [github.com/airblackbox/air-platform](https://github.com/airblackbox/air-platform)

---

### Supporting Tools

| Tool | What It Does | Repository |
|---|---|---|
| **air-blackbox-mcp** | MCP server — 14 compliance tools for Claude Desktop, Cursor, Claude Code | [air-blackbox-mcp](https://github.com/airblackbox/air-blackbox-mcp) |
| **air-controls** | Runtime visibility — dashboards for LangChain, CrewAI, AutoGen agents | [air-controls](https://github.com/airblackbox/air-controls) |
| **compliance-action** | GitHub Action — run EU AI Act checks on every pull request | [compliance-action](https://github.com/airblackbox/compliance-action) |

---

## How They Compose

### Minimal setup (one package)

Most developers start here. Just air-trust, wrapping their existing AI client:

```python
import air_trust
client = air_trust.trust(OpenAI())
# Every call is now audited. That's it.
```

### Adding compliance scanning

Layer the scanner on top for EU AI Act / GDPR checks:

```bash
pip install air-blackbox
air-blackbox scan agent.py      # Static compliance scan
air-blackbox comply -v          # Full 39-check audit
```

### Multi-agent with signed handoffs

When agents hand off work to each other, add Ed25519 signatures:

```bash
pip install air-trust[handoffs]
```

```python
from air_trust.keys import generate_keypair, compute_payload_hash, generate_nonce

# Each agent gets a keypair
generate_keypair(agent_a.fingerprint)
generate_keypair(agent_b.fingerprint)

# Handoffs are auto-signed when written to the chain
chain.write(Event(
    type="handoff_request",
    identity=agent_a,
    interaction_id="task-001",
    counterparty_id=agent_b.fingerprint,
    payload_hash=compute_payload_hash("Research this topic"),
    nonce=generate_nonce(),
))
```

### Adding human approval gates

When agents need human sign-off on dangerous actions:

```python
from air_gate import Gate

gate = Gate(policy="require_approval", tools=["delete_file", "send_email"])
# Agent pauses and waits for human approval before proceeding
```

### Full stack deployment

For multi-team environments with shared infrastructure:

```bash
git clone https://github.com/airblackbox/air-platform.git
cd air-platform && docker compose up
# Gateway proxy + Jaeger + MinIO + Prometheus running
```

---

## Data Flow

```
Agent makes LLM call
        │
        ▼
air-trust intercepts (via adapter)
        │
        ├─ Creates Event with metadata
        ├─ HMAC-SHA256 signs and chains to previous record
        ├─ If handoff: Ed25519 signs with agent's private key
        ├─ Assigns session_seq for completeness tracking
        └─ Writes to SQLite (~/.air-trust/events.db)
        │
        ▼
Verification (anytime, offline)
        │
        ├─ Integrity: replay HMAC chain, detect tampering
        ├─ Completeness: check session sequences, detect gaps
        └─ Handoffs: verify Ed25519 signatures, check protocol
```

---

## Design Principles

1. **Local-first.** No cloud. No API keys. No network calls. Everything runs on your machine. Evidence stays on your infrastructure.

2. **Zero dependencies for the core.** air-trust's base install is pure Python + stdlib. Optional extras add framework-specific features.

3. **Additive, not breaking.** Each spec version adds new fields and capabilities without changing existing behavior. v1.0 records still verify in a v1.2 verifier.

4. **Framework-agnostic.** Auto-detection handles 15+ frameworks. You don't change your code — air-trust adapts to whatever you're using.

5. **Separate concerns.** Recording (air-trust) is separate from scanning (air-blackbox) is separate from gating (air-gate) is separate from deployment (air-platform). Use one, some, or all.

---

## EU AI Act Timeline

**Deadline: August 2, 2026** — roughly 16 weeks from today.

High-risk AI systems must have technical documentation (Art. 11) and record-keeping (Art. 12) in place. air-trust provides the tamper-evident audit trail. air-blackbox provides the compliance scanning. Together they give you the evidence trail regulators require.

---

## PyPI Packages (11 total)

| Package | Version | Purpose |
|---|---|---|
| [air-trust](https://pypi.org/project/air-trust/) | 0.6.1 | Runtime trust layer — HMAC chain + Ed25519 handoffs |
| [air-blackbox](https://pypi.org/project/air-blackbox/) | 1.10.0 | Compliance scanner + trust layers |
| [air-compliance](https://pypi.org/project/air-compliance/) | — | CLI scanner |
| [air-blackbox-sdk](https://pypi.org/project/air-blackbox-sdk/) | — | Python SDK |
| [air-blackbox-mcp](https://pypi.org/project/air-blackbox-mcp/) | — | MCP server for AI editors |
| [air-langchain-trust](https://pypi.org/project/air-langchain-trust/) | — | LangChain trust layer |
| [air-crewai-trust](https://pypi.org/project/air-crewai-trust/) | — | CrewAI trust layer |
| [air-anthropic-trust](https://pypi.org/project/air-anthropic-trust/) | — | Anthropic Claude trust layer |
| [air-adk-trust](https://pypi.org/project/air-adk-trust/) | — | Google ADK trust layer |
| [air-openai-trust](https://pypi.org/project/air-openai-trust/) | — | OpenAI trust layer |
| [air-gate](https://pypi.org/project/air-gate/) | — | Human-in-the-loop tool gating |
