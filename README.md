# AIR Blackbox

**Open-source trust infrastructure for AI agents. Scan. Sign. Prove.**

[![PyPI](https://img.shields.io/pypi/v/air-blackbox)](https://pypi.org/project/air-blackbox/)
[![Downloads](https://img.shields.io/badge/PyPI_Downloads-14%2C294%2B-brightgreen)](https://pypi.org/project/air-blackbox/)
[![EU AI Act](https://img.shields.io/badge/EU_AI_Act-audit--ready-blue)](https://airblackbox.ai)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

```bash
pip install air-blackbox
air-blackbox demo
```

No Docker. No API keys. No cloud. Runs entirely on your machine.

---

## What It Does

AIR Blackbox is a compliance scanner + cryptographic audit layer for Python AI agents. It answers the question enterprise teams can't today: **can we trace what happened, prove it wasn't tampered with, and show an auditor?**

```
Your AI Agent Code
       │
       ├── air-blackbox scan .        →  39 EU AI Act checks + GDPR + bias
       ├── air-blackbox scan-injection →  20 prompt injection patterns
       ├── air-blackbox evidence-export → Signed ZIP for auditors
       │
       └── air-trust verify            →  Tamper-evident audit chain
                                           + Ed25519 signed handoffs
```

## Quick Start

**Scan your codebase:**

```bash
pip install air-blackbox
air-blackbox scan agent.py           # 39 compliance checks
air-blackbox comply -v               # EU AI Act Articles 9-15
```

**Wrap your client for runtime tracing:**

```python
from air_blackbox import AirBlackbox

air = AirBlackbox()
client = air.wrap(openai.OpenAI())
response = client.chat.completions.create(...)  # Traced + scanned
```

**Framework trust layers (LangChain, CrewAI, etc.):**

```python
from air_blackbox.trust.langchain import AirLangChainHandler

chain.invoke(input, config={"callbacks": [AirLangChainHandler()]})
```

## What It Checks

| Area | Checks | What It Finds |
|---|---|---|
| **EU AI Act** (Arts 9-15) | 39 | Risk management, data governance, record-keeping, human oversight, robustness |
| **GDPR** | 8 | Consent, minimization, erasure, retention, DPIA, breach notification |
| **Bias & Fairness** | 6 | Demographic parity, equalized odds, calibration, explainability |
| **Prompt Injection** | 20 patterns | Role override, delimiter injection, privilege escalation, data exfiltration, jailbreak |
| **Standards Crosswalk** | 3 frameworks | Maps to EU AI Act + ISO 42001 + NIST AI RMF simultaneously |

## CLI

```bash
air-blackbox scan [file]          # Full compliance scan
air-blackbox scan-injection       # Prompt injection detection
air-blackbox scan-gdpr            # GDPR gap analysis
air-blackbox scan-bias            # Fairness checks
air-blackbox comply -v            # EU AI Act articles 9-15
air-blackbox standards [file]     # EU AI Act + ISO 42001 + NIST AI RMF
air-blackbox evidence-export      # Signed evidence ZIP for auditors
air-blackbox a2a-verify [card]    # Agent-to-agent compliance verification
air-blackbox demo                 # Interactive walkthrough
```

## Trust Layers: 7 Frameworks

Non-blocking observers that log to `.air.json` audit records. Auto-detection — no config needed.

| Framework | Install |
|---|---|
| LangChain / LangGraph | `pip install "air-blackbox[langchain]"` |
| CrewAI | `pip install "air-blackbox[crewai]"` |
| AutoGen | `pip install "air-blackbox[autogen]"` |
| OpenAI Agents SDK | `pip install "air-blackbox[openai]"` |
| Google ADK | `pip install "air-blackbox[google]"` |
| Haystack | `pip install "air-blackbox[haystack]"` |
| Claude Agent SDK | `pip install "air-blackbox[claude]"` |

## Cryptographic Audit Layer (air-trust)

The scanner tells you what's wrong. **[air-trust](air-trust/)** proves what happened.

```bash
pip install "air-trust[handoffs]"
```

Three layers of cryptographic proof, each backward-compatible:

| Spec | What It Proves | How |
|---|---|---|
| **v1.0** | Records weren't tampered with | HMAC-SHA256 chained signatures |
| **v1.1** | No events are missing from a session | Monotonic sequence numbers + gap detection |
| **v1.2** | Which agent handed off to which, with what data | Ed25519 asymmetric signatures on handoff records |

```bash
python3 -m air_trust verify audit_chain.jsonl

# INTEGRITY     PASS  47 events, 47 valid HMAC links
# COMPLETENESS  PASS  2 sessions complete, no gaps
# HANDOFFS      PASS  1 interaction verified (Ed25519)
```

See [air-trust/README.md](air-trust/README.md) for the full signed handoff protocol, key management, and spec v1.2.

**[Interactive demo →](https://airblackbox.ai/demo/signed-handoff)**

## Evidence Bundles

Export everything an auditor needs as a cryptographically signed ZIP:

```bash
air-blackbox evidence-export

# Creates: audit_2026-04-10.zip
# ├── compliance_report.json   (EU AI Act + GDPR + Bias)
# ├── audit_chain.hmac         (Tamper-proof record chain)
# ├── aibom.json               (CycloneDX AI Bill of Materials)
# ├── manifest.sha256           (File hashes)
# └── signature.hmac            (Bundle-level HMAC)
```

## Why Not Langfuse / Helicone / Datadog?

Those answer "how is the system performing?" AIR answers **"can we trust it, trace it, and prove it?"**

| | Observability Tools | AIR Blackbox |
|---|---|---|
| **Data location** | Their cloud | Your machine |
| **Tamper-proof** | No | HMAC-SHA256 chain |
| **EU AI Act checks** | No | 39 checks, 6 articles |
| **Signed handoffs** | No | Ed25519 non-repudiation |
| **Evidence export** | No | Signed ZIP for auditors |
| **Prompt injection** | No | 20 weighted patterns |

Use both: Langfuse for ops, AIR for compliance.

## Ecosystem Architecture

AIR Blackbox is a modular stack. Use one package or all of them. See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the full guide.

| Layer | Package | What It Does | Version |
|---|---|---|---|
| **Runtime evidence** | [air-trust](air-trust/) | HMAC-SHA256 audit chain + Ed25519 signed handoffs + session completeness | v0.6.1 |
| **Approval gates** | [air-gate](https://pypi.org/project/air-gate/) | Human-in-the-loop tool approval — pauses agents before dangerous actions | — |
| **Compliance scanning** | [air-blackbox](https://pypi.org/project/air-blackbox/) | 39 EU AI Act checks, GDPR, bias, prompt injection, standards crosswalk | v1.8.0 |
| **MCP server** | [air-blackbox-mcp](https://pypi.org/project/air-blackbox-mcp/) | 14 compliance tools for Claude Desktop, Cursor, and any MCP client | — |
| **CI/CD** | [compliance-action](https://github.com/airblackbox/compliance-action) | GitHub Action — EU AI Act checks on every pull request | — |

All 11 PyPI packages: [pypi.org/search/?q=air+blackbox](https://pypi.org/search/?q=air+blackbox)

## Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: air-blackbox-scan
        name: AIR Blackbox Compliance
        entry: air-blackbox scan
        language: python
        types: [python]
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `AIR_VAULT_TYPE` | `local` | Storage: local, s3, minio |
| `AIR_VAULT_PATH` | `./audit_records` | Local storage path |
| `AIR_TRUST_SIGNING_KEY` | *(generated)* | HMAC-SHA256 signing key |
| `AIR_STRICT_MODE` | `false` | Fail on any finding (for CI/CD) |
| `AIR_INJECTION_THRESHOLD` | `0.75` | Confidence threshold for injection detection |

## Contributing

We welcome contributions in compliance scanners (ISO 27001, SOC 2, FedRAMP), framework trust layers, prompt injection patterns, and documentation. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

---

**EU AI Act enforcement: August 2, 2026.** If this helps your team prepare, [star the repo](https://github.com/airblackbox/gateway) — it helps others find it.

[GitHub](https://github.com/airblackbox) · [PyPI](https://pypi.org/project/air-blackbox/) · [Demo](https://airblackbox.ai/demo/signed-handoff) · [Docs](https://airblackbox.ai)
