# AIR Blackbox

**The EU AI Act enforcement deadline is August 2, 2026. Scan your AI agent in 5 minutes. Get audit-ready evidence for four compliance frameworks from a single scan.**

[![PyPI](https://img.shields.io/pypi/v/air-blackbox)](https://pypi.org/project/air-blackbox/)
[![SDK Tests](https://github.com/airblackbox/air-trust/actions/workflows/sdk-tests.yml/badge.svg)](https://github.com/airblackbox/air-trust/actions/workflows/sdk-tests.yml)
[![Python](https://img.shields.io/pypi/pyversions/air-blackbox)](https://pypi.org/project/air-blackbox/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://github.com/airblackbox/gateway/blob/main/LICENSE)
[![EU AI Act](https://img.shields.io/badge/EU_AI_Act-ready-green)](https://airblackbox.ai)

## Install

```bash
pip install air-blackbox
```

## First scan in 30 seconds

```bash
air-blackbox comply --scan .
```

That's it. 48 checks across 6 EU AI Act articles + GDPR. No config, no API keys, no Docker.

Want the demo instead? Generate sample data and see everything in action:

```bash
air-blackbox demo
```

## What you get

```
Article  9 (Risk Management):       3/5  (1 warn, 1 fail)
Article 10 (Data Governance):       3/5  (2 fail)
Article 11 (Technical Docs):        3/5  (1 warn, 1 fail)
Article 12 (Record-Keeping):        6/8  (2 warn)
Article 14 (Human Oversight):       8/9  (1 warn)
Article 15 (Robustness):            3/8  (4 warn, 1 fail)
GDPR (Data Protection):             8/8  (all pass)

Compliance: 34 passed  9 warned  5 failed  out of 48 checks

Run with -v to see fix hints for each failing check.
```

Every check tells you what's wrong and how to fix it. Run with `-v` for remediation guidance.

## One scan, four compliance standards

Most compliance tools cover one framework. AIR Blackbox maps every check to four simultaneously:

```bash
air-blackbox standards
```

| Category | EU AI Act | ISO 42001 | NIST AI RMF | Colorado SB 205 |
|---|---|---|---|---|
| Risk Management | Article 9 | 6.1, 6.1.2, A.6.2.1 | GOVERN 1, MAP 1, MAP 3 | Section 6(2)(a-b) |
| Data Governance | Article 10 | A.6.2.4, A.6.2.5 | MAP 2, MEASURE 2 | Section 6(2)(c) |
| Documentation | Article 11 | 7.5, A.6.2.2 | GOVERN 4, MAP 5 | Section 6(2)(d), 6(3) |
| Record-Keeping | Article 12 | A.6.2.6, 9.1 | MEASURE 1, MANAGE 4 | Section 6(4) |
| Human Oversight | Article 14 | A.6.2.3 | GOVERN 2, MANAGE 1 | Section 6(2)(e), 7 |
| Robustness | Article 15 | A.6.2.8, A.6.2.9 | MEASURE 3, MANAGE 2 | Section 6(2)(f) |
| Consent | GDPR Art. 6/7 | A.6.2.5, A.6.2.11 | GOVERN 3 | Section 5 |
| Bias/Fairness | Article 10 | A.6.2.4, A.6.2.10 | MAP 2, MEASURE 2 | Section 2, 6(2)(c) |

Filter by framework:

```bash
air-blackbox comply --frameworks eu,iso42001       # Just EU + ISO
air-blackbox comply --frameworks colorado           # Just Colorado
air-blackbox standards -f nist                      # NIST detail view
air-blackbox standards --lookup "Article 9"         # Reverse lookup
```

## Choose your path

**I want a quick compliance scan** -- Use the CLI (you're here)

```bash
air-blackbox comply --scan . -v
```

**I want runtime audit trails** -- Add air-trust to your AI client

```bash
pip install air-trust
```

```python
import air_trust
client = air_trust.trust(OpenAI())  # every call is now HMAC-SHA256 audited
```

**I want human approval gates** -- Add air-gate for tool-level oversight

```bash
pip install air-gate
```

**I need auditor-ready evidence** -- Export a signed bundle

```bash
air-blackbox export --format pdf
```

**I use Claude Desktop or Cursor** -- Install the MCP server

```bash
pip install air-blackbox-mcp
```

## All commands

| Command | What it does |
|---------|-------------|
| `air-blackbox comply` | EU AI Act compliance scan with multi-framework crosswalk |
| `air-blackbox standards` | Browse the 4-framework standards crosswalk |
| `air-blackbox discover` | Shadow AI inventory + CycloneDX AI-BOM generation |
| `air-blackbox replay` | Incident reconstruction from HMAC audit chain |
| `air-blackbox export` | Signed evidence bundle (JSON or PDF) for auditors |
| `air-blackbox validate` | Pre-execution runtime checks for agent actions |
| `air-blackbox history` | Compliance score trends over time with diff |
| `air-blackbox demo` | Zero-config demo with sample data |
| `air-blackbox test` | End-to-end stack validation |
| `air-blackbox setup` | One-command model install + verification |
| `air-blackbox init` | Create compliance doc templates in your project |
| `air-blackbox attest` | Create, sign, and publish compliance attestations |
| `air-blackbox sign` | ML-DSA-65 key management and evidence signing |

## Framework trust layers

Drop-in compliance for your existing AI stack. No code changes beyond the import:

```bash
pip install air-blackbox[langchain]    # LangChain / LangGraph
pip install air-blackbox[crewai]       # CrewAI
pip install air-blackbox[openai]       # OpenAI Agents SDK
pip install air-blackbox[all]          # Everything
```

Auto-detected frameworks: OpenAI, Anthropic, Google ADK, LangChain, CrewAI, LlamaIndex, Haystack, AutoGen, Semantic Kernel, Smolagents, PydanticAI, DSPy, Browser Use, and more.

## How it works

1. **Static analysis** -- Scans your Python code for compliance patterns (error handling, logging, PII detection, human oversight gates, documentation)
2. **Hybrid AI analysis** -- Optionally uses a local LLM (air-compliance model via Ollama) for deeper assessment beyond regex
3. **Runtime checks** -- With trust layers installed, validates live AI traffic against EU AI Act requirements
4. **Evidence export** -- Packages compliance results + AI-BOM + audit trail into a single verifiable document

Your code never leaves your machine. No cloud, no API keys, no vendor lock-in.

## Why this exists

The EU AI Act (Regulation 2024/1689) requires organizations deploying high-risk AI systems to demonstrate compliance across Articles 9-15. Penalties reach 35M euros or 7% of global turnover. The first enforcement deadline is August 2, 2026.

Existing compliance tools are either manual checklists that take weeks, enterprise SaaS that costs thousands per month, or generic linters that don't understand AI-specific requirements.

AIR Blackbox is a developer tool that runs locally, scans in minutes, and produces audit-ready evidence. Open source, no vendor lock-in, and free.

## Links

- **Website**: [airblackbox.ai](https://airblackbox.ai)
- **Interactive demo**: [airblackbox.ai/demo/signed-handoff](https://airblackbox.ai/demo/signed-handoff)
- **Repository**: [github.com/airblackbox/gateway](https://github.com/airblackbox/gateway)
- **MCP server**: [github.com/airblackbox/air-blackbox-mcp](https://github.com/airblackbox/air-blackbox-mcp)
- **Changelog**: [CHANGELOG.md](https://github.com/airblackbox/gateway/blob/main/CHANGELOG.md)
- **PyPI**: [pypi.org/project/air-blackbox](https://pypi.org/project/air-blackbox/)

## License

Apache-2.0. See [LICENSE](https://github.com/airblackbox/gateway/blob/main/LICENSE).
