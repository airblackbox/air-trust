# AIR Blackbox

**Trust infrastructure for AI systems. Compliance scanning, quantum-safe signing, tamper-evident audit chains.**

The EU AI Act enforcement deadline is **August 2, 2026**. AIR Blackbox gives development teams the tooling to scan, sign, and prove compliance from their terminal.

## What we build

| Package | What it does | Install |
|---------|-------------|---------|
| [air-blackbox](https://github.com/airblackbox/gateway) | 48 compliance checks across 6 EU AI Act articles + GDPR. ML-DSA-65 signing. Evidence bundles. Attestation registry. | `pip install air-blackbox` |
| [air-trust](https://github.com/airblackbox/gateway/tree/main/air-trust) | HMAC-SHA256 tamper-evident audit chains. Ed25519 signed handoffs. Session completeness. | `pip install air-trust` |
| [air-openai-trust](https://github.com/airblackbox/gateway/tree/main/packages/air-openai-trust) | Drop-in OpenAI SDK wrapper that adds audit chains without code changes. | `pip install air-openai-trust` |
| [air-blackbox-mcp](https://github.com/airblackbox/air-blackbox-mcp) | MCP server for Claude Desktop and Cursor. 14 compliance tools. | `pip install air-blackbox-mcp` |

## Quick start

```bash
pip install air-blackbox
air-blackbox comply --scan .
```

48 checks. 6 articles. No config, no API keys, no Docker.

## Trust layers for 7 frameworks

LangChain, CrewAI, OpenAI Agents SDK, Google ADK, Claude Agent SDK, AutoGen, Haystack.

## Standards crosswalk

Every check maps to four compliance frameworks simultaneously: EU AI Act, ISO/IEC 42001, NIST AI RMF, and Colorado SB 24-205.

## Links

[airblackbox.ai](https://airblackbox.ai) | [PyPI](https://pypi.org/project/air-blackbox/) | [Documentation](https://airblackbox.ai/quickstart) | [Attestation Registry](https://airblackbox.ai/attest)

---

Apache-2.0 licensed. Built by [Jason Shotwell](mailto:jason@airblackbox.ai).
