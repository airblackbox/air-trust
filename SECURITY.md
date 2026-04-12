# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| air-blackbox 1.8.x | Yes |
| air-trust 1.2.x | Yes |
| Older versions | Best effort |

## Reporting Vulnerabilities

If you discover a security vulnerability in any AIR Blackbox package, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

**Email:** [jason@airblackbox.ai](mailto:jason@airblackbox.ai)
**Subject line:** `[SECURITY] AIR Blackbox — <brief description>`

Include:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

We will acknowledge your report within 48 hours and aim to provide a fix within 7 days for critical issues.

## Scope

This policy covers:

- **air-blackbox** (CLI compliance scanner)
- **air-trust** (HMAC audit chain + Ed25519 handoffs)
- **air-gate** (human-in-the-loop approval)
- **air-blackbox-mcp** (MCP server for Claude/Cursor)
- **airblackbox.ai** (website and interactive demo)

## Security Design

AIR Blackbox is built with a local-first, zero-trust architecture:

- **Local-first**: Your code and compliance data never leave your machine. No cloud dependency, no external API calls for scanning.
- **No phone-home**: The scanner makes zero network calls. Telemetry is anonymous and opt-out (`AIR_BLACKBOX_TELEMETRY=off`).
- **No credential storage**: AIR Blackbox does not require API keys, tokens, or credentials to operate.
- **Dependency minimization**: Core packages use minimal dependencies to reduce supply chain risk.

## Cryptographic Components

| Component | Algorithm | Purpose |
|---|---|---|
| Audit chain | HMAC-SHA256 | Tamper-evident record linking |
| Agent handoffs | Ed25519 | Signed inter-agent provenance |
| Signing keys | Auto-generated | Stored locally at `~/.air-trust/signing.key` |
| Record checksums | SHA-256 | Request/response content verification |

## What AIR Blackbox Stores

| Data | Where | Who Controls It |
|---|---|---|
| Compliance scan results | Local SQLite (`~/.air-blackbox/compliance.db`) | You |
| Audit chain events | Local SQLite (`~/.air-trust/events.db`) | You |
| Signing keys | Local file (`~/.air-trust/signing.key`) | You |
| Raw prompts (if gateway used) | Your MinIO/S3 vault | You |

## Threat Model

1. **Signing key security** — The Ed25519 and HMAC-SHA256 keys at `~/.air-trust/` control audit chain integrity. Protect these files with appropriate filesystem permissions.
2. **Audit record files** — `.air.json` files contain vault references and checksums, not raw content. Metadata (model names, timestamps, token counts) may still be sensitive. Apply appropriate access controls.
3. **Gateway network position** — If using the full gateway, it terminates your agent's API call and forwards it. Deploy it in the same trust boundary as your agent.

## Responsible Disclosure

We follow coordinated disclosure. If you report a vulnerability, we will:

1. Acknowledge receipt within 48 hours
2. Provide an estimated timeline for a fix
3. Credit you in the release notes (unless you prefer anonymity)
4. Not pursue legal action against good-faith security researchers
