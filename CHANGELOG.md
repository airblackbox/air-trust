# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.12.0] - 2026-04-14

### Added
- **Hardware determinism scanning (Article 15)** — three new compliance checks
  target a documented EU AI Act Article 15 robustness failure mode that no other
  compliance scanner covers:
  - **RNG seed determinism** — checks Python random, NumPy, PyTorch (CPU + CUDA),
    TensorFlow, and JAX for seed setting. Partial coverage warns; missing seeds in
    an ML codebase fails.
  - **Deterministic algorithm flags** — detects `torch.use_deterministic_algorithms`,
    `torch.backends.cudnn.deterministic`, `torch.backends.cudnn.benchmark = False`,
    `CUBLAS_WORKSPACE_CONFIG`, and TensorFlow `enable_op_determinism`. Scans across
    code, YAML, `.env`, Dockerfile, and shell scripts.
  - **Hardware abstraction** — flags hardcoded `.to("cuda")`, `cuda:0`, `.cuda()`,
    or `device="cuda"` patterns without a `torch.cuda.is_available()` capability
    fallback. Prevents CPU-only / Apple Silicon / AMD hardware crashes.
- 16 new tests covering torch, TensorFlow, partial coverage, env file detection,
  device-agnostic patterns, and mixed-pattern warn states
- `air-blackbox --version` now reports `1.12.0`

### Context
Addresses a regulatory gap: EU AI Act Article 15 requires consistent behavior
across deployment environments, and SR 11-7 model validation requires
reproducibility. Atherik was just acquired for solving this at runtime; AIR
Blackbox now detects the anti-patterns at CI/CD time so teams can fix them
before production. Complementary, not competitive.

## [1.11.1] - 2026-04-14

### Added
- **Multi-scheme agent identity detection** — the `agent-identity-binding` compliance
  check now recognizes three identity schemes instead of one:
  - `air-trust` — Ed25519 keygen + HMAC-SHA256 chain (this project)
  - **AAR** — Agent Action Receipt per-action signing (`botindex-aar` npm / Python SDK)
  - **SCC** — Session Continuity Certificate for session-level identity with Merkle
    memory roots, capability hash lineage, and prior-session chaining
    (`botindex-aar@1.1.0`+, co-designed in FINOS AIGF thread by botbotfromuk and
    Cyberweasel777)
- Evidence strings now list which schemes were detected (e.g., "air-trust, AAR, SCC")
- Fix hints reference all three supported schemes so teams can pick what fits their stack
- 5 new tests covering AAR detection, SCC detection, combined-scheme evidence,
  multi-scheme fix hints, and SCC-schema-field-only detection

### Fixed
- Hardcoded `1.10.0` version string in CLI `--version` output, `a2a/export.py`
  scanner version metadata, and self-audit version-consistency check

### Context
Positions AIR Blackbox as the EU AI Act compliance scanner that audits *all* major
agent identity specs — not a competitor to them. Complements the co-design work
around the FINOS AIGF response to NIST RFI Docket NIST-2025-0035.

## [1.11.0] - 2026-04-13

### Added
- **Article 13 transparency scanner** (`air_blackbox.compliance.transparency_scanner`)
  - 6 new checks: AI disclosure, capability documentation, instructions for use,
    provider identity, output interpretation support, change logging and versioning
  - Maps to EU AI Act Article 13 + Article 50 (interactive AI disclosure)
  - Full coverage of EU AI Act Articles 9, 10, 11, 12, 13, 14, 15 (was 6 articles, now 7)
- **Agent identity binding compliance check** in `code_scanner.py`
  - Detects autonomous-agent patterns (tick loops, continuous decision loops)
  - Flags missing stable cryptographic identity binding across sessions
  - Maps to NIST RFI Docket NIST-2025-0035 agent identity gap and NIST AI RMF GOVERN-1.5
- **`air-trust agent-identity` CLI subcommand** (`air_trust.agent_identity`)
  - Verifies cryptographic identity continuity across the audit chain
  - Ghost agent detection: flags same agent_name under multiple fingerprints
  - Session segmentation based on configurable timestamp gaps (`--max-gap`)
  - JSON output for CI/CD pipelines (`--json`)
  - Exit codes: 0 pass, 2 warn, 1 fail
- 25 new tests (19 transparency + agent-identity-binding, 6 air-trust agent-identity)

### Community
- Roadmap shaped by feedback from @botbotfromuk (HN Show HN thread) and FINOS AIGF
  response to NIST RFI Docket NIST-2025-0035

## [1.10.0] - 2026-04-12

### Added
- **A2A Transaction Layer** -- signed, chained, tamper-evident agent-to-agent audit middleware
  - `TransactionRecord`: core data structure with SHA-256 content hashing (content never stored)
  - `TransactionLedger`: HMAC-SHA256 tamper-evident chain with optional ML-DSA-65 signing
  - `A2AGateway`: middleware wrapping agent send/receive with PII detection and injection blocking
  - `bilateral_verify()`: cross-verify two agents' ledgers agree on what happened
  - `export_evidence_bundle()`: self-verifying .air-a2a-evidence ZIP with standalone Python verifier
  - `build_transaction_trace()`: chronological timeline across multiple agents' ledgers
- Framework adapters for A2A compliance (LangChain, OpenAI, CrewAI, AutoGen)
- Co-attestation demo with bilateral ML-DSA-65 proof between agents
- 295 new tests (459 total, up from 164) covering A2A layer, adapters, compliance engine, trust layers, and CLI

### Fixed
- **CrewAI adapter**: rewrote hallucinated `step_callback`/`task_callback` hooks that don't exist in CrewAI API
- **AutoGen adapter**: rewrote to support both legacy pyautogen v0.2.x and modern autogen-agentchat v0.4+ (was targeting nonexistent API)
- Removed 13 unused imports across A2A module (ruff clean)
- Removed 5 dead timing variables in adapters

### Changed
- Test coverage increased from ~40% to ~80-85%
- All 459 tests passing across Python 3.10, 3.11, 3.12

## [1.9.0] - 2026-04-12

### Added
- Compliance Oracle and Attestation Pool (Phase 2D)
  - `air-blackbox attest create --publish` publishes signed attestations to public registry
  - `air-blackbox attest publish --id` publishes existing local attestations
  - Public verification pages at airblackbox.ai/verify/:id
  - Embeddable SVG compliance badges at airblackbox.ai/badge/:id
- Article 12 Compliance Layer rewrite with static + runtime code analysis
  - Detects logging infrastructure, tamper-evident patterns, retention config
  - Hybrid analysis: static pattern matching + runtime gateway verification
- 48 total compliance checks (up from 39) across 6 EU AI Act articles + GDPR

### Fixed
- Injection module missing exports (broke 25 tests)
- Injection detector regex too rigid for article prefixes
- Removed internal business docs accidentally committed to public repo

### Security
- Replaced hardcoded HMAC default key with random ephemeral key + warning
  - Previously all users shared the same default signing key "air-blackbox-default"
  - Now generates cryptographically random key when TRUST_SIGNING_KEY is not set

### Changed
- License changed from MIT to Apache-2.0
- SDK docstring updated to reflect actual command count and check count

## [1.8.1] - 2026-04-05

### Fixed
- Tuple unpacking bug in 4 CLI commands
- Version string consistency
- Stale package count references

## [1.8.0] - 2026-04-03

### Added
- Smart framework auto-detection in compliance scanner
- Trust layer recommendations based on detected frameworks
- Colorado SB 24-205 compliance crosswalk

## [1.7.0] - 2026-03-31

### Added
- Phase 2A: Multi-framework compliance mapping (EU AI Act + ISO 42001 + NIST AI RMF + Colorado SB 24-205)
- Phase 2B: ML-DSA-65 (FIPS 204) quantum-safe digital signatures for evidence
- Phase 2C: Self-verifying .air-evidence ZIP bundles with embedded public key + manifest
- `air-blackbox sign` command for key management and evidence signing
- `air-blackbox attest` command for creating signed compliance attestations
- `air-blackbox bundle` command for creating evidence bundles
- `air-blackbox standards` command for browsing the 4-framework crosswalk

## [1.6.1] - 2026-03-28

**Fixed**
- Fix standards_map.py STANDARDS_CROSSWALK dict closing prematurely (blocked GDPR/bias imports)
- Fix evidence_bundle.py hash serialization mismatch between manifest and ZIP (sort_keys consistency)

## [1.6.0] - 2026-03-27

**Added**
- Prompt injection detection: 20 weighted patterns across 5 categories
- GDPR scanner: 8 automated checks (consent, minimization, erasure, retention, cross-border, DPIA, processing records, breach notification)
- Bias/fairness scanner: 6 checks (fairness metrics, bias detection, protected attributes, dataset balance, model card, output monitoring)
- ISO 42001 + NIST AI RMF standards crosswalk mapping (8 categories)
- A2A (Agent-to-Agent) compliance protocol with compliance cards, peer verification, signed handshakes
- Evidence bundle exporter: signed ZIP with SHA-256 manifest for auditors
- Feedback loop MVP: user corrections flow into training data for fine-tuned model
- Pre-commit hooks: 4 configurations (basic, strict, GDPR, full)
- Audit chain specification v1.0 (RFC-style document)
- Training data phase 35: injection and GDPR patterns (15 examples)
## [1.5.0] - 2026-03-26

**Added**
- Haystack trust layer
- Claude Agent SDK trust layer
- MCP server registry listing (air-blackbox-mcp v0.1.6)
- Enhanced CLI with verbose compliance output

## [1.4.0] - 2026-03-20

**Added**
- Google ADK trust layer
- Enterprise air-gapped VPS deployment with fine-tuned model
- OTel tracing + dual pipeline
- Deep scan with fine-tuned compliance model

## [1.3.0] - 2026-03-15

**Added**
- MCP server for Claude Desktop and Cursor
- AI-BOM generation (CycloneDX 1.6)
- Shadow AI detection with approved model registry

## [1.2.0] - 2026-03-10

**Added**
- Compliance engine with 20+ checks across 6 EU AI Act articles
- PDF gap analysis reports
- Replay engine with HMAC verification

## [1.1.0] - 2026-03-05

**Added**
- Trust layer framework (LangChain, CrewAI, AutoGen, OpenAI)
- PII detection in prompts
- Non-blocking callback architecture

## [1.0.0] - 2026-03-01

**Added**
- Python SDK (pip install air-blackbox)
- CLI commands: comply, discover, replay, export
- HMAC-SHA256 audit chain
- Gateway client integration

## [0.1.0] - 2026-02-22

**Added**
- Initial release of AIR Blackbox Gateway
- OpenAI-compatible reverse proxy with full request/response capture
- HMAC-SHA256 tamper-evident audit chain
- OpenTelemetry trace emission
- Prompt vault integration with MinIO
- Docker Compose stack
- GitHub Container Registry publishing via CI
