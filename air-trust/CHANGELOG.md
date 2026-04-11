# Changelog

All notable changes to air-trust will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.1] - 2026-04-10

**Fixed**

- **CRITICAL**: Handoff records now raise `ImportError` if `cryptography` package is missing (previously silent no-op)
- **CRITICAL**: Handoff records without a keypair now emit `UserWarning` instead of silently writing unsigned records
- **CRITICAL**: Verifier now flags unsigned handoff records as `missing_signature` (previously skipped them)
- **HIGH**: Verifier validates all required signing fields before attempting signature verification (`malformed_record` check)
- **HIGH**: Session `__exit__` now resets `_active_session_id` ContextVar in a `finally` block (prevents session ID leak on exception)
- **HIGH**: Global `_global_chain` and `_global_identity` protected by threading lock (prevents cross-thread identity clobbering)
- **HIGH**: HMAC signing key validated on load — warns on loose permissions, rejects invalid hex content
- Handoff structural completeness: added missing branch for request + result without ack
- Stress test suite: 19 additional tests covering false positives, false negatives, mixed-version chains, and edge cases

**Changed**

- README now documents Ed25519 signed handoffs and the `[handoffs]` optional extra

## [0.6.0] - 2026-04-10

**Added — Signed Handoffs (Spec v1.2)**

- Ed25519 key management: `air_trust.keys` module for keypair generation, storage (`~/.air-trust/keys/`), loading, signing, and verification
- Three new handoff record types: `handoff_request`, `handoff_ack`, `handoff_result`
- Seven new Event fields for handoffs: `interaction_id`, `counterparty_id`, `payload_hash`, `nonce`, `signature`, `signature_alg`, `public_key`
- Auto-signing: `AuditChain.write()` automatically Ed25519-signs handoff records when agent has a keypair
- Handoff verifier in `verify()`: checks structural completeness, Ed25519 signature validity, payload hash matching, counterparty matching, nonce uniqueness
- `verify()` now returns three sections: `integrity` + `completeness` + `handoffs`
- CLI `python3 -m air_trust verify` shows handoff verification with PASS/WARN/FAIL
- CLI JSON output includes handoff section
- End-to-end signed handoff demo: `examples/signed_handoff.py`
- `SPEC.md` updated to v1.2 with handoff protocol, Ed25519 signing rules, and threat model
- 32 new handoff tests (286 total)
- Backward compatible: v1.0 and v1.1 records still verify cleanly

**Changed**

- Event.version default bumped from "1.1.0" to "1.2.0"
- `verify()` output structure changed: now returns `handoffs` section alongside `integrity` and `completeness`
- First external dependency: `cryptography` library (optional, required only for Ed25519 handoffs)

## [0.5.0] - 2026-04-10

**Added — Session Completeness (Spec v1.1)**

- `session_seq` and `prev_session_seq` fields on every Event within a session
- Monotonic sequence numbering scoped per session_id
- ContextVar-based session_id propagation: adapter events written inside
  `air_trust.session()` blocks automatically inherit the session_id and
  get sequence numbers — zero adapter code changes needed
- Completeness verifier: detects gaps, duplicates, rewinds, missing
  session_start, and missing session_end within each session
- `verify()` now returns both `integrity` (v1.0 HMAC check) and
  `completeness` (v1.1 session check) in a structured report
- CLI `python3 -m air_trust verify` upgraded with PASS/WARN/FAIL tiers
- CLI `--json` flag for machine-readable CI/CD output
- CLI `--key` flag for specifying the signing key
- `SPEC.md` v1.1 specification with threat model and scope statement
- 31 new tests (22 completeness + 9 propagation/CLI)
- Backward compatible: v1.0 records without session_seq still verify

**Changed**

- Event.version default bumped from "1.0.0" to "1.1.0"
- `verify()` output structure changed: now returns `{"integrity": {...}, "completeness": {...}}`
  with top-level `valid`/`records`/`broken_at` preserved for backward compat

## [0.4.0] - 2026-04-09

**Added — CSA Agentic Trust Framework (ATF) Conformance**

- AgentIdentity with ATF Identity Core Elements (I-1 through I-5)
- Four maturity levels: Intern, Junior, Senior, Principal
- `atf.conformance()`, `atf.level_compliant()`, `atf.gaps()` functions
- CLI `python3 -m air_trust atf` for ATF conformance checking
- MCP adapter for Claude Desktop, Cursor, Claude Code, Windsurf
- Policy enforcement with block/warn/log modes
- PII detection (email, SSN, phone, credit card, IBAN, national ID)
- Prompt injection scanning (20 weighted patterns)

## [0.3.0] - 2026-04-01

**Added**

- Decorator adapter: CrewAI, Smolagents, PydanticAI, DSPy, AutoGen, Browser Use
- OTel adapter: Semantic Kernel, generic OpenTelemetry
- Callback adapter: LangChain, LlamaIndex, Haystack
- Framework auto-detection from installed packages and objects

## [0.2.0] - 2026-03-25

**Added**

- Proxy adapter: OpenAI, Anthropic, Google, Ollama, LiteLLM, vLLM, Together, Groq, Mistral, Cohere
- `trust()` one-liner API
- `@monitor` decorator
- `session()` context manager with `.log()` and `.scan()`

## [0.1.0] - 2026-03-20

**Added**

- HMAC-SHA256 tamper-evident audit chain
- SQLite storage (local-first, zero dependencies)
- `verify()` integrity check
- CLI: verify, stats, export, badge
