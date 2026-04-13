# LangChain EU AI Act Compliance — Before & After

This demo shows how a typical LangChain agent goes from **zero compliance** to **EU AI Act ready** in 5 minutes using [AIR Blackbox](https://github.com/airblackbox/gateway).

## The Problem

Most LangChain agents ship with no logging, no audit trail, no input validation, and no human oversight. After **August 2, 2026**, this means non-compliance with the EU AI Act.

## The Demo

### `agent_before.py` — How most developers build today

A working LangChain customer service agent with 3 tools. It does the job, but:

- No logging or audit trail (Article 12 violation)
- No input validation or PII detection (Article 10 violation)
- No error handling or fallbacks (Article 9 violation)
- No human approval for sensitive actions (Article 14 violation)
- No injection defense (Article 15 violation)
- Raw user input piped straight to the LLM

### `agent_after.py` — Same agent, now compliant

The exact same agent with 5 additions:

1. **`pip install air-blackbox[langchain]`** — one-line install
2. **`AirLangChainHandler`** — drop-in callback that logs every LLM call with HMAC-SHA256 tamper-evident audit chain, PII detection, and injection scanning
3. **Pydantic input validation** — sanitizes user input, redacts PII, blocks injection attempts
4. **Error handling** — try/except on every tool with structured logging
5. **Human approval gate** — agent asks for permission before sending emails

## Run the Scanner

```bash
# Install
pip install air-blackbox

# Scan the 'before' agent
air-blackbox comply --scan ./agent_before.py --verbose

# Scan the 'after' agent
air-blackbox comply --scan ./agent_after.py --verbose

# Scan both together
air-blackbox comply --scan . --verbose
```

## What the Scanner Finds

| Article | Before | After | What Changed |
|---------|--------|-------|-------------|
| Art 9 — Risk Management | FAIL | PASS | Added try/except + fallback responses |
| Art 10 — Data Governance | FAIL | PASS | Pydantic validation + PII redaction |
| Art 11 — Technical Documentation | WARN | PASS | Docstrings + type annotations |
| Art 12 — Record-Keeping | FAIL | PASS | AirLangChainHandler + structured logging |
| Art 14 — Human Oversight | FAIL | PASS | Approval gate + max_iterations limit |
| Art 15 — Accuracy & Security | FAIL | PASS | Injection defense + input sanitization |

## The Trust Layer

The core of the compliance upgrade is one import:

```python
from air_blackbox.trust.langchain import AirLangChainHandler

handler = AirLangChainHandler(detect_pii=True, detect_injection=True)
llm = ChatOpenAI(model="gpt-4o-mini", callbacks=[handler])
```

Every LLM call now generates a `.air.json` audit record with:
- Run ID and timestamp
- Model and provider
- Token usage
- PII alerts (if detected)
- Injection alerts (if detected)
- HMAC-SHA256 chain hash (tamper-evident)

## Links

- **Scanner**: `pip install air-blackbox`
- **Fine-tuned model**: `ollama pull airblackbox/air-compliance`
- **GitHub**: [github.com/airblackbox/gateway](https://github.com/airblackbox/gateway)
- **Website**: [airblackbox.ai](https://airblackbox.ai)
