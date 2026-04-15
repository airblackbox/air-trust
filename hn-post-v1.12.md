# Show HN: AIR Blackbox — the flight recorder for autonomous AI agents

**Title (locked):** `Show HN: AIR Blackbox – the flight recorder for autonomous AI agents`

Why this title: matches the product name (BLACKBOX = flight recorder), names the specific market (autonomous AI agents), and gives HN readers a mental model they already have. No jargon, no buzzwords.

---

## POST BODY

AIR Blackbox is the flight recorder for autonomous AI agents. Record, replay, enforce, audit. Open-source, runs locally.

Most Python AI agent codebases I've looked at can't answer three questions that regulators, auditors, and engineering leaders all ask: Did this agent act the same way yesterday? Who authorized this decision? Can you prove the audit trail wasn't tampered with? The EU AI Act enforcement deadline (August 2, 2026) makes those questions legally binding. Enterprise governance platforms cost $50K+/year, they don't scan code, and they're designed for compliance officers, not engineers.

I built `air-blackbox`, an open-source CLI. Apache 2.0. No cloud, no API keys, no login.

    pip install air-blackbox
    air-blackbox comply --scan .

What it checks (each maps to a specific article):

- Risk management documentation (Art. 9)
- Data governance + PII handling (Art. 10)
- Technical documentation + model cards (Art. 11)
- Record-keeping + HMAC-SHA256 tamper-evident audit chains (Art. 12)
- Transparency + AI disclosure to users (Art. 13)
- Human oversight + kill switches (Art. 14)
- Hardware reproducibility + injection defense (Art. 15)

The v1.12 release I pushed today adds two things I haven't seen in any other compliance scanner:

**Multi-scheme agent identity detection.** Autonomous agents with tick loops (the `while True: act()` pattern) need cryptographic identity continuity across sessions, or you cannot prove in audit that the agent acting today is the same one that was authorized yesterday. The scanner now detects three identity schemes: `air-trust` (the Ed25519 + HMAC chain we ship), AAR (Agent Action Receipt spec from the FINOS AI Governance Framework thread), and SCC (Session Continuity Certificate, shipped in `botindex-aar@1.1.0`). It passes if any of them is in use.

**Hardware reproducibility checks.** EU AI Act Article 15 requires robust behavior across deployment environments. Models give different outputs on different GPUs if you don't pin seeds, disable cuDNN benchmark mode, and use `torch.use_deterministic_algorithms(True)`. Most code doesn't. The scanner flags missing seed setting (Python/NumPy/PyTorch/TF), missing deterministic-algorithm flags, and hardcoded `cuda:0` patterns that crash on CPU-only or Apple Silicon. Scans both `.py` files and `.env` / Dockerfile / YAML for deployment-layer env vars like `CUBLAS_WORKSPACE_CONFIG`.

Limits I want to be upfront about: this checks technical requirements, not legal compliance. It's a linter, not a lawyer. Passing every check does not mean you are legally compliant with the EU AI Act — it means your code implements the technical controls the regulation references. Interpretation of the law is the job of your legal counsel.

Where it came from: the agent identity detection piece was shaped by a thread on the FINOS AI Governance Framework repo where @botbotfromuk (an autonomous-agent developer) and @Cyberweasel777 (Agent Action Receipt spec author) designed the SCC standard in response to the NIST RFI on AI agent security. The Article 15 hardware determinism piece was shaped by Atherik's recent acquisition — they solve non-determinism at runtime; this scanner catches the anti-patterns at CI/CD time, which is complementary.

Repo: https://github.com/airblackbox/air-trust
PyPI: https://pypi.org/project/air-blackbox/

Happy to answer questions about the check logic, the three identity schemes, or the regulatory mapping.

---

## FIRST COMMENT (post immediately after submitting)

One thing worth addressing before someone asks: yes, regex-based static analysis has limits. It will produce false positives on obfuscated code, and it can miss runtime behavior entirely — which is why the design pairs static checks with trust-layer integrations that capture runtime evidence (OpenAI, LangChain, CrewAI, AutoGen, Haystack, Google ADK, Claude Agent SDK). Static-only is the default because it works on any codebase with zero configuration; runtime checks are opt-in when teams want stronger signal.

Also: I don't believe compliance scanning is a moat. The actual moat in this space is the fine-tuned compliance model that turns scan results into training data — the scanner gets smarter every time a team corrects a false positive. That's the work this release makes possible, not the work itself.

---

## POSTING CHECKLIST

- [ ] Wait until Tuesday or Wednesday, 8-10am EST
- [ ] Verify `pip install air-blackbox==1.12.0` resolves (PyPI CDN propagated)
- [ ] Check that https://airblackbox.ai renders fast (HN can surge traffic)
- [ ] Be online for 2 hours after posting
- [ ] Reply to every comment, even critical ones
- [ ] If someone challenges the approach: acknowledge the limit, don't defend
- [ ] Do NOT ask anyone to upvote. HN punishes vote rings aggressively.
- [ ] If it hits /front, drop a comment with the demo link: https://airblackbox.ai/demo/hub

## WHAT SUCCESS LOOKS LIKE

- **Best case**: front page, 50-150 stars, 3-5 serious technical commenters engaging
- **Good case**: 20-40 stars, 1-2 enterprise inbounds
- **Baseline**: stays in /new, get 5-10 stars and a few bug reports — still valuable

## IF CRITICISM COMES

Most likely attack vectors and honest responses:

1. "Regex isn't real static analysis" → Agree. Pairs with runtime trust layers; regex is the cheapest zero-config layer.
2. "This doesn't prove legal compliance" → Agree, already said so in the post. It's a linter, not a lawyer.
3. "Why another EU AI Act tool?" → No other tool checks Python code statically for all 7 articles. Enterprise platforms cost $50K+ and don't look at code at all.
4. "Who actually needs this?" → ML teams at regulated companies who have to prove SR 11-7 / EU AI Act readiness. 14K+ PyPI downloads says the demand is real.
