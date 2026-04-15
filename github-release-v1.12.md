# GitHub Release — v1.12.0

Post this as a GitHub Release on the gateway repo:
https://github.com/airblackbox/air-trust/releases/new

**Tag version**: `v1.12.0`
**Release title**: `v1.12.0 — Flight recorder for autonomous AI agents`

---

## RELEASE BODY

AIR Blackbox is the flight recorder for autonomous AI agents. Record, replay, enforce, audit.

This release expands EU AI Act coverage from 6 articles to 7 (adds Article 13 transparency), detects three open agent identity standards in a single scan, and ships the first hardware reproducibility scanner in the compliance tooling space.

```bash
pip install --upgrade air-blackbox
air-blackbox comply --scan .
```

## What's new

### Multi-scheme agent identity detection (Articles 12 + 14)

The `agent-identity-binding` check now recognizes three identity schemes, not just `air-trust`. For autonomous agents (tick loops, continuous decision loops), it verifies at least one is in use:

- **`air-trust`** — Ed25519 agent keys + HMAC-SHA256 audit chain (this project)
- **AAR** — Agent Action Receipt per-action signing ([agent-action-receipt-spec](https://github.com/Cyberweasel777/agent-action-receipt-spec))
- **SCC** — Session Continuity Certificate with Merkle memory roots, capability hash lineage, and prior-session chaining ([botindex-aar@1.1.0+](https://www.npmjs.com/package/botindex-aar))

Shaped by the public discussion on [FINOS ai-governance-framework #266](https://github.com/finos/ai-governance-framework/issues/266) and the NIST RFI Docket NIST-2025-0035 on AI agent security. Co-credit to @botbotfromuk and @Cyberweasel777 for the SCC spec.

### Article 13 transparency scanner (new)

Six new checks covering EU AI Act Article 13 (transparency and provision of information to users):

- AI disclosure to users (Art. 50 + 13(3)(b))
- Capability and limitation documentation (13(3)(b))
- Instructions for use (13(2))
- Provider identity disclosure (13(3)(a))
- Output interpretation support — confidence scores, rationale (13(3)(d))
- Change logging and versioning (13(3)(c))

### Article 15 hardware determinism scanner (new)

Three checks addressing a robustness failure mode no other compliance scanner covers — non-deterministic outputs across GPU types, driver versions, and cuDNN settings:

- **RNG seed determinism** — Python `random`, NumPy, PyTorch (CPU + CUDA), TensorFlow, JAX
- **Deterministic algorithm flags** — `torch.use_deterministic_algorithms`, `torch.backends.cudnn.deterministic`, `torch.backends.cudnn.benchmark = False`, `CUBLAS_WORKSPACE_CONFIG`, `tf.config.experimental.enable_op_determinism`. Scans both code and deployment config (`.env`, Dockerfile, YAML, shell).
- **Hardware abstraction** — flags hardcoded `.to("cuda")`, `cuda:0`, `.cuda()`, `device="cuda"` patterns without a `torch.cuda.is_available()` fallback.

Directly supports SR 11-7 model validation (which requires reproducibility) and EU AI Act Article 15 (robustness across deployment environments).

### `air-trust agent-identity` CLI (shipped in `air-trust==0.7.0`)

New subcommand verifies identity continuity across a chain:

```bash
python3 -m air_trust agent-identity --agent <name>
```

Ghost agent detection, session segmentation by timestamp gaps, JSON output for CI/CD, pass/warn/fail exit codes.

### Fixed

- Hardcoded `1.10.0` in CLI `--version` output, scanner metadata, and self-audit consistency check — all references now correctly report the running version.

## Verify the install

```bash
pip install air-blackbox==1.12.0
air-blackbox --version
# air-blackbox, version 1.12.0
```

## Test stats

1,526 sdk tests passing (41 new), 311 air-trust tests passing (6 new). Zero regressions.

## Full changelog

See [CHANGELOG.md](https://github.com/airblackbox/air-trust/blob/main/CHANGELOG.md) for detailed change history.

## Community

If any of the new checks catch a pattern you're using (or mis-flag a pattern you're using), open an issue. Compliance scanning only gets better with corrections.

---

## ASSETS TO ATTACH

Leave empty on first post. If it gets traction, consider uploading:
- A PNG screenshot of the CLI output showing the new Article 13 + Article 15 checks pass/fail
- The compiled wheel (optional — PyPI already hosts it)

## TAG STRATEGY

After clicking "Publish release", verify:
- Tag `v1.12.0` created on main branch
- Release appears at https://github.com/airblackbox/air-trust/releases/tag/v1.12.0
- Email notifications fire to anyone watching the repo
- Discord/Slack notifications fire if any integrations are set up

## FOLLOW-UP ACTIONS

Within 1 hour of publishing:
- [ ] Pin the release in the repo sidebar (helps new visitors)
- [ ] Tweet/LinkedIn the release URL
- [ ] Post in any relevant Discord channels (FINOS, open-source ML, etc.)
- [ ] Cross-link from airblackbox.ai/changelog page if one exists
