# AIR Blackbox v1.11.0 Roadmap

**Target release:** Before August 2, 2026 EU AI Act high-risk deadline
**Current state:** v1.10.0 - 459 tests, 16,372 LOC, 56 source files, 84 ruff warnings

---

## Phase 1: Code Hygiene (Day 1)

Clean the 84 ruff warnings to get a zero-warning codebase. This is mechanical work that makes every future PR cleaner.

### 1A. Fix 39 unused imports (F401)

Worst offenders by file:

| File | Unused imports |
|------|---------------|
| cli.py | 14 |
| attestation/registry.py | 3 |
| evidence/bundle.py | 3 |
| trust/claude_agent/__init__.py | 3 |
| trust/openai_agents/__init__.py | 2 |
| trust/langchain/__init__.py | 2 |
| compliance/gdpr_scanner.py | 2 |
| 10 other files | 1 each |

Fix: `ruff check sdk/ --select F401 --fix` (auto-fixable), then verify tests pass.

### 1B. Fix 36 f-strings without placeholders (F541)

Strings like `f"No traffic data found"` where the `f` prefix is unnecessary. Mostly in cli.py.

Fix: `ruff check sdk/ --select F541 --fix` (auto-fixable).

### 1C. Fix 6 multi-statement lines (E701)

Lines like `if x: return y` that should be split across two lines.

Fix: Manual (6 lines).

### 1D. Fix 2 unused variables (F841)

Fix: Manual (2 lines).

### 1E. Fix 1 undefined name (F821)

`AuditChain` used as a string type hint in `trust/claude_agent/__init__.py:132` but the class is imported at runtime inside the function, not at module level. Fix by adding a `TYPE_CHECKING` import or changing the return annotation.

### 1F. Verify

- Run `ruff check sdk/` -- expect 0 errors
- Run `pytest tests/ -x -q` -- expect 459 passed
- Commit: "chore: clean all 84 ruff warnings"

---

## Phase 2: Test Coverage Expansion (Days 2-3)

Current: 459 tests covering ~55% of source lines. Target: 600+ tests, ~80% coverage.

### Untested modules (3,492 lines with zero tests):

| Module | Lines | Priority | Complexity |
|--------|-------|----------|------------|
| compliance/code_scanner.py | 656 | HIGH | Medium -- regex-based scanning |
| compliance/deep_scan.py | 563 | HIGH | High -- LLM integration |
| a2a/protocol.py | 444 | HIGH | Medium -- A2A protocol layer |
| export/pdf_report.py | 392 | LOW | High -- PDF generation deps |
| compliance/gdpr_scanner.py | 341 | HIGH | Medium -- GDPR checks |
| compliance/bias_scanner.py | 270 | MEDIUM | Medium -- bias detection |
| demo_generator.py | 241 | LOW | Low -- demo output only |
| aibom/shadow.py | 190 | MEDIUM | Medium -- shadow AI detection |
| precommit.py | 134 | LOW | Low -- git hook integration |
| feedback.py | 133 | LOW | Low -- telemetry |
| telemetry.py | 128 | LOW | Low -- telemetry |

### Test writing order (by impact):

1. **test_code_scanner.py** (~40 tests) -- core scanning engine, most user-facing
2. **test_gdpr_scanner.py** (~25 tests) -- GDPR is a major compliance vector
3. **test_a2a_protocol.py** (~30 tests) -- protocol layer for the A2A system
4. **test_deep_scan.py** (~20 tests) -- mock the LLM calls, test parsing
5. **test_bias_scanner.py** (~20 tests) -- bias detection patterns
6. **test_shadow_aibom.py** (~15 tests) -- shadow AI inventory scanning

Skip for now: pdf_report.py (heavy deps), demo_generator.py (output-only), precommit.py (git-coupled), feedback.py and telemetry.py (side-effect-heavy).

### CLI coverage deepening

cli.py is 2,664 lines with only 37 smoke tests. Add 30+ targeted tests for:
- `comply` command output parsing
- `scan-code` with mock files
- `export` bundle generation
- `attest` with mock signing
- Error paths (missing files, bad input)

### Phase 2 target: ~150 new tests, total ~610

---

## Phase 3: Integration Tests (Days 4-5)

The current test suite is 100% unit tests with mocked dependencies. Phase 3 adds integration tests that verify real framework installs work.

### 3A. CI matrix with optional framework installs

Update `.github/workflows/sdk-tests.yml`:

```yaml
jobs:
  unit-tests:
    # Existing: runs on all Python versions, no framework deps
    ...
  
  integration-tests:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        framework:
          - {name: "langchain", deps: "langchain langchain-openai"}
          - {name: "crewai", deps: "crewai"}
          - {name: "openai", deps: "openai"}
    steps:
      - pip install ${{ matrix.framework.deps }}
      - pytest tests/integration/ -x -q --tb=short -k ${{ matrix.framework.name }}
```

### 3B. Integration test files

Create `tests/integration/` directory:

- **test_langchain_integration.py** -- import real LangChain, attach trust layer, verify callbacks fire
- **test_openai_integration.py** -- import real OpenAI SDK, wrap client, verify audit records written
- **test_crewai_integration.py** -- import real CrewAI, attach adapter, verify kickoff wrapping works

Each test verifies:
1. The framework import works
2. The trust layer attaches without error
3. Audit records are written to disk
4. The HMAC chain is valid

### 3C. What NOT to integration test

- AutoGen (API is unstable across versions, keep mocked)
- Haystack (heavy install, low user base for now)
- ADK (Google dependency, keep mocked)

---

## Phase 4: New Features (Days 6-8)

### 4A. `ruff` and `mypy` in CI

Add a lint job that enforces zero ruff warnings on every PR:

```yaml
lint:
  steps:
    - run: ruff check sdk/ --select E,F,W
    - run: ruff format sdk/ --check
```

### 4B. Coverage reporting in CI

Add `pytest-cov` to CI:

```yaml
- run: pytest tests/ --cov=air_blackbox --cov-report=term-missing --cov-fail-under=70
```

This blocks PRs that drop coverage below 70%.

### 4C. py.typed marker

Add `sdk/air_blackbox/py.typed` (empty file) so type checkers recognize the package. This is a one-line change that signals quality to enterprise users.

### 4D. A2A adapter `__init__.py` re-exports

The adapter classes aren't importable from `air_blackbox.a2a.adapters` -- they need to be added to the `__init__.py` so users can do:

```python
from air_blackbox.a2a.adapters import A2ALangChainHandler
```

### 4E. Configurable ruff in `pyproject.toml`

Add ruff config so all contributors use the same rules:

```toml
[tool.ruff]
target-version = "py310"
line-length = 120
select = ["E", "F", "W", "I"]
ignore = ["E501"]

[tool.ruff.isort]
known-first-party = ["air_blackbox"]
```

---

## Phase 5: Documentation (Day 9)

### 5A. API reference (auto-generated)

Add `pdoc` or `mkdocs` with `mkdocstrings` to auto-generate API docs from docstrings. Deploy to GitHub Pages or airblackbox.ai/docs.

### 5B. CONTRIBUTING.md

Standard contributor guide: how to set up dev environment, run tests, submit PRs, coding standards.

### 5C. Model card for fine-tuned LLM

When the compliance model ships, include a model card documenting training data, evaluation metrics, known limitations, and intended use.

---

## Phase 6: Verification and Release (Day 10)

### Pre-release checklist:

- [ ] `ruff check sdk/` returns 0 errors
- [ ] `pytest tests/ -q` passes 600+ tests
- [ ] CI green on Python 3.10, 3.11, 3.12
- [ ] Integration tests pass for LangChain, OpenAI, CrewAI
- [ ] Coverage >= 70% (measured by pytest-cov)
- [ ] CHANGELOG.md updated with 1.11.0 entry
- [ ] Version bumped in pyproject.toml, __init__.py, cli.py, export.py, ARCHITECTURE.md
- [ ] `python -m build` succeeds
- [ ] `twine upload` to PyPI
- [ ] `pip install air-blackbox==1.11.0` verified
- [ ] airblackbox.ai version updated

---

## Summary

| Phase | Work | Tests added | Days |
|-------|------|------------|------|
| 1. Code Hygiene | Fix 84 ruff warnings | 0 | 1 |
| 2. Test Coverage | 6 new test files + CLI deepening | ~150 | 2 |
| 3. Integration Tests | 3 framework integration suites | ~30 | 2 |
| 4. New Features | CI lint, coverage gate, py.typed, ruff config | ~0 | 2 |
| 5. Documentation | API docs, CONTRIBUTING.md | 0 | 1 |
| 6. Release | Version bump, build, publish | 0 | 1 |
| **Total** | | **~180 new tests (639 total)** | **~9 days** |

### v1.11.0 headline:

> "Zero lint warnings. 70%+ measured coverage. Framework integration tests. CI-enforced quality gates."

This positions AIR Blackbox as auditor-ready: not just "it works" but "we can prove it works, and every PR must maintain that standard."
