#!/usr/bin/env python3
"""
AIR Blackbox — Framework Benchmark Scanner

Scans CrewAI, LangFlow, and Quivr for EU AI Act compliance using
both the rule-based engine AND the fine-tuned AI model, then outputs
a structured comparison report.

Usage:
    python benchmarks/benchmark_frameworks.py

Requirements:
    - Ollama running with air-compliance model
    - Repos cloned to /tmp/crewai, /tmp/langflow, /tmp/quivr
      (script will clone them if missing)

Output:
    - benchmarks/results/  — JSON results per framework
    - benchmarks/results/comparison.json — side-by-side comparison
    - Console table showing the matrix
"""

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

# Add SDK to path so we can import air_blackbox directly
SDK_PATH = Path(__file__).parent.parent / "sdk"
sys.path.insert(0, str(SDK_PATH))

from air_blackbox.compliance.engine import run_all_checks
from air_blackbox.compliance.deep_scan import deep_scan, _ollama_available, _model_available
from air_blackbox.gateway_client import GatewayStatus


# ── Configuration ──

FRAMEWORKS = {
    "crewai": {
        "name": "CrewAI",
        "repo": "https://github.com/crewAIInc/crewAI.git",
        "local_path": "/tmp/crewai",
        "description": "Multi-agent orchestration framework",
    },
    "langflow": {
        "name": "LangFlow",
        "repo": "https://github.com/langflow-ai/langflow.git",
        "local_path": "/tmp/langflow",
        "description": "Visual framework for building AI workflows",
    },
    "quivr": {
        "name": "Quivr",
        "repo": "https://github.com/QuivrHQ/quivr.git",
        "local_path": "/tmp/quivr",
        "description": "RAG-based AI assistant framework",
    },
}

# What we expect to find (from manual code analysis) — for validation
EXPECTED = {
    "crewai": {
        9: "warn",   # Risk mgmt: RPM controller, guardrails, but no circuit breakers
        10: "warn",  # Data gov: Pydantic validators, Fingerprint, but no PII detection lib
        11: "pass",  # Tech docs: 1918 typed functions, multi-language docs, 73% docstrings
        12: "pass",  # Record-keeping: OpenTelemetry, event bus, 72 event files
        14: "pass",  # Human oversight: @human_feedback decorator (560 lines)
        15: "pass",  # Security: guardrails, output validation, retry logic — scanner correctly finds these
    },
    "langflow": {
        9: "warn",   # Risk mgmt: GuardrailsComponent is strong but scanner also checks for risk docs/mitigations
        10: "warn",  # Data gov: SSRF protection + PII detection, but validation found in many files
        11: "pass",  # Tech docs: SECURITY.md with CVEs, component docs
        12: "pass",  # Record-keeping: 8 tracing backends
        14: "pass",  # Human oversight: auth + flow control + execution limits
        15: "pass",  # Security: Prompt injection detection, SSRF blocking, Fernet encryption
    },
    "quivr": {
        9: "warn",   # Risk mgmt: Basic error handling, tokenizer fallback
        10: "warn",  # Data gov: Pydantic BaseModel exists (15/77 files), but no PII lib → WARN is correct
        11: "pass",  # Tech docs: 73%+ docstrings, type hints — scanner correctly scores PASS
        12: "warn",  # Record-keeping: Langfuse in 6 files but only 1 action audit file — thin
        14: "warn",  # Human oversight: no real HITL, basic iteration limits only → WARN after tightening
        15: "warn",  # Security: minimal retry (1 file), output validation (2 files) — thin
    },
}

ARTICLE_NAMES = {
    9: "Risk Management",
    10: "Data Governance",
    11: "Technical Documentation",
    12: "Record-Keeping",
    14: "Human Oversight",
    15: "Accuracy & Security",
}

RESULTS_DIR = Path(__file__).parent / "results"


# ── Helper Functions ──

def clone_if_missing(key: str, config: dict) -> bool:
    """Clone the repo if not present locally."""
    path = config["local_path"]
    if os.path.isdir(path):
        print(f"  [OK] {config['name']} already cloned at {path}")
        return True

    print(f"  [..] Cloning {config['name']}...")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", config["repo"], path],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            print(f"  [OK] {config['name']} cloned")
            return True
        else:
            print(f"  [FAIL] Clone failed: {result.stderr[:200]}")
            return False
    except Exception as e:
        print(f"  [FAIL] Clone error: {e}")
        return False


def count_python_files(scan_path: str) -> int:
    """Count non-test Python files."""
    count = 0
    skip_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv",
                 "dist", "build", ".eggs", "site-packages", ".tox",
                 ".mypy_cache", ".pytest_cache"}
    for root, dirs, files in os.walk(scan_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.endswith(".egg-info")]
        for f in files:
            if f.endswith(".py"):
                count += 1
    return count


def sample_code(scan_path: str, max_total: int = 10000) -> tuple:
    """
    Smart-sample compliance-relevant Python files.
    Returns (merged_code, files_included, total_files, total_chars).
    """
    py_files = []
    skip_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv",
                 "dist", "build", ".eggs", "site-packages", ".tox",
                 ".mypy_cache", ".pytest_cache"}

    for root, dirs, files in os.walk(scan_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.endswith(".egg-info")]
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))

    total_files = len(py_files)

    # Priority keywords for compliance-relevant files
    priority_keywords = [
        "agent", "pipeline", "tool", "llm", "model", "chat",
        "safety", "guard", "policy", "policies", "hitl", "human",
        "trace", "tracing", "logging", "log", "audit", "monitor",
        "auth", "token", "scope", "permission", "identity",
        "validate", "validation", "schema", "pii", "redact",
        "retry", "fallback", "error", "exception", "handler",
        "inject", "sanitize", "filter", "boundary", "limit",
        "config", "settings", "core", "main", "app", "run",
        "security", "ssrf", "guardrail", "oversight", "approve",
    ]

    def _score_file(fp):
        rel = os.path.relpath(fp, scan_path).lower()
        basename = os.path.basename(fp).lower()
        score = 0
        parts = rel.replace("\\", "/").split("/")
        if any(p in {"tests", "test", "testing"} for p in parts):
            return -1
        if basename.startswith("test_") or basename == "conftest.py":
            return -1
        for kw in priority_keywords:
            if kw in basename:
                score += 3
            elif kw in rel:
                score += 1
        if any(p in {"src", "core", "lib", "components"} for p in parts):
            score += 2
        try:
            size = os.path.getsize(fp)
            if size > 5000:
                score += 2
            elif size > 1000:
                score += 1
        except OSError:
            pass
        return score

    scored = [(fp, _score_file(fp)) for fp in py_files]
    scored = [(fp, s) for fp, s in scored if s >= 0]
    scored.sort(key=lambda x: x[1], reverse=True)

    MAX_PER_FILE = 3000
    code_parts = []
    total_chars = 0
    files_included = 0

    for fp, score in scored:
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
            if len(content.strip()) < 50:
                continue
            if len(content) > MAX_PER_FILE:
                content = content[:MAX_PER_FILE] + "\n# ... (file truncated for sampling)"
            code_parts.append(f"# File: {os.path.relpath(fp, scan_path)}\n{content}")
            total_chars += len(content)
            files_included += 1
            if total_chars > max_total:
                break
        except Exception:
            continue

    merged_code = "\n\n".join(code_parts)
    return merged_code, files_included, total_files, total_chars


def build_rule_context(articles: list) -> str:
    """Build rule-based context string from article results."""
    article_map = {9: "Risk Management", 10: "Data Governance",
                   11: "Technical Documentation", 12: "Record-Keeping",
                   14: "Human Oversight", 15: "Accuracy & Security"}
    lines = []
    for article in articles:
        art_num = article.get("number", 0)
        if art_num not in article_map:
            continue
        passes = []
        fails = []
        warns = []
        for check in article.get("checks", []):
            name = check.get("name", "")
            evidence = check.get("evidence", "")
            status = check.get("status", "")
            summary = f"{name}: {evidence[:80]}" if evidence else name
            if status == "pass":
                passes.append(summary)
            elif status == "fail":
                fails.append(summary)
            elif status == "warn":
                warns.append(summary)
        line = f"Article {art_num} ({article_map[art_num]}): "
        if passes:
            line += f"{len(passes)} PASS ({'; '.join(passes[:2])})"
        if fails:
            line += f", {len(fails)} FAIL" if passes else f"{len(fails)} FAIL"
        if warns:
            line += f", {len(warns)} WARN" if (passes or fails) else f"{len(warns)} WARN"
        lines.append(line)
    return "\n".join(lines)


def reconcile(deep_findings: list, articles: list) -> int:
    """Smart reconciliation — override model FAILs when rule-based has strong PASS."""
    rule_pass_counts = {}
    rule_evidence_map = {}
    for article in articles:
        art_num = article.get("number", 0)
        passes = [c for c in article.get("checks", []) if c.get("status") == "pass"]
        rule_pass_counts[art_num] = len(passes)
        if passes:
            rule_evidence_map[art_num] = "; ".join(
                c.get("evidence", "")[:60] for c in passes[:3]
            )

    overrides = 0
    for finding in deep_findings:
        art = finding.get("article", 0)
        model_status = finding.get("status", "")
        rule_passes = rule_pass_counts.get(art, 0)

        if model_status == "fail" and rule_passes >= 2:
            finding["status"] = "pass"
            rule_ev = rule_evidence_map.get(art, "")
            finding["evidence"] = (
                f"[Corrected by rule-based] Scanner found {rule_passes} passing checks: "
                f"{rule_ev}. Model original: {finding.get('evidence', '')}"
            )
            finding["fix_hint"] = ""
            overrides += 1
        elif model_status == "fail" and rule_passes == 1:
            finding["status"] = "warn"
            rule_ev = rule_evidence_map.get(art, "")
            finding["evidence"] = (
                f"[Partial — rule-based found evidence] {rule_ev}. "
                f"Model noted: {finding.get('evidence', '')}"
            )
            overrides += 1

    return overrides


def scan_framework(key: str, config: dict) -> dict:
    """
    Run the full AIR Blackbox scan pipeline on a framework.
    Returns structured results.
    """
    scan_path = config["local_path"]
    name = config["name"]

    print(f"\n{'='*60}")
    print(f"  Scanning: {name}")
    print(f"  Path:     {scan_path}")
    print(f"{'='*60}")

    start_time = time.time()

    # Step 1: Count files
    total_py = count_python_files(scan_path)
    print(f"  Python files found: {total_py}")

    # Step 2: Run rule-based engine
    # We create a dummy GatewayStatus since we're scanning code, not live traffic
    dummy_status = GatewayStatus(reachable=False, total_runs=0)
    print(f"  Running rule-based scanner...")
    articles = run_all_checks(dummy_status, scan_path)

    rule_results = {}
    for article in articles:
        art_num = article.get("number", 0)
        checks = article.get("checks", [])
        passes = sum(1 for c in checks if c.get("status") == "pass")
        warns = sum(1 for c in checks if c.get("status") == "warn")
        fails = sum(1 for c in checks if c.get("status") == "fail")
        total = passes + warns + fails

        # Determine article-level status — proportional scoring
        # When scanning code-only (no gateway), exclude runtime checks that
        # auto-fail just because "gateway not reachable" — those aren't fair
        static_checks = [c for c in checks if c.get("tier") == "static"]
        static_passes = sum(1 for c in static_checks if c.get("status") == "pass")
        static_warns = sum(1 for c in static_checks if c.get("status") == "warn")
        static_fails = sum(1 for c in static_checks if c.get("status") == "fail")
        static_total = len(static_checks)

        # Use static checks for scoring when gateway isn't running
        s_passes = static_passes if static_total > 0 else passes
        s_total = static_total if static_total > 0 else total
        s_fails = static_fails if static_total > 0 else fails

        if s_total == 0:
            overall = "warn"
        elif s_passes > 0 and s_passes >= s_fails and (s_passes / s_total) >= 0.4:
            overall = "pass"
        elif s_passes >= 1 or static_warns >= 1 or warns >= 1:
            overall = "warn"
        else:
            overall = "fail"

        rule_results[art_num] = {
            "status": overall,
            "passes": passes,
            "warns": warns,
            "fails": fails,
            "checks": checks,
        }

    print(f"  Rule-based results:")
    for art_num in [9, 10, 11, 12, 14, 15]:
        r = rule_results.get(art_num, {})
        status = r.get("status", "?").upper()
        icon = {"PASS": "✅", "WARN": "⚠️ ", "FAIL": "❌"}.get(status, "?")
        print(f"    Art {art_num} ({ARTICLE_NAMES[art_num]}): {icon} {status} "
              f"({r.get('passes',0)}P/{r.get('warns',0)}W/{r.get('fails',0)}F)")

    # Step 3: Sample code for AI model
    print(f"\n  Sampling code for AI model...")
    merged_code, files_included, total_files, total_chars = sample_code(scan_path)
    print(f"  Sampled {files_included} files ({total_chars:,} chars) from {total_files} total")

    # Step 4: Run AI model (deep scan)
    model_results = {}
    overrides = 0
    model_raw_findings = []

    if _ollama_available() and _model_available("air-compliance"):
        print(f"  Running AI model (air-compliance)...")
        rule_context = build_rule_context(articles)
        sample_desc = f"targeted sample of {files_included} compliance-relevant files"

        os.environ["AIR_VERBOSE"] = "1"
        result = deep_scan(
            merged_code,
            model="air-compliance",
            sample_context=sample_desc,
            total_files=total_files,
            rule_context=rule_context,
        )
        os.environ.pop("AIR_VERBOSE", None)

        if result.get("available") and not result.get("error"):
            model_raw_findings = result.get("findings", [])
            print(f"  AI model returned {len(model_raw_findings)} finding(s)")

            # Smart reconciliation
            overrides = reconcile(model_raw_findings, articles)
            if overrides:
                print(f"  Smart reconciliation: {overrides} verdict(s) corrected")

            for finding in model_raw_findings:
                art = finding.get("article", 0)
                model_results[art] = {
                    "status": finding.get("status", "unknown"),
                    "evidence": finding.get("evidence", ""),
                    "fix_hint": finding.get("fix_hint", ""),
                }
        else:
            print(f"  AI model error: {result.get('error', 'unknown')}")
    else:
        print(f"  AI model not available — rule-based only")

    # Step 5: Merge into final results
    elapsed = time.time() - start_time
    final_articles = {}
    for art_num in [9, 10, 11, 12, 14, 15]:
        rule = rule_results.get(art_num, {})
        model = model_results.get(art_num, {})

        # Final status: use rule-based as primary, model as supplementary
        final_status = rule.get("status", "fail")

        final_articles[art_num] = {
            "article": art_num,
            "name": ARTICLE_NAMES[art_num],
            "rule_status": rule.get("status", "unknown"),
            "rule_passes": rule.get("passes", 0),
            "rule_warns": rule.get("warns", 0),
            "rule_fails": rule.get("fails", 0),
            "rule_checks": rule.get("checks", []),
            "model_status": model.get("status", "not_run"),
            "model_evidence": model.get("evidence", ""),
            "model_fix_hint": model.get("fix_hint", ""),
            "final_status": final_status,
        }

    # Compare against expected
    expected = EXPECTED.get(key, {})
    matches = 0
    mismatches = []
    for art_num in [9, 10, 11, 12, 14, 15]:
        exp = expected.get(art_num, "?")
        got = final_articles[art_num]["final_status"]
        if exp == got:
            matches += 1
        else:
            mismatches.append({
                "article": art_num,
                "expected": exp,
                "got": got,
                "name": ARTICLE_NAMES[art_num],
            })

    pass_count = sum(1 for a in final_articles.values() if a["final_status"] == "pass")
    warn_count = sum(1 for a in final_articles.values() if a["final_status"] == "warn")
    fail_count = sum(1 for a in final_articles.values() if a["final_status"] == "fail")

    scan_result = {
        "framework": name,
        "key": key,
        "scan_path": scan_path,
        "timestamp": datetime.now().isoformat(),
        "elapsed_seconds": round(elapsed, 1),
        "total_python_files": total_py,
        "files_sampled": files_included,
        "chars_sampled": total_chars,
        "model_used": "air-compliance" if model_results else "none",
        "model_findings_count": len(model_raw_findings),
        "reconciliation_overrides": overrides,
        "summary": {
            "pass": pass_count,
            "warn": warn_count,
            "fail": fail_count,
            "score": f"{pass_count}/6",
        },
        "articles": final_articles,
        "validation": {
            "expected_matches": matches,
            "total_articles": 6,
            "accuracy": f"{matches}/6 ({round(matches/6*100)}%)",
            "mismatches": mismatches,
        },
    }

    # Print summary
    print(f"\n  {'─'*40}")
    print(f"  {name} Summary: {pass_count} PASS, {warn_count} WARN, {fail_count} FAIL")
    print(f"  Validation: {matches}/6 match expected ({round(matches/6*100)}%)")
    if mismatches:
        for m in mismatches:
            print(f"    ⚠️  Art {m['article']} ({m['name']}): expected {m['expected'].upper()}, got {m['got'].upper()}")
    print(f"  Time: {elapsed:.1f}s")

    return scan_result


def print_comparison_table(results: dict):
    """Print a formatted comparison table to console."""
    print(f"\n\n{'='*80}")
    print(f"  AIR BLACKBOX — EU AI ACT BENCHMARK COMPARISON")
    print(f"{'='*80}\n")

    # Header
    header = f"{'Article':<30} {'CrewAI':^12} {'LangFlow':^12} {'Quivr':^12}"
    print(header)
    print("─" * 70)

    icons = {"pass": "✅ PASS", "warn": "⚠️  WARN", "fail": "❌ FAIL", "unknown": "?"}

    for art_num in [9, 10, 11, 12, 14, 15]:
        name = f"Art. {art_num} — {ARTICLE_NAMES[art_num]}"
        cols = []
        for fw_key in ["crewai", "langflow", "quivr"]:
            if fw_key in results:
                status = results[fw_key]["articles"][art_num]["final_status"]
                cols.append(icons.get(status, "?"))
            else:
                cols.append("—")

        print(f"{name:<30} {cols[0]:^12} {cols[1]:^12} {cols[2]:^12}")

    print("─" * 70)

    # Totals
    totals = []
    for fw_key in ["crewai", "langflow", "quivr"]:
        if fw_key in results:
            s = results[fw_key]["summary"]
            totals.append(f"{s['score']}")
        else:
            totals.append("—")

    print(f"{'TOTAL PASS':<30} {totals[0]:^12} {totals[1]:^12} {totals[2]:^12}")

    # Validation
    print(f"\n{'Validation vs. Expected':^70}")
    print("─" * 70)
    for fw_key in ["crewai", "langflow", "quivr"]:
        if fw_key in results:
            v = results[fw_key]["validation"]
            name = results[fw_key]["framework"]
            print(f"  {name}: {v['accuracy']}")
            for m in v["mismatches"]:
                print(f"    ↳ Art {m['article']} ({m['name']}): expected {m['expected'].upper()}, got {m['got'].upper()}")


def main():
    print("╔══════════════════════════════════════════════════════════╗")
    print("║    AIR Blackbox — Framework Benchmark Scanner           ║")
    print("║    Scanning CrewAI, LangFlow, Quivr                     ║")
    print("╚══════════════════════════════════════════════════════════╝")

    # Check prerequisites
    print("\nChecking prerequisites...")
    if _ollama_available():
        print("  [OK] Ollama installed")
        if _model_available("air-compliance"):
            print("  [OK] air-compliance model available")
        else:
            print("  [!!] air-compliance model NOT found — will use rule-based only")
            print("       Run: air-blackbox setup")
    else:
        print("  [!!] Ollama NOT installed — will use rule-based only")
        print("       Install: https://ollama.com")

    # Clone repos
    print("\nPreparing frameworks...")
    available = {}
    for key, config in FRAMEWORKS.items():
        if clone_if_missing(key, config):
            available[key] = config

    if not available:
        print("\n[ERROR] No frameworks available to scan. Exiting.")
        sys.exit(1)

    # Run scans
    all_results = {}
    for key, config in available.items():
        result = scan_framework(key, config)
        all_results[key] = result

        # Save individual result
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        result_file = RESULTS_DIR / f"{key}_scan.json"
        with open(result_file, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"  Saved: {result_file}")

    # Save comparison
    comparison = {
        "generated": datetime.now().isoformat(),
        "scanner_version": "1.4.0",
        "model": "air-compliance" if _ollama_available() and _model_available("air-compliance") else "rule-based-only",
        "frameworks": all_results,
    }
    comparison_file = RESULTS_DIR / "comparison.json"
    with open(comparison_file, "w") as f:
        json.dump(comparison, f, indent=2, default=str)
    print(f"\n  Comparison saved: {comparison_file}")

    # Print table
    print_comparison_table(all_results)

    # Final summary
    print(f"\n\nDone. Results in: {RESULTS_DIR}/")
    print("Next steps:")
    print("  1. Review mismatches — are they scanner bugs or expected data?")
    print("  2. If model didn't run, install it: air-blackbox setup")
    print("  3. Share comparison.json with framework maintainers for validation")


if __name__ == "__main__":
    main()
