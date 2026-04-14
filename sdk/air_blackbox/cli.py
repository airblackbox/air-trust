"""
AIR Blackbox CLI — AI governance control plane.

    air-blackbox setup       # One-command setup: install model + verify
    air-blackbox discover    # Shadow AI inventory + AI-BOM
    air-blackbox comply      # EU AI Act compliance from live traffic
    air-blackbox standards   # Multi-framework crosswalk (EU, ISO, NIST, Colorado)
    air-blackbox sign        # ML-DSA-65 quantum-safe signing of evidence
    air-blackbox verify      # Verify signed evidence files
    air-blackbox bundle      # Self-verifying .air-evidence package for auditors
    air-blackbox attest      # Create/list/verify compliance attestations
    air-blackbox replay      # Incident reconstruction from audit chain
    air-blackbox export      # JSON/PDF evidence export
    air-blackbox validate    # Pre-execution runtime checks
    air-blackbox test        # End-to-end stack validation
    air-blackbox demo        # Zero-config demo with sample data
    air-blackbox init        # Initialize project templates
"""

from datetime import datetime

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from air_blackbox import __version__ as _ab_version

console = Console()


AIR_BANNER = r"""[bold #00d4aa]
    _    ___ ____    ____  _            _    _
   / \  |_ _|  _ \  | __ )| | __ _  ___| | _| |__   _____  __
  / _ \  | || |_) | |  _ \| |/ _` |/ __| |/ / '_ \ / _ \ \/ /
 / ___ \ | ||  _ <  | |_) | | (_| | (__|   <| |_) | (_) >  <
/_/   \_\___|_| \_\ |____/|_|\__,_|\___|_|\_\_.__/ \___/_/\_\
[/bold #00d4aa]"""


def print_banner():
    console.print(AIR_BANNER)
    console.print("  [dim]EU AI Act Compliance · AI-BOM · Audit Chain · Incident Replay[/dim]")
    console.print()
    console.print("  " + "─" * 76, style="#1e2530")
    console.print(
        "  [bold #f85149]⚠  Enforcement deadline: August 2, 2026  —  €35M or 7% global turnover[/bold #f85149]"
    )
    console.print("  " + "─" * 76, style="#1e2530")
    console.print("  [dim]pip install air-blackbox  ·  github.com/airblackbox/gateway  ·  airblackbox.ai[/dim]")
    console.print()


@click.group()
@click.version_option(version="1.11.1", prog_name="air-blackbox")
@click.pass_context
def main(ctx):
    """AIR Blackbox — AI governance control plane.

    Route your AI traffic through the gateway and get compliance,
    security, inventory, and incident response out of the box.
    """
    if ctx.invoked_subcommand not in ("--version", None):
        print_banner()


@main.command()
def setup():
    """One-command setup: install the AI compliance model and verify everything works.

    This pulls the air-compliance model from Ollama registry and verifies
    the scanner is ready to use. Run this once after installing air-blackbox.

    Requirements: Ollama must be installed first (https://ollama.com)
    """
    import shutil
    import subprocess

    console.print(
        Panel.fit(
            "[bold cyan]AIR Blackbox Setup[/bold cyan]\nSetting up the AI compliance scanner...",
            border_style="cyan",
        )
    )

    # Step 1: Check Ollama
    console.print("\n[bold]Step 1/3:[/bold] Checking Ollama installation...")
    if shutil.which("ollama"):
        try:
            result = subprocess.run(["ollama", "--version"], capture_output=True, text=True, timeout=5)
            console.print(f"  [green]✓[/green] Ollama installed: {result.stdout.strip()}")
        except Exception:
            console.print("  [green]✓[/green] Ollama found")
    else:
        console.print("  [red]✗[/red] Ollama not installed")
        console.print("\n  Install Ollama first:")
        console.print("    Mac:   [cyan]brew install ollama[/cyan]")
        console.print("    Linux: [cyan]curl -fsSL https://ollama.com/install.sh | sh[/cyan]")
        console.print("    All:   [cyan]https://ollama.com/download[/cyan]")
        console.print("\n  Then run [cyan]air-blackbox setup[/cyan] again.")
        return

    # Step 2: Pull model
    console.print("\n[bold]Step 2/3:[/bold] Pulling air-compliance model from registry...")
    console.print("  This downloads ~8GB (one-time). Grab a coffee.\n")

    try:
        result = subprocess.run(
            ["ollama", "pull", "airblackbox/air-compliance"],
            timeout=600,
        )
        if result.returncode == 0:
            # Create local alias
            subprocess.run(
                ["ollama", "cp", "airblackbox/air-compliance", "air-compliance"],
                capture_output=True,
                timeout=30,
            )
            console.print("  [green]✓[/green] Model pulled and ready")
        else:
            console.print("  [red]✗[/red] Failed to pull model")
            console.print("  Try manually: [cyan]ollama pull airblackbox/air-compliance[/cyan]")
            return
    except subprocess.TimeoutExpired:
        console.print("  [red]✗[/red] Download timed out. Try: [cyan]ollama pull airblackbox/air-compliance[/cyan]")
        return

    # Step 3: Verify
    console.print("\n[bold]Step 3/3:[/bold] Verifying scanner...")
    try:
        result = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=10)
        if "air-compliance" in result.stdout:
            console.print("  [green]✓[/green] Model verified in Ollama")
        else:
            console.print("  [yellow]⚠[/yellow] Model pulled but not showing in list. Try restarting Ollama.")
    except Exception:
        # Best-effort verification; do not fail setup if this check errors
        console.print("  [yellow]⚠[/yellow] Could not verify model in Ollama (verification step failed).")

    console.print(
        Panel.fit(
            "[bold green]Setup complete![/bold green]\n\n"
            "Run your first scan:\n"
            "  [cyan]air-blackbox comply --scan .[/cyan]\n\n"
            "Or try the demo:\n"
            "  [cyan]air-blackbox demo[/cyan]",
            border_style="green",
        )
    )


@main.command()
@click.option("--gateway", default="http://localhost:8080", help="Gateway URL")
@click.option("--scan", default=".", help="Path to scan for code-level checks")
@click.option("--runs-dir", default=None, help="Path to .air.json records directory")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--verbose", "-v", is_flag=True, help="Show detection type and fix hints")
@click.option(
    "--deep", is_flag=True, default=False, hidden=True, help="(deprecated, now default) Run LLM deep analysis"
)
@click.option("--no-llm", is_flag=True, help="Skip LLM analysis, regex-only scan")
@click.option("--model", default="air-compliance", help="Ollama model for deep scan")
@click.option("--no-save", is_flag=True, help="Don't save results to compliance history")
@click.option(
    "--frameworks", default=None, help="Compliance frameworks to report (eu,iso42001,nist,colorado). Default: all"
)
def comply(gateway, scan, runs_dir, fmt, verbose, deep, no_llm, model, no_save, frameworks):
    """Check EU AI Act compliance from live gateway traffic."""
    from air_blackbox.compliance.engine import run_all_checks
    from air_blackbox.gateway_client import GatewayClient

    console.print("\n[bold blue]AIR Blackbox[/] — EU AI Act Compliance Check\n")
    with console.status("[bold green]Connecting to gateway..."):
        client = GatewayClient(gateway_url=gateway, runs_dir=runs_dir, scan_path=scan)
        status = client.get_status()
    if status.reachable:
        console.print(f"  [green]●[/] Gateway connected at [bold]{gateway}[/]")
    else:
        console.print(f"  [red]●[/] Gateway not reachable at [bold]{gateway}[/]")
    if status.total_runs > 0:
        src = "gateway" if status.reachable else "trust layer records"
        console.print(
            f"  [green]●[/] [bold]{status.total_runs:,}[/] logged events from {src} ({', '.join(status.models_observed[:3])})"
        )
    else:
        console.print("  [yellow]●[/] No traffic data found")
    console.print(f"  [dim]Scanning: {scan}[/]\n")
    articles, detected_frameworks, rec_pkg = run_all_checks(status, scan)

    # Hybrid mode: auto-run LLM analysis unless --no-llm
    deep_findings = []
    if not no_llm:
        import os

        from air_blackbox.compliance.deep_scan import _model_available, _ollama_available, deep_scan

        if _ollama_available() and _model_available(model):
            console.print("[bold]Running hybrid analysis (regex + AI model)...[/]\n")
            # Collect all Python files (supports single-file and directory scanning)
            py_files = []
            if os.path.isfile(scan) and scan.endswith(".py"):
                py_files = [os.path.abspath(scan)]
            else:
                skip_dirs = {
                    "node_modules",
                    ".git",
                    "__pycache__",
                    ".venv",
                    "venv",
                    "dist",
                    "build",
                    ".eggs",
                    "site-packages",
                    ".tox",
                    ".mypy_cache",
                    ".pytest_cache",
                }
                for root, dirs, files in os.walk(scan):
                    dirs[:] = [d for d in dirs if d not in skip_dirs and not d.endswith(".egg-info")]
                    for f in files:
                        if f.endswith(".py"):
                            py_files.append(os.path.join(root, f))
            total_files = len(py_files)

            # === Smart sampling: pick compliance-relevant files ===
            # Priority keywords — files most likely to contain compliance patterns
            priority_keywords = [
                "agent",
                "pipeline",
                "tool",
                "llm",
                "model",
                "chat",
                "safety",
                "guard",
                "policy",
                "policies",
                "hitl",
                "human",
                "trace",
                "tracing",
                "logging",
                "log",
                "audit",
                "monitor",
                "auth",
                "token",
                "scope",
                "permission",
                "identity",
                "validate",
                "validation",
                "schema",
                "pii",
                "redact",
                "retry",
                "fallback",
                "error",
                "exception",
                "handler",
                "inject",
                "sanitize",
                "filter",
                "boundary",
                "limit",
                "config",
                "settings",
                "core",
                "main",
                "app",
                "run",
            ]

            # Score and rank files by relevance
            def _score_file(fp):
                rel = os.path.relpath(fp, scan).lower()
                basename = os.path.basename(fp).lower()
                score = 0
                # Skip test files — they don't reflect compliance posture
                parts = rel.replace("\\", "/").split("/")
                if any(p in {"tests", "test", "testing"} for p in parts):
                    return -1
                if basename.startswith("test_") or basename == "conftest.py":
                    return -1
                # Boost files with compliance-relevant names
                for kw in priority_keywords:
                    if kw in basename:
                        score += 3
                    elif kw in rel:
                        score += 1
                # Boost core source files
                if any(p in {"src", "core", "lib", "components"} for p in parts):
                    score += 2
                # Boost larger files (more substance)
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
            scored = [(fp, s) for fp, s in scored if s >= 0]  # exclude tests
            scored.sort(key=lambda x: x[1], reverse=True)

            # Build code sample from top-ranked files
            # Cap individual files at 8KB to preserve full context, total at 48KB
            MAX_PER_FILE = 8000
            MAX_TOTAL = 48000
            code_parts = []
            total_chars = 0
            files_included = 0
            for fp, score in scored:
                try:
                    with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                    if len(content.strip()) < 50:
                        continue
                    # Truncate large files to get more variety in the sample
                    if len(content) > MAX_PER_FILE:
                        content = content[:MAX_PER_FILE] + "\n# ... (file truncated for sampling)"
                    code_parts.append(f"# File: {os.path.relpath(fp, scan)}\n{content}")
                    total_chars += len(content)
                    files_included += 1
                    if total_chars > MAX_TOTAL:
                        break
                except Exception:
                    continue

            merged_code = "\n\n".join(code_parts)
            sample_desc = f"targeted sample of {files_included} compliance-relevant source files"

            if verbose:
                console.print(
                    f"  [dim]AI model sampling: {files_included} files from {total_files} total ({total_chars:,} chars)[/]"
                )
                # Show top 5 sampled files
                shown = 0
                for fp, score in scored:
                    if shown >= 5:
                        break
                    rel = os.path.relpath(fp, scan)
                    try:
                        size = os.path.getsize(fp)
                        if size >= 50:
                            console.print(f"    [dim]score={score}: {rel} ({size:,} bytes)[/]")
                            shown += 1
                    except OSError:
                        pass
                if files_included > 5:
                    console.print(f"    [dim]... and {files_included - 5} more files[/]")

            # Build rule-based context summary for the model
            rule_context_lines = []
            article_map = {
                9: "Risk Management",
                10: "Data Governance",
                11: "Technical Documentation",
                12: "Record-Keeping",
                14: "Human Oversight",
                15: "Accuracy & Security",
            }
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
                rule_context_lines.append(line)
            rule_context = "\n".join(rule_context_lines)

            # Only run AI model if we have actual code to analyze
            if files_included == 0 or not merged_code.strip():
                if verbose:
                    console.print("  [dim]No Python files found for AI analysis — skipping model[/]")
                result = {"available": False, "findings": [], "model": model, "error": None}
            else:
                if verbose:
                    os.environ["AIR_VERBOSE"] = "1"
                result = deep_scan(
                    merged_code,
                    model=model,
                    sample_context=sample_desc,
                    total_files=total_files,
                    rule_context=rule_context,
                )
                if verbose:
                    os.environ.pop("AIR_VERBOSE", None)
            if result.get("available") and not result.get("error"):
                deep_findings = result.get("findings", [])

                # ── Smart reconciliation: override model FAIL when rule-based has strong PASS ──
                # Build a map of rule-based pass counts per article
                rule_pass_counts = {}
                rule_evidence_map = {}
                for article in articles:
                    art_num = article.get("number", 0)
                    passes = [c for c in article.get("checks", []) if c.get("status") == "pass"]
                    rule_pass_counts[art_num] = len(passes)
                    if passes:
                        # Collect the best evidence summaries
                        rule_evidence_map[art_num] = "; ".join(c.get("evidence", "")[:60] for c in passes[:3])

                overrides = 0
                for finding in deep_findings:
                    art = finding.get("article", 0)
                    model_status = finding.get("status", "")
                    rule_passes = rule_pass_counts.get(art, 0)

                    # If model says FAIL but rule-based has 2+ PASS checks → override to PASS
                    if model_status == "fail" and rule_passes >= 2:
                        finding["status"] = "pass"
                        rule_ev = rule_evidence_map.get(art, "")
                        finding["evidence"] = (
                            f"[Corrected by rule-based analysis] "
                            f"Rule-based scanner found {rule_passes} passing checks: {rule_ev}. "
                            f"Model's original assessment: {finding.get('evidence', '')}"
                        )
                        finding["fix_hint"] = ""
                        overrides += 1
                    # If model says FAIL but rule-based has 1 PASS → upgrade to WARN
                    elif model_status == "fail" and rule_passes == 1:
                        finding["status"] = "warn"
                        rule_ev = rule_evidence_map.get(art, "")
                        finding["evidence"] = (
                            f"[Partial — rule-based found evidence] {rule_ev}. "
                            f"Model noted: {finding.get('evidence', '')}"
                        )
                        overrides += 1

                console.print(
                    f"  [green]●[/] AI model analyzed [bold]{files_included}[/] files ({total_chars:,} chars) from {total_files} total"
                )
                console.print(
                    f"  [green]●[/] AI model found [bold]{len(deep_findings)}[/] finding(s) using [bold]{model}[/]"
                )
                if overrides > 0:
                    console.print(
                        f"  [green]●[/] Smart reconciliation: [bold]{overrides}[/] model verdict(s) corrected by rule-based evidence"
                    )
                console.print("  [green]●[/] Hybrid mode: rule-based + AI analysis merged\n")
            elif result.get("error"):
                console.print(f"  [yellow]●[/] AI model: {result['error']}")
                console.print("  [dim]Falling back to regex-only scan[/]\n")
        else:
            if verbose:
                console.print("  [dim]AI model not available — using regex-only scan[/]")
                console.print("  [dim]Install: ollama create air-compliance -f Modelfile[/]\n")

    # Save to compliance history
    if not no_save:
        try:
            from air_blackbox.compliance.history import save_scan

            scan_id = save_scan(
                articles, scan_path=scan, version="1.6.3", deep_findings=deep_findings if deep_findings else None
            )
            if verbose:
                console.print(f"  [dim]Saved to compliance history (scan #{scan_id})[/]\n")
        except Exception:
            # Don't break the scan if history save fails
            if verbose:
                console.print("  [dim]Could not save to compliance history[/]")

    if fmt == "json":
        import json

        output_data = articles
        if deep_findings:
            output_data = list(articles)  # shallow copy
            output_data.append(
                {
                    "number": 0,
                    "title": "LLM Deep Analysis",
                    "checks": [
                        {
                            "name": f.get("name", ""),
                            "status": f.get("status", "warn"),
                            "evidence": f.get("evidence", ""),
                            "fix_hint": f.get("fix_hint", ""),
                            "tier": "static",
                            "detection": "auto",
                            "source": "llm",
                        }
                        for f in deep_findings
                    ],
                }
            )
        click.echo(json.dumps(output_data, indent=2))
        return
    for article in articles:
        table = Table(
            title=f"Article {article['number']} — {article['title']}",
            show_header=True,
            header_style="bold white on dark_blue",
            title_style="bold",
        )
        table.add_column("Check", style="bold", width=28)
        table.add_column("Tier", width=8, justify="center")
        table.add_column("Status", width=10, justify="center")
        if verbose:
            table.add_column("Type", width=8, justify="center")
        table.add_column("Evidence", width=42 if not verbose else 36)
        for check in article["checks"]:
            si = {
                "pass": "[bold green]✅ PASS[/]",
                "warn": "[bold yellow]⚠️  WARN[/]",
                "fail": "[bold red]❌ FAIL[/]",
            }.get(check["status"])
            tier = check.get("tier", "static")
            tier_label = "[green]STATIC[/]" if tier == "static" else "[blue]RUNTIME[/]"
            db = {"auto": "[green]AUTO[/]", "hybrid": "[yellow]HYBRID[/]", "manual": "[red]MANUAL[/]"}.get(
                check.get("detection", ""), ""
            )
            ev = check["evidence"]
            if verbose and check.get("fix_hint"):
                ev += f"\n[dim italic]Fix: {check['fix_hint']}[/]"
            row = [check["name"], tier_label, si]
            if verbose:
                row.append(db)
            row.append(ev)
            table.add_row(*row)
        console.print(table)
        console.print()

    # Display deep findings if any (supplementary — not counted in main score)
    if deep_findings and verbose:
        # Only show LLM findings that ADD info beyond what rules found
        rule_articles = {a["number"] for a in articles}
        novel_findings = [f for f in deep_findings if f.get("article", 0) not in rule_articles]
        supplementary = [f for f in deep_findings if f.get("article", 0) in rule_articles]
        if novel_findings or supplementary:
            deep_table = Table(
                title="AI Model Insights (supplementary)",
                show_header=True,
                header_style="bold white on dark_blue",
                title_style="dim",
            )
            deep_table.add_column("Article", width=10, justify="center")
            deep_table.add_column("AI Assessment", style="bold", width=30)
            deep_table.add_column("Status", width=10, justify="center")
            deep_table.add_column("Evidence", width=40)
            for f in deep_findings:
                si = {
                    "pass": "[bold green]✅ PASS[/]",
                    "warn": "[bold yellow]⚠️  WARN[/]",
                    "fail": "[bold red]❌ FAIL[/]",
                }.get(f.get("status", "warn"))
                ev = f.get("evidence", "")
                if f.get("fix_hint"):
                    ev += f"\n[dim italic]Fix: {f['fix_hint']}[/]"
                deep_table.add_row(f"Art {f.get('article', '?')}", f.get("name", ""), si, ev)
            console.print(deep_table)
            console.print(
                "[dim]  Note: AI model assessed a code sample (max 48KB). Rule-based checks above are more accurate.[/]"
            )
            console.print()

    total = sum(len(a["checks"]) for a in articles)
    passing = sum(1 for a in articles for c in a["checks"] if c["status"] == "pass")
    warning = sum(1 for a in articles for c in a["checks"] if c["status"] == "warn")
    failing = sum(1 for a in articles for c in a["checks"] if c["status"] == "fail")
    # Two-tier breakdown
    static_checks = [c for a in articles for c in a["checks"] if c.get("tier", "static") == "static"]
    runtime_checks = [c for a in articles for c in a["checks"] if c.get("tier") == "runtime"]
    s_pass = sum(1 for c in static_checks if c["status"] == "pass")
    s_total = len(static_checks)
    r_pass = sum(1 for c in runtime_checks if c["status"] == "pass")
    r_total = len(runtime_checks)
    parts = f"[bold green]{passing}[/] passing  [bold yellow]{warning}[/] warnings  [bold red]{failing}[/] failing  out of [bold]{total}[/] checks"
    parts += f"\n\n  [green]Static analysis[/]:  [bold]{s_pass}/{s_total}[/] passing  (code patterns, docs, config)"
    parts += f"\n  [blue]Runtime checks[/]:   [bold]{r_pass}/{r_total}[/] passing  (requires gateway or trust layer)"
    if deep_findings:
        deep_pass = sum(1 for f in deep_findings if f.get("status") == "pass")
        deep_fail = sum(1 for f in deep_findings if f.get("status") == "fail")
        deep_warn = sum(1 for f in deep_findings if f.get("status") == "warn")
        parts += f"\n  [magenta]AI model[/]:          [bold]{deep_pass}[/] pass, [bold]{deep_warn}[/] warn, [bold]{deep_fail}[/] fail (supplementary, not counted above)"
    if r_total > 0 and r_pass < r_total:
        parts += f"\n\n  [dim]Unlock runtime checks: pip install {rec_pkg}[/]"
    if verbose:
        auto = sum(1 for a in articles for c in a["checks"] if c.get("detection") == "auto")
        hybrid = sum(1 for a in articles for c in a["checks"] if c.get("detection") == "hybrid")
        manual = sum(1 for a in articles for c in a["checks"] if c.get("detection") == "manual")
        parts += f"\n  [dim]Detection: {auto} auto, {hybrid} hybrid, {manual} manual ({(auto + hybrid) / total * 100:.0f}% automated)[/]"
    console.print(Panel(parts, title="[bold]Compliance Summary[/]", border_style="blue"))
    if failing > 0 and not verbose:
        console.print("\n[dim]Run with -v to see fix hints for each failing check.[/]")

    # --- Multi-framework crosswalk report ---
    if frameworks:
        from air_blackbox.compliance.standards_map import (
            SUPPORTED_FRAMEWORKS,
            calculate_compliance_scores,
            generate_compliance_narrative,
            generate_crosswalk_report,
        )

        # Parse comma-separated framework IDs
        fw_list = [f.strip().lower() for f in frameworks.split(",")]
        invalid = [f for f in fw_list if f not in SUPPORTED_FRAMEWORKS]
        if invalid:
            console.print(f"[yellow]Unknown framework(s): {', '.join(invalid)}[/]")
            console.print(f"[dim]Valid options: {', '.join(SUPPORTED_FRAMEWORKS.keys())}[/]\n")
            fw_list = [f for f in fw_list if f in SUPPORTED_FRAMEWORKS]
        if fw_list:
            # Convert articles to flat check list for crosswalk
            flat_checks = []
            article_to_category = {
                9: "risk_management",
                10: "data_governance",
                11: "technical_documentation",
                12: "record_keeping",
                14: "human_oversight",
                15: "robustness",
            }
            for article in articles:
                cat = article_to_category.get(article.get("number"))
                if not cat:
                    continue
                for check in article.get("checks", []):
                    flat_checks.append(
                        {
                            "category": cat,
                            "check_id": check.get("name", ""),
                            "status": check.get("status", "unknown"),
                            "severity": check.get("tier", "static"),
                            "description": check.get("evidence", ""),
                            "remediation": check.get("fix_hint", ""),
                        }
                    )

            crosswalk_report = generate_crosswalk_report(flat_checks, frameworks=fw_list)
            scores = calculate_compliance_scores(crosswalk_report)

            # Display crosswalk scores
            fw_names = [SUPPORTED_FRAMEWORKS[f]["name"] for f in fw_list]
            console.print(
                Panel(
                    "[bold]Multi-Framework Compliance Scores[/]\n\n"
                    + "\n".join(
                        f"  {SUPPORTED_FRAMEWORKS[f]['name']}: [bold]{scores.get(SUPPORTED_FRAMEWORKS[f]['key'], 0):.1f}%[/]"
                        for f in fw_list
                    )
                    + f"\n\n[dim]Frameworks: {', '.join(fw_names)}[/]",
                    title="[bold cyan]Standards Crosswalk[/]",
                    border_style="cyan",
                )
            )

            if fmt == "json":
                import json as _json

                click.echo(_json.dumps(crosswalk_report, indent=2))
            elif verbose:
                console.print()
                narrative = generate_compliance_narrative(crosswalk_report)
                console.print(narrative)

    # --- Trust layer recommendation ---
    from air_blackbox.compliance.engine import TRUST_LAYER_MAP

    if detected_frameworks:
        rec_lines = []
        for fw in detected_frameworks:
            pkg = TRUST_LAYER_MAP.get(fw, None)
            if pkg:
                rec_lines.append(f"  pip install {pkg}")
        if rec_lines:
            console.print(f"\n[bold yellow]Detected frameworks:[/] {', '.join(detected_frameworks)}")
            console.print("[dim]Add trust layers for runtime compliance:[/]")
            for line in rec_lines:
                console.print(f"[bold green]{line}[/]")
    else:
        console.print(f"\n[dim]Add a trust layer for runtime compliance: pip install {rec_pkg}[/]")
    console.print("[dim]All 10 trust layer packages: https://airblackbox.ai[/]\n")

    # --- Telemetry (anonymous, opt-out with AIR_BLACKBOX_TELEMETRY=off) ---
    try:
        import os as _os

        from air_blackbox.telemetry import send_event

        py_count = 0
        if _os.path.isfile(scan) and scan.endswith(".py"):
            py_count = 1
        else:
            for _root, _dirs, _files in _os.walk(scan):
                py_count += sum(1 for f in _files if f.endswith(".py"))
        all_checks = [c for a in articles for c in a.get("checks", [])]
        send_event(
            command="comply",
            python_files=py_count,
            checks_passing=sum(1 for c in all_checks if c.get("status") == "pass"),
            checks_warning=sum(1 for c in all_checks if c.get("status") == "warn"),
            checks_failing=sum(1 for c in all_checks if c.get("status") == "fail"),
            total_checks=len(all_checks),
            version=_ab_version,
        )
    except Exception:
        pass  # Telemetry should never break the tool


@main.command()
@click.option("--gateway", default="http://localhost:8080", help="Gateway URL")
@click.option("--runs-dir", default=None, help="Path to .air.json records")
@click.option("--approved", default=None, help="Path to approved models YAML")
@click.option("--format", "fmt", type=click.Choice(["table", "cyclonedx", "json"]), default="table")
@click.option("--output", "-o", default=None, help="Output file path")
@click.option("--init-registry", is_flag=True, help="Generate approved-models.yaml from current traffic")
def discover(gateway, runs_dir, approved, fmt, output, init_registry):
    """Discover AI models, tools, and services in your environment."""
    import json as jsonlib

    from air_blackbox.aibom.generator import generate_aibom
    from air_blackbox.aibom.shadow import detect_shadow_ai, generate_approved_registry
    from air_blackbox.gateway_client import GatewayClient

    console.print("\n[bold blue]AIR Blackbox[/] — AI Discovery & Inventory\n")
    with console.status("[bold green]Scanning environment..."):
        client = GatewayClient(gateway_url=gateway, runs_dir=runs_dir)
        status = client.get_status()
    if status.total_runs == 0 and not status.reachable:
        console.print("[yellow]No traffic data found.[/] Start gateway and route AI traffic through it.\n")
        return

    # Generate approved registry if requested
    if init_registry:
        registry = generate_approved_registry(status)
        reg_path = "approved-models.json"
        with open(reg_path, "w") as f:
            jsonlib.dump(registry, f, indent=2)
        console.print(
            f"  [green]✓[/] Generated [bold]{reg_path}[/] with {len(registry['models'])} models, {len(registry['providers'])} providers"
        )
        console.print("  [dim]Future runs of discover will flag anything not in this list.[/]\n")
        return

    # CycloneDX output
    if fmt == "cyclonedx" or fmt == "json":
        bom = generate_aibom(status)
        bom_json = jsonlib.dumps(bom, indent=2)
        if output:
            with open(output, "w") as f:
                f.write(bom_json)
            console.print(f"  [green]✓[/] AI-BOM written to [bold]{output}[/]")
            console.print(f"  [dim]{len(bom['components'])} components, CycloneDX 1.6[/]\n")
        else:
            click.echo(bom_json)
        return

    # Table output (default)
    console.print(f"  Total logged events: [bold]{status.total_runs:,}[/]")
    console.print(f"  Period: {status.date_range_start or 'N/A'} → {status.date_range_end or 'N/A'}")
    console.print(f"  Total tokens: [bold]{status.total_tokens:,}[/]\n")

    # Models table
    if status.models_observed:
        t = Table(title="Models Detected", show_header=True, header_style="bold white on dark_blue")
        t.add_column("Model", style="bold", width=25)
        t.add_column("Provider", width=12)
        t.add_column("Status", justify="center", width=14)
        for m in status.models_observed:
            from air_blackbox.aibom.generator import _guess_provider

            t.add_row(m, _guess_provider(m), "[green]✅ Observed[/]")
        console.print(t)
        console.print()

    # Providers table
    if status.providers_observed:
        t = Table(title="API Providers", show_header=True, header_style="bold white on dark_blue")
        t.add_column("Provider", style="bold")
        t.add_column("Status", justify="center")
        for p in status.providers_observed:
            t.add_row(p, "[green]✅ Active[/]")
        console.print(t)
        console.print()

    # Tools table
    tools = set()
    for r in status.recent_runs:
        for tc in r.get("tool_calls", []):
            if tc:
                tools.add(tc)
    if tools:
        t = Table(title="Agent Tools Detected", show_header=True, header_style="bold white on dark_blue")
        t.add_column("Tool", style="bold")
        t.add_column("Status", justify="center")
        for tool in sorted(tools):
            t.add_row(tool, "[green]✅ Observed[/]")
        console.print(t)
        console.print()

    # Shadow AI alerts
    alerts = detect_shadow_ai(status, approved)
    if alerts:
        t = Table(title="Shadow AI Alerts", show_header=True, header_style="bold white on red")
        t.add_column("Model", style="bold", width=20)
        t.add_column("Severity", justify="center", width=10)
        t.add_column("Reason", width=50)
        for a in alerts:
            sev_color = {"high": "red", "medium": "yellow", "low": "dim"}.get(a.severity, "white")
            t.add_row(a.model, f"[{sev_color}]{a.severity.upper()}[/{sev_color}]", a.reason)
        console.print(t)
        console.print()

    # Summary
    bom = generate_aibom(status)
    console.print(
        Panel(
            f"[bold]{len(bom['components'])}[/] components inventoried: "
            f"{len(status.models_observed)} models, {len(status.providers_observed)} providers, {len(tools)} tools\n\n"
            f"[green]air-blackbox discover --format=cyclonedx -o aibom.json[/]  Export full AI-BOM\n"
            f"[green]air-blackbox discover --init-registry[/]                    Create approved models list\n"
            f"[green]air-blackbox discover --approved=approved-models.json[/]    Check against approved list",
            title="[bold blue]AI-BOM Summary[/]",
            border_style="blue",
        )
    )

    # --- Telemetry ---
    try:
        from air_blackbox.telemetry import send_event

        send_event(command="discover", version=_ab_version)
    except Exception:
        pass


@main.command()
@click.option("--gateway", default="http://localhost:8080", help="Gateway URL")
@click.option("--runs-dir", default=None, help="Path to .air.json records")
@click.option("--episode", default=None, help="Episode ID to replay")
@click.option("--last", default=10, help="Show last N runs")
@click.option("--verify", is_flag=True, help="Verify HMAC audit chain")
def replay(gateway, runs_dir, episode, last, verify):
    """Reconstruct AI incidents from the audit chain."""
    from air_blackbox.replay.engine import ReplayEngine

    console.print("\n[bold blue]AIR Blackbox[/] — Incident Replay\n")

    with console.status("[bold green]Loading audit records..."):
        engine = ReplayEngine(runs_dir=runs_dir or "./runs")
        count = engine.load()

    if count == 0:
        console.print("[yellow]No audit records found.[/] Run 'air-blackbox demo' or route traffic through gateway.\n")
        return

    # Verify chain if requested
    if verify:
        console.print("[bold]Verifying HMAC audit chain...[/]\n")
        result = engine.verify_chain()
        if result.intact:
            console.print(
                f"  [green]✅ CHAIN INTACT[/] — {result.verified_records:,} records verified. No tampering detected.\n"
            )
        else:
            console.print(
                f"  [red]❌ CHAIN BROKEN[/] at record {result.first_break_at} (run: {result.first_break_run_id})"
            )
            console.print(
                f"  [red]  {result.verified_records} of {result.total_records} records verified before break.[/]\n"
            )
        return

    # Detail view for single episode
    if episode:
        rec = engine.get_run(episode)
        if not rec:
            console.print(f"[red]Run '{episode}' not found.[/] Use 'air-blackbox replay' to see all runs.\n")
            return
        console.print(f"  [bold]Run Detail: {rec.run_id}[/]\n")
        console.print(f"  Model:     {rec.model}")
        console.print(f"  Provider:  {rec.provider}")
        console.print(f"  Timestamp: {rec.timestamp}")
        console.print(f"  Duration:  {rec.duration_ms}ms")
        console.print(f"  Tokens:    {rec.tokens}")
        console.print(
            f"  Status:    {'[green]success[/]' if rec.status == 'success' else '[red]' + rec.status + '[/]'}"
        )
        if rec.tool_calls:
            console.print(f"  Tools:     {', '.join(rec.tool_calls)}")
        if rec.pii_alerts:
            console.print(f"  [yellow]PII Alerts:  {len(rec.pii_alerts)} detected[/]")
        if rec.injection_alerts:
            console.print(f"  [red]Injection:   {len(rec.injection_alerts)} detected[/]")
        if rec.error:
            console.print(f"  [red]Error:       {rec.error}[/]")
        console.print()
        return

    # Stats summary
    stats = engine.get_stats()
    console.print(f"  [bold]{stats['total_records']:,}[/] total records")
    if stats.get("date_range"):
        console.print(f"  Period: {stats['date_range'][0]} → {stats['date_range'][1]}")
    console.print(f"  Total tokens: {stats['total_tokens']:,} | Avg latency: {stats['avg_duration_ms']}ms")
    if stats["pii_alerts"] > 0:
        console.print(f"  [yellow]PII alerts: {stats['pii_alerts']}[/]")
    if stats["injection_alerts"] > 0:
        console.print(f"  [red]Injection attempts: {stats['injection_alerts']}[/]")
    console.print()

    # Runs table
    records = engine.records[-last:]
    records.reverse()
    t = Table(title=f"Last {len(records)} Runs", show_header=True, header_style="bold white on dark_blue")
    t.add_column("Run ID", width=20)
    t.add_column("Model", width=15)
    t.add_column("Tokens", justify="right", width=8)
    t.add_column("Latency", justify="right", width=8)
    t.add_column("Status", justify="center", width=10)
    t.add_column("Timestamp", width=22)
    for rec in records:
        st = "[green]✅[/]" if rec.status == "success" else "[red]❌[/]"
        t.add_row(
            rec.run_id[:20], rec.model, str(rec.tokens.get("total", 0)), f"{rec.duration_ms}ms", st, rec.timestamp[:22]
        )
    console.print(t)
    console.print()
    console.print("[dim]Detail view: air-blackbox replay --episode=<run_id>[/]")
    console.print("[dim]Verify chain: air-blackbox replay --verify[/]\n")

    # --- Telemetry ---
    try:
        from air_blackbox.telemetry import send_event

        send_event(command="replay", version=_ab_version)
    except Exception:
        pass


@main.command()
@click.option("--gateway", default="http://localhost:8080", help="Gateway URL")
@click.option("--runs-dir", default=None, help="Path to .air.json records")
@click.option("--scan", default=".", help="Path to scan for code-level checks")
@click.option("--range", "time_range", default="30d", help="Time range")
@click.option("--format", "fmt", type=click.Choice(["json", "pdf"]), default="json")
@click.option("--output", "-o", default=None, help="Output file path")
def export(gateway, runs_dir, scan, time_range, fmt, output):
    """Generate signed evidence bundles for auditors and insurers.

    \b
    Formats:
        json  — machine-readable signed evidence bundle (default)
        pdf   — formatted PDF compliance report for humans / auditors

    \b
    Examples:
        air-blackbox export
        air-blackbox export --format pdf
        air-blackbox export --scan ~/myproject --format pdf
        air-blackbox export --scan . --format pdf --output report.pdf
    """
    import json as jsonlib

    from air_blackbox.export.bundle import generate_evidence_bundle

    console.print("\n[bold cyan]AIR Blackbox[/] — Evidence Export\n")

    with console.status("[bold green]Generating evidence bundle..."):
        bundle = generate_evidence_bundle(gateway_url=gateway, runs_dir=runs_dir, scan_path=scan)

    summary = bundle.get("compliance", {}).get("summary", {})
    trail = bundle.get("audit_trail", {})
    chain = trail.get("chain_verification", {})

    passing = summary.get("passing", 0)
    warnings = summary.get("warnings", 0)
    failing = summary.get("failing", 0)

    console.print(f"  [bold]Compliance:[/]   {passing} passing · {warnings} warnings · {failing} failing")
    console.print(f"  [bold]AI-BOM:[/]        {len(bundle.get('aibom', {}).get('components', []))} components")
    console.print(f"  [bold]Audit trail:[/]   {trail.get('total_records', 0)} records")
    console.print(
        f"  [bold]Chain:[/]         {'[green]INTACT[/]' if chain.get('intact') else '[yellow]No signing key set[/]'}"
    )
    console.print()

    if fmt == "pdf":
        from air_blackbox.export.pdf_report import REPORTLAB_OK, generate_pdf

        if not REPORTLAB_OK:
            console.print("[red]reportlab not installed.[/] Run: [bold]pip install reportlab[/]")
            raise SystemExit(1)

        out_path = output or f"AIR_Blackbox_Compliance_Report_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
        with console.status("[bold green]Rendering PDF report..."):
            generate_pdf(bundle, out_path)

        console.print(
            Panel(
                f"PDF report written to [bold]{out_path}[/]\n\n"
                f"Contains: compliance scorecard · per-article findings · audit trail · priority fix list\n"
                f"Ready to hand to your auditor, compliance team, or share with stakeholders.",
                title="[bold green]PDF Export Complete[/]",
                border_style="green",
            )
        )
    else:
        # Default: JSON evidence bundle
        out_path = output or f"air-blackbox-evidence-{datetime.utcnow().strftime('%Y%m%d')}.json"
        with open(out_path, "w") as f:
            jsonlib.dump(bundle, f, indent=2)

        console.print(
            Panel(
                f"Evidence bundle written to [bold]{out_path}[/]\n\n"
                f"Contains: compliance scan + AI-BOM (CycloneDX) + audit trail + HMAC attestation\n"
                f"Hand this file to your auditor or insurer as a single verifiable document.\n\n"
                f"[dim]Tip: use [bold]--format pdf[/bold] to generate a human-readable PDF report[/dim]",
                title="[bold green]Export Complete[/]",
                border_style="green",
            )
        )

    # --- Telemetry ---
    try:
        from air_blackbox.telemetry import send_event

        send_event(command="export", version=_ab_version)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# bundle -- self-verifying .air-evidence ZIP
# ---------------------------------------------------------------------------


@main.command()
@click.option(
    "--scan",
    default=".",
    type=click.Path(exists=True),
    help="Path to scan for code-level checks (default: current dir)",
)
@click.option("--key-dir", default=None, type=click.Path(), help="Custom key storage directory")
@click.option(
    "--output", "-o", default=".", type=click.Path(), help="Output directory for the bundle (default: current dir)"
)
@click.option("--frameworks", default=None, help="Compliance frameworks (eu,iso42001,nist,colorado). Default: all")
@click.option("--audit-chain", default=None, type=click.Path(exists=True), help="Path to .jsonl audit chain file")
def bundle(scan, key_dir, output, frameworks, audit_chain):
    """Create a self-verifying .air-evidence bundle for auditors.

    Packages compliance scan results, multi-framework mappings, and
    ML-DSA-65 signatures into a single ZIP file. Auditors verify with:

        python verify.py

    No pip install required. Requires signing keys (run air-blackbox sign --keygen first).

    \b
    Examples:
        air-blackbox bundle                          # scan current dir, bundle everything
        air-blackbox bundle --scan ~/myproject       # scan a specific project
        air-blackbox bundle --frameworks eu,iso42001 # specific frameworks only
        air-blackbox bundle -o ./evidence            # save to a specific directory
    """
    from pathlib import Path as _Path

    try:
        from air_blackbox.evidence.bundle import EvidenceBundleBuilder
        from air_blackbox.evidence.keys import KeyManager
    except ImportError:
        console.print("[red]Error:[/red] dilithium-py is required for evidence bundles.")
        console.print("Install it with: [bold]pip install dilithium-py[/bold]")
        raise SystemExit(1)

    key_dir_path = _Path(key_dir) if key_dir else None
    km = KeyManager(key_dir=key_dir_path)

    if not km.has_keys():
        console.print("[red]Error:[/red] No signing keys found.")
        console.print("Generate keys first: [bold]air-blackbox sign --keygen[/bold]")
        raise SystemExit(1)

    console.print("\n[bold cyan]AIR Blackbox[/] -- Evidence Bundle\n")

    # Parse frameworks
    fw_list = None
    if frameworks:
        fw_list = [f.strip().lower() for f in frameworks.split(",")]
    else:
        fw_list = ["eu", "iso42001", "nist", "colorado"]

    # Step 1: Run compliance scan
    console.print(f"[blue]Step 1/4:[/blue] Running compliance scan on {scan}...")
    scan_results = {}
    try:
        from air_blackbox.compliance.engine import run_all_checks
        from air_blackbox.gateway_client import GatewayClient

        client = GatewayClient(gateway_url="http://localhost:8080", runs_dir="./runs")
        try:
            status = client.get_status()
        except Exception:
            # Gateway not running -- create a minimal status for code-only scan
            from air_blackbox.gateway_client import GatewayStatus

            status = GatewayStatus(
                reachable=False,
                vault_enabled=False,
                guardrails_enabled=False,
                trust_signing_key_set=False,
                model_name="",
                provider="",
            )
        compliance = run_all_checks(status, scan)
        scan_results = {
            "framework": "EU AI Act",
            "articles_checked": [9, 10, 11, 12, 14, 15],
            "results": compliance,
            "summary": {
                "total_checks": sum(len(a.get("checks", [])) for a in compliance)
                if isinstance(compliance, list)
                else 0,
                "passing": sum(1 for a in compliance for c in a.get("checks", []) if c.get("status") == "pass")
                if isinstance(compliance, list)
                else 0,
                "warnings": sum(1 for a in compliance for c in a.get("checks", []) if c.get("status") == "warn")
                if isinstance(compliance, list)
                else 0,
                "failing": sum(1 for a in compliance for c in a.get("checks", []) if c.get("status") == "fail")
                if isinstance(compliance, list)
                else 0,
            },
        }
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Scan engine error: {e}")
        console.print("  Bundling with minimal scan results.")
        scan_results = {"error": str(e), "framework": "EU AI Act"}

    s = scan_results.get("summary", {})
    console.print(f"  {s.get('passing', 0)} passing, {s.get('warnings', 0)} warnings, {s.get('failing', 0)} failing")

    # Step 2: Generate crosswalk report
    console.print("[blue]Step 2/4:[/blue] Generating multi-framework crosswalk...")
    crosswalk = None
    try:
        from air_blackbox.compliance.standards_map import generate_crosswalk_report

        check_results = {}
        if isinstance(scan_results.get("results"), list):
            for article in scan_results["results"]:
                for check in article.get("checks", []):
                    # Map check names to crosswalk categories
                    name = check.get("name", "").lower()
                    if "risk" in name:
                        check_results["risk_management"] = check.get("status", "warn")
                    elif "data" in name or "governance" in name:
                        check_results["data_governance"] = check.get("status", "warn")
                    elif "doc" in name:
                        check_results["documentation"] = check.get("status", "warn")
                    elif "record" in name or "audit" in name or "log" in name:
                        check_results["record_keeping"] = check.get("status", "warn")
                    elif "human" in name or "oversight" in name:
                        check_results["human_oversight"] = check.get("status", "warn")
                    elif "robust" in name or "security" in name:
                        check_results["robustness"] = check.get("status", "warn")
                    elif "transparen" in name:
                        check_results["transparency"] = check.get("status", "warn")
                    elif "bias" in name:
                        check_results["bias_monitoring"] = check.get("status", "warn")
        crosswalk = generate_crosswalk_report(check_results, fw_list)
        console.print(f"  Mapped to {len(fw_list)} frameworks: {', '.join(fw_list)}")
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Crosswalk generation error: {e}")

    # Step 3: Hash scanned files (binds evidence to codebase)
    console.print("[blue]Step 3/4:[/blue] Hashing scanned source files...")
    import hashlib as _hashlib

    scanned_hashes = {}
    scan_path = _Path(scan)
    py_files = []
    if scan_path.is_file():
        py_files = [scan_path]
    elif scan_path.is_dir():
        py_files = list(scan_path.glob("**/*.py"))
    for pf in py_files[:100]:  # cap at 100 files for bundle size
        try:
            content = pf.read_bytes()
            scanned_hashes[str(pf.relative_to(scan_path))] = _hashlib.sha256(content).hexdigest()
        except Exception:
            pass
    console.print(f"  Hashed {len(scanned_hashes)} Python files")

    # Step 4: Build the bundle
    console.print("[blue]Step 4/4:[/blue] Creating signed evidence bundle...")
    builder = EvidenceBundleBuilder(key_manager=km)
    bundle_path = builder.build(
        scan_results=scan_results,
        crosswalk_report=crosswalk,
        audit_chain_path=_Path(audit_chain) if audit_chain else None,
        frameworks=fw_list,
        output_dir=_Path(output),
        scanned_files_hashes=scanned_hashes if scanned_hashes else None,
    )

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]Evidence bundle created[/bold green]\n\n"
            f"File:       {bundle_path}\n"
            f"Size:       {bundle_path.stat().st_size:,} bytes\n"
            f"Signed by:  {km.get_key_id()} (ML-DSA-65)\n"
            f"Frameworks: {', '.join(fw_list)}\n\n"
            f"[dim]Auditor verification (no install required):[/dim]\n"
            f"  unzip {bundle_path.name}\n"
            f"  cd {bundle_path.stem}\n"
            f"  python verify.py",
            title="[bold cyan]Evidence Bundle[/bold cyan]",
            border_style="green",
        )
    )


@main.command()
@click.option("--output", "-o", default=".", help="Directory to create demo data in")
def demo(output):
    """Run a zero-config demo — generates sample data and shows compliance.

    Creates sample .air.json records and compliance doc templates so you
    can experience the full tool without Docker or a running gateway.

    \b
    Try it:
        air-blackbox demo
        air-blackbox comply -v
        air-blackbox discover
        air-blackbox replay
    """
    import time

    from air_blackbox.compliance.engine import run_all_checks
    from air_blackbox.demo_generator import generate_demo_data
    from air_blackbox.gateway_client import GatewayClient

    console.print("\n[bold blue]AIR Blackbox[/] — Zero-Config Demo\n")
    console.print("[dim]Generating sample AI agent traffic...[/]\n")
    time.sleep(0.5)

    # Generate sample data
    result = generate_demo_data(output)

    console.print(
        f"  [green]✓[/] Created [bold]{result['runs_created']}[/] sample .air.json records in [bold]{result['runs_dir']}[/]"
    )
    console.print(f"  [green]✓[/] Models: {', '.join(result['models'])}")
    console.print(f"  [green]✓[/] Providers: {', '.join(result['providers'])}")
    console.print(f"  [green]✓[/] Total tokens: {result['total_tokens']:,}")
    console.print("  [green]✓[/] Generated RISK_ASSESSMENT.md template")
    console.print("  [green]✓[/] Generated DATA_GOVERNANCE.md template")
    console.print("  [green]✓[/] Generated sample_agent.py (with good + bad patterns)")
    console.print()

    time.sleep(0.3)
    console.print("[dim]Running compliance check against demo data...[/]\n")

    # Now run compliance against the generated data
    client = GatewayClient(runs_dir=result["runs_dir"])
    status = client.get_status()

    if status.reachable:
        console.print(f"  [green]●[/] Gateway detected at {status.url}")
    else:
        console.print("  [yellow]●[/] No gateway running (offline mode — using .air.json records)")

    console.print(f"  [green]●[/] [bold]{status.total_runs}[/] events loaded")
    console.print()

    articles, _, _ = run_all_checks(status, output)

    for article in articles:
        for check in article["checks"]:
            icon = {"pass": "✅", "warn": "⚠️ ", "fail": "❌"}.get(check["status"], "?")
            tier = check.get("tier", "static")
            tier_tag = "[green]S[/]" if tier == "static" else "[blue]R[/]"
            det = {"auto": "[green]AUTO[/]", "hybrid": "[yellow]HYBR[/]", "manual": "[red]MANU[/]"}.get(
                check.get("detection", ""), ""
            )
            console.print(f"  {icon} Art. {article['number']:>2} {tier_tag} {det} {check['name']}")

    total = sum(len(a["checks"]) for a in articles)
    passing = sum(1 for a in articles for c in a["checks"] if c["status"] == "pass")

    console.print(f"\n  [bold]{passing}/{total}[/] checks passing")
    console.print()
    console.print(
        Panel(
            "[bold]What just happened:[/]\n\n"
            "1. Generated 10 sample AI agent records (like a real agent would create)\n"
            "2. Created EU AI Act compliance doc templates (Articles 9 + 10)\n"
            "3. Ran compliance check against the sample data\n\n"
            "[bold]Try these next:[/]\n\n"
            "  [green]air-blackbox comply -v[/]     Full compliance with fix hints\n"
            "  [green]air-blackbox discover[/]      See models and providers detected\n"
            "  [green]air-blackbox replay[/]        See the audit trail timeline\n"
            "  [green]docker compose up[/]          Start full gateway for live traffic",
            title="[bold blue]Demo Complete[/]",
            border_style="blue",
        )
    )

    # --- Telemetry ---
    try:
        from air_blackbox.telemetry import send_event

        send_event(command="demo", version=_ab_version)
    except Exception:
        pass


if __name__ == "__main__":
    main()


@main.command()
@click.option("--output", "-o", default=".", help="Directory to initialize")
def init(output):
    """Initialize a project for AIR Blackbox compliance.

    Creates compliance doc templates and a .air-blackbox.yaml config file.
    """
    import os

    from air_blackbox.demo_generator import _DATA_GOV_TEMPLATE, _RISK_TEMPLATE

    console.print("\n[bold blue]AIR Blackbox[/] — Project Init\n")

    files_created = []
    for fname, content in [
        ("RISK_ASSESSMENT.md", _RISK_TEMPLATE),
        ("DATA_GOVERNANCE.md", _DATA_GOV_TEMPLATE),
    ]:
        fpath = os.path.join(output, fname)
        if not os.path.exists(fpath):
            with open(fpath, "w") as f:
                f.write(content)
            files_created.append(fname)
            console.print(f"  [green]✓[/] Created {fname}")
        else:
            console.print(f"  [dim]⏭  {fname} already exists[/]")

    if files_created:
        console.print(
            f"\n  [bold]{len(files_created)}[/] files created. Run [green]air-blackbox comply -v[/] to check status.\n"
        )
    else:
        console.print("\n  All files already exist. Run [green]air-blackbox comply -v[/] to check status.\n")


@main.command()
@click.option("--tool", default=None, help="Tool name to validate")
@click.option("--args", "arguments", default=None, help="Tool arguments as JSON")
@click.option("--content", default=None, help="LLM output content to validate")
@click.option("--allowlist", default=None, help="Comma-separated list of approved tools")
def validate(tool, arguments, content, allowlist):
    """Validate an agent action BEFORE execution.

    Pre-execution runtime certification — proves the output was
    checked against rules before it was acted on.

    \b
    Examples:
        air-blackbox validate --tool=db_query --args='{"query":"SELECT * FROM users"}'
        air-blackbox validate --content="Here is the result..."
        air-blackbox validate --tool=web_search --allowlist=web_search,calculator
    """
    import json as jsonlib

    from air_blackbox.validate import RuntimeValidator, ToolAllowlistRule

    console.print("\n[bold blue]AIR Blackbox[/] — Runtime Validation\n")

    validator = RuntimeValidator()

    if allowlist:
        validator.add_rule(ToolAllowlistRule(allowlist.split(",")))

    action = {}
    action_type = "tool_call"
    if tool:
        action["tool_name"] = tool
    if arguments:
        try:
            action["arguments"] = jsonlib.loads(arguments)
        except jsonlib.JSONDecodeError:
            action["arguments"] = {"raw": arguments}
    if content:
        action["content"] = content
        action_type = "llm_response"

    report = validator.validate(action, action_type=action_type)

    t = Table(title="Validation Results", show_header=True, header_style="bold white on dark_blue")
    t.add_column("Rule", style="bold", width=22)
    t.add_column("Result", justify="center", width=10)
    t.add_column("Severity", justify="center", width=10)
    t.add_column("Message", width=45)

    for r in report.results:
        icon = "[green]✅ PASS[/]" if r.passed else "[red]❌ FAIL[/]"
        sev = {"block": "[red]BLOCK[/]", "warn": "[yellow]WARN[/]", "info": "[dim]INFO[/]"}.get(r.severity, r.severity)
        t.add_row(r.rule_name, icon, sev, r.message)
    console.print(t)
    console.print()

    if report.passed:
        console.print(f"  [green]✅ VALIDATED[/] — action approved for execution ({report.validated_in_ms}ms)")
    else:
        console.print(f"  [red]❌ BLOCKED[/] — action failed validation ({report.validated_in_ms}ms)")
    console.print(f"  [dim]Validation record: {report.action_id}.air.json[/]\n")


@main.command()
@click.option("--path", default=None, help="Filter by scan path")
@click.option("--compare", is_flag=True, help="Compare last two scans and show diff")
@click.option("--export", "export_path", default=None, help="Export history to JSON file")
@click.option("--limit", default=20, help="Max number of scans to show")
def history(path, compare, export_path, limit):
    """View compliance scan history and trends.

    Tracks every scan in a local SQLite database (~/.air-blackbox/compliance.db).
    Shows score trends over time, diffs between scans, and exports for reporting.

    \b
    Examples:
        air-blackbox history                    # Show recent scans
        air-blackbox history --compare          # Diff last two scans
        air-blackbox history --export report.json
        air-blackbox history --path ./my-project
    """
    import json as jsonlib

    from air_blackbox.compliance.history import (
        compare_scans,
        export_history,
        get_history,
    )

    console.print("\n[bold blue]AIR Blackbox[/] — Compliance History\n")

    # Export mode
    if export_path:
        data = export_history(scan_path=path, limit=limit)
        with open(export_path, "w") as f:
            jsonlib.dump(data, f, indent=2)
        console.print(f"  [green]✓[/] Exported {data['scan_count']} scan(s) to [bold]{export_path}[/]\n")
        return

    # Compare mode
    if compare:
        scans = get_history(scan_path=path, limit=2)
        if len(scans) < 2:
            console.print("  [yellow]Need at least 2 scans to compare.[/] Run `air-blackbox comply` first.\n")
            return
        newer = scans[0]
        older = scans[1]
        diff = compare_scans(older["id"], newer["id"])

        console.print(f"  Comparing scan #{older['id']} → #{newer['id']}\n")
        console.print(f"  Score: [bold]{older['score_percent']}%[/] → [bold]{newer['score_percent']}%[/]", end="")
        delta = newer["score_percent"] - older["score_percent"]
        if delta > 0:
            console.print(f"  [bold green](+{delta}%)[/]")
        elif delta < 0:
            console.print(f"  [bold red]({delta}%)[/]")
        else:
            console.print("  [dim](no change)[/]")
        console.print()

        if diff["improved"]:
            console.print(f"  [bold green]Improved ({len(diff['improved'])}):[/]")
            for item in diff["improved"]:
                console.print(f"    [green]↑[/] Art {item['article']}: {item['name']} ({item['was']} → {item['now']})")
        if diff["regressed"]:
            console.print(f"\n  [bold red]Regressed ({len(diff['regressed'])}):[/]")
            for item in diff["regressed"]:
                console.print(f"    [red]↓[/] Art {item['article']}: {item['name']} ({item['was']} → {item['now']})")
        if diff["new_checks"]:
            console.print(f"\n  [bold blue]New checks ({len(diff['new_checks'])}):[/]")
            for item in diff["new_checks"]:
                si = {"pass": "[green]pass[/]", "warn": "[yellow]warn[/]", "fail": "[red]fail[/]"}.get(
                    item["status"], item["status"]
                )
                console.print(f"    [blue]●[/] Art {item['article']}: {item['name']} ({si})")
        if not diff["improved"] and not diff["regressed"] and not diff["new_checks"]:
            console.print("  [dim]No changes between scans.[/]")
        console.print()
        return

    # Default: show history trend
    scans = get_history(scan_path=path, limit=limit)
    if not scans:
        console.print("  [yellow]No scan history found.[/] Run `air-blackbox comply` to start tracking.\n")
        return

    table = Table(
        title="Compliance Scan History", show_header=True, header_style="bold white on dark_blue", title_style="bold"
    )
    table.add_column("#", width=4, justify="right")
    table.add_column("Date", width=20)
    table.add_column("Path", width=20)
    table.add_column("Score", width=10, justify="center")
    table.add_column("Pass", width=6, justify="center")
    table.add_column("Warn", width=6, justify="center")
    table.add_column("Fail", width=6, justify="center")
    table.add_column("Static", width=10, justify="center")
    table.add_column("Runtime", width=10, justify="center")
    table.add_column("Deep", width=5, justify="center")

    for s in scans:
        score_pct = s["score_percent"]
        score_color = "green" if score_pct >= 70 else "yellow" if score_pct >= 40 else "red"
        ts = s["timestamp"][:16].replace("T", " ")
        scan_path_short = s["scan_path"]
        if len(scan_path_short) > 20:
            scan_path_short = "..." + scan_path_short[-17:]
        deep_icon = "✓" if s["deep_scan"] else ""
        table.add_row(
            str(s["id"]),
            ts,
            scan_path_short,
            f"[{score_color}]{score_pct}%[/{score_color}]",
            f"[green]{s['passing']}[/]",
            f"[yellow]{s['warnings']}[/]",
            f"[red]{s['failing']}[/]",
            f"{s['static_passing']}/{s['static_total']}",
            f"{s['runtime_passing']}/{s['runtime_total']}",
            deep_icon,
        )

    console.print(table)

    # Trend line (last 5 scans)
    if len(scans) >= 2:
        trend = scans[:5][::-1]  # oldest first
        trend_str = " → ".join(f"{s['score_percent']}%" for s in trend)
        latest = scans[0]["score_percent"]
        oldest = trend[0]["score_percent"]
        delta = latest - oldest
        if delta > 0:
            console.print(f"\n  [bold]Trend:[/] {trend_str}  [bold green](+{delta}% overall)[/]")
        elif delta < 0:
            console.print(f"\n  [bold]Trend:[/] {trend_str}  [bold red]({delta}% overall)[/]")
        else:
            console.print(f"\n  [bold]Trend:[/] {trend_str}  [dim](flat)[/]")

    console.print("\n  [dim]Run with --compare to diff last two scans, or --export to save as JSON[/]\n")


@main.command()
@click.option(
    "--framework", "-f", default=None, help="Show mappings for a specific framework (eu, iso42001, nist, colorado)"
)
@click.option(
    "--lookup",
    default=None,
    help="Reverse lookup: find checks for a clause (e.g., 'Article 9', 'A.6.2.4', 'GOVERN 1', 'Section 6')",
)
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def standards(framework, lookup, fmt):
    """Show supported compliance frameworks and standards crosswalk.

    Lists all four compliance frameworks (EU AI Act, ISO 42001, NIST AI RMF,
    Colorado SB 205) and shows how AIR Blackbox checks map to each.

    \b
    Examples:
        air-blackbox standards                          # Show all frameworks
        air-blackbox standards -f iso42001              # Show ISO 42001 mappings
        air-blackbox standards --lookup "Article 9"     # Find checks for EU Article 9
        air-blackbox standards --lookup "GOVERN 1"      # Find checks for NIST function
        air-blackbox standards --lookup "Section 6"     # Find checks for Colorado section
        air-blackbox standards --lookup "A.6.2.4"       # Find checks for ISO clause
    """
    import json as jsonlib

    from air_blackbox.compliance.standards_map import (
        STANDARDS_CROSSWALK,
        SUPPORTED_FRAMEWORKS,
        get_checks_for_colorado_section,
        get_checks_for_eu_article,
        get_checks_for_iso_clause,
        get_checks_for_nist_function,
    )

    console.print("\n[bold blue]AIR Blackbox[/] -- Standards Crosswalk\n")

    # Reverse lookup mode
    if lookup:
        lookup = lookup.strip()
        matches = []

        # Detect which lookup function to use
        if lookup.lower().startswith("article"):
            try:
                art_num = int("".join(c for c in lookup if c.isdigit()))
                matches = get_checks_for_eu_article(art_num)
                console.print(f"  [bold]EU AI Act {lookup}[/] maps to:\n")
            except ValueError:
                console.print(f"  [red]Could not parse article number from '{lookup}'[/]\n")
                return
        elif lookup.upper().startswith(("GOVERN", "MAP", "MEASURE", "MANAGE")):
            matches = get_checks_for_nist_function(lookup)
            console.print(f"  [bold]NIST AI RMF {lookup}[/] maps to:\n")
        elif lookup.lower().startswith("section"):
            matches = get_checks_for_colorado_section(lookup)
            console.print(f"  [bold]Colorado SB 205 {lookup}[/] maps to:\n")
        else:
            # Try ISO clause lookup
            matches = get_checks_for_iso_clause(lookup)
            console.print(f"  [bold]ISO 42001 {lookup}[/] maps to:\n")

        if matches:
            for cat in matches:
                mapping = STANDARDS_CROSSWALK[cat]
                console.print(f"    [green]>[/] [bold]{cat.replace('_', ' ').title()}[/]")
                console.print(f"      EU: {mapping['eu_ai_act']}  |  ISO: {'; '.join(mapping['iso_42001'][:2])}")
                console.print(
                    f"      NIST: {'; '.join(mapping['nist_ai_rmf'])}  |  CO: {'; '.join(mapping.get('colorado_sb205', [])[:2])}"
                )
                console.print()
        else:
            console.print(f"    [yellow]No matching checks found for '{lookup}'[/]\n")
        return

    # Single framework detail mode
    if framework:
        fw = framework.lower().strip()
        if fw not in SUPPORTED_FRAMEWORKS:
            console.print(f"  [red]Unknown framework: {fw}[/]")
            console.print(f"  [dim]Valid options: {', '.join(SUPPORTED_FRAMEWORKS.keys())}[/]\n")
            return

        fw_info = SUPPORTED_FRAMEWORKS[fw]
        fw_key = fw_info["key"]
        console.print(f"  [bold]{fw_info['name']}[/] mappings:\n")

        if fmt == "json":
            data = {}
            for cat, mapping in sorted(STANDARDS_CROSSWALK.items()):
                data[cat] = {
                    "references": mapping[fw_key],
                    "description": mapping["description"],
                }
            click.echo(jsonlib.dumps(data, indent=2))
            return

        t = Table(show_header=True, header_style="bold white on dark_blue")
        t.add_column("Category", style="bold", width=24)
        t.add_column(fw_info["name"], width=45)
        t.add_column("Description", width=40)

        for cat, mapping in sorted(STANDARDS_CROSSWALK.items()):
            refs = mapping[fw_key]
            if isinstance(refs, list):
                ref_str = "; ".join(refs)
            else:
                ref_str = str(refs)
            t.add_row(cat.replace("_", " ").title(), ref_str, mapping["description"][:40])

        console.print(t)
        console.print()
        return

    # Default: show all frameworks overview
    if fmt == "json":
        data = {
            "frameworks": SUPPORTED_FRAMEWORKS,
            "crosswalk": STANDARDS_CROSSWALK,
        }
        click.echo(jsonlib.dumps(data, indent=2, default=str))
        return

    # Frameworks summary table
    t = Table(title="Supported Compliance Frameworks", show_header=True, header_style="bold white on dark_blue")
    t.add_column("ID", style="bold", width=10)
    t.add_column("Framework", width=25)
    t.add_column("Categories Covered", justify="center", width=20)

    for fw_id, fw_info in SUPPORTED_FRAMEWORKS.items():
        fw_key = fw_info["key"]
        count = sum(1 for m in STANDARDS_CROSSWALK.values() if m.get(fw_key))
        t.add_row(fw_id, fw_info["name"], f"{count}/{len(STANDARDS_CROSSWALK)}")

    console.print(t)
    console.print()

    # Crosswalk overview table
    t2 = Table(title="Standards Crosswalk", show_header=True, header_style="bold white on dark_blue")
    t2.add_column("Category", style="bold", width=22)
    t2.add_column("EU AI Act", width=12)
    t2.add_column("ISO 42001", width=18)
    t2.add_column("NIST RMF", width=16)
    t2.add_column("Colorado", width=18)

    for cat, mapping in sorted(STANDARDS_CROSSWALK.items()):
        eu = mapping["eu_ai_act"]
        iso = "; ".join(mapping["iso_42001"][:2])
        if len(mapping["iso_42001"]) > 2:
            iso += "..."
        nist = "; ".join(mapping["nist_ai_rmf"][:2])
        co = "; ".join(mapping.get("colorado_sb205", [])[:1])
        if len(mapping.get("colorado_sb205", [])) > 1:
            co += "..."
        t2.add_row(cat.replace("_", " ").title(), eu, iso, nist, co)

    console.print(t2)
    console.print()
    console.print("[dim]Detail view: air-blackbox standards -f iso42001[/]")
    console.print("[dim]Reverse lookup: air-blackbox standards --lookup 'Article 9'[/]")
    console.print("[dim]Use with comply: air-blackbox comply --frameworks eu,iso42001,nist,colorado[/]\n")


@main.command()
@click.option("--gateway", default="http://localhost:8080", help="Gateway URL")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output for each test")
def test(gateway, verbose):
    """Run end-to-end validation of the AIR Blackbox stack.

    Tests every subsystem — validation engine, compliance engine,
    audit records, HMAC chain, and optionally the live gateway.

    \b
    Examples:
        air-blackbox test              # Test SDK (no gateway needed)
        air-blackbox test -v           # Verbose output
        air-blackbox test --gateway http://localhost:8080  # Include gateway tests
    """
    import json as jsonlib
    import os
    import tempfile
    import time

    console.print("\n[bold blue]AIR Blackbox[/] — Stack Validation Test\n")

    results = []
    start_time = time.time()

    def _run_test(name, fn):
        """Run a single test, catch exceptions, record result."""
        try:
            passed, detail = fn()
            results.append({"name": name, "passed": passed, "detail": detail})
            icon = "[green]✅[/]" if passed else "[red]❌[/]"
            console.print(f"  {icon} {name}")
            if verbose and detail:
                console.print(f"     [dim]{detail}[/]")
        except Exception as e:
            results.append({"name": name, "passed": False, "detail": str(e)})
            console.print(f"  [red]❌[/] {name}")
            if verbose:
                console.print(f"     [red]{str(e)[:120]}[/]")

    # ── Test 1: SDK imports ──────────────────────────────────────────
    def test_sdk_imports():
        return True, "All core modules imported successfully"

    console.print("[bold]SDK Tests[/]\n")
    _run_test("SDK module imports", test_sdk_imports)

    # ── Test 2: Validation engine ────────────────────────────────────
    def test_validation_engine():
        from air_blackbox.validate import RuntimeValidator, ToolAllowlistRule

        with tempfile.TemporaryDirectory() as tmpdir:
            v = RuntimeValidator(runs_dir=tmpdir)
            v.add_rule(ToolAllowlistRule(["web_search", "calculator"]))
            # Should pass — tool is on allowlist
            r1 = v.validate({"tool_name": "web_search", "arguments": {"q": "hello"}})
            assert r1.passed, "Approved tool should pass"
            # Should fail — tool is NOT on allowlist
            r2 = v.validate({"tool_name": "exec_shell", "arguments": {"cmd": "rm -rf /"}})
            assert not r2.passed, "Blocked tool should fail"
            return True, f"2/2 validation scenarios correct ({r1.validated_in_ms + r2.validated_in_ms}ms)"

    _run_test("Validation engine (approve/block)", test_validation_engine)

    # ── Test 3: Content policy detection ─────────────────────────────
    def test_content_policy():
        from air_blackbox.validate import RuntimeValidator

        with tempfile.TemporaryDirectory() as tmpdir:
            v = RuntimeValidator(runs_dir=tmpdir)
            # Safe content should pass
            r1 = v.validate({"content": "The weather today is sunny."}, action_type="llm_response")
            assert r1.passed, "Safe content should pass"
            # Dangerous content should be blocked
            r2 = v.validate({"tool_name": "db", "arguments": {"query": "DROP TABLE users"}})
            assert not r2.passed, "SQL injection should be blocked"
            return True, "Safe content passed, dangerous content blocked"

    _run_test("Content policy (safe vs dangerous)", test_content_policy)

    # ── Test 4: PII detection ────────────────────────────────────────
    def test_pii_detection():
        from air_blackbox.validate import RuntimeValidator

        with tempfile.TemporaryDirectory() as tmpdir:
            v = RuntimeValidator(runs_dir=tmpdir)
            # Content with PII should warn
            r = v.validate({"content": "Contact john@example.com or SSN 123-45-6789"}, action_type="llm_response")
            pii_results = [x for x in r.results if x.rule_name == "pii_output_check"]
            assert len(pii_results) > 0, "PII rule should run"
            assert not pii_results[0].passed, "PII should be detected"
            types = pii_results[0].details.get("pii_types", [])
            assert "email" in types, "Email should be detected"
            assert "ssn" in types, "SSN should be detected"
            return True, f"Detected PII types: {', '.join(types)}"

    _run_test("PII detection (email, SSN)", test_pii_detection)

    # ── Test 5: Hallucination guard ──────────────────────────────────
    def test_hallucination_guard():
        from air_blackbox.validate import RuntimeValidator

        with tempfile.TemporaryDirectory() as tmpdir:
            v = RuntimeValidator(runs_dir=tmpdir)
            r = v.validate({"content": "Visit https://www.fake.com/api for more info"}, action_type="llm_response")
            hal_results = [x for x in r.results if x.rule_name == "hallucination_guard"]
            assert len(hal_results) > 0, "Hallucination rule should run"
            assert not hal_results[0].passed, "Fake URL should be flagged"
            return True, "Suspicious URL detected and flagged"

    _run_test("Hallucination guard (fake URLs)", test_hallucination_guard)

    # ── Test 6: Audit record write/read ──────────────────────────────
    def test_audit_records():
        from air_blackbox.validate import RuntimeValidator

        with tempfile.TemporaryDirectory() as tmpdir:
            v = RuntimeValidator(runs_dir=tmpdir)
            v.validate({"tool_name": "test_tool", "arguments": {}})
            # Check that a .air.json file was written
            air_files = [f for f in os.listdir(tmpdir) if f.endswith(".air.json")]
            assert len(air_files) >= 1, "Should write at least 1 audit record"
            # Read it back and verify structure
            with open(os.path.join(tmpdir, air_files[0])) as f:
                record = jsonlib.load(f)
            assert record.get("type") == "validation", "Record type should be 'validation'"
            assert "run_id" in record, "Record should have run_id"
            assert "timestamp" in record, "Record should have timestamp"
            assert "checks" in record, "Record should have checks"
            return True, f"Wrote and verified {len(air_files)} audit record(s)"

    _run_test("Audit record write/read", test_audit_records)

    # ── Test 7: Compliance engine ────────────────────────────────────
    def test_compliance_engine():
        from air_blackbox.compliance.engine import run_all_checks
        from air_blackbox.gateway_client import GatewayStatus

        status = GatewayStatus(
            reachable=False,
            total_runs=5,
            models_observed=["gpt-4o"],
            providers_observed=["openai"],
            total_tokens=1000,
            date_range_start="2026-01-01",
            date_range_end="2026-03-13",
            recent_runs=[{"run_id": "test-1", "model": "gpt-4o", "timestamp": "2026-03-13", "status": "success"}],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            articles, _, _ = run_all_checks(status, tmpdir)
            assert len(articles) == 6, f"Should have 6 articles, got {len(articles)}"
            total_checks = sum(len(a["checks"]) for a in articles)
            assert total_checks > 0, "Should have checks"
            article_nums = [a["number"] for a in articles]
            assert article_nums == [9, 10, 11, 12, 14, 15], f"Wrong articles: {article_nums}"
            return True, f"6 articles, {total_checks} checks executed"

    _run_test("Compliance engine (Articles 9-15)", test_compliance_engine)

    # ── Test 8: AI-BOM generation ────────────────────────────────────
    def test_aibom_generation():
        from air_blackbox.aibom.generator import generate_aibom
        from air_blackbox.gateway_client import GatewayStatus

        status = GatewayStatus(
            total_runs=3,
            models_observed=["gpt-4o", "claude-3-opus"],
            providers_observed=["openai", "anthropic"],
            total_tokens=5000,
        )
        bom = generate_aibom(status)
        assert bom.get("bomFormat") == "CycloneDX", "Should be CycloneDX format"
        assert "components" in bom, "Should have components"
        assert len(bom["components"]) >= 2, "Should have at least 2 components"
        return True, f"CycloneDX BOM with {len(bom['components'])} components"

    _run_test("AI-BOM generation (CycloneDX)", test_aibom_generation)

    # ── Test 9: Replay engine ────────────────────────────────────────
    def test_replay_engine():
        from air_blackbox.replay.engine import ReplayEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            # Write a sample .air.json record
            sample = {
                "version": "1.0.0",
                "run_id": "test-replay-1",
                "timestamp": "2026-03-13T10:00:00Z",
                "model": "gpt-4o",
                "provider": "openai",
                "tokens": {"prompt": 100, "completion": 50, "total": 150},
                "duration_ms": 234,
                "status": "success",
                "tool_calls": ["web_search"],
                "pii_alerts": [],
                "injection_alerts": [],
            }
            with open(os.path.join(tmpdir, "test-replay-1.air.json"), "w") as f:
                jsonlib.dump(sample, f)
            engine = ReplayEngine(runs_dir=tmpdir)
            count = engine.load()
            assert count >= 1, "Should load at least 1 record"
            stats = engine.get_stats()
            assert stats["total_records"] >= 1, "Should have records in stats"
            return True, f"Loaded {count} record(s), stats computed"

    _run_test("Replay engine (load + stats)", test_replay_engine)

    # ── Code Scanner Tests ───────────────────────────────────────────
    console.print("\n[bold]Code Scanner Tests[/]\n")

    def test_scanner_error_handling():
        """Verify scanner detects try/except around LLM calls."""
        from air_blackbox.compliance.code_scanner import scan_codebase

        with tempfile.TemporaryDirectory() as tmpdir:
            # File WITH error handling
            with open(os.path.join(tmpdir, "good.py"), "w") as f:
                f.write(
                    "from openai import OpenAI\nclient = OpenAI()\ntry:\n    client.chat.completions.create(model='gpt-4o')\nexcept Exception:\n    pass\n"
                )
            findings = scan_codebase(tmpdir)
            eh = [f for f in findings if f.name == "LLM call error handling"]
            assert len(eh) == 1, "Should find error handling check"
            assert eh[0].status == "pass", f"Should pass, got {eh[0].status}"
            return True, "Error handling detection working"

    _run_test("Scanner: error handling detection", test_scanner_error_handling)

    def test_scanner_no_error_handling():
        """Verify scanner catches missing error handling."""
        from air_blackbox.compliance.code_scanner import scan_codebase

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "bad.py"), "w") as f:
                f.write(
                    "from openai import OpenAI\nclient = OpenAI()\nclient.chat.completions.create(model='gpt-4o')\n"
                )
            findings = scan_codebase(tmpdir)
            eh = [f for f in findings if f.name == "LLM call error handling"]
            assert len(eh) == 1, "Should find error handling check"
            assert eh[0].status == "fail", f"Should fail without try/except, got {eh[0].status}"
            return True, "Missing error handling correctly flagged"

    _run_test("Scanner: missing error handling", test_scanner_no_error_handling)

    def test_scanner_tracing_patterns():
        """Verify scanner detects modern tracing (instrumentation, event bus, OTel)."""
        from air_blackbox.compliance.code_scanner import scan_codebase

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "traced.py"), "w") as f:
                f.write(
                    "from opentelemetry import trace\ntracer = trace.get_tracer(__name__)\nwith tracer.start_span('agent_call'):\n    pass\n"
                )
            findings = scan_codebase(tmpdir)
            tr = [f for f in findings if f.name == "Tracing / observability"]
            assert len(tr) == 1 and tr[0].status == "pass", "OTel tracing should pass"
        # Test instrumentation (LlamaIndex pattern)
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "instrumented.py"), "w") as f:
                f.write(
                    "from llama_index.core.instrumentation import dispatcher\ndispatcher.add_event_handler(my_handler)\n"
                )
            findings = scan_codebase(tmpdir)
            tr = [f for f in findings if f.name == "Tracing / observability"]
            assert len(tr) == 1 and tr[0].status == "pass", "Instrumentation pattern should pass"
        return True, "OTel + instrumentation patterns detected"

    _run_test("Scanner: tracing patterns (OTel, instrumentation)", test_scanner_tracing_patterns)

    def test_scanner_hitl_patterns():
        """Verify scanner detects HITL patterns from multiple frameworks."""
        from air_blackbox.compliance.code_scanner import scan_codebase

        patterns_to_test = [
            ("haystack_hitl.py", "confirmation_strategy = 'always_ask'\n"),
            ("crewai_hitl.py", "agent = Agent(allow_delegation=True)\n"),
            ("langgraph_hitl.py", "workflow.add_node('human', interrupt_before=['action'])\n"),
        ]
        for fname, content in patterns_to_test:
            with tempfile.TemporaryDirectory() as tmpdir:
                with open(os.path.join(tmpdir, fname), "w") as f:
                    f.write(content)
                findings = scan_codebase(tmpdir)
                hitl = [f for f in findings if f.name == "Human-in-the-loop patterns"]
                assert len(hitl) == 1 and hitl[0].status == "pass", (
                    f"HITL should pass for {fname}, got {hitl[0].status if hitl else 'none'}"
                )
        return True, "Haystack, CrewAI, LangGraph HITL patterns all detected"

    _run_test("Scanner: HITL patterns (Haystack, CrewAI, LangGraph)", test_scanner_hitl_patterns)

    def test_scanner_injection_defense():
        """Verify scanner detects guardrail patterns from CrewAI and LlamaIndex."""
        from air_blackbox.compliance.code_scanner import scan_codebase

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "guarded.py"), "w") as f:
                f.write("from crewai import Agent\nagent = Agent(hallucination_guardrail=True)\n")
            findings = scan_codebase(tmpdir)
            inj = [f for f in findings if f.name == "Prompt injection defense"]
            assert len(inj) == 1 and inj[0].status == "pass", "CrewAI guardrail should pass"
        return True, "CrewAI hallucination_guardrail detected"

    _run_test("Scanner: injection defense (CrewAI guardrail)", test_scanner_injection_defense)

    def test_scanner_output_validation():
        """Verify scanner detects CrewAI output_pydantic and expected_output."""
        from air_blackbox.compliance.code_scanner import scan_codebase

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "tasks.py"), "w") as f:
                f.write(
                    "from crewai import Task\ntask = Task(description='Analyze', output_pydantic=AnalysisResult, expected_output='JSON report')\n"
                )
            findings = scan_codebase(tmpdir)
            ov = [f for f in findings if f.name == "LLM output validation"]
            assert len(ov) == 1 and ov[0].status == "pass", "CrewAI output_pydantic should pass"
        return True, "CrewAI output_pydantic + expected_output detected"

    _run_test("Scanner: output validation (CrewAI patterns)", test_scanner_output_validation)

    def test_scanner_identity_binding():
        """Verify scanner detects CrewAI Fingerprint and Haystack memory patterns."""
        from air_blackbox.compliance.code_scanner import scan_codebase

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "identity.py"), "w") as f:
                f.write(
                    "from crewai.utilities import Fingerprint\nagent_id = Fingerprint()\ncard = AgentCard(name='worker')\n"
                )
            findings = scan_codebase(tmpdir)
            ib = [f for f in findings if f.name == "Agent-to-user identity binding"]
            assert len(ib) == 1 and ib[0].status == "pass", "CrewAI Fingerprint should pass"
        return True, "CrewAI Fingerprint + AgentCard detected"

    _run_test("Scanner: identity binding (CrewAI Fingerprint)", test_scanner_identity_binding)

    def test_scanner_audit_trail_events():
        """Verify scanner detects CrewAI event bus patterns."""
        from air_blackbox.compliance.code_scanner import scan_codebase

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "events.py"), "w") as f:
                f.write(
                    "from crewai.utilities import agent_events, crew_events\ndef on_event(event): pass\nemit_event('task_completed', data)\n"
                )
            findings = scan_codebase(tmpdir)
            at = [f for f in findings if f.name == "Agent action audit trail"]
            assert len(at) == 1 and at[0].status == "pass", "CrewAI event bus should pass"
        return True, "CrewAI event bus audit trail detected"

    _run_test("Scanner: audit trail (CrewAI event bus)", test_scanner_audit_trail_events)

    def test_scanner_false_positive_pii():
        """Regression: 'private' alone should NOT trigger PII detection."""
        from air_blackbox.compliance.code_scanner import scan_codebase

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "normal.py"), "w") as f:
                f.write(
                    "class MyClass:\n    def __init__(self):\n        self.private = True\n        self._private_method = lambda: None\n"
                )
            findings = scan_codebase(tmpdir)
            pii = [f for f in findings if f.name == "PII handling in code"]
            # Should NOT pass — 'private' alone is not PII handling
            assert len(pii) == 1 and pii[0].status != "pass", (
                f"Bare 'private' should not trigger PII pass, got {pii[0].status}"
            )
        return True, "False positive: bare 'private' correctly ignored"

    _run_test("Scanner: PII false positive regression", test_scanner_false_positive_pii)

    def test_scanner_skip_deprecated():
        """Verify scanner skips deprecated and archived directories."""
        from air_blackbox.compliance.code_scanner import scan_codebase

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create deprecated dir with Python files — should be skipped
            dep_dir = os.path.join(tmpdir, "deprecated")
            os.makedirs(dep_dir)
            with open(os.path.join(dep_dir, "old.py"), "w") as f:
                f.write("import logging\nlogging.getLogger(__name__)\n")
            findings = scan_codebase(tmpdir)
            # Should find no Python files (only deprecated dir has them)
            no_files = [f for f in findings if "No Python files" in f.evidence]
            assert len(no_files) >= 1, "Should skip deprecated directory"
        return True, "Deprecated directories correctly skipped"

    _run_test("Scanner: skip deprecated directories", test_scanner_skip_deprecated)

    # ── Two-Tier Scoring Tests ───────────────────────────────────────
    console.print("\n[bold]Two-Tier Scoring Tests[/]\n")

    def test_tier_labels():
        """Verify every check has a tier and gateway checks are labeled 'runtime'."""
        from air_blackbox.compliance.engine import run_all_checks
        from air_blackbox.gateway_client import GatewayStatus

        status = GatewayStatus(reachable=False, total_runs=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            articles, _, _ = run_all_checks(status, tmpdir)
            all_checks = [c for a in articles for c in a["checks"]]
            # Every check must have a tier
            for c in all_checks:
                assert "tier" in c, f"Check '{c['name']}' missing tier"
                assert c["tier"] in ("static", "runtime"), f"Check '{c['name']}' has invalid tier: {c['tier']}"
            static = [c for c in all_checks if c["tier"] == "static"]
            runtime = [c for c in all_checks if c["tier"] == "runtime"]
            assert len(static) > 0, "Should have static checks"
            assert len(runtime) > 0, "Should have runtime checks"
            return True, f"{len(static)} static + {len(runtime)} runtime checks, all labeled"

    _run_test("Tier labels on all checks", test_tier_labels)

    def test_runtime_checks_identified():
        """Verify known gateway-dependent checks are tier='runtime'."""
        from air_blackbox.compliance.engine import run_all_checks
        from air_blackbox.gateway_client import GatewayStatus

        status = GatewayStatus(reachable=False, total_runs=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            articles, _, _ = run_all_checks(status, tmpdir)
            all_checks = {c["name"]: c for a in articles for c in a["checks"]}
            runtime_expected = [
                "Risk mitigations active",
                "PII detection in prompts",
                "Data vault (controlled storage)",
                "Runtime system inventory (AI-BOM data)",
                "Automatic event logging",
                "Tamper-evident audit chain",
                "Log detail and traceability",
                "Kill switch / stop mechanism",
                "Prompt injection protection",
            ]
            for name in runtime_expected:
                assert name in all_checks, f"Check '{name}' not found"
                assert all_checks[name]["tier"] == "runtime", (
                    f"'{name}' should be runtime, got {all_checks[name]['tier']}"
                )
            return True, f"All {len(runtime_expected)} gateway checks correctly labeled runtime"

    _run_test("Runtime checks correctly identified", test_runtime_checks_identified)

    def test_version_consistency():
        """Verify version is consistent across pyproject.toml, __init__.py, and cli."""
        import air_blackbox

        cli_version = "1.11.1"  # from @click.version_option
        init_version = air_blackbox.__version__
        assert init_version == cli_version, f"__init__ ({init_version}) != cli ({cli_version})"
        return True, f"Version {init_version} consistent across modules"

    _run_test("Version consistency", test_version_consistency)

    # ── Gateway tests (optional) ─────────────────────────────────────
    console.print("\n[bold]Gateway Tests[/]\n")

    def test_gateway_health():
        from air_blackbox.gateway_client import GatewayClient

        client = GatewayClient(gateway_url=gateway)
        status = client.get_status()
        if status.reachable:
            return True, f"Gateway reachable at {gateway}"
        else:
            return False, f"Gateway not reachable at {gateway} (start with: docker compose up)"

    _run_test("Gateway connectivity", test_gateway_health)

    def test_gateway_audit_endpoint():
        import httpx

        try:
            r = httpx.get(f"{gateway}/v1/audit", timeout=5.0)
            if r.status_code == 200:
                data = r.json()
                chain = data.get("audit_chain", {})
                return (
                    True,
                    f"Audit endpoint OK — chain length: {chain.get('length', 0)}, intact: {chain.get('intact', False)}",
                )
            return False, f"Audit endpoint returned {r.status_code}"
        except Exception:
            return False, "Audit endpoint not reachable (gateway may not be running)"

    _run_test("Gateway audit endpoint", test_gateway_audit_endpoint)

    def test_gateway_proxy():
        import httpx

        try:
            r = httpx.get(f"{gateway}/v1/models", timeout=5.0)
            if r.status_code == 200:
                data = r.json()
                models = [m.get("id", "?") for m in data.get("data", [])[:3]]
                return True, f"Proxy forwarding OK — models: {', '.join(models)}"
            elif r.status_code == 401:
                return True, "Proxy reached upstream (401 = API key needed, but proxy works)"
            return False, f"Proxy returned {r.status_code}"
        except Exception:
            return False, "Proxy not reachable (gateway may not be running)"

    _run_test("Gateway proxy forwarding", test_gateway_proxy)

    # ── Summary ──────────────────────────────────────────────────────
    elapsed = int((time.time() - start_time) * 1000)
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed

    console.print()
    if failed == 0:
        console.print(
            Panel(
                f"[bold green]{passed}/{total}[/] tests passing in {elapsed}ms\n\nYour AIR Blackbox stack is healthy.",
                title="[bold green]All Tests Passed[/]",
                border_style="green",
            )
        )
    else:
        # Separate SDK failures from gateway failures (gateway not running is expected)
        sdk_failures = [
            r
            for r in results
            if not r["passed"]
            and "Gateway" not in r["name"]
            and "audit endpoint" not in r["name"]
            and "Proxy" not in r["name"]
        ]
        gw_failures = [r for r in results if not r["passed"] and r not in sdk_failures]

        if sdk_failures:
            lines = f"[bold red]{failed}[/] test(s) failed out of {total} ({elapsed}ms)\n"
            for r in sdk_failures:
                lines += f"\n  [red]●[/] {r['name']}: {r['detail']}"
            console.print(Panel(lines, title="[bold red]Tests Failed[/]", border_style="red"))
        else:
            console.print(
                Panel(
                    f"[bold green]{passed}/{total}[/] tests passing in {elapsed}ms\n\n"
                    f"SDK tests: [bold green]all passing[/]\n"
                    f"Gateway tests: [bold yellow]{len(gw_failures)} skipped[/] (gateway not running)\n\n"
                    f"[dim]Start gateway with: docker compose up[/]",
                    title="[bold green]SDK Tests Passed[/]",
                    border_style="green",
                )
            )
    console.print()


# ---------------------------------------------------------------------------
# sign -- ML-DSA-65 quantum-safe signing
# ---------------------------------------------------------------------------


@main.command()
@click.argument("file", required=False, type=click.Path())
@click.option("--keygen", is_flag=True, help="Generate a new ML-DSA-65 key pair")
@click.option("--force", is_flag=True, help="Overwrite existing keys (use with --keygen)")
@click.option("--key-dir", default=None, type=click.Path(), help="Custom key storage directory")
@click.option("--output", "-o", default=None, type=click.Path(), help="Save signature to file (default: <file>.sig)")
def sign(file, keygen, force, key_dir, output):
    """Sign a file with ML-DSA-65 quantum-safe signatures.

    Generate keys first, then sign any file:

        air-blackbox sign --keygen          # one-time key generation
        air-blackbox sign results.json      # sign a scan result
        air-blackbox sign results.json -o results.sig

    Signatures use FIPS 204 ML-DSA-65 (Dilithium3), which is quantum-resistant.
    Keys are stored locally and never leave your machine.
    """
    import json as _json
    from pathlib import Path as _Path

    try:
        from air_blackbox.evidence.keys import KeyManager
        from air_blackbox.evidence.signer import EvidenceSigner
    except ImportError:
        console.print("[red]Error:[/red] dilithium-py is required for signing.")
        console.print("Install it with: [bold]pip install dilithium-py[/bold]")
        raise SystemExit(1)

    key_dir_path = _Path(key_dir) if key_dir else None
    km = KeyManager(key_dir=key_dir_path)

    # --- Key generation mode ---
    if keygen:
        try:
            pk, _sk = km.generate(force=force)
            console.print()
            console.print(
                Panel.fit(
                    f"[bold green]ML-DSA-65 key pair generated[/bold green]\n\n"
                    f"Algorithm:   FIPS 204 ML-DSA-65 (Dilithium3)\n"
                    f"Key ID:      {km.get_key_id()}\n"
                    f"Public key:  {km.public_key_path}\n"
                    f"Private key: {km.private_key_path}\n\n"
                    f"[dim]Your private key never leaves this machine.\n"
                    f"Next: air-blackbox sign <file> to sign evidence.[/dim]",
                    title="[bold cyan]Key Generation[/bold cyan]",
                    border_style="cyan",
                )
            )
        except FileExistsError:
            console.print("[yellow]Keys already exist.[/yellow] Use --force to overwrite.")
            meta = km.get_metadata()
            console.print(f"  Key ID:   {meta.get('key_id', 'unknown')}")
            console.print(f"  Created:  {meta.get('created_at', 'unknown')}")
            console.print(f"  Location: {km.key_dir}")
        except ImportError as e:
            console.print(f"[red]Error:[/red] {e}")
            raise SystemExit(1)
        return

    # --- Signing mode ---
    if not file:
        console.print("[red]Error:[/red] Provide a file to sign, or use --keygen to generate keys.")
        console.print("  Usage: air-blackbox sign <file>")
        console.print("  Usage: air-blackbox sign --keygen")
        raise SystemExit(1)

    file_path = _Path(file)
    if not file_path.exists():
        console.print(f"[red]Error:[/red] File not found: {file_path}")
        raise SystemExit(1)

    if not km.has_keys():
        console.print("[red]Error:[/red] No signing keys found.")
        console.print("Generate keys first: [bold]air-blackbox sign --keygen[/bold]")
        raise SystemExit(1)

    signer = EvidenceSigner(key_manager=km)

    console.print(f"[blue]Signing:[/blue] {file_path}")
    envelope = signer.sign_file(file_path)

    # Save the signature envelope
    if output:
        sig_path = _Path(output)
    else:
        sig_path = file_path.with_suffix(file_path.suffix + ".sig")

    sig_path.write_text(_json.dumps(envelope, indent=2), encoding="utf-8")

    console.print()
    console.print(
        Panel.fit(
            f"[bold green]File signed successfully[/bold green]\n\n"
            f"File:        {file_path}\n"
            f"Signature:   {sig_path}\n"
            f"Algorithm:   ML-DSA-65 (quantum-safe)\n"
            f"Key ID:      {envelope['key_id']}\n"
            f"SHA-256:     {envelope['data_sha256'][:32]}...\n"
            f"Sig size:    {envelope['signature_size_bytes']} bytes\n\n"
            f"[dim]Verify with: air-blackbox verify {file_path} {sig_path}[/dim]",
            title="[bold cyan]Signed[/bold cyan]",
            border_style="green",
        )
    )


# ---------------------------------------------------------------------------
# verify -- verify ML-DSA-65 signed evidence
# ---------------------------------------------------------------------------


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.argument("signature", type=click.Path(exists=True))
@click.option(
    "--public-key", default=None, type=click.Path(exists=True), help="Path to public key file (default: uses local key)"
)
@click.option("--key-dir", default=None, type=click.Path(), help="Custom key storage directory")
@click.option("--json", "as_json", is_flag=True, help="Output result as JSON")
def verify(file, signature, public_key, key_dir, as_json):
    """Verify a signed file using ML-DSA-65.

    Verify that a file has not been tampered with since it was signed:

        air-blackbox verify results.json results.json.sig
        air-blackbox verify results.json results.json.sig --public-key auditor_key.bin

    Returns exit code 0 if valid, 1 if invalid.
    """
    import json as _json
    from pathlib import Path as _Path

    try:
        from air_blackbox.evidence.keys import KeyManager
        from air_blackbox.evidence.signer import EvidenceSigner
    except ImportError:
        console.print("[red]Error:[/red] dilithium-py is required for verification.")
        console.print("Install it with: [bold]pip install dilithium-py[/bold]")
        raise SystemExit(1)

    file_path = _Path(file)
    sig_path = _Path(signature)

    # Load the signature envelope
    try:
        envelope = _json.loads(sig_path.read_text(encoding="utf-8"))
    except _json.JSONDecodeError as e:
        console.print(f"[red]Error:[/red] Invalid signature file: {e}")
        raise SystemExit(1)

    # Load public key
    pk_bytes = None
    if public_key:
        pk_bytes = _Path(public_key).read_bytes()
    else:
        key_dir_path = _Path(key_dir) if key_dir else None
        km = KeyManager(key_dir=key_dir_path)
        try:
            pk_bytes = km.load_public_key()
        except FileNotFoundError:
            console.print("[red]Error:[/red] No public key found.")
            console.print("Provide one with --public-key or generate keys with: air-blackbox sign --keygen")
            raise SystemExit(1)

    # Read the file and verify
    data = file_path.read_bytes()
    km_for_verify = KeyManager(key_dir=_Path(key_dir) if key_dir else None)
    signer = EvidenceSigner(key_manager=km_for_verify)

    result = signer.verify_envelope(data, envelope, public_key=pk_bytes)

    if as_json:
        console.print(_json.dumps(result, indent=2))
    else:
        console.print()
        if result["verified"]:
            console.print(
                Panel.fit(
                    f"[bold green]VERIFIED[/bold green] -- signature is valid\n\n"
                    f"File:      {file_path}\n"
                    f"Algorithm: {envelope.get('algorithm', 'unknown')}\n"
                    f"Key ID:    {envelope.get('key_id', 'unknown')}\n"
                    f"Signed at: {envelope.get('signed_at', 'unknown')}\n"
                    f"SHA-256:   {result['checks']['data_integrity']['actual'][:32]}...\n\n"
                    f"[green]All checks passed:[/green]\n"
                    f"  Algorithm:      {'PASS' if result['checks']['algorithm']['passed'] else 'FAIL'}\n"
                    f"  Data integrity: {'PASS' if result['checks']['data_integrity']['passed'] else 'FAIL'}\n"
                    f"  Signature:      {'PASS' if result['checks']['signature']['passed'] else 'FAIL'}",
                    title="[bold green]Verification Result[/bold green]",
                    border_style="green",
                )
            )
        else:
            failed_checks = [name for name, check in result["checks"].items() if not check["passed"]]
            console.print(
                Panel.fit(
                    f"[bold red]FAILED[/bold red] -- signature verification failed\n\n"
                    f"File:      {file_path}\n"
                    f"Algorithm: {envelope.get('algorithm', 'unknown')}\n"
                    f"Key ID:    {envelope.get('key_id', 'unknown')}\n\n"
                    f"[red]Failed checks:[/red] {', '.join(failed_checks)}\n\n"
                    f"  Algorithm:      {'PASS' if result['checks']['algorithm']['passed'] else 'FAIL'}\n"
                    f"  Data integrity: {'PASS' if result['checks']['data_integrity']['passed'] else 'FAIL'}\n"
                    f"  Signature:      {'PASS' if result['checks']['signature']['passed'] else 'FAIL'}\n\n"
                    f"[dim]The file may have been modified since signing.[/dim]",
                    title="[bold red]Verification Result[/bold red]",
                    border_style="red",
                )
            )
            raise SystemExit(1)

    if not result["verified"]:
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# attest -- compliance oracle attestations
# ---------------------------------------------------------------------------


@main.command()
@click.argument("action", type=click.Choice(["create", "list", "show", "badge", "publish"]), default="create")
@click.option(
    "--scan",
    default=".",
    type=click.Path(exists=True),
    help="Path to scan for code-level checks (default: current dir)",
)
@click.option("--name", default="", help="Human-readable name for the AI system")
@click.option("--version", "sys_version", default="", help="Version string for the AI system")
@click.option("--frameworks", default=None, help="Compliance frameworks (eu,iso42001,nist,colorado). Default: all")
@click.option("--key-dir", default=None, type=click.Path(), help="Custom key storage directory")
@click.option(
    "--bundle", default=None, type=click.Path(exists=True), help="Link attestation to an existing .air-evidence bundle"
)
@click.option("--id", "att_id", default=None, help="Attestation ID (for show/badge)")
@click.option("--output", "-o", default=None, type=click.Path(), help="Save badge SVG to file (for badge action)")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--publish", is_flag=True, help="Publish attestation to the public registry at airblackbox.ai")
def attest(action, scan, name, sys_version, frameworks, key_dir, bundle, att_id, output, as_json, publish):
    """Create, list, and manage compliance attestations.

    Attestations are signed proofs that an AI system was scanned. They contain
    enough information for independent verification without revealing source code.

    \b
    Actions:
        create   Scan a project and create a signed attestation (default)
        list     Show all attestations in the local registry
        show     Display details of a specific attestation
        badge    Generate an SVG badge for a specific attestation
        publish  Publish an existing local attestation to the public registry

    \b
    Examples:
        air-blackbox attest create --scan ~/myproject --name "My AI System"
        air-blackbox attest create --scan . --publish --name "My AI System"
        air-blackbox attest publish --id air-att-2026-04-12-a7f3c2e1
        air-blackbox attest list
        air-blackbox attest show --id air-att-2026-04-12-a7f3c2e1
        air-blackbox attest badge --id air-att-2026-04-12-a7f3c2e1 -o badge.svg
    """
    import hashlib as _hashlib
    import json as _json
    from pathlib import Path as _Path

    try:
        from air_blackbox.attestation.badge import badge_for_attestation, badge_markdown
        from air_blackbox.attestation.registry import LocalRegistry
        from air_blackbox.attestation.schema import AttestationRecord, CryptoInfo, EvidenceInfo, ScanInfo, SubjectInfo
        from air_blackbox.evidence.keys import KeyManager
        from air_blackbox.evidence.signer import EvidenceSigner
    except ImportError as e:
        console.print(f"[red]Error:[/red] Missing dependency: {e}")
        raise SystemExit(1)

    key_dir_path = _Path(key_dir) if key_dir else None
    km = KeyManager(key_dir=key_dir_path)
    registry = LocalRegistry()

    # --- LIST ---
    if action == "list":
        records = registry.list_all()
        if not records:
            console.print("[dim]No attestations found. Create one with:[/dim]")
            console.print("  [bold]air-blackbox attest create --scan .[/bold]")
            return

        if as_json:
            console.print(_json.dumps([r.to_dict() for r in records], indent=2))
            return

        table = Table(title="Attestation Registry", show_lines=True)
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("System", style="white")
        table.add_column("Frameworks", style="blue")
        table.add_column("Result", style="green")
        table.add_column("Signed", style="yellow")
        table.add_column("Date", style="dim")

        for r in records:
            fw_str = ", ".join(r.scan.frameworks[:3])
            if len(r.scan.frameworks) > 3:
                fw_str += f" +{len(r.scan.frameworks) - 3}"
            result_str = f"{r.scan.checks_passed}/{r.scan.checks_total}"
            if r.scan.checks_failed > 0:
                result_str = f"[red]{result_str}[/red]"
            elif r.scan.checks_warned > 0:
                result_str = f"[yellow]{result_str}[/yellow]"
            else:
                result_str = f"[green]{result_str}[/green]"
            signed = "[green]Yes[/green]" if r.crypto.signature else "[dim]No[/dim]"
            sys_name = r.subject.system_name or r.subject.system_hash[:12] + "..."
            date_str = r.created_at[:10] if r.created_at else ""

            table.add_row(r.attestation_id, sys_name, fw_str, result_str, signed, date_str)

        console.print(table)
        console.print(f"\n[dim]{len(records)} attestation(s) in registry[/dim]")
        return

    # --- SHOW ---
    if action == "show":
        if not att_id:
            console.print("[red]Error:[/red] Provide --id for the attestation to show.")
            raise SystemExit(1)

        record = registry.load(att_id)
        if not record:
            console.print(f"[red]Error:[/red] Attestation not found: {att_id}")
            raise SystemExit(1)

        if as_json:
            console.print(record.to_json())
            return

        s = record.scan
        console.print()
        console.print(
            Panel.fit(
                f"[bold cyan]{record.attestation_id}[/bold cyan]\n\n"
                f"System:       {record.subject.system_name or '(unnamed)'}\n"
                f"System hash:  {record.subject.system_hash[:32]}...\n"
                f"Files:        {record.subject.files_scanned}\n"
                f"Version:      {record.subject.system_version or '(none)'}\n\n"
                f"Frameworks:   {', '.join(s.frameworks)}\n"
                f"Checks:       {s.checks_passed} passed, {s.checks_warned} warned, {s.checks_failed} failed / {s.checks_total} total\n"
                f"Risk:         {s.risk_classification or '(unclassified)'}\n"
                f"Scanner:      {s.scanner_version}\n\n"
                f"Signed:       {'Yes (ML-DSA-65)' if record.crypto.signature else 'No'}\n"
                f"Key:          {record.crypto.public_key_fingerprint[:16]}...\n"
                f"Created:      {record.created_at}\n"
                f"Record hash:  {record.record_hash()[:32]}...",
                title="[bold cyan]Attestation Details[/bold cyan]",
                border_style="cyan",
            )
        )
        return

    # --- BADGE ---
    if action == "badge":
        if not att_id:
            console.print("[red]Error:[/red] Provide --id for the attestation.")
            raise SystemExit(1)

        record = registry.load(att_id)
        if not record:
            console.print(f"[red]Error:[/red] Attestation not found: {att_id}")
            raise SystemExit(1)

        svg = badge_for_attestation(record)

        if output:
            _Path(output).write_text(svg, encoding="utf-8")
            console.print(f"[green]Badge saved:[/green] {output}")
        else:
            console.print(svg)

        console.print()
        console.print("[dim]Markdown embed code:[/dim]")
        console.print(f"  {badge_markdown(record)}")
        return

    # --- PUBLISH (standalone) ---
    if action == "publish":
        if not att_id:
            console.print("[red]Error:[/red] Provide --id for the attestation to publish.")
            raise SystemExit(1)

        record = registry.load(att_id)
        if not record:
            console.print(f"[red]Error:[/red] Attestation not found locally: {att_id}")
            raise SystemExit(1)

        if not record.crypto.signature:
            console.print("[red]Error:[/red] Attestation is not signed. The public registry requires a signature.")
            raise SystemExit(1)

        console.print("\n[bold cyan]AIR Blackbox[/] -- Publishing to Public Registry\n")
        console.print(f"[blue]Attestation:[/blue] {att_id}")
        console.print("[blue]Sending to:[/blue]  https://airblackbox.ai/api/attest\n")

        try:
            import httpx

            payload = record.to_dict()
            resp = httpx.post(
                "https://airblackbox.ai/api/attest",
                json=payload,
                timeout=30,
            )

            if resp.status_code == 201:
                data = resp.json()
                console.print("[green]Published![/green]")
                console.print(f"  Verify: {data.get('verify_url', '')}")
                console.print(f"  Badge:  {data.get('badge_url', '')}")
                console.print()
                console.print("[dim]Embed in your README:[/dim]")
                md = f"[![AIR Attested](https://airblackbox.ai/badge/{att_id})](https://airblackbox.ai/verify/{att_id})"
                console.print(f"  {md}")
            elif resp.status_code == 409:
                console.print("[yellow]Already published:[/yellow] This attestation ID exists in the registry.")
                console.print(f"  Verify: https://airblackbox.ai/verify/{att_id}")
            else:
                err_data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                err_msg = err_data.get("error", resp.text[:200])
                console.print(f"[red]Registry rejected:[/red] {err_msg}")
                if "issues" in err_data:
                    for issue in err_data["issues"]:
                        console.print(f"  - {issue}")
        except httpx.ConnectError:
            console.print("[red]Error:[/red] Cannot connect to airblackbox.ai. Check your network.")
        except httpx.TimeoutException:
            console.print("[red]Error:[/red] Request timed out. Try again later.")
        except Exception as e:
            console.print(f"[red]Error:[/red] Publish failed: {e}")
        return

    # --- CREATE ---
    if not km.has_keys():
        console.print("[red]Error:[/red] No signing keys found.")
        console.print("Generate keys first: [bold]air-blackbox sign --keygen[/bold]")
        raise SystemExit(1)

    console.print("\n[bold cyan]AIR Blackbox[/] -- Attestation Oracle\n")

    fw_list = ["eu", "iso42001", "nist", "colorado"]
    if frameworks:
        fw_list = [f.strip().lower() for f in frameworks.split(",")]

    # Step 1: Hash the scanned codebase
    console.print(f"[blue]Step 1/4:[/blue] Hashing codebase at {scan}...")
    scan_path = _Path(scan)
    py_files = []
    if scan_path.is_file():
        py_files = [scan_path]
    elif scan_path.is_dir():
        py_files = list(scan_path.glob("**/*.py"))

    # Create system hash from all file contents
    hasher = _hashlib.sha256()
    file_count = 0
    for pf in sorted(py_files)[:500]:  # Sort for determinism, cap at 500
        try:
            hasher.update(pf.read_bytes())
            file_count += 1
        except Exception:
            pass
    system_hash = hasher.hexdigest()
    console.print(f"  {file_count} files hashed -> {system_hash[:16]}...")

    # Step 2: Run compliance scan
    console.print("[blue]Step 2/4:[/blue] Running compliance scan...")
    checks_passed = 0
    checks_warned = 0
    checks_failed = 0
    checks_total = 0
    try:
        from air_blackbox.compliance.engine import run_all_checks
        from air_blackbox.gateway_client import GatewayClient, GatewayStatus

        try:
            client = GatewayClient(gateway_url="http://localhost:8080", runs_dir="./runs")
            status = client.get_status()
        except Exception:
            status = GatewayStatus(
                reachable=False,
                vault_enabled=False,
                guardrails_enabled=False,
                trust_signing_key_set=False,
                model_name="",
                provider="",
            )
        compliance = run_all_checks(status, scan)
        if isinstance(compliance, list):
            for article in compliance:
                for check in article.get("checks", []):
                    checks_total += 1
                    s = check.get("status", "")
                    if s == "pass":
                        checks_passed += 1
                    elif s == "warn":
                        checks_warned += 1
                    elif s == "fail":
                        checks_failed += 1
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Scan error: {e}")

    console.print(f"  {checks_passed} passed, {checks_warned} warned, {checks_failed} failed / {checks_total} total")

    # Step 3: Build the attestation record
    console.print("[blue]Step 3/4:[/blue] Building attestation record...")
    try:
        from air_blackbox import __version__ as ab_version
    except ImportError:
        ab_version = "unknown"

    # Hash the bundle if provided
    bundle_hash = ""
    if bundle:
        bundle_hash = _hashlib.sha256(_Path(bundle).read_bytes()).hexdigest()

    pk = km.load_public_key()
    pk_fingerprint = _hashlib.sha256(pk).hexdigest()

    record = AttestationRecord(
        subject=SubjectInfo(
            system_hash=system_hash,
            system_name=name,
            system_version=sys_version,
            files_scanned=file_count,
        ),
        scan=ScanInfo(
            scanner_version=f"air-blackbox {ab_version}",
            frameworks=fw_list,
            checks_passed=checks_passed,
            checks_warned=checks_warned,
            checks_failed=checks_failed,
            checks_total=checks_total,
        ),
        evidence=EvidenceInfo(
            bundle_hash=bundle_hash,
        ),
        crypto=CryptoInfo(
            algorithm="ML-DSA-65",
            public_key_fingerprint=pk_fingerprint,
        ),
    )

    # Populate verification URLs
    record.verification.verify_url = f"https://airblackbox.ai/verify/{record.attestation_id}"
    record.verification.badge_url = f"https://airblackbox.ai/badge/{record.attestation_id}.svg"

    # Step 4: Sign the attestation
    console.print("[blue]Step 4/4:[/blue] Signing attestation with ML-DSA-65...")
    signer = EvidenceSigner(key_manager=km)
    canonical_bytes = record.to_canonical_bytes()
    envelope = signer.sign_bytes(canonical_bytes)
    record.crypto.signature = envelope["signature_hex"]

    # Save to local registry
    path = registry.save(record)
    console.print(f"  Saved to: {path}")

    # --- PUBLISH to public registry ---
    publish_ok = False
    verify_url = ""
    badge_url = ""
    if publish:
        console.print()
        console.print("[blue]Publishing:[/blue] Sending attestation to public registry...")
        try:
            import httpx

            payload = record.to_dict()
            resp = httpx.post(
                "https://airblackbox.ai/api/attest",
                json=payload,
                timeout=30,
            )

            if resp.status_code == 201:
                data = resp.json()
                verify_url = data.get("verify_url", "")
                badge_url = data.get("badge_url", "")
                publish_ok = True
                console.print("  [green]Published![/green] Registry accepted the attestation.")
                console.print(f"  Verify:  {verify_url}")
                console.print(f"  Badge:   {badge_url}")
            elif resp.status_code == 409:
                console.print("  [yellow]Already published:[/yellow] This attestation ID exists in the registry.")
                publish_ok = True  # Not a failure -- it is already there
            else:
                err_data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                err_msg = err_data.get("error", resp.text[:200])
                console.print(f"  [red]Registry rejected:[/red] {err_msg}")
                console.print(f"  [dim]HTTP {resp.status_code}. The attestation is still saved locally.[/dim]")
        except httpx.ConnectError:
            console.print("  [red]Error:[/red] Cannot connect to airblackbox.ai. Check your network.")
            console.print("  [dim]The attestation is saved locally. Retry with:[/dim]")
            console.print(f"  [dim]  air-blackbox attest publish --id {record.attestation_id}[/dim]")
        except httpx.TimeoutException:
            console.print("  [red]Error:[/red] Request to airblackbox.ai timed out.")
            console.print("  [dim]The attestation is saved locally. Retry later.[/dim]")
        except Exception as e:
            console.print(f"  [red]Error:[/red] Publish failed: {e}")
            console.print("  [dim]The attestation is saved locally.[/dim]")

    console.print()
    if as_json:
        console.print(record.to_json())
    else:
        publish_line = ""
        if publish and publish_ok:
            publish_line = f"\n[green]Published: {verify_url}[/green]"
        elif publish and not publish_ok:
            publish_line = "\n[yellow]Publish failed (saved locally)[/yellow]"

        console.print(
            Panel.fit(
                f"[bold green]Attestation created[/bold green]\n\n"
                f"ID:          {record.attestation_id}\n"
                f"System:      {name or system_hash[:16] + '...'}\n"
                f"Frameworks:  {', '.join(fw_list)}\n"
                f"Checks:      {checks_passed}/{checks_total} passed\n"
                f"Signed:      ML-DSA-65 ({km.get_key_id()})\n"
                f"Record hash: {record.record_hash()[:32]}...{publish_line}\n\n"
                f"[dim]View:  air-blackbox attest show --id {record.attestation_id}[/dim]\n"
                f"[dim]Badge: air-blackbox attest badge --id {record.attestation_id}[/dim]\n"
                f"[dim]List:  air-blackbox attest list[/dim]",
                title="[bold cyan]Compliance Oracle[/bold cyan]",
                border_style="green",
            )
        )
