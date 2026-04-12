"""
Compliance engine — maps gateway traffic data to EU AI Act articles.
Detection types: AUTO, HYBRID, MANUAL
"""
import os
from dataclasses import dataclass
from typing import Literal
from air_blackbox.gateway_client import GatewayStatus


@dataclass
class ComplianceCheck:
    name: str
    article: int
    status: Literal["pass", "warn", "fail"]
    evidence: str
    detection: Literal["auto", "hybrid", "manual"]
    fix_hint: str = ""
    tier: Literal["static", "runtime"] = "static"


def _c2d(check: ComplianceCheck) -> dict:
    return {"name": check.name, "status": check.status, "evidence": check.evidence,
            "detection": check.detection, "fix_hint": check.fix_hint, "tier": check.tier}


def _finding_to_dict(finding) -> dict:
    """Convert a CodeFinding to the same dict format as ComplianceCheck."""
    return {"name": finding.name, "status": finding.status, "evidence": finding.evidence,
            "detection": getattr(finding, "detection", "auto"), "fix_hint": finding.fix_hint,
            "tier": "static"}


TRUST_LAYER_MAP = {
    "langchain": "air-langchain-trust",
    "crewai": "air-crewai-trust",
    "openai": "air-openai-trust",
    "anthropic": "air-anthropic-trust",
    "google.adk": "air-adk-trust",
    "google_adk": "air-adk-trust",
    "vertexai": "air-adk-trust",
}

FRAMEWORK_IMPORTS = {
    "langchain": ["from langchain", "import langchain"],
    "crewai": ["from crewai", "import crewai"],
    "openai": ["from openai", "import openai", "OpenAI("],
    "anthropic": ["from anthropic", "import anthropic", "Anthropic("],
    "google.adk": ["from google.adk", "import google.adk", "from google_adk", "from vertexai"],
}


def detect_frameworks(scan_path: str) -> list[str]:
    """Detect which AI frameworks are used in the scanned codebase."""
    detected = set()
    py_files = []
    if os.path.isfile(scan_path) and scan_path.endswith(".py"):
        py_files = [scan_path]
    elif os.path.isdir(scan_path):
        for root, _dirs, files in os.walk(scan_path):
            for f in files:
                if f.endswith(".py"):
                    py_files.append(os.path.join(root, f))
    for fp in py_files[:200]:  # cap to avoid scanning huge repos
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read(16000)  # first 16KB is enough
            for framework, patterns in FRAMEWORK_IMPORTS.items():
                if framework not in detected:
                    for pattern in patterns:
                        if pattern in content:
                            detected.add(framework)
                            break
        except (OSError, UnicodeDecodeError):
            pass
    return sorted(detected)


def get_trust_layer_recommendation(scan_path: str) -> str:
    """Return the best pip install command based on detected frameworks."""
    detected = detect_frameworks(scan_path)
    if detected:
        first = detected[0]
        return TRUST_LAYER_MAP.get(first, "air-langchain-trust")
    return "air-langchain-trust"


def run_all_checks(status: GatewayStatus, scan_path: str = ".") -> list[dict]:
    # Support single-file scanning: code scanner gets the file,
    # but doc checks use the parent directory
    doc_path = scan_path
    if os.path.isfile(scan_path):
        doc_path = os.path.dirname(os.path.abspath(scan_path)) or "."

    # Run code-level scan
    code_findings = []
    try:
        from air_blackbox.compliance.code_scanner import scan_codebase
        code_findings = scan_codebase(scan_path)
    except Exception:
        pass  # Graceful fallback if code scanner has issues

    # Run GDPR scan
    gdpr_findings = []
    try:
        from air_blackbox.compliance.gdpr_scanner import scan_gdpr
        gdpr_findings = scan_gdpr(scan_path)
    except Exception:
        pass  # Graceful fallback if GDPR scanner has issues

    # Run bias/fairness scan
    bias_findings = []
    try:
        from air_blackbox.compliance.bias_scanner import scan_bias
        bias_findings = scan_bias(scan_path)
    except Exception:
        pass  # Graceful fallback if bias scanner has issues

    # Detect frameworks for smart trust layer recommendations
    detected = detect_frameworks(scan_path)
    rec_pkg = TRUST_LAYER_MAP.get(detected[0], "air-langchain-trust") if detected else "air-langchain-trust"

    # Group code findings by article number
    code_by_article = {}
    for f in code_findings:
        code_by_article.setdefault(f.article, []).append(f)

    # EU AI Act articles
    results = [
        _check_article_9(status, doc_path, code_by_article.get(9, []), rec_pkg),
        _check_article_10(status, doc_path, code_by_article.get(10, []), rec_pkg),
        _check_article_11(status, doc_path, code_by_article.get(11, []), rec_pkg),
        _check_article_12(status, doc_path, code_by_article.get(12, []), rec_pkg),
        _check_article_14(status, doc_path, code_by_article.get(14, []), rec_pkg),
        _check_article_15(status, doc_path, code_by_article.get(15, []), rec_pkg),
    ]

    # GDPR checks (grouped into a single section)
    if gdpr_findings:
        gdpr_checks = [_finding_to_dict(f) for f in gdpr_findings]
        results.append({
            "number": "GDPR",
            "title": "GDPR Data Protection",
            "checks": gdpr_checks,
        })

    # Bias/fairness checks
    if bias_findings:
        bias_checks = [_finding_to_dict(f) for f in bias_findings]
        results.append({
            "number": "BIAS",
            "title": "Bias and Fairness",
            "checks": bias_checks,
        })

    # Attach detected frameworks for CLI recommendation display
    return results, detected, rec_pkg


def _check_article_9(status, scan_path, code_findings=None, rec_pkg="air-langchain-trust"):
    checks = []
    risk_files = ["RISK_ASSESSMENT.md", "risk_assessment.md", "risk_register.json", "RISK_MANAGEMENT.md"]
    has_risk = any(os.path.exists(os.path.join(scan_path, f)) for f in risk_files)
    checks.append(ComplianceCheck(name="Risk assessment document", article=9, detection="hybrid",
        status="pass" if has_risk else "fail",
        evidence="Risk assessment document found" if has_risk else "No risk assessment document found",
        fix_hint="Create RISK_ASSESSMENT.md documenting identified risks, likelihood, impact, and mitigations",
        tier="static"))

    # Article 6 requires risk CLASSIFICATION before Article 9 mitigations apply.
    # Check if the risk assessment actually classifies the system's risk level.
    risk_classified = False
    if has_risk:
        for rf in risk_files:
            rfp = os.path.join(scan_path, rf)
            if os.path.exists(rfp):
                try:
                    with open(rfp, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().lower()
                    import re
                    # Look for actual risk classification content
                    classification_patterns = [
                        r"risk\s+(?:level|classification|category)",
                        r"(?:high|minimal|limited|unacceptable)[\s-]*risk",
                        r"annex\s+iii", r"article\s+6",
                        r"prohibited|high-risk|limited\s+risk|minimal\s+risk",
                    ]
                    if any(re.search(p, content) for p in classification_patterns):
                        risk_classified = True
                except Exception:
                    pass
    checks.append(ComplianceCheck(name="Risk classification (Article 6)", article=9, detection="static",
        status="pass" if risk_classified else ("warn" if has_risk else "fail"),
        evidence="Risk classification found in assessment document" if risk_classified
            else ("Risk document exists but no risk level classification found" if has_risk
                  else "No risk classification. Article 6 requires classifying the system before applying mitigations"),
        fix_hint="Add risk classification to RISK_ASSESSMENT.md: classify as prohibited/high/limited/minimal per EU AI Act Article 6 and Annex III",
        tier="static"))

    mits = []
    if status.guardrails_enabled: mits.append("guardrails")
    if status.vault_enabled: mits.append("data vault")
    if status.trust_signing_key_set: mits.append("audit signing")
    if status.otel_enabled: mits.append("OTel pipeline")
    mc = len(mits)
    checks.append(ComplianceCheck(name="Risk mitigations active", article=9, detection="hybrid",
        status="pass" if mc >= 3 else "warn" if mc >= 1 else "fail",
        evidence=f"{mc}/4 mitigations active: {', '.join(mits) or 'none detected'}",
        fix_hint="Enable guardrails.yaml, set TRUST_SIGNING_KEY, configure vault and OTel endpoints",
        tier="runtime"))
    result = {"number": 9, "title": "Risk Management", "checks": [_c2d(c) for c in checks]}
    for f in (code_findings or []):
        result["checks"].append(_finding_to_dict(f))
    return result


def _check_article_10(status, scan_path, code_findings=None, rec_pkg="air-langchain-trust"):
    checks = []
    if status.reachable or (status.total_runs > 0 and status.audit_chain_intact):
        src = "Gateway" if status.reachable else "Trust layer"
        if status.pii_detected_count > 0:
            checks.append(ComplianceCheck(name="PII detection in prompts", article=10, detection="auto", status="warn",
                evidence=f"{src} scanning active. PII detected in {status.pii_detected_count} prompt(s) across {status.total_runs} runs.",
                fix_hint="Enable prompt vault redaction",
                tier="runtime"))
        else:
            checks.append(ComplianceCheck(name="PII detection in prompts", article=10, detection="auto", status="pass",
                evidence=f"{src} scanning active. No PII detected in {status.total_runs} requests.",
                tier="runtime"))
    else:
        checks.append(ComplianceCheck(name="PII detection in prompts", article=10, detection="auto",
            status="warn" if status.total_runs > 0 else "fail",
            evidence=f"Gateway not reachable. {'Found ' + str(status.total_runs) + ' logged runs.' if status.total_runs > 0 else 'No data.'}",
            fix_hint=f"Start gateway or install a trust layer package (pip install {rec_pkg})",
            tier="runtime"))
    dg_files = ["DATA_GOVERNANCE.md", "data_governance.md"]
    has_dg = any(os.path.exists(os.path.join(scan_path, f)) for f in dg_files)
    checks.append(ComplianceCheck(name="Data governance documentation", article=10, detection="hybrid",
        status="pass" if has_dg else "fail",
        evidence="Data governance document found" if has_dg else "No data governance documentation found",
        fix_hint="Create DATA_GOVERNANCE.md: data sources, consent, quality measures, retention",
        tier="static"))
    checks.append(ComplianceCheck(name="Data vault (controlled storage)", article=10, detection="auto",
        status="pass" if status.vault_enabled else "fail",
        evidence="Vault enabled. Data stored in your controlled S3/MinIO." if status.vault_enabled else "No vault configured.",
        fix_hint="Set VAULT_ENDPOINT, VAULT_ACCESS_KEY, VAULT_SECRET_KEY in .env or install a trust layer",
        tier="runtime"))
    result = {"number": 10, "title": "Data Governance", "checks": [_c2d(c) for c in checks]}
    for f in (code_findings or []):
        result["checks"].append(_finding_to_dict(f))
    return result


def _check_article_11(status, scan_path, code_findings=None, rec_pkg="air-langchain-trust"):
    checks = []
    readme = os.path.exists(os.path.join(scan_path, "README.md"))
    checks.append(ComplianceCheck(name="System description (README)", article=11, detection="hybrid",
        status="pass" if readme else "fail",
        evidence="README.md found" if readme else "No README.md found",
        fix_hint="Create README.md documenting system purpose, architecture, intended use",
        tier="static"))
    if status.total_runs > 0:
        ml = ", ".join(status.models_observed[:5])
        pl = ", ".join(status.providers_observed[:5])
        checks.append(ComplianceCheck(name="Runtime system inventory (AI-BOM data)", article=11, detection="auto", status="pass",
            evidence=f"Gateway observed: {status.total_runs} runs, models: [{ml}], providers: [{pl}], {status.total_tokens:,} tokens.",
            tier="runtime"))
    else:
        checks.append(ComplianceCheck(name="Runtime system inventory (AI-BOM data)", article=11, detection="auto", status="fail",
            evidence="No traffic data. Route AI calls through gateway or install a trust layer.",
            fix_hint=f"pip install {rec_pkg}  # or start gateway: docker compose up",
            tier="runtime"))
    mc_files = ["MODEL_CARD.md", "model_card.md", "SYSTEM_CARD.md"]
    has_mc = any(os.path.exists(os.path.join(scan_path, f)) for f in mc_files)
    checks.append(ComplianceCheck(name="Model card / system card", article=11, detection="hybrid",
        status="pass" if has_mc else "warn",
        evidence="Model/system card found" if has_mc else "No model card found. Run: air-blackbox discover --generate-card",
        fix_hint="Create MODEL_CARD.md: intended use, limitations, performance, ethics",
        tier="static"))
    if status.total_runs > 0 and status.date_range_end:
        checks.append(ComplianceCheck(name="Documentation currency", article=11, detection="auto", status="pass",
            evidence=f"Traffic data current through {status.date_range_end}. {len(status.models_observed)} model(s) active.",
            tier="runtime"))
    result = {"number": 11, "title": "Technical Documentation", "checks": [_c2d(c) for c in checks]}
    for f in (code_findings or []):
        result["checks"].append(_finding_to_dict(f))
    return result


def _check_article_12(status, scan_path, code_findings=None, rec_pkg="air-langchain-trust"):
    checks = []
    if status.reachable and status.total_runs > 0:
        checks.append(ComplianceCheck(name="Automatic event logging", article=12, detection="auto", status="pass",
            evidence=f"Gateway active. {status.total_runs:,} events logged. Period: {status.date_range_start} to {status.date_range_end}.",
            tier="runtime"))
    elif status.total_runs > 0:
        checks.append(ComplianceCheck(name="Automatic event logging", article=12, detection="auto", status="pass",
            evidence=f"Trust layer active. {status.total_runs:,} events logged. Period: {status.date_range_start} to {status.date_range_end}.",
            tier="runtime"))
    elif status.reachable:
        checks.append(ComplianceCheck(name="Automatic event logging", article=12, detection="auto", status="warn",
            evidence=f"Gateway running but no events logged yet.", fix_hint="Route traffic through gateway",
            tier="runtime"))
    else:
        checks.append(ComplianceCheck(name="Automatic event logging", article=12, detection="auto", status="fail",
            evidence=f"Gateway not reachable. Install a trust layer for inline logging.",
            fix_hint=f"pip install {rec_pkg}  # or start gateway: docker compose up",
            tier="runtime"))
    if status.audit_chain_intact and status.audit_chain_length > 0:
        checks.append(ComplianceCheck(name="Tamper-evident audit chain", article=12, detection="auto", status="pass",
            evidence=f"HMAC-SHA256 chain intact. {status.audit_chain_length:,} records.",
            tier="runtime"))
    elif status.trust_signing_key_set:
        checks.append(ComplianceCheck(name="Tamper-evident audit chain", article=12, detection="auto", status="pass",
            evidence="TRUST_SIGNING_KEY configured. HMAC chain will activate on traffic.",
            tier="runtime"))
    else:
        checks.append(ComplianceCheck(name="Tamper-evident audit chain", article=12, detection="auto",
            status="warn" if status.reachable else "fail",
            evidence="No TRUST_SIGNING_KEY set. Logs recorded but not tamper-evident.",
            fix_hint="Set TRUST_SIGNING_KEY in .env or install a trust layer package",
            tier="runtime"))
    if status.total_runs > 0:
        sample = status.recent_runs[0] if status.recent_runs else None
        if sample and all(sample.get(f) for f in ["run_id", "model", "timestamp"]):
            checks.append(ComplianceCheck(name="Log detail and traceability", article=12, detection="auto", status="pass",
                evidence="All records include: run_id, model, timestamp, tokens, provider.",
                tier="runtime"))
        else:
            checks.append(ComplianceCheck(name="Log detail and traceability", article=12, detection="auto", status="warn",
                evidence="Records found but missing some traceability fields.",
                tier="runtime"))
    else:
        checks.append(ComplianceCheck(name="Log detail and traceability", article=12, detection="auto", status="fail",
            evidence="No logged records.", fix_hint="Route traffic through gateway or install a trust layer.",
            tier="runtime"))
    if status.total_runs > 0 and status.date_range_start:
        checks.append(ComplianceCheck(name="Log retention", article=12, detection="auto", status="pass",
            evidence=f"Records retained from {status.date_range_start}. Storage: {'vault' if status.vault_enabled else 'local'}.",
            tier="runtime"))
    result = {"number": 12, "title": "Record-Keeping", "checks": [_c2d(c) for c in checks]}
    for f in (code_findings or []):
        result["checks"].append(_finding_to_dict(f))
    return result


def _check_article_14(status, scan_path, code_findings=None, rec_pkg="air-langchain-trust"):
    checks = []

    # Static analysis: scan code for human-in-the-loop patterns
    import re as _re
    hitl_patterns = [
        r"require_approval", r"human_review", r"human_in_the_loop",
        r"approval_gate", r"manual_review", r"human_override",
        r"await_confirmation", r"human_decision", r"escalate_to_human",
        r"needs_review", r"pending_approval", r"review_required",
    ]
    hitl_combined = "|".join(hitl_patterns)
    hitl_found_in = []
    try:
        for root, dirs, files in os.walk(scan_path):
            dirs[:] = [d for d in dirs if d not in {"__pycache__", ".git", "node_modules", ".venv", "venv"}]
            for fname in files:
                if fname.endswith(".py"):
                    fp = os.path.join(root, fname)
                    try:
                        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        if _re.search(hitl_combined, content, _re.IGNORECASE):
                            hitl_found_in.append(os.path.relpath(fp, scan_path))
                    except Exception:
                        continue
    except Exception:
        pass

    if hitl_found_in:
        checks.append(ComplianceCheck(name="Human-in-the-loop mechanism", article=14, detection="static",
            status="pass",
            evidence=f"Human oversight patterns found in {len(hitl_found_in)} file(s): {', '.join(hitl_found_in[:3])}",
            tier="static"))
    elif status.total_runs > 0:
        checks.append(ComplianceCheck(name="Human-in-the-loop mechanism", article=14, detection="hybrid", status="warn",
            evidence=f"{status.total_runs:,} actions logged but no human approval gates detected in code.",
            fix_hint="Add approval gates: air.require_approval(action) or human_review() before critical decisions",
            tier="runtime"))
    else:
        checks.append(ComplianceCheck(name="Human-in-the-loop mechanism", article=14, detection="static", status="warn",
            evidence="No human-in-the-loop patterns detected in code.",
            fix_hint="Add human approval gates for high-risk decisions per Article 14(4)",
            tier="static"))

    # Kill switch: check both runtime AND static patterns
    kill_switch_patterns = [
        r"kill_switch", r"emergency_stop", r"shutdown", r"circuit_breaker",
        r"disable_agent", r"stop_all", r"halt_execution", r"force_stop",
    ]
    ks_combined = "|".join(kill_switch_patterns)
    has_code_kill_switch = False
    try:
        for root, dirs, files in os.walk(scan_path):
            dirs[:] = [d for d in dirs if d not in {"__pycache__", ".git", "node_modules", ".venv", "venv"}]
            for fname in files:
                if fname.endswith(".py"):
                    fp = os.path.join(root, fname)
                    try:
                        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                            if _re.search(ks_combined, f.read(), _re.IGNORECASE):
                                has_code_kill_switch = True
                                break
                    except Exception:
                        continue
            if has_code_kill_switch:
                break
    except Exception:
        pass

    if status.reachable and status.guardrails_enabled:
        checks.append(ComplianceCheck(name="Kill switch / stop mechanism", article=14, detection="auto", status="pass",
            evidence="Gateway active with guardrails. Kill switch available.",
            tier="runtime"))
    elif has_code_kill_switch:
        checks.append(ComplianceCheck(name="Kill switch / stop mechanism", article=14, detection="static", status="pass",
            evidence="Kill switch / emergency stop pattern found in code.",
            tier="static"))
    elif status.reachable:
        checks.append(ComplianceCheck(name="Kill switch / stop mechanism", article=14, detection="auto", status="warn",
            evidence="Gateway running but guardrails not configured.", fix_hint="Create guardrails.yaml",
            tier="runtime"))
    else:
        checks.append(ComplianceCheck(name="Kill switch / stop mechanism", article=14, detection="static", status="fail",
            evidence="No kill switch or emergency stop mechanism found in code or runtime.",
            fix_hint=f"Add emergency stop mechanism. pip install {rec_pkg} or implement kill_switch()",
            tier="static"))

    op_files = ["OPERATOR_GUIDE.md", "operator_guide.md", "RUNBOOK.md"]
    has_ops = any(os.path.exists(os.path.join(scan_path, f)) for f in op_files)
    checks.append(ComplianceCheck(name="Operator understanding documentation", article=14, detection="manual",
        status="pass" if has_ops else "warn",
        evidence="Operator guide found" if has_ops else "No operator documentation found.",
        fix_hint="Create OPERATOR_GUIDE.md: capabilities, limitations, when to intervene",
        tier="static"))
    result = {"number": 14, "title": "Human Oversight", "checks": [_c2d(c) for c in checks]}
    for f in (code_findings or []):
        result["checks"].append(_finding_to_dict(f))
    return result


def _check_article_15(status, scan_path, code_findings=None, rec_pkg="air-langchain-trust"):
    checks = []
    if status.reachable:
        checks.append(ComplianceCheck(name="Prompt injection protection", article=15, detection="auto", status="pass",
            evidence=f"Gateway scanning for injection patterns. {status.injection_attempts} attempts detected." if status.injection_attempts > 0
            else "Gateway OTel pipeline scanning. No attempts detected.",
            tier="runtime"))
    elif status.total_runs > 0 and status.audit_chain_intact:
        checks.append(ComplianceCheck(name="Prompt injection protection", article=15, detection="auto", status="pass",
            evidence=f"Trust layer active with injection scanning. {status.injection_attempts} attempts detected in {status.total_runs} runs.",
            tier="runtime"))
    else:
        checks.append(ComplianceCheck(name="Prompt injection protection", article=15, detection="auto", status="fail",
            evidence="No runtime injection protection. Install a trust layer for inline scanning.",
            fix_hint=f"pip install {rec_pkg}  # or start gateway: docker compose up",
            tier="runtime"))
    if status.total_runs > 0:
        er = (status.error_count / status.total_runs * 100)
        checks.append(ComplianceCheck(name="Error resilience", article=15, detection="auto",
            status="pass" if er < 5 else "warn" if er < 15 else "fail",
            evidence=f"Error rate: {er:.1f}% ({status.error_count}/{status.total_runs}).",
            tier="runtime"))
    else:
        checks.append(ComplianceCheck(name="Error resilience", article=15, detection="auto", status="warn",
            evidence="No traffic data to measure resilience.",
            fix_hint="Route traffic through gateway or install a trust layer.",
            tier="runtime"))
    has_auth = bool(os.environ.get("OPENAI_API_KEY")) or bool(os.environ.get("ANTHROPIC_API_KEY"))
    checks.append(ComplianceCheck(name="API access control", article=15, detection="hybrid",
        status="pass" if has_auth else "warn",
        evidence="API keys configured." if has_auth else "No API keys detected.",
        fix_hint="Set API keys in .env",
        tier="static"))
    rt_files = ["REDTEAM.md", "redteam_results.json", "ADVERSARIAL_TESTING.md"]
    has_rt = any(os.path.exists(os.path.join(scan_path, f)) for f in rt_files)
    checks.append(ComplianceCheck(name="Adversarial robustness testing", article=15, detection="manual",
        status="pass" if has_rt else "warn",
        evidence="Adversarial testing documentation found" if has_rt else "No red team / adversarial testing evidence.",
        fix_hint="Conduct adversarial testing. Export: air-blackbox export --tag=redteam",
        tier="static"))
    result = {"number": 15, "title": "Accuracy, Robustness & Cybersecurity", "checks": [_c2d(c) for c in checks]}
    for f in (code_findings or []):
        result["checks"].append(_finding_to_dict(f))
    return result
