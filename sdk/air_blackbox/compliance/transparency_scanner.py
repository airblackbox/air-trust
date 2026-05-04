"""
Article 13 - Transparency and Provision of Information to Users.

EU AI Act Article 13 requires high-risk AI systems to be transparent about:
  13(1): Designed so deployers can interpret the output and use it appropriately
  13(2): Instructions for use - clear, complete, correct, and relevant info
  13(3)(a): Identity of provider
  13(3)(b): Characteristics, capabilities, and limitations of performance
  13(3)(c): Changes to the system after conformity assessment
  13(3)(d): Human oversight measures - technical measures to facilitate output interpretation
  13(3)(e): Computational and hardware resources needed
  13(3)(f): Expected lifetime, maintenance, and care

For AI agents specifically, Article 13 intersects with Article 50 (transparency
obligations for interactive AI) - users must be informed they are interacting
with an AI system.

Related NIST RFI Docket NIST-2025-0035 identifies agent identity disclosure as
a gap in current AI transparency practices.
"""

import os
import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class TransparencyFinding:
    """A single Article 13 transparency finding."""

    article: int
    name: str
    status: str  # "pass", "warn", "fail"
    evidence: str
    detection: str = "auto"
    fix_hint: str = ""
    files: list = field(default_factory=list)


# Disclosure patterns - code indicating the AI identifies itself to users
AI_DISCLOSURE_PATTERNS = [
    r"['\"].*?(?:I am an? AI|AI assistant|language model|this is an AI|powered by AI).*?['\"]",
    r"ai_disclosure",
    r"disclose_ai",
    r"identify_as_ai",
    r"system_prompt.*?AI",
    r"assistant_message.*?AI",
    r"AI_DISCLAIMER",
    r"AI_IDENTITY",
]

# Capability documentation patterns
CAPABILITY_DOC_PATTERNS = [
    r"capabilities\s*=",
    r"limitations\s*=",
    r"model_capabilities",
    r"system_capabilities",
    r"describe_capabilities",
    r"model_card",
    r"system_card",
    r"CAPABILITIES",
    r"LIMITATIONS",
]

# Instructions-for-use patterns - user-facing guidance
INSTRUCTIONS_PATTERNS = [
    r"INSTRUCTIONS_FOR_USE",
    r"user_guide",
    r"USER_GUIDE",
    r"how_to_use",
    r"usage_instructions",
    r"operator_instructions",
]

# Provider identity patterns
PROVIDER_IDENTITY_PATTERNS = [
    r"provider_name",
    r"provider_identity",
    r"system_provider",
    r"organization\s*[=:]",
    r"vendor\s*[=:]",
    r"contact_info",
    r"support_email",
    r"provider_contact",
]

# Output interpretation / confidence patterns
OUTPUT_INTERPRETATION_PATTERNS = [
    r"confidence_score",
    r"confidence_level",
    r"uncertainty",
    r"prediction_confidence",
    r"response_confidence",
    r"interpret_output",
    r"explain_output",
    r"rationale",
    r"reasoning_trace",
    r"chain_of_thought",
]


def scan_transparency(scan_path: str) -> List[TransparencyFinding]:
    """Scan a codebase for Article 13 transparency signals.

    Returns a list of findings covering the six main Article 13 checks:
      1. AI disclosure (13(3)(b) + Article 50)
      2. Capability and limitation documentation (13(3)(b))
      3. Instructions for use (13(2))
      4. Provider identity (13(3)(a))
      5. Output interpretation support (13(3)(d))
      6. Change logging (13(3)(c))
    """
    py_files = _find_python_files(scan_path)
    findings: List[TransparencyFinding] = []

    file_contents = {}
    for fp in py_files:
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                file_contents[fp] = f.read()
        except (OSError, UnicodeDecodeError):
            continue

    findings.append(_check_ai_disclosure(file_contents))
    findings.append(_check_capability_docs(file_contents, scan_path))
    findings.append(_check_instructions_for_use(scan_path))
    findings.append(_check_provider_identity(file_contents, scan_path))
    findings.append(_check_output_interpretation(file_contents))
    findings.append(_check_change_logging(scan_path))

    return findings


def _find_python_files(scan_path: str) -> List[str]:
    """Walk scan_path and return all .py files, skipping common junk dirs."""
    if os.path.isfile(scan_path) and scan_path.endswith(".py"):
        return [os.path.abspath(scan_path)]

    skip_dirs = {
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".env",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        "egg-info",
        ".eggs",
        "site-packages",
        "deprecated",
        "archived",
    }
    py_files: List[str] = []
    if not os.path.isdir(scan_path):
        return py_files
    for root, dirs, files in os.walk(scan_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.endswith(".egg-info")]
        for fname in files:
            if fname.endswith(".py"):
                py_files.append(os.path.join(root, fname))
    return py_files


def _check_ai_disclosure(file_contents: dict) -> TransparencyFinding:
    """Check whether the system discloses itself as an AI to users (Article 50 + 13(3)(b))."""
    combined = "|".join(AI_DISCLOSURE_PATTERNS)
    hits = [fp for fp, content in file_contents.items() if re.search(combined, content, re.IGNORECASE)]
    if hits:
        return TransparencyFinding(
            article=13,
            name="AI disclosure to users",
            status="pass",
            evidence=f"AI disclosure patterns found in {len(hits)} file(s)",
            files=hits,
        )
    if not file_contents:
        return TransparencyFinding(
            article=13,
            name="AI disclosure to users",
            status="warn",
            evidence="No Python files scanned - cannot verify AI disclosure",
            fix_hint="Article 50 requires users be informed they are interacting with AI",
        )
    return TransparencyFinding(
        article=13,
        name="AI disclosure to users",
        status="warn",
        evidence="No AI self-identification patterns detected in code",
        fix_hint='Add AI disclosure (e.g., system prompt: "I am an AI assistant...") to comply with Article 50',
    )


def _check_capability_docs(file_contents: dict, scan_path: str) -> TransparencyFinding:
    """Check for capability + limitation documentation (13(3)(b))."""
    doc_files = ["MODEL_CARD.md", "SYSTEM_CARD.md", "CAPABILITIES.md", "LIMITATIONS.md"]
    has_doc = any(os.path.exists(os.path.join(scan_path, f)) for f in doc_files)
    if has_doc:
        return TransparencyFinding(
            article=13,
            name="Capability and limitation documentation",
            status="pass",
            evidence="Model card or capability documentation found",
            detection="hybrid",
        )

    combined = "|".join(CAPABILITY_DOC_PATTERNS)
    hits = [fp for fp, content in file_contents.items() if re.search(combined, content)]
    if hits:
        return TransparencyFinding(
            article=13,
            name="Capability and limitation documentation",
            status="warn",
            evidence=f"Capability patterns in code ({len(hits)} file(s)) but no MODEL_CARD.md",
            fix_hint="Create MODEL_CARD.md documenting capabilities, limitations, and intended use",
            files=hits,
        )
    return TransparencyFinding(
        article=13,
        name="Capability and limitation documentation",
        status="fail",
        evidence="No MODEL_CARD.md, SYSTEM_CARD.md, or capability documentation found",
        fix_hint="Create MODEL_CARD.md per Article 13(3)(b): capabilities, limitations, intended use, known failure modes",
    )


def _check_instructions_for_use(scan_path: str) -> TransparencyFinding:
    """Check for instructions-for-use documentation (13(2))."""
    doc_files = [
        "OPERATOR_GUIDE.md",
        "USER_GUIDE.md",
        "INSTRUCTIONS.md",
        "RUNBOOK.md",
        "USAGE.md",
        "HOW_TO_USE.md",
    ]
    found = [f for f in doc_files if os.path.exists(os.path.join(scan_path, f))]
    if found:
        return TransparencyFinding(
            article=13,
            name="Instructions for use",
            status="pass",
            evidence=f"Operator or user guide documentation found: {', '.join(found)}",
            detection="hybrid",
        )
    # README is a weak fallback
    readme_path = None
    for candidate in ("README.md", "readme.md", "README.rst"):
        if os.path.exists(os.path.join(scan_path, candidate)):
            readme_path = candidate
            break
    if readme_path:
        return TransparencyFinding(
            article=13,
            name="Instructions for use",
            status="warn",
            evidence=f"Only {readme_path} found - Article 13(2) expects dedicated instructions for use",
            fix_hint="Create OPERATOR_GUIDE.md or USER_GUIDE.md with usage instructions, known limitations, and escalation procedures",
            detection="hybrid",
        )
    return TransparencyFinding(
        article=13,
        name="Instructions for use",
        status="fail",
        evidence="No operator guide, user guide, or README found",
        fix_hint="Create OPERATOR_GUIDE.md per Article 13(2): clear, complete, relevant usage instructions",
    )


def _check_provider_identity(file_contents: dict, scan_path: str) -> TransparencyFinding:
    """Check for provider identity disclosure (13(3)(a))."""
    combined = "|".join(PROVIDER_IDENTITY_PATTERNS)
    code_hits = [fp for fp, content in file_contents.items() if re.search(combined, content)]

    # Also check for doc-level provider identity
    doc_files = ["AUTHORS", "AUTHORS.md", "MAINTAINERS.md", "PROVIDER.md", "LICENSE"]
    has_doc = any(os.path.exists(os.path.join(scan_path, f)) for f in doc_files)

    if code_hits and has_doc:
        return TransparencyFinding(
            article=13,
            name="Provider identity disclosure",
            status="pass",
            evidence=f"Provider identity in code ({len(code_hits)} file(s)) and documentation",
            detection="hybrid",
            files=code_hits,
        )
    if has_doc:
        return TransparencyFinding(
            article=13,
            name="Provider identity disclosure",
            status="pass",
            evidence="Provider identity documented (AUTHORS/LICENSE/MAINTAINERS)",
            detection="hybrid",
        )
    if code_hits:
        return TransparencyFinding(
            article=13,
            name="Provider identity disclosure",
            status="warn",
            evidence=f"Provider patterns in code ({len(code_hits)} file(s)) but no AUTHORS or MAINTAINERS file",
            fix_hint="Add AUTHORS or MAINTAINERS.md with provider name, organization, and contact info",
            files=code_hits,
        )
    return TransparencyFinding(
        article=13,
        name="Provider identity disclosure",
        status="fail",
        evidence="No provider identity patterns in code or documentation",
        fix_hint="Add AUTHORS.md per Article 13(3)(a): provider name, organization, and contact information",
    )


def _check_output_interpretation(file_contents: dict) -> TransparencyFinding:
    """Check for output interpretation support - confidence, rationale, explanation (13(3)(d))."""
    combined = "|".join(OUTPUT_INTERPRETATION_PATTERNS)
    hits = [fp for fp, content in file_contents.items() if re.search(combined, content, re.IGNORECASE)]
    if hits:
        return TransparencyFinding(
            article=13,
            name="Output interpretation support",
            status="pass",
            evidence=f"Confidence or rationale patterns found in {len(hits)} file(s)",
            files=hits,
        )
    return TransparencyFinding(
        article=13,
        name="Output interpretation support",
        status="warn",
        evidence="No confidence scores, rationale, or explanation patterns detected",
        fix_hint="Return confidence scores or reasoning traces so operators can interpret outputs (Article 13(3)(d))",
    )


def _check_change_logging(scan_path: str) -> TransparencyFinding:
    """Check for change logging (13(3)(c)) - CHANGELOG or git history."""
    change_files = ["CHANGELOG.md", "CHANGELOG.rst", "CHANGES.md", "HISTORY.md", "RELEASES.md"]
    has_changelog = any(os.path.exists(os.path.join(scan_path, f)) for f in change_files)
    if has_changelog:
        return TransparencyFinding(
            article=13,
            name="Change logging and versioning",
            status="pass",
            evidence="CHANGELOG or release history file found",
            detection="hybrid",
        )
    if os.path.exists(os.path.join(scan_path, ".git")):
        return TransparencyFinding(
            article=13,
            name="Change logging and versioning",
            status="warn",
            evidence="Git history exists but no CHANGELOG.md documenting changes",
            fix_hint="Add CHANGELOG.md per Article 13(3)(c) to track changes after conformity assessment",
            detection="hybrid",
        )
    return TransparencyFinding(
        article=13,
        name="Change logging and versioning",
        status="fail",
        evidence="No CHANGELOG.md and no git history found",
        fix_hint="Initialize version control and add CHANGELOG.md per Article 13(3)(c)",
    )
