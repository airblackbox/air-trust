"""
CSA Agentic Trust Framework (ATF) conformance for air-trust.

ATF is an open specification from the Cloud Security Alliance for
Zero Trust governance of autonomous AI agents. It defines 5 core
elements and 4 maturity levels.

Reference: https://github.com/massivescale-ai/agentic-trust-framework

This module implements the Identity core element (Element 1) and
provides conformance checking for all 4 maturity levels.

                ATF Identity Requirements Matrix
    ┌─────┬──────────────────────┬────────┬────────┬────────┬───────────┐
    │ ID  │ Name                 │ Intern │ Junior │ Senior │ Principal │
    ├─────┼──────────────────────┼────────┼────────┼────────┼───────────┤
    │ I-1 │ Unique Identifier    │  MUST  │  MUST  │  MUST  │   MUST    │
    │ I-2 │ Credential Binding   │ SHOULD │  MUST  │  MUST  │   MUST    │
    │ I-3 │ Ownership Chain      │  MUST  │  MUST  │  MUST  │   MUST    │
    │ I-4 │ Purpose Declaration  │  MUST  │  MUST  │  MUST  │   MUST    │
    │ I-5 │ Capability Manifest  │ SHOULD │  MUST  │  MUST  │   MUST    │
    └─────┴──────────────────────┴────────┴────────┴────────┴───────────┘

Usage:

    from air_trust import AgentIdentity
    from air_trust.atf import conformance, level_compliant, conformance_statement

    identity = AgentIdentity(
        agent_name="my-agent",
        owner="jason@airblackbox.ai",
        purpose="Summarize customer support tickets",
        capabilities=["read:tickets", "generate:summary"],
    )

    # Check which ATF requirements are satisfied
    print(conformance(identity))
    # {"I-1": True, "I-2": True, "I-3": True, "I-4": True, "I-5": True}

    # Check compliance at a specific level
    print(level_compliant(identity, "intern"))    # True
    print(level_compliant(identity, "principal")) # True (same identity)

    # Export a conformance statement for auditors
    print(conformance_statement(identity))
"""

from __future__ import annotations
from typing import Dict, List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from air_trust.events import AgentIdentity


# ── ATF Constants ───────────────────────────────────────────────

LEVELS = ("intern", "junior", "senior", "principal")

LEVEL_DESCRIPTIONS = {
    "intern": "Observe + Report — continuous human oversight",
    "junior": "Recommend + Approve — human approves all actions",
    "senior": "Act + Notify — post-action notification",
    "principal": "Autonomous — strategic oversight only",
}

REQUIREMENT_NAMES = {
    "I-1": "Unique Identifier",
    "I-2": "Credential Binding",
    "I-3": "Ownership Chain",
    "I-4": "Purpose Declaration",
    "I-5": "Capability Manifest",
}

# MUST / SHOULD / MAY matrix per maturity level
# Values: "MUST", "SHOULD", "MAY"
LEVEL_MATRIX: Dict[str, Dict[str, str]] = {
    "intern": {
        "I-1": "MUST",
        "I-2": "SHOULD",
        "I-3": "MUST",
        "I-4": "MUST",
        "I-5": "SHOULD",
    },
    "junior": {
        "I-1": "MUST",
        "I-2": "MUST",
        "I-3": "MUST",
        "I-4": "MUST",
        "I-5": "MUST",
    },
    "senior": {
        "I-1": "MUST",
        "I-2": "MUST",
        "I-3": "MUST",
        "I-4": "MUST",
        "I-5": "MUST",
    },
    "principal": {
        "I-1": "MUST",
        "I-2": "MUST",
        "I-3": "MUST",
        "I-4": "MUST",
        "I-5": "MUST",
    },
}


# ── Conformance Checks ─────────────────────────────────────────

def check_i1_unique_identifier(identity: "AgentIdentity") -> bool:
    """I-1: Globally unique, immutable identifier.

    Satisfied when identity has a non-empty URN.
    """
    return bool(identity.urn and identity.urn.startswith("urn:"))


def check_i2_credential_binding(identity: "AgentIdentity") -> bool:
    """I-2: Agent identity bound to cryptographic credentials.

    Satisfied when identity has a fingerprint (SHA-256 derived
    from immutable fields).
    """
    return bool(identity.fingerprint and len(identity.fingerprint) >= 16)


def check_i3_ownership_chain(identity: "AgentIdentity") -> bool:
    """I-3: Clear documentation of ownership and operational responsibility.

    Satisfied when identity has a non-empty owner.
    Strengthened when org is also present.
    """
    return bool(identity.owner and len(identity.owner) > 0)


def check_i4_purpose_declaration(identity: "AgentIdentity") -> bool:
    """I-4: Documented intended use and operational scope.

    Satisfied when identity has a non-empty purpose.
    Falls back to description for backward compatibility.
    """
    return bool(
        (identity.purpose and len(identity.purpose) > 0)
        or (identity.description and len(identity.description) > 0)
    )


def check_i5_capability_manifest(identity: "AgentIdentity") -> bool:
    """I-5: Machine-readable list of claimed agent capabilities.

    Satisfied when identity has a non-empty capabilities list.
    Falls back to permissions for backward compatibility.
    """
    return bool(
        (identity.capabilities and len(identity.capabilities) > 0)
        or (identity.permissions and len(identity.permissions) > 0)
    )


CHECKS = {
    "I-1": check_i1_unique_identifier,
    "I-2": check_i2_credential_binding,
    "I-3": check_i3_ownership_chain,
    "I-4": check_i4_purpose_declaration,
    "I-5": check_i5_capability_manifest,
}


def conformance(identity: "AgentIdentity") -> Dict[str, bool]:
    """Return a dict showing which ATF Identity requirements are satisfied.

    Returns:
        {"I-1": True, "I-2": True, "I-3": True, "I-4": False, "I-5": True}
    """
    return {req: check(identity) for req, check in CHECKS.items()}


def level_compliant(identity: "AgentIdentity", level: str) -> bool:
    """Check if identity satisfies all MUST requirements for a maturity level.

    Args:
        identity: The AgentIdentity to check.
        level: One of "intern", "junior", "senior", "principal".

    Returns:
        True if all MUST requirements at that level are satisfied.
    """
    if level not in LEVEL_MATRIX:
        raise ValueError(f"Unknown ATF level: {level}. Must be one of {LEVELS}")

    results = conformance(identity)
    matrix = LEVEL_MATRIX[level]

    for req, requirement in matrix.items():
        if requirement == "MUST" and not results.get(req, False):
            return False
    return True


def highest_compliant_level(identity: "AgentIdentity") -> str:
    """Return the highest ATF level this identity satisfies.

    Returns one of the LEVELS, or "none" if not even intern-compliant.
    """
    # Check from highest to lowest
    for level in ("principal", "senior", "junior", "intern"):
        if level_compliant(identity, level):
            return level
    return "none"


def gaps(identity: "AgentIdentity", level: str = "intern") -> List[Tuple[str, str]]:
    """Return list of (requirement_id, name) tuples that are NOT satisfied
    for the given maturity level.

    Args:
        identity: The AgentIdentity to check.
        level: The target level (default: "intern").

    Returns:
        List of (req_id, requirement_name) for unmet MUST requirements.
    """
    if level not in LEVEL_MATRIX:
        raise ValueError(f"Unknown ATF level: {level}")

    results = conformance(identity)
    matrix = LEVEL_MATRIX[level]
    unmet = []

    for req, requirement in matrix.items():
        if requirement == "MUST" and not results.get(req, False):
            unmet.append((req, REQUIREMENT_NAMES[req]))
    return unmet


# ── Conformance Statement Export ───────────────────────────────

def conformance_statement(identity: "AgentIdentity") -> str:
    """Generate a human-readable ATF conformance statement.

    Suitable for inclusion in compliance reports and audit exports.
    """
    results = conformance(identity)
    highest = highest_compliant_level(identity)
    target = identity.atf_level

    lines = [
        "=" * 60,
        "CSA Agentic Trust Framework (ATF) Conformance Statement",
        "=" * 60,
        "",
        f"Agent:        {identity.agent_name}",
        f"URN:          {identity.urn}",
        f"Owner:        {identity.owner}",
        f"Org:          {identity.org or '(not specified)'}",
        f"Version:      {identity.agent_version}",
        f"External ID:  {identity.external_id or '(local only)'}",
        f"Target level: {target}",
        f"Actual level: {highest}",
        "",
        "Identity Core Element Conformance:",
        "",
    ]

    for req in ("I-1", "I-2", "I-3", "I-4", "I-5"):
        name = REQUIREMENT_NAMES[req]
        status = "PASS" if results[req] else "FAIL"
        required = LEVEL_MATRIX[target][req]
        lines.append(f"  {req}  {name:22} [{required:6}]  {status}")

    lines.extend([
        "",
        f"Conformance level achieved: {highest.upper()}",
    ])

    unmet = gaps(identity, target)
    if unmet:
        lines.append("")
        lines.append(f"Gaps to reach '{target}' level:")
        for req, name in unmet:
            lines.append(f"  - {req} {name}")
    else:
        lines.append(f"All MUST requirements for '{target}' level are satisfied.")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


def conformance_dict(identity: "AgentIdentity") -> dict:
    """Return full ATF conformance as a structured dict.

    Suitable for JSON export, regulatory submissions, and programmatic use.
    """
    results = conformance(identity)
    highest = highest_compliant_level(identity)
    target = identity.atf_level

    return {
        "framework": "CSA Agentic Trust Framework",
        "framework_version": "v0.9.1",
        "core_element": "Identity (Element 1)",
        "agent": {
            "name": identity.agent_name,
            "urn": identity.urn,
            "owner": identity.owner,
            "org": identity.org,
            "version": identity.agent_version,
            "external_id": identity.external_id,
        },
        "target_level": target,
        "achieved_level": highest,
        "requirements": {
            req: {
                "name": REQUIREMENT_NAMES[req],
                "required_at_target": LEVEL_MATRIX[target][req],
                "satisfied": results[req],
            }
            for req in ("I-1", "I-2", "I-3", "I-4", "I-5")
        },
        "gaps": [
            {"id": req, "name": name}
            for req, name in gaps(identity, target)
        ],
    }
