"""
PII detection and prompt injection scanning.

Runs on every event before it hits the chain.
Zero dependencies — pure regex.
"""

from __future__ import annotations
import re
import time
from typing import List, Tuple

from air_trust.events import PIIAlert, InjectionAlert


# ── PII Patterns ─────────────────────────────────────────────
PII_PATTERNS: List[Tuple[str, str]] = [
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'email'),
    (r'\b\d{3}-\d{2}-\d{4}\b', 'ssn'),
    (r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b', 'phone'),
    (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', 'credit_card'),
    (r'\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b', 'iban'),
    (r'\b\d{3}-\d{3}-\d{3}\b', 'national_id'),
]

# ── Injection Patterns (weighted) ────────────────────────────
INJECTION_PATTERNS: List[Tuple[str, float]] = [
    (r'ignore (?:all )?previous instructions', 0.95),
    (r'you are now (?:a |an )?(?:new |different )', 0.95),
    (r'ignore (?:all )?above instructions', 0.90),
    (r'disregard (?:all )?(?:previous|prior|above)', 0.90),
    (r'system prompt:', 0.85),
    (r'new instructions:', 0.85),
    (r'override:', 0.80),
    (r'forget (?:everything|all|your) (?:previous|prior)', 0.80),
    (r'pretend you (?:are|have)', 0.75),
    (r'act as (?:if|though) you', 0.75),
    (r'do not follow', 0.70),
    (r'bypass (?:safety|security|filter)', 0.65),
    (r'jailbreak', 0.65),
    (r'DAN (?:mode|prompt)', 0.60),
    (r'developer mode', 0.55),
    (r'<\|system\|>', 0.50),
    (r'<\|im_start\|>', 0.50),
    (r'\\x[0-9a-f]{2}', 0.40),
    (r'base64:', 0.35),
    (r'eval\(', 0.30),
]


def scan_pii(text: str) -> List[PIIAlert]:
    """Scan text for PII patterns. Returns list of alerts."""
    if not text:
        return []
    alerts = []
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for pattern, pii_type in PII_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            alerts.append(PIIAlert(type=pii_type, count=len(matches), timestamp=ts))
    return alerts


def scan_injection(text: str) -> Tuple[List[InjectionAlert], float]:
    """Scan text for prompt injection attempts.

    Returns: (alerts, max_score)
        alerts: list of matched patterns
        max_score: highest confidence score (0.0 - 1.0)
    """
    if not text:
        return [], 0.0
    alerts = []
    max_score = 0.0
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for pattern, weight in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            alerts.append(InjectionAlert(pattern=pattern, weight=weight, timestamp=ts))
            max_score = max(max_score, weight)
    return alerts, max_score
