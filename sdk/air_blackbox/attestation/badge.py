"""
Badge generator -- creates SVG badges for attestation records.

Generates shields.io-style badges that can be embedded in READMEs,
websites, and marketing materials. Badges link to the verification URL.

Badge types:
  - AIR Attested (green): All checks passed
  - AIR Scanned (yellow): Some checks need attention
  - AIR Attested: Multi-Framework (blue): Passed across 2+ frameworks
"""

from typing import Optional

from .schema import AttestationRecord


# Badge colors
COLOR_GREEN = "#4c1"       # All checks passed
COLOR_YELLOW = "#dfb317"   # Some warnings
COLOR_RED = "#e05d44"      # Failures present
COLOR_BLUE = "#007ec6"     # Multi-framework
COLOR_GRAY = "#555"        # Label background


def _escape_xml(text: str) -> str:
    """Escape special characters for SVG/XML."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _estimate_text_width(text: str) -> int:
    """Rough estimate of text width in pixels (at ~6.5px per char)."""
    return int(len(text) * 6.5) + 10


def generate_badge_svg(
    label: str,
    message: str,
    color: str = COLOR_GREEN,
    link: str = "",
) -> str:
    """Generate a shields.io-style SVG badge.

    Args:
        label: Left side text (e.g. "AIR Attested").
        message: Right side text (e.g. "EU AI Act | 6/6").
        color: Hex color for the right side.
        link: URL the badge links to.

    Returns:
        SVG string.
    """
    label_esc = _escape_xml(label)
    message_esc = _escape_xml(message)

    label_width = _estimate_text_width(label)
    message_width = _estimate_text_width(message)
    total_width = label_width + message_width

    label_x = label_width / 2
    message_x = label_width + message_width / 2

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{label_esc}: {message_esc}">
  <title>{label_esc}: {message_esc}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="{COLOR_GRAY}"/>
    <rect x="{label_width}" width="{message_width}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text aria-hidden="true" x="{label_x}" y="15" fill="#010101" fill-opacity=".3">{label_esc}</text>
    <text x="{label_x}" y="14" fill="#fff">{label_esc}</text>
    <text aria-hidden="true" x="{message_x}" y="15" fill="#010101" fill-opacity=".3">{message_esc}</text>
    <text x="{message_x}" y="14" fill="#fff">{message_esc}</text>
  </g>
</svg>"""

    if link:
        svg = f'<a href="{_escape_xml(link)}">{svg}</a>'

    return svg


def badge_for_attestation(record: AttestationRecord) -> str:
    """Generate the appropriate badge SVG for an attestation record.

    Automatically picks the right label, message, and color based on
    the attestation scan results.

    Args:
        record: The attestation record to generate a badge for.

    Returns:
        SVG badge string.
    """
    scan = record.scan
    passed = scan.checks_passed
    total = scan.checks_total
    frameworks = scan.frameworks

    # Determine badge type and color
    if scan.checks_failed > 0:
        label = "AIR Scanned"
        color = COLOR_YELLOW
    elif len(frameworks) >= 2:
        label = "AIR Attested"
        color = COLOR_BLUE
    else:
        label = "AIR Attested"
        color = COLOR_GREEN

    # Build message
    if total > 0:
        fw_short = _framework_short(frameworks)
        message = f"{fw_short} | {passed}/{total}"
    else:
        message = "scanned"

    link = record.verification.verify_url or ""

    return generate_badge_svg(label=label, message=message, color=color, link=link)


def badge_markdown(record: AttestationRecord) -> str:
    """Generate markdown embed code for a badge.

    Args:
        record: The attestation record.

    Returns:
        Markdown string like: [![AIR Attested](badge_url)](verify_url)
    """
    att_id = record.attestation_id
    verify_url = record.verification.verify_url or f"https://airblackbox.ai/verify/{att_id}"
    badge_url = record.verification.badge_url or f"https://airblackbox.ai/badge/{att_id}.svg"

    scan = record.scan
    passed = scan.checks_passed
    total = scan.checks_total

    alt_text = f"AIR Attested {passed}/{total}"
    return f"[![{alt_text}]({badge_url})]({verify_url})"


def _framework_short(frameworks: list) -> str:
    """Shorten framework names for badge display."""
    name_map = {
        "eu": "EU",
        "eu_ai_act": "EU",
        "iso42001": "ISO",
        "iso_42001": "ISO",
        "nist": "NIST",
        "nist_rmf": "NIST",
        "colorado": "CO",
        "colorado_sb205": "CO",
    }
    shorts = []
    for fw in frameworks:
        short = name_map.get(fw.lower(), fw.upper()[:4])
        if short not in shorts:
            shorts.append(short)
    return "+".join(shorts[:4])  # Cap at 4 for badge width
