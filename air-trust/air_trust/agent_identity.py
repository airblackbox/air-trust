"""
air_trust.agent_identity - verify agent identity continuity across the audit chain.

Answers the three NIST RFI Docket NIST-2025-0035 questions for AI agents:
  1. Is this the same agent instance that made previous decisions?
  2. If the agent was restarted or forked, is there a verifiable lineage?
  3. Can the agent's claimed memory state be trusted as unmodified?

Also detects "ghost agent" risk: multiple simultaneous instances of the same
agent writing to the same chain without awareness of each other.

Usage (from CLI):
    python3 -m air_trust agent-identity verify --agent botbotfromuk
    python3 -m air_trust agent-identity lineage --agent botbotfromuk
    python3 -m air_trust agent-identity ghosts
"""

import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class IdentityReport:
    """Report produced by verifying agent identity in a chain."""
    agent_name: Optional[str]
    total_records: int
    agent_records: int
    distinct_fingerprints: int
    fingerprint_list: list = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    sessions: list = field(default_factory=list)
    gaps: list = field(default_factory=list)
    ghost_risk: bool = False
    ghost_evidence: list = field(default_factory=list)
    verdict: str = "unknown"  # "pass", "warn", "fail"
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _load_records(db_path: str) -> list:
    """Load all records from the chain in order."""
    if not Path(db_path).exists():
        return []
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT id, data FROM events ORDER BY id ASC").fetchall()
    finally:
        conn.close()
    records = []
    for _id, data_json in rows:
        try:
            records.append(json.loads(data_json))
        except (json.JSONDecodeError, TypeError):
            continue
    return records


def _extract_identity(record: dict) -> dict:
    """Pull the identity block out of a record (if present)."""
    ident = record.get("identity") or {}
    if isinstance(ident, str):
        try:
            ident = json.loads(ident)
        except (json.JSONDecodeError, TypeError):
            ident = {}
    return ident if isinstance(ident, dict) else {}


def _parse_ts(value) -> Optional[datetime]:
    """Parse an ISO-ish timestamp string; return None if unparseable."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        s = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def verify_identity(
    db_path: str,
    agent_name: Optional[str] = None,
    max_gap_seconds: int = 3600,
) -> IdentityReport:
    """Verify cryptographic identity continuity for an agent across a chain.

    Args:
        db_path: path to the events.db SQLite file
        agent_name: filter records to this agent (None = all agents in chain)
        max_gap_seconds: timestamp gap above this is flagged as a possible
            restart boundary (default 1 hour)

    Returns:
        IdentityReport with verdict pass/warn/fail
    """
    records = _load_records(db_path)
    report = IdentityReport(
        agent_name=agent_name,
        total_records=len(records),
        agent_records=0,
        distinct_fingerprints=0,
    )

    if not records:
        report.verdict = "warn"
        report.notes.append(f"No records found at {db_path}")
        return report

    fingerprints_seen: dict = {}
    agent_records: list = []
    for rec in records:
        ident = _extract_identity(rec)
        name = ident.get("agent_name", "")
        fp = ident.get("fingerprint", "")
        if agent_name and name != agent_name:
            continue
        if not fp:
            continue
        agent_records.append(rec)
        if fp not in fingerprints_seen:
            fingerprints_seen[fp] = {
                "fingerprint": fp,
                "agent_name": name,
                "urn": ident.get("urn", ""),
                "first_record_id": rec.get("id") or rec.get("event_id") or "",
                "first_ts": rec.get("timestamp") or rec.get("ts") or "",
                "count": 0,
            }
        fingerprints_seen[fp]["count"] += 1
        fingerprints_seen[fp]["last_ts"] = rec.get("timestamp") or rec.get("ts") or ""

    report.agent_records = len(agent_records)
    report.distinct_fingerprints = len(fingerprints_seen)
    report.fingerprint_list = list(fingerprints_seen.values())

    if not agent_records:
        report.verdict = "warn"
        if agent_name:
            report.notes.append(
                f"No records found for agent '{agent_name}'. "
                "Did you mean one of the agents listed in fingerprint_list?"
            )
        else:
            report.notes.append("Records exist but none carry an identity block")
        return report

    # Timeline analysis
    timestamps = [_parse_ts(r.get("timestamp") or r.get("ts")) for r in agent_records]
    timestamps = [t for t in timestamps if t is not None]
    if timestamps:
        timestamps.sort()
        report.first_seen = timestamps[0].isoformat()
        report.last_seen = timestamps[-1].isoformat()

        # Session segmentation - gap > max_gap_seconds = new session
        sessions: list = []
        current = [timestamps[0]]
        for t in timestamps[1:]:
            delta = (t - current[-1]).total_seconds()
            if delta > max_gap_seconds:
                sessions.append({
                    "start": current[0].isoformat(),
                    "end": current[-1].isoformat(),
                    "records": len(current),
                })
                report.gaps.append({
                    "after": current[-1].isoformat(),
                    "before": t.isoformat(),
                    "gap_seconds": delta,
                })
                current = [t]
            else:
                current.append(t)
        sessions.append({
            "start": current[0].isoformat(),
            "end": current[-1].isoformat(),
            "records": len(current),
        })
        report.sessions = sessions

    # Ghost-agent detection - multiple fingerprints for same agent_name
    if agent_name:
        fps_for_name = [fp for fp, meta in fingerprints_seen.items()
                        if meta["agent_name"] == agent_name]
        if len(fps_for_name) > 1:
            report.ghost_risk = True
            report.ghost_evidence.append(
                f"Agent '{agent_name}' appears under {len(fps_for_name)} distinct fingerprints. "
                "This indicates the agent was re-keyed (new version/owner) OR multiple instances "
                "are running with different identities."
            )
    else:
        # Check across all agent_names for the same condition
        name_to_fps: dict = defaultdict(set)
        for fp, meta in fingerprints_seen.items():
            name_to_fps[meta["agent_name"]].add(fp)
        for name, fps in name_to_fps.items():
            if len(fps) > 1:
                report.ghost_risk = True
                report.ghost_evidence.append(
                    f"Agent '{name}' has {len(fps)} distinct fingerprints - possible ghost instances or version drift"
                )

    # Verdict logic
    if report.ghost_risk:
        report.verdict = "fail"
        report.notes.append(
            "Ghost agent risk detected. Verify only one instance is authorized to sign "
            "records for this agent_name, or explicitly version-bump when rotating keys."
        )
    elif agent_name and report.distinct_fingerprints == 1 and report.agent_records > 0:
        report.verdict = "pass"
        report.notes.append(
            f"Stable identity binding confirmed: {report.agent_records} records "
            f"signed by a single fingerprint across {len(report.sessions)} session(s)."
        )
    elif report.distinct_fingerprints == 1:
        report.verdict = "pass"
        report.notes.append("Chain shows a single consistent agent identity.")
    else:
        report.verdict = "warn"
        report.notes.append(
            f"{report.distinct_fingerprints} distinct agent identities in chain. "
            "Pass --agent <name> to verify a specific agent's continuity."
        )

    return report


def format_report(report: IdentityReport) -> str:
    """Render an IdentityReport as a human-readable string."""
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

    color = {"pass": GREEN, "warn": YELLOW, "fail": RED}.get(report.verdict, "")
    lines = []
    lines.append(f"{BOLD}Agent Identity Continuity Report{RESET}")
    lines.append("=" * 50)
    if report.agent_name:
        lines.append(f"Agent: {report.agent_name}")
    lines.append(f"Records inspected: {report.total_records}")
    lines.append(f"Records for this agent: {report.agent_records}")
    lines.append(f"Distinct fingerprints: {report.distinct_fingerprints}")
    if report.first_seen:
        lines.append(f"First seen: {report.first_seen}")
        lines.append(f"Last seen:  {report.last_seen}")
    if report.sessions:
        lines.append(f"Detected sessions: {len(report.sessions)}")
        for i, s in enumerate(report.sessions, 1):
            lines.append(
                f"  {i}. {s['start']} -> {s['end']} ({s['records']} records)"
            )
    if report.ghost_risk:
        lines.append(f"{RED}Ghost agent risk: YES{RESET}")
        for e in report.ghost_evidence:
            lines.append(f"  - {e}")
    else:
        lines.append("Ghost agent risk: no")
    lines.append("")
    lines.append(f"Verdict: {color}{report.verdict.upper()}{RESET}")
    for note in report.notes:
        lines.append(f"  {note}")
    return "\n".join(lines)
