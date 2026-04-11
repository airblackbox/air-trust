"""
HMAC-SHA256 tamper-evident audit chain with Ed25519 handoff signing.

Every Event gets HMAC-signed and linked to the previous record (integrity).
Handoff records also get Ed25519-signed for cross-agent identity proof (v1.2).

Chain formula (integrity, v1.0):
    HMAC(key, previous_hash_bytes || JSON(record, sort_keys=True))

Handoff signing (identity, v1.2):
    Ed25519.sign(agent_private_key, interaction_id|counterparty_id|payload_hash|nonce|type|timestamp)

If anyone modifies a record after the fact, the HMAC chain breaks.
If anyone forges a handoff record, the Ed25519 signature fails.
"""

from __future__ import annotations
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from contextvars import ContextVar
from pathlib import Path
from typing import Optional, Dict

from air_trust.events import Event

# v1.1: Active session ID propagation.
# When code runs inside an air_trust.session() block, this ContextVar
# holds the session_id so that ALL events (including adapter events)
# automatically inherit it. Set by AirTrustSession.__enter__,
# cleared by AirTrustSession.__exit__.
_active_session_id: ContextVar[Optional[str]] = ContextVar(
    "_active_session_id", default=None
)


class AuditChain:
    """Local-first, zero-dependency HMAC-SHA256 audit chain.

    Writes to SQLite (default) or .air.json files.
    All signing happens in-process. No network calls. No API keys.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        signing_key: Optional[str] = None,
        runs_dir: Optional[str] = None,
    ):
        # SQLite is the default — single file, no setup
        self._db_path = db_path or os.path.expanduser("~/.air-trust/events.db")
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)

        # Optional: also write .air.json files for legacy compatibility
        self._runs_dir = runs_dir
        if runs_dir:
            os.makedirs(runs_dir, exist_ok=True)

        # Signing key — from env, argument, or auto-generated
        self._key = (
            signing_key
            or os.environ.get("AIR_TRUST_KEY")
            or self._ensure_key()
        ).encode()

        self._prev_hash = b"genesis"
        self._count = 0
        self._lock = threading.Lock()

        # v1.1: per-session sequence counters  {session_id: next_seq}
        self._session_seqs: dict = {}

        # Initialize SQLite
        self._init_db()
        self._load_last_hash()

    def _ensure_key(self) -> str:
        """Generate and persist a signing key on first run."""
        key_path = os.path.expanduser("~/.air-trust/signing.key")
        if os.path.exists(key_path):
            return Path(key_path).read_text().strip()
        key = hashlib.sha256(os.urandom(32)).hexdigest()
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        Path(key_path).write_text(key)
        os.chmod(key_path, 0o600)  # owner-read only
        return key

    def _init_db(self):
        conn = sqlite3.connect(self._db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                trace_id TEXT,
                timestamp TEXT,
                type TEXT,
                framework TEXT,
                agent TEXT,
                model TEXT,
                status TEXT,
                chain_hash TEXT,
                agent_identity TEXT,
                owner TEXT,
                fingerprint TEXT,
                data JSON,
                created_at REAL DEFAULT (strftime('%s', 'now'))
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_framework ON events(framework)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_type ON events(type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent ON events(agent)")
        # Migration: add columns if they don't exist (for existing DBs)
        # Must run BEFORE creating indexes on these columns
        for col, col_type in [("agent_identity", "TEXT"), ("owner", "TEXT"), ("fingerprint", "TEXT"),
                               ("session_seq", "INTEGER"), ("prev_session_seq", "INTEGER"),
                               ("interaction_id", "TEXT"), ("counterparty_id", "TEXT"),
                               ("payload_hash", "TEXT"), ("nonce", "TEXT"),
                               ("signature", "TEXT"), ("signature_alg", "TEXT"),
                               ("public_key", "TEXT")]:
            try:
                conn.execute(f"ALTER TABLE events ADD COLUMN {col} {col_type}")
            except sqlite3.OperationalError:
                pass  # Column already exists
        conn.execute("CREATE INDEX IF NOT EXISTS idx_owner ON events(owner)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_fingerprint ON events(fingerprint)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_session_id ON events(trace_id)")  # session_id stored in data
        conn.execute("CREATE INDEX IF NOT EXISTS idx_interaction_id ON events(interaction_id)")
        conn.commit()
        conn.close()

    def _load_last_hash(self):
        """Resume the chain from the last stored hash."""
        conn = sqlite3.connect(self._db_path)
        row = conn.execute(
            "SELECT chain_hash FROM events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row and row[0]:
            self._prev_hash = bytes.fromhex(row[0])
        conn.close()

    def write(self, event: Event) -> str:
        """Sign an event and append it to the chain.

        If the event has a session_id, auto-assigns session_seq and
        prev_session_seq for v1.1 completeness tracking.

        Returns the chain_hash (hex string).
        """
        with self._lock:
            # v1.1: auto-inherit active session_id if event doesn't have one
            if event.session_id is None:
                active_sid = _active_session_id.get()
                if active_sid is not None:
                    event.session_id = active_sid

            # v1.1: assign session sequence numbers if event has a session_id
            if event.session_id is not None:
                sid = event.session_id
                if sid not in self._session_seqs:
                    self._session_seqs[sid] = 0
                seq = self._session_seqs[sid]
                event.session_seq = seq
                event.prev_session_seq = seq - 1
                self._session_seqs[sid] = seq + 1

            # v1.2: auto-sign handoff records with Ed25519
            _HANDOFF_TYPES = {"handoff_request", "handoff_ack", "handoff_result"}
            if event.type in _HANDOFF_TYPES and event.signature is None:
                # Only sign if the event has the required handoff fields
                if (event.interaction_id and event.counterparty_id
                        and event.payload_hash and event.nonce
                        and event.identity and event.identity.fingerprint):
                    try:
                        from air_trust.keys import build_signing_payload, sign as ed25519_sign, load_public_key_hex
                        signing_data = build_signing_payload(
                            event.interaction_id,
                            event.counterparty_id,
                            event.payload_hash,
                            event.nonce,
                            event.type,
                            event.timestamp,
                        )
                        event.signature = ed25519_sign(event.identity.fingerprint, signing_data)
                        event.signature_alg = "ed25519"
                        event.public_key = load_public_key_hex(event.identity.fingerprint)
                    except (FileNotFoundError, ImportError):
                        pass  # No key available — skip auto-signing

            record = event.to_dict()

            # Compute HMAC-SHA256
            payload = self._prev_hash + json.dumps(
                record, sort_keys=True, default=str
            ).encode()
            chain_hash = hmac.new(self._key, payload, hashlib.sha256).hexdigest()

            # Update event with hash
            event.chain_hash = chain_hash
            record["chain_hash"] = chain_hash

            # Extract identity fields for indexed columns
            agent_identity = None
            owner = None
            fingerprint = None
            if hasattr(event, 'identity') and event.identity is not None:
                agent_identity = event.identity.agent_name
                owner = event.identity.owner
                fingerprint = event.identity.fingerprint

            # Write to SQLite
            conn = sqlite3.connect(self._db_path)
            conn.execute(
                """INSERT INTO events
                   (run_id, trace_id, timestamp, type, framework, agent, model, status,
                    chain_hash, agent_identity, owner, fingerprint,
                    session_seq, prev_session_seq,
                    interaction_id, counterparty_id, payload_hash, nonce,
                    signature, signature_alg, public_key, data)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.run_id,
                    event.trace_id,
                    event.timestamp,
                    event.type,
                    event.framework,
                    event.agent,
                    event.model,
                    event.status,
                    chain_hash,
                    agent_identity,
                    owner,
                    fingerprint,
                    event.session_seq,
                    event.prev_session_seq,
                    event.interaction_id,
                    event.counterparty_id,
                    event.payload_hash,
                    event.nonce,
                    event.signature,
                    event.signature_alg,
                    event.public_key,
                    json.dumps(record, default=str),
                ),
            )
            conn.commit()
            conn.close()

            # Optionally write .air.json
            if self._runs_dir:
                fname = f"{event.timestamp.replace(':', '-')}_{event.type}_{chain_hash[:8]}.air.json"
                fpath = os.path.join(self._runs_dir, fname)
                with open(fpath, "w") as f:
                    json.dump(record, f, indent=2, default=str)

            self._prev_hash = bytes.fromhex(chain_hash)
            self._count += 1
            return chain_hash

    def verify(self) -> Dict:
        """Verify the entire chain: integrity, completeness, and handoffs.

        Returns a dict with three sections:
            {
                "integrity": {"valid": bool, "records": int, "broken_at": int|None},
                "completeness": {...},
                "handoffs": {
                    "interactions_checked": int,
                    "interactions_complete": int,
                    "interactions_incomplete": int,
                    "issues": [...]
                }
            }

        For backward compatibility, the top-level dict also has "valid",
        "records", and "broken_at" mirroring the integrity section.
        """
        conn = sqlite3.connect(self._db_path)
        rows = conn.execute(
            "SELECT chain_hash, data FROM events ORDER BY id ASC"
        ).fetchall()
        conn.close()

        # ── Integrity check (v1.0) ────────────────────────────────
        integrity = {"valid": True, "records": len(rows), "broken_at": None}
        all_records = []

        prev = b"genesis"
        for i, (stored_hash, data_json) in enumerate(rows):
            record = json.loads(data_json)
            all_records.append(record)
            record_clean = {k: v for k, v in record.items() if k != "chain_hash"}
            payload = prev + json.dumps(record_clean, sort_keys=True, default=str).encode()
            expected = hmac.new(self._key, payload, hashlib.sha256).hexdigest()

            if expected != stored_hash:
                integrity = {"valid": False, "records": len(rows), "broken_at": i}
                break
            prev = bytes.fromhex(stored_hash)

        # ── Completeness check (v1.1) ────────────────────────────
        completeness = self._check_completeness(all_records)

        # ── Handoff check (v1.2) ─────────────────────────────────
        handoffs = self._check_handoffs(all_records)

        return {
            # v1.2 structured output
            "integrity": integrity,
            "completeness": completeness,
            "handoffs": handoffs,
            # v1.0 backward compat (mirror integrity at top level)
            "valid": integrity["valid"],
            "records": integrity["records"],
            "broken_at": integrity["broken_at"],
        }

    def _check_completeness(self, records: list) -> Dict:
        """Check session completeness across all records.

        Groups records by session_id, then checks each session for:
        - sequence gaps
        - duplicate sequence numbers
        - rewinds (counter went backward)
        - missing session_start / session_end
        """
        # Group records by session_id (skip unscoped records)
        sessions: dict = {}  # session_id -> list of (global_index, record)
        for i, record in enumerate(records):
            sid = record.get("session_id")
            if sid is None:
                continue
            if sid not in sessions:
                sessions[sid] = []
            sessions[sid].append((i, record))

        issues = []
        sessions_complete = 0

        for sid, session_records in sessions.items():
            session_issues = []

            # Check lifecycle: first record should be session_start
            first_record = session_records[0][1]
            if first_record.get("type") != "session_start":
                session_issues.append({
                    "session_id": sid,
                    "issue": "missing_session_start",
                    "record_index": session_records[0][0],
                })

            # Check lifecycle: last record should be session_end
            last_record = session_records[-1][1]
            if last_record.get("type") != "session_end":
                session_issues.append({
                    "session_id": sid,
                    "issue": "missing_session_end",
                    "last_seq": last_record.get("session_seq"),
                })

            # Check sequence continuity
            prev_seq = None
            seen_seqs = set()
            for idx, record in session_records:
                seq = record.get("session_seq")
                if seq is None:
                    continue  # v1.0 record mixed in, skip

                # Duplicate check
                if seq in seen_seqs:
                    session_issues.append({
                        "session_id": sid,
                        "issue": "duplicate",
                        "session_seq": seq,
                        "record_index": idx,
                    })
                seen_seqs.add(seq)

                if prev_seq is not None:
                    expected = prev_seq + 1
                    if seq < prev_seq:
                        # Rewind
                        session_issues.append({
                            "session_id": sid,
                            "issue": "rewind",
                            "expected_seq": expected,
                            "actual_seq": seq,
                            "record_index": idx,
                        })
                    elif seq != expected:
                        # Gap
                        session_issues.append({
                            "session_id": sid,
                            "issue": "gap",
                            "expected_seq": expected,
                            "actual_seq": seq,
                            "record_index": idx,
                        })

                prev_seq = seq

            if len(session_issues) == 0:
                sessions_complete += 1
            issues.extend(session_issues)

        return {
            "sessions_checked": len(sessions),
            "sessions_complete": sessions_complete,
            "sessions_incomplete": len(sessions) - sessions_complete,
            "issues": issues,
        }

    def _check_handoffs(self, records: list) -> Dict:
        """Check handoff protocol compliance across all records (v1.2).

        Groups records by interaction_id, then checks each handoff for:
        - Structural completeness (request + ack + result)
        - Ed25519 signature validity
        - Payload hash matching between request and ack
        - Counterparty matching
        - Nonce uniqueness
        """
        _HANDOFF_TYPES = {"handoff_request", "handoff_ack", "handoff_result"}

        # Group handoff records by interaction_id
        interactions: dict = {}  # interaction_id -> {type: record}
        all_nonces: list = []    # for global uniqueness check

        for i, record in enumerate(records):
            rtype = record.get("type", "")
            iid = record.get("interaction_id")
            if rtype not in _HANDOFF_TYPES or iid is None:
                continue
            if iid not in interactions:
                interactions[iid] = {}
            interactions[iid][rtype] = (i, record)

            nonce = record.get("nonce")
            if nonce:
                all_nonces.append((nonce, iid, i))

        if not interactions:
            return {
                "interactions_checked": 0,
                "interactions_complete": 0,
                "interactions_incomplete": 0,
                "issues": [],
            }

        issues = []
        interactions_complete = 0

        # Check nonce uniqueness across all handoff records
        seen_nonces: dict = {}  # nonce -> (interaction_id, record_index)
        for nonce, iid, idx in all_nonces:
            if nonce in seen_nonces:
                issues.append({
                    "interaction_id": iid,
                    "issue": "duplicate_nonce",
                    "severity": "warn",
                    "nonce": nonce,
                    "record_index": idx,
                    "first_seen_index": seen_nonces[nonce][1],
                })
            else:
                seen_nonces[nonce] = (iid, idx)

        for iid, type_map in interactions.items():
            interaction_issues = []
            has_request = "handoff_request" in type_map
            has_ack = "handoff_ack" in type_map
            has_result = "handoff_result" in type_map

            # ── Structural completeness ───────────────────────────
            if has_request and not has_ack and not has_result:
                interaction_issues.append({
                    "interaction_id": iid,
                    "issue": "missing_ack",
                    "severity": "warn",
                })
            elif has_request and has_ack and not has_result:
                interaction_issues.append({
                    "interaction_id": iid,
                    "issue": "missing_result",
                    "severity": "info",
                })
            elif not has_request and (has_ack or has_result):
                interaction_issues.append({
                    "interaction_id": iid,
                    "issue": "orphaned_response",
                    "severity": "warn",
                })

            # ── Signature verification ────────────────────────────
            try:
                from air_trust.keys import build_signing_payload, verify_signature
                _can_verify_sigs = True
            except ImportError:
                _can_verify_sigs = False

            for rtype, (idx, record) in type_map.items():
                sig = record.get("signature")
                pub = record.get("public_key")
                if sig and pub and _can_verify_sigs:
                    signing_data = build_signing_payload(
                        record.get("interaction_id", ""),
                        record.get("counterparty_id", ""),
                        record.get("payload_hash", ""),
                        record.get("nonce", ""),
                        record.get("type", ""),
                        record.get("timestamp", ""),
                    )
                    if not verify_signature(pub, sig, signing_data):
                        interaction_issues.append({
                            "interaction_id": iid,
                            "issue": "signature_invalid",
                            "severity": "fail",
                            "record_type": rtype,
                            "record_index": idx,
                        })

            # ── Payload hash matching (request vs ack) ────────────
            if has_request and has_ack:
                req_hash = type_map["handoff_request"][1].get("payload_hash")
                ack_hash = type_map["handoff_ack"][1].get("payload_hash")
                if req_hash and ack_hash and req_hash != ack_hash:
                    interaction_issues.append({
                        "interaction_id": iid,
                        "issue": "payload_mismatch",
                        "severity": "warn",
                        "request_hash": req_hash,
                        "ack_hash": ack_hash,
                    })

            # ── Counterparty matching ─────────────────────────────
            if has_request and has_ack:
                req_counterparty = type_map["handoff_request"][1].get("counterparty_id")
                ack_public_key = type_map["handoff_ack"][1].get("public_key")
                # The request's counterparty_id should match the ack signer's identity
                # We check if the request named Agent B as counterparty,
                # and the ack's signer public key is consistent
                req_public_key = type_map["handoff_request"][1].get("public_key")
                ack_counterparty = type_map["handoff_ack"][1].get("counterparty_id")
                # ack's counterparty_id should reference the requester's fingerprint
                # We can check identity field if present
                req_identity = type_map["handoff_request"][1].get("identity")
                ack_identity = type_map["handoff_ack"][1].get("identity")
                if req_identity and ack_counterparty:
                    req_fp = req_identity.get("fingerprint", "") if isinstance(req_identity, dict) else ""
                    if req_fp and ack_counterparty != req_fp:
                        interaction_issues.append({
                            "interaction_id": iid,
                            "issue": "counterparty_mismatch",
                            "severity": "warn",
                            "detail": "ack counterparty_id does not match request agent fingerprint",
                        })

            if len(interaction_issues) == 0 and has_request and has_ack and has_result:
                interactions_complete += 1
            issues.extend(interaction_issues)

        return {
            "interactions_checked": len(interactions),
            "interactions_complete": interactions_complete,
            "interactions_incomplete": len(interactions) - interactions_complete,
            "issues": issues,
        }

    @property
    def record_count(self) -> int:
        conn = sqlite3.connect(self._db_path)
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        conn.close()
        return count

    @property
    def current_hash(self) -> str:
        return self._prev_hash.hex()
