"""
HMAC-SHA256 tamper-evident audit chain.

Thin wrapper around the existing air-gate chain logic.
Every Event gets signed and linked to the previous record.

Chain formula:
    HMAC(key, previous_hash_bytes || JSON(record, sort_keys=True))

If anyone modifies a record after the fact, the chain breaks.
"""

from __future__ import annotations
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional, Dict

from air_trust.events import Event


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
        for col, col_type in [("agent_identity", "TEXT"), ("owner", "TEXT"), ("fingerprint", "TEXT")]:
            try:
                conn.execute(f"ALTER TABLE events ADD COLUMN {col} {col_type}")
            except sqlite3.OperationalError:
                pass  # Column already exists
        conn.execute("CREATE INDEX IF NOT EXISTS idx_owner ON events(owner)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_fingerprint ON events(fingerprint)")
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

        Returns the chain_hash (hex string).
        """
        with self._lock:
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
                   (run_id, trace_id, timestamp, type, framework, agent, model, status, chain_hash, agent_identity, owner, fingerprint, data)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
        """Verify the entire chain for tampering.

        Returns: {"valid": bool, "records": int, "broken_at": int|None}
        """
        conn = sqlite3.connect(self._db_path)
        rows = conn.execute(
            "SELECT chain_hash, data FROM events ORDER BY id ASC"
        ).fetchall()
        conn.close()

        prev = b"genesis"
        for i, (stored_hash, data_json) in enumerate(rows):
            record = json.loads(data_json)
            # Remove chain_hash from record before verifying
            record_clean = {k: v for k, v in record.items() if k != "chain_hash"}
            payload = prev + json.dumps(record_clean, sort_keys=True, default=str).encode()
            expected = hmac.new(self._key, payload, hashlib.sha256).hexdigest()

            if expected != stored_hash:
                return {"valid": False, "records": len(rows), "broken_at": i}
            prev = bytes.fromhex(stored_hash)

        return {"valid": True, "records": len(rows), "broken_at": None}

    @property
    def record_count(self) -> int:
        conn = sqlite3.connect(self._db_path)
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        conn.close()
        return count

    @property
    def current_hash(self) -> str:
        return self._prev_hash.hex()
