"""SafePrompt Structured Audit Logging Service with SHA-256 Hash Chaining.

Implements the audit-event schema defined in docs/architecture.md Section F.
Guarantees:
- Structured JSON audit records stored in SQLite.
- Immutable tamper-evident SHA-256 hash chaining.
- Safe for concurrent multi-threaded writes.
- Strict data privacy: Never logs raw prompts, original PII, API keys, or vault plaintext.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict

BACKEND_DIR = Path(__file__).resolve().parent
GENESIS_HASH = "0" * 64


class AuditMetadata(TypedDict, total=False):
    redacted_prompt: str
    placeholders: list[str]
    threat_type: str
    error_code: str | int
    details: str
    entity_types: list[str]


class AuditEvent(TypedDict):
    event_id: str
    timestamp: str
    request_id: str
    user_id: str
    role: str
    event_type: str
    policy_decision: str
    outcome: str
    metadata: AuditMetadata
    prev_hash: str
    integrity_hash: str


class AuditService:
    """Thread-safe structured audit logger with SHA-256 hash chaining."""

    def __init__(self, db_path: Path | str | None = None):
        if db_path is None:
            configured_path = os.getenv("AUDIT_DB_PATH")
            self.db_path = Path(configured_path) if configured_path else BACKEND_DIR / "audit.db"
        else:
            self.db_path = Path(db_path)

        self._lock = threading.Lock()
        self._init_database()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_database(self) -> None:
        """Create audit table and indexes if they do not exist."""
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    policy_decision TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    integrity_hash TEXT NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_event_id ON audit_events(event_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_request_id ON audit_events(request_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);")
            conn.commit()

    @staticmethod
    def _compute_canonical_payload(
        event_id: str,
        timestamp: str,
        request_id: str,
        user_id: str,
        role: str,
        event_type: str,
        policy_decision: str,
        outcome: str,
        metadata: dict[str, Any],
    ) -> str:
        """Serialize payload into a deterministic canonical JSON string."""
        payload = {
            "event_id": event_id,
            "timestamp": timestamp,
            "request_id": request_id,
            "user_id": user_id,
            "role": role,
            "event_type": event_type,
            "policy_decision": policy_decision,
            "outcome": outcome,
            "metadata": metadata,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def log_event(
        self,
        request_id: str,
        event_type: str,
        policy_decision: str = "allow",
        outcome: str = "success",
        user_id: str = "anonymous",
        role: str = "Employee",
        metadata: AuditMetadata | None = None,
    ) -> AuditEvent:
        """Record a structured audit event linked into the SHA-256 hash chain.
        
        Thread-safe and atomic. Never stores raw sensitive content.
        """
        clean_metadata = dict(metadata or {})
        # Safety guarantee: Never log raw prompts or keys
        for sensitive_key in ("prompt", "raw_prompt", "api_key", "secret", "key"):
            clean_metadata.pop(sensitive_key, None)

        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        with self._lock, self._get_connection() as conn:
            # Fetch the previous event's integrity hash
            cursor = conn.execute(
                "SELECT integrity_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            )
            last_row = cursor.fetchone()
            prev_hash = last_row["integrity_hash"] if last_row else GENESIS_HASH

            # Compute canonical payload and hash chain
            canonical_payload = self._compute_canonical_payload(
                event_id=event_id,
                timestamp=timestamp,
                request_id=request_id,
                user_id=user_id,
                role=role,
                event_type=event_type,
                policy_decision=policy_decision,
                outcome=outcome,
                metadata=clean_metadata,
            )

            chain_input = f"{prev_hash}{canonical_payload}".encode("utf-8")
            integrity_hash = hashlib.sha256(chain_input).hexdigest()

            metadata_json = json.dumps(clean_metadata, sort_keys=True)

            conn.execute(
                """
                INSERT INTO audit_events (
                    event_id, timestamp, request_id, user_id, role,
                    event_type, policy_decision, outcome, metadata_json,
                    prev_hash, integrity_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    timestamp,
                    request_id,
                    user_id,
                    role,
                    event_type,
                    policy_decision,
                    outcome,
                    metadata_json,
                    prev_hash,
                    integrity_hash,
                ),
            )
            conn.commit()

        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "request_id": request_id,
            "user_id": user_id,
            "role": role,
            "event_type": event_type,
            "policy_decision": policy_decision,
            "outcome": outcome,
            "metadata": clean_metadata,
            "prev_hash": prev_hash,
            "integrity_hash": integrity_hash,
        }

    def verify_chain(self) -> tuple[bool, str]:
        """Verify the cryptographic integrity of the entire audit hash chain.
        
        Returns (True, "Chain valid: N events verified") or (False, reason).
        Handles empty logs, broken links, payload tampering, and hash mismatches.
        """
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, event_id, timestamp, request_id, user_id, role,
                       event_type, policy_decision, outcome, metadata_json,
                       prev_hash, integrity_hash
                FROM audit_events ORDER BY id ASC
                """
            )
            rows = cursor.fetchall()

        if not rows:
            return True, "Chain valid: 0 events recorded."

        expected_prev_hash = GENESIS_HASH

        for idx, row in enumerate(rows):
            actual_prev_hash = row["prev_hash"]
            if actual_prev_hash != expected_prev_hash:
                return (
                    False,
                    f"Chain broken at record #{row['id']} (event_id={row['event_id']}): "
                    f"prev_hash '{actual_prev_hash}' does not match expected '{expected_prev_hash}'",
                )

            try:
                metadata = json.loads(row["metadata_json"])
            except Exception as exc:
                return (
                    False,
                    f"Malformed metadata at record #{row['id']}: {exc}",
                )

            canonical_payload = self._compute_canonical_payload(
                event_id=row["event_id"],
                timestamp=row["timestamp"],
                request_id=row["request_id"],
                user_id=row["user_id"],
                role=row["role"],
                event_type=row["event_type"],
                policy_decision=row["policy_decision"],
                outcome=row["outcome"],
                metadata=metadata,
            )

            expected_hash = hashlib.sha256(
                f"{expected_prev_hash}{canonical_payload}".encode("utf-8")
            ).hexdigest()

            if row["integrity_hash"] != expected_hash:
                return (
                    False,
                    f"Tampered record detected at #{row['id']} (event_id={row['event_id']}): "
                    f"stored integrity_hash does not match recomputed hash.",
                )

            expected_prev_hash = row["integrity_hash"]

        return True, f"Chain valid: {len(rows)} events successfully verified."

    def get_events(self, request_id: str | None = None) -> list[AuditEvent]:
        """Retrieve recorded audit events (optionally filtered by request_id)."""
        with self._lock, self._get_connection() as conn:
            if request_id:
                cursor = conn.execute(
                    """
                    SELECT event_id, timestamp, request_id, user_id, role,
                           event_type, policy_decision, outcome, metadata_json,
                           prev_hash, integrity_hash
                    FROM audit_events WHERE request_id = ? ORDER BY id ASC
                    """,
                    (request_id,),
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT event_id, timestamp, request_id, user_id, role,
                           event_type, policy_decision, outcome, metadata_json,
                           prev_hash, integrity_hash
                    FROM audit_events ORDER BY id ASC
                    """
                )
            rows = cursor.fetchall()

        events: list[AuditEvent] = []
        for r in rows:
            events.append({
                "event_id": r["event_id"],
                "timestamp": r["timestamp"],
                "request_id": r["request_id"],
                "user_id": r["user_id"],
                "role": r["role"],
                "event_type": r["event_type"],
                "policy_decision": r["policy_decision"],
                "outcome": r["outcome"],
                "metadata": json.loads(r["metadata_json"]),
                "prev_hash": r["prev_hash"],
                "integrity_hash": r["integrity_hash"],
            })
        return events


_audit_instance: AuditService | None = None
_instance_lock = threading.Lock()


def get_audit_service() -> AuditService:
    """Retrieve or create the singleton AuditService instance."""
    global _audit_instance
    if _audit_instance is None:
        with _instance_lock:
            if _audit_instance is None:
                _audit_instance = AuditService()
    return _audit_instance
