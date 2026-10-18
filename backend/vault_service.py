"""SafePrompt Encrypted SQLite Vault Service.

Provides AES-256-GCM authenticated encryption for sensitive prompt entities.
Never stores sensitive data in plaintext. Uses fresh 96-bit (12-byte) nonces per encryption.
Fails closed on unauthorized restoration requests or data tampering.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(BACKEND_DIR / ".env")


class VaultIntegrityError(Exception):
    """Raised when vault data fails cryptographic authentication tag verification."""
    pass


class VaultService:
    """Thread-safe encrypted SQLite vault utilizing AES-256-GCM."""

    def __init__(self, db_path: Path | str | None = None, key_hex: str | None = None):
        if db_path is None:
            configured_path = os.getenv("VAULT_DB_PATH")
            self.db_path = Path(configured_path) if configured_path else BACKEND_DIR / "vault.db"
        else:
            self.db_path = Path(db_path)

        # Resolve 32-byte AES-256 key
        raw_key = key_hex or os.getenv("VAULT_KEY")
        if not raw_key:
            raise RuntimeError(
                "VAULT_KEY environment variable is missing. A 32-byte hex key is required."
            )

        try:
            self._key = bytes.fromhex(raw_key.strip())
        except ValueError as exc:
            raise RuntimeError("VAULT_KEY must be a valid 64-character hexadecimal string.") from exc

        if len(self._key) != 32:
            raise RuntimeError(
                f"VAULT_KEY must be exactly 32 bytes (64 hex characters). Got {len(self._key)} bytes."
            )

        self._aesgcm = AESGCM(self._key)
        self._lock = threading.Lock()
        self._init_database()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_database(self) -> None:
        """Create vault tables and indexes if they do not exist."""
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vault_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token TEXT UNIQUE NOT NULL,
                    request_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    ciphertext BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ttl_seconds INTEGER DEFAULT 3600
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_vault_token ON vault_entries(token);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_vault_request_id ON vault_entries(request_id);"
            )
            conn.commit()

    def store_entity(
        self,
        original_value: str,
        entity_type: str,
        request_id: str,
        ttl_seconds: int = 3600,
    ) -> str:
        """Encrypt and store an original sensitive entity using AES-256-GCM.
        
        Returns a deterministic, request-scoped placeholder token.
        Never stores original_value in plaintext.
        """
        if not original_value:
            raise ValueError("original_value cannot be empty.")

        # Generate deterministic request-scoped token: {{TOKEN_<12-hex-hash>}}
        token_hash = hashlib.sha256(
            f"{request_id}:{entity_type}:{original_value}".encode("utf-8")
        ).hexdigest()[:12]
        token = f"{{{{TOKEN_{token_hash}}}}}"

        # Generate fresh cryptographically secure 96-bit (12-byte) nonce
        nonce = os.urandom(12)

        # Authenticate binding to request_id and token
        associated_data = f"{request_id}:{token}".encode("utf-8")
        plaintext_bytes = original_value.encode("utf-8")

        # AES-256-GCM encryption
        ciphertext = self._aesgcm.encrypt(nonce, plaintext_bytes, associated_data)

        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO vault_entries (token, request_id, entity_type, ciphertext, nonce, ttl_seconds)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(token) DO UPDATE SET
                    ciphertext = excluded.ciphertext,
                    nonce = excluded.nonce,
                    ttl_seconds = excluded.ttl_seconds;
                """,
                (token, request_id, entity_type, ciphertext, nonce, ttl_seconds),
            )
            conn.commit()

        # Record vault_store audit event (never records plaintext original_value)
        try:
            from backend.audit_service import get_audit_service
            get_audit_service().log_event(
                request_id=request_id,
                event_type="vault_store",
                policy_decision="allow",
                outcome="success",
                metadata={
                    "placeholders": [token],
                    "entity_types": [entity_type],
                    "details": f"Encrypted and stored sensitive token for {entity_type}.",
                },
            )
        except Exception:
            pass

        return token

    def _decrypt_token(self, token: str) -> str:
        """Internal decryption with GCM authentication tag verification."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT request_id, ciphertext, nonce FROM vault_entries WHERE token = ?",
                (token,),
            )
            row = cursor.fetchone()

        if not row:
            raise KeyError(f"Token '{token}' was not found in the vault.")

        request_id = row["request_id"]
        ciphertext = bytes(row["ciphertext"])
        nonce = bytes(row["nonce"])

        associated_data = f"{request_id}:{token}".encode("utf-8")

        try:
            decrypted_bytes = self._aesgcm.decrypt(nonce, ciphertext, associated_data)
            return decrypted_bytes.decode("utf-8")
        except InvalidTag as exc:
            raise VaultIntegrityError(
                f"Integrity verification failed for token '{token}'. Data has been tampered with or key is invalid."
            ) from exc

    def restore_token(self, token: str, auth_context: dict[str, Any] | None = None) -> str:
        """Restore an original value from the vault.
        
        Enforces fail-closed authorization:
        Unauthenticated callers and unauthorized roles (e.g., Standard Employee) are strictly rejected.
        Only verified HR or Admin roles may access raw vault values.
        """
        # Fail closed if auth context is missing or unauthenticated
        if not auth_context or not auth_context.get("is_authenticated", False):
            try:
                from backend.audit_service import get_audit_service
                get_audit_service().log_event(
                    request_id="vault-restore",
                    event_type="vault_retrieve",
                    policy_decision="block",
                    outcome="error",
                    user_id=auth_context.get("user_id", "unauthenticated") if auth_context else "anonymous",
                    role=auth_context.get("role", "none") if auth_context else "none",
                    metadata={
                        "placeholders": [token],
                        "error_code": 401,
                        "details": "Restoration rejected: unauthenticated request.",
                    },
                )
            except Exception:
                pass
            raise PermissionError(
                "Access denied: Unauthenticated request. Vault restoration requires verified credentials."
            )

        role = str(auth_context.get("role", "")).lower()
        if role not in {"hr", "admin"}:
            try:
                from backend.audit_service import get_audit_service
                get_audit_service().log_event(
                    request_id="vault-restore",
                    event_type="vault_retrieve",
                    policy_decision="block",
                    outcome="error",
                    user_id=auth_context.get("user_id", "unauthorized_user"),
                    role=auth_context.get("role", "Employee"),
                    metadata={
                        "placeholders": [token],
                        "error_code": 403,
                        "details": f"Restoration rejected: role '{auth_context.get('role')}' unauthorized.",
                    },
                )
            except Exception:
                pass
            raise PermissionError(
                f"Access denied: Role '{auth_context.get('role')}' is not authorized to restore vault entries."
            )

        restored_value = self._decrypt_token(token)

        try:
            from backend.audit_service import get_audit_service
            get_audit_service().log_event(
                request_id="vault-restore",
                event_type="vault_retrieve",
                policy_decision="allow",
                outcome="success",
                user_id=auth_context.get("user_id", "authorized_user"),
                role=auth_context.get("role", "HR"),
                metadata={
                    "placeholders": [token],
                    "details": "Authorized vault restoration succeeded.",
                },
            )
        except Exception:
            pass

        return restored_value

    def restore_text(self, text: str, auth_context: dict[str, Any] | None = None) -> str:
        """Replace all tokens in a text string with their decrypted original values if authorized."""
        import re

        tokens = set(re.findall(r"\{\{TOKEN_[0-9a-fA-F]+\}\}", text))
        if not tokens:
            return text

        result = text
        for token in tokens:
            original = self.restore_token(token, auth_context=auth_context)
            result = result.replace(token, original)
        return result


_vault_instance: VaultService | None = None
_instance_lock = threading.Lock()


def get_vault_service() -> VaultService:
    """Retrieve or create the singleton VaultService instance."""
    global _vault_instance
    if _vault_instance is None:
        with _instance_lock:
            if _vault_instance is None:
                _vault_instance = VaultService()
    return _vault_instance
