"""SafePrompt Authentication & RBAC Service.

Implements:
- Standard-compliant HS256 signed Bearer tokens (strict HMAC-SHA256, expiration, and claim checks).
- Secure user store backed by SQLite with PBKDF2-HMAC-SHA256 password hashing (100,000 iterations + 16-byte random salts).
- Zero hardcoded passwords in source code; initial accounts provisioned from environment variables.
- Anti-spoofing and server-side role enforcement.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(BACKEND_DIR / ".env")


class AuthenticationError(Exception):
    """Raised when authentication credentials are missing, invalid, expired, or forged."""
    pass


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s.encode("utf-8"))


class AuthService:
    """Thread-safe authentication service providing HS256 tokens and user credential management."""

    def __init__(self, db_path: Path | str | None = None, secret_key: str | None = None):
        if db_path is None:
            configured_path = os.getenv("AUTH_DB_PATH")
            self.db_path = Path(configured_path) if configured_path else BACKEND_DIR / "users.db"
        else:
            self.db_path = Path(db_path)

        # Resolve and validate AUTH_SECRET_KEY
        raw_secret = secret_key or os.getenv("AUTH_SECRET_KEY")
        if not raw_secret:
            raise RuntimeError(
                "AUTH_SECRET_KEY is not configured in backend/.env. Authentication cannot initialize."
            )

        # Ensure key is at least 32 bytes (256 bits)
        if len(raw_secret) >= 64:
            try:
                self._secret_bytes = bytes.fromhex(raw_secret.strip())
            except ValueError:
                self._secret_bytes = raw_secret.strip().encode("utf-8")
        else:
            self._secret_bytes = raw_secret.strip().encode("utf-8")

        if len(self._secret_bytes) < 32:
            raise RuntimeError("AUTH_SECRET_KEY must be at least 32 bytes for secure HS256 signing.")

        self._lock = threading.Lock()
        self._init_database()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_database(self) -> None:
        """Create users table and bootstrap initial credentials outside source code."""
        with self._lock, self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE COLLATE NOCASE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
            conn.commit()

            # Bootstrap initial accounts if table is empty
            cursor = conn.execute("SELECT COUNT(*) FROM users")
            count = cursor.fetchone()[0]
            if count == 0:
                self._provision_initial_users(conn)

    def _provision_initial_users(self, conn: sqlite3.Connection) -> None:
        """Provision initial Admin, HR, and Employee accounts from environment variables."""
        initial_accounts = [
            ("admin", os.getenv("INITIAL_ADMIN_PASSWORD"), "admin"),
            ("hr_specialist", os.getenv("INITIAL_HR_PASSWORD"), "hr"),
            ("employee_user", os.getenv("INITIAL_EMPLOYEE_PASSWORD"), "employee"),
            ("manager", os.getenv("INITIAL_HR_PASSWORD"), "hr"),
            ("worker", os.getenv("INITIAL_EMPLOYEE_PASSWORD"), "employee"),
        ]

        for username, plain_password, role in initial_accounts:
            if not plain_password:
                continue
            salt_hex, hash_hex = self.hash_password(plain_password)
            user_id = f"u-{role}-{uuid.uuid4().hex[:8]}"
            conn.execute(
                """
                INSERT OR IGNORE INTO users (id, username, password_hash, salt, role)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, username.lower(), hash_hex, salt_hex, role),
            )
        conn.commit()

    def sync_configured_users(self, overwrite_existing: bool = True) -> list[dict[str, str]]:
        """Safely provision or synchronize configured accounts from environment variables.
        
        Never prints or logs passwords, salts, or hashes.
        """
        initial_accounts = [
            ("admin", os.getenv("INITIAL_ADMIN_PASSWORD"), "admin"),
            ("hr_specialist", os.getenv("INITIAL_HR_PASSWORD"), "hr"),
            ("employee_user", os.getenv("INITIAL_EMPLOYEE_PASSWORD"), "employee"),
            ("manager", os.getenv("INITIAL_HR_PASSWORD"), "hr"),
            ("worker", os.getenv("INITIAL_EMPLOYEE_PASSWORD"), "employee"),
        ]

        results = []
        with self._lock, self._get_connection() as conn:
            for username, plain_password, role in initial_accounts:
                if not plain_password:
                    continue

                clean_user = username.strip().lower()
                cursor = conn.execute(
                    "SELECT id, username FROM users WHERE LOWER(username) = ?",
                    (clean_user,),
                )
                existing = cursor.fetchone()

                if existing and not overwrite_existing:
                    results.append({"username": clean_user, "role": role, "status": "existing (skipped)"})
                    continue

                salt_hex, hash_hex = self.hash_password(plain_password)
                if existing:
                    conn.execute(
                        "UPDATE users SET password_hash = ?, salt = ?, role = ? WHERE LOWER(username) = ?",
                        (hash_hex, salt_hex, role, clean_user),
                    )
                    results.append({"username": clean_user, "role": role, "status": "updated"})
                else:
                    user_id = f"u-{role}-{uuid.uuid4().hex[:8]}"
                    conn.execute(
                        """
                        INSERT INTO users (id, username, password_hash, salt, role)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (user_id, clean_user, hash_hex, salt_hex, role),
                    )
                    results.append({"username": clean_user, "role": role, "status": "created"})
            conn.commit()

        return results

    def update_user_password(self, username: str, new_password: str) -> bool:
        """Update password for an existing user or insert if missing.
        
        Preserves existing user ID and role. Never logs or prints password.
        """
        if not username or not new_password:
            raise ValueError("Username and password cannot be empty.")

        clean_user = username.strip().lower()
        salt_hex, hash_hex = self.hash_password(new_password)
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT id, role FROM users WHERE LOWER(username) = ?",
                (clean_user,),
            )
            row = cursor.fetchone()
            if row:
                conn.execute(
                    "UPDATE users SET password_hash = ?, salt = ? WHERE LOWER(username) = ?",
                    (hash_hex, salt_hex, clean_user),
                )
            else:
                role = (
                    "admin"
                    if "admin" in clean_user
                    else ("hr" if "hr" in clean_user or "manager" in clean_user else "employee")
                )
                user_id = f"u-{role}-{uuid.uuid4().hex[:8]}"
                conn.execute(
                    """
                    INSERT INTO users (id, username, password_hash, salt, role)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (user_id, clean_user, hash_hex, salt_hex, role),
                )
            conn.commit()
            return True

    @staticmethod
    def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
        """Hash password using PBKDF2-HMAC-SHA256 with 100,000 iterations and 16-byte random salt."""
        if not password:
            raise ValueError("Password cannot be empty.")
        if salt is None:
            salt = os.urandom(16)
        pw_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations=100_000,
        )
        return salt.hex(), pw_hash.hex()

    @staticmethod
    def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
        """Constant-time verification of password against salt and PBKDF2 hash."""
        try:
            salt = bytes.fromhex(salt_hex)
            computed = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt,
                iterations=100_000,
            ).hex()
            return hmac.compare_digest(computed, hash_hex)
        except Exception:
            return False

    def authenticate_user(self, username: str, password: str) -> dict[str, Any] | None:
        """Verify username and password against the secure user store."""
        if not username or not password:
            return None

        clean_user = username.strip().lower()
        with self._lock, self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT id, username, password_hash, salt, role FROM users WHERE LOWER(username) = ?",
                (clean_user,),
            )
            row = cursor.fetchone()

        if not row:
            return None

        if not self.verify_password(password, row["salt"], row["password_hash"]):
            return None

        return {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
        }

    def create_access_token(
        self,
        user_id: str,
        username: str,
        role: str,
        expires_in_seconds: int = 3600,
    ) -> str:
        """Create a signed HS256 Bearer token with expiration and claim validation."""
        header = {"alg": "HS256", "typ": "JWT"}
        now = int(time.time())
        payload = {
            "sub": user_id,
            "username": username,
            "role": role.lower(),
            "iat": now,
            "exp": now + expires_in_seconds,
        }

        encoded_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        encoded_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")

        signature = hmac.new(self._secret_bytes, signing_input, hashlib.sha256).digest()
        encoded_signature = _b64url_encode(signature)

        return f"{encoded_header}.{encoded_payload}.{encoded_signature}"

    def verify_token(self, token: str) -> dict[str, Any]:
        """Verify HS256 signature, expiration timestamp, and claims.
        
        Raises AuthenticationError if invalid, tampered, expired, or malformed.
        """
        if not token or not isinstance(token, str):
            raise AuthenticationError("Authentication token is missing or invalid.")

        parts = token.strip().split(".")
        if len(parts) != 3:
            raise AuthenticationError("Malformed token structure. Expected 3 segments.")

        encoded_header, encoded_payload, encoded_signature = parts

        # Verify signature
        signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
        expected_sig = hmac.new(self._secret_bytes, signing_input, hashlib.sha256).digest()

        try:
            actual_sig = _b64url_decode(encoded_signature)
        except Exception as exc:
            raise AuthenticationError("Invalid token signature encoding.") from exc

        if not hmac.compare_digest(expected_sig, actual_sig):
            raise AuthenticationError("Token signature verification failed.")

        # Decode and validate header
        try:
            header = json.loads(_b64url_decode(encoded_header).decode("utf-8"))
            if header.get("alg") != "HS256":
                raise AuthenticationError(f"Unsupported algorithm '{header.get('alg')}'.")
        except Exception as exc:
            raise AuthenticationError("Invalid token header.") from exc

        # Decode and validate payload claims
        try:
            payload = json.loads(_b64url_decode(encoded_payload).decode("utf-8"))
        except Exception as exc:
            raise AuthenticationError("Invalid token payload claims.") from exc

        # Verify expiration
        exp = payload.get("exp")
        if exp is None or not isinstance(exp, (int, float)):
            raise AuthenticationError("Token has no valid expiration claim.")

        if time.time() >= exp:
            raise AuthenticationError("Token has expired. Please re-authenticate.")

        # Verify subject and role
        if not payload.get("sub") or not payload.get("role"):
            raise AuthenticationError("Token payload is missing essential identity claims.")

        return payload


_auth_instance: AuthService | None = None
_auth_lock = threading.Lock()


def get_auth_service() -> AuthService:
    """Retrieve or create singleton AuthService instance."""
    global _auth_instance
    if _auth_instance is None:
        with _auth_lock:
            if _auth_instance is None:
                _auth_instance = AuthService()
    return _auth_instance
