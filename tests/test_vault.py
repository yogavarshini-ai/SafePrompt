"""Focused tests for SafePrompt Encrypted SQLite Vault (Step 2).

Tests:
1. Encryption at rest (ciphertext != plaintext, raw PII absent from database).
2. Nonce length & cryptographic freshness (96-bit / 12-byte CSPRNG nonces).
3. Tamper detection (GCM authentication tag mismatch raises integrity error).
4. Request isolation (identical PII in separate requests yields distinct tokens).
5. Unauthorized restoration fails closed (unauthenticated & Employee roles rejected).
6. Public restoration endpoint is locked (HTTP 403 Forbidden).
7. End-to-end /prompt tokenization and schema preservation.
"""

import re
import sqlite3
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.vault_service import VaultService, VaultIntegrityError, get_vault_service

client = TestClient(app)

TEST_VAULT_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def temp_vault(tmp_path):
    """Provide an isolated VaultService instance backed by a temporary SQLite file."""
    db_file = tmp_path / "test_vault.db"
    return VaultService(db_path=db_file, key_hex=TEST_VAULT_KEY)


def test_encryption_at_rest_and_nonce_length(temp_vault):
    """Verify sensitive data is never stored in plaintext and nonces are 12 bytes."""
    secret_value = "CONFIDENTIAL_SALARY_250000"
    token = temp_vault.store_entity(
        original_value=secret_value,
        entity_type="SALARY",
        request_id="req-test-001",
    )

    assert re.match(r"^\{\{TOKEN_[0-9a-fA-F]{12}\}\}$", token)

    # Query SQLite database directly to inspect raw bytes at rest
    conn = sqlite3.connect(str(temp_vault.db_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT ciphertext, nonce FROM vault_entries WHERE token = ?", (token,))
    row = cursor.fetchone()
    conn.close()

    assert row is not None, "Vault entry was not found in database."
    raw_ciphertext = bytes(row["ciphertext"])
    raw_nonce = bytes(row["nonce"])

    # Nonce must be 96 bits (12 bytes)
    assert len(raw_nonce) == 12, f"Expected 12-byte nonce, got {len(raw_nonce)}"

    # Plaintext must NOT appear in raw ciphertext
    assert secret_value.encode("utf-8") not in raw_ciphertext
    assert raw_ciphertext != secret_value.encode("utf-8")


def test_fresh_nonce_per_encryption(temp_vault):
    """Verify distinct random nonces are generated for each encryption operation."""
    token1 = temp_vault.store_entity("test_email_1@corp.internal", "EMAIL", "req-1")
    token2 = temp_vault.store_entity("test_email_1@corp.internal", "EMAIL", "req-2")

    conn = sqlite3.connect(str(temp_vault.db_path))
    cursor = conn.cursor()
    cursor.execute("SELECT nonce FROM vault_entries WHERE token IN (?, ?)", (token1, token2))
    nonces = [bytes(r[0]) for r in cursor.fetchall()]
    conn.close()

    assert len(nonces) == 2
    assert nonces[0] != nonces[1], "Nonces must be unique per encryption operation."
    assert len(nonces[0]) == 12
    assert len(nonces[1]) == 12


def test_tamper_detection(temp_vault):
    """Verify modifying ciphertext in storage causes authentication tag validation failure."""
    token = temp_vault.store_entity("super_sensitive_api_key_xyz", "API_KEY", "req-tamper")

    # Tamper with ciphertext in the SQLite database
    conn = sqlite3.connect(str(temp_vault.db_path))
    cursor = conn.cursor()
    cursor.execute("SELECT ciphertext FROM vault_entries WHERE token = ?", (token,))
    original_ct = bytearray(cursor.fetchone()[0])

    # Flip the first byte of the ciphertext
    original_ct[0] ^= 0xFF
    cursor.execute("UPDATE vault_entries SET ciphertext = ? WHERE token = ?", (bytes(original_ct), token))
    conn.commit()
    conn.close()

    # Attempting to restore tampered entry must fail with VaultIntegrityError
    auth_hr = {"is_authenticated": True, "role": "HR"}
    with pytest.raises(VaultIntegrityError):
        temp_vault.restore_token(token, auth_context=auth_hr)


def test_request_isolation(temp_vault):
    """Verify identical PII values across different requests yield distinct request-scoped tokens."""
    same_email = "victim@example.com"
    token_req_a = temp_vault.store_entity(same_email, "EMAIL", request_id="request-AAA")
    token_req_b = temp_vault.store_entity(same_email, "EMAIL", request_id="request-BBB")

    assert token_req_a != token_req_b, "Tokens must be isolated and unique per request_id."


def test_unauthorized_restoration_fails_closed(temp_vault):
    """Verify restoration strictly fails closed for unauthenticated and unauthorized callers."""
    token = temp_vault.store_entity("Secret PII Data", "PERSON", request_id="req-auth-test")

    # 1. Unauthenticated (no context)
    with pytest.raises(PermissionError, match="Unauthenticated"):
        temp_vault.restore_token(token, auth_context=None)

    # 2. Unauthenticated flag
    with pytest.raises(PermissionError, match="Unauthenticated"):
        temp_vault.restore_token(token, auth_context={"is_authenticated": False, "role": "HR"})

    # 3. Standard Employee role (forbidden)
    with pytest.raises(PermissionError, match="not authorized"):
        temp_vault.restore_token(token, auth_context={"is_authenticated": True, "role": "Employee"})

    # 4. Authorized HR role (permitted)
    hr_restored = temp_vault.restore_token(token, auth_context={"is_authenticated": True, "role": "HR"})
    assert hr_restored == "Secret PII Data"

    # 5. Authorized Admin role (permitted)
    admin_restored = temp_vault.restore_token(token, auth_context={"is_authenticated": True, "role": "Admin"})
    assert admin_restored == "Secret PII Data"


def test_public_restoration_endpoint_fails_closed(auth_headers_employee):
    """Verify unauthenticated requests return 401 and Employee role returns 403 Forbidden."""
    # 1. Unauthenticated -> 401 Unauthorized
    resp_unauth = client.get("/vault/{{TOKEN_abcdef123456}}")
    assert resp_unauth.status_code == 401

    # 2. Authenticated as Employee -> 403 Forbidden
    resp_emp = client.get("/vault/{{TOKEN_abcdef123456}}", headers=auth_headers_employee)
    assert resp_emp.status_code == 403
    assert "not authorized" in resp_emp.json()["detail"].lower()


def test_prompt_tokenization_and_schema_preservation(auth_headers_employee):
    """Verify /prompt replaces PII with {{TOKEN_<hash>}} and preserves response schema."""
    sample_prompt = "Schedule meeting with Alice Cooper at alice@workplace.com or call 5551234567"
    response = client.post("/prompt", json={"prompt": sample_prompt}, headers=auth_headers_employee)
    assert response.status_code == 200

    data = response.json()
    assert "masked" in data
    assert "response" in data

    # Tokens must be in data["masked"]
    assert re.search(r"\{\{TOKEN_[0-9a-fA-F]{12}\}\}", data["masked"]) is not None

    # Original sensitive values must NOT be in masked prompt or AI response
    assert "Alice Cooper" not in data["masked"]
    assert "alice@workplace.com" not in data["masked"]
    assert "5551234567" not in data["masked"]

    assert "alice@workplace.com" not in data["response"]
    assert "5551234567" not in data["response"]
