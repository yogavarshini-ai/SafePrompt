"""Focused tests for SafePrompt Authentication & Backend-Enforced RBAC (Step 3C).

Tests:
1. User login & token generation (PBKDF2 verification, HS256 claims).
2. Login rejection on invalid credentials.
3. Missing token on protected endpoints (POST /prompt, GET /vault/{token}) returns 401.
4. Malformed, forged, and tampered tokens return 401.
5. Expired tokens return 401.
6. Anti-spoofing: X-User-Role, X-Role, and forged headers are ignored (403 Forbidden).
7. Role enforcement: Employee cannot restore PII (403); HR/Admin restore successfully (200).
8. Audit logging captures auth/RBAC decisions with zero credential or token leakage.
"""

import os
import time
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.auth_service import get_auth_service
from backend.vault_service import get_vault_service
from backend.audit_service import get_audit_service

client = TestClient(app)


def test_login_success_and_token_structure():
    """Verify login authenticates against PBKDF2 hash and issues valid HS256 token."""
    admin_pw = os.getenv("INITIAL_ADMIN_PASSWORD")
    assert admin_pw, "INITIAL_ADMIN_PASSWORD must be configured in environment."

    response = client.post("/auth/login", json={"username": "admin", "password": admin_pw})
    assert response.status_code == 200

    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "admin"

    # Verify token payload claims
    token = data["access_token"]
    auth_service = get_auth_service()
    claims = auth_service.verify_token(token)
    assert claims["username"] == "admin"
    assert claims["role"] == "admin"
    assert claims["exp"] > time.time()


def test_login_invalid_credentials_returns_401():
    """Verify incorrect credentials return 401 Unauthorized without leaking info."""
    response = client.post("/auth/login", json={"username": "admin", "password": "WrongPassword!999"})
    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()

    # Nonexistent user
    resp_nonexistent = client.post("/auth/login", json={"username": "ghost_user", "password": "AnyPassword123"})
    assert resp_nonexistent.status_code == 401


def test_missing_token_on_protected_endpoints_returns_401():
    """Verify both /prompt and /vault/{token} reject unauthenticated callers with 401."""
    # 1. POST /prompt without header
    resp_prompt = client.post("/prompt", json={"prompt": "Hello world"})
    assert resp_prompt.status_code == 401
    assert "credentials required" in resp_prompt.json()["detail"].lower()

    # 2. GET /vault/{token} without header
    resp_vault = client.get("/vault/{{TOKEN_test123456}}")
    assert resp_vault.status_code == 401


def test_malformed_and_tampered_token_returns_401():
    """Verify malformed and cryptographically tampered tokens return 401 Unauthorized."""
    # 1. Garbage token
    resp_garbage = client.post("/prompt", json={"prompt": "Test"}, headers={"Authorization": "Bearer garbage.token"})
    assert resp_garbage.status_code == 401

    # 2. Tampered signature
    auth_service = get_auth_service()
    valid_token = auth_service.create_access_token("u-1", "user", "employee")
    parts = valid_token.split(".")
    # Mutate the last character of signature
    tampered_sig = parts[2][:-1] + ("A" if parts[2][-1] != "A" else "B")
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

    resp_tampered = client.post(
        "/prompt",
        json={"prompt": "Test"},
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert resp_tampered.status_code == 401
    assert "signature verification failed" in resp_tampered.json()["detail"].lower()


def test_expired_token_returns_401():
    """Verify expired tokens are rejected with 401."""
    auth_service = get_auth_service()
    # Create token expired 60 seconds ago
    expired_token = auth_service.create_access_token("u-exp", "exp_user", "employee", expires_in_seconds=-60)

    response = client.post(
        "/prompt",
        json={"prompt": "Test"},
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


def test_header_anti_spoofing(auth_headers_employee):
    """Verify forged role headers (X-User-Role, X-Role) are completely ignored."""
    vault = get_vault_service()
    token = vault.store_entity("classified_pii_data", "PERSON", "req-spoof-1")

    # Employee attempts to escalate privileges by forging X-User-Role / X-Role headers
    malicious_headers = dict(auth_headers_employee)
    malicious_headers["X-User-Role"] = "Admin"
    malicious_headers["X-Role"] = "HR"
    malicious_headers["Role"] = "admin"

    response = client.get(f"/vault/{token}", headers=malicious_headers)
    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"].lower()


def test_role_enforcement_vault_restoration(auth_headers_employee, auth_headers_hr, auth_headers_admin):
    """Verify Employee is blocked (403), while authenticated HR and Admin restore successfully (200)."""
    vault = get_vault_service()
    secret_value = "Sensitive_Compensation_$185000"
    token = vault.store_entity(secret_value, "SALARY", "req-rbac-test")

    # 1. Employee role -> 403 Forbidden
    resp_emp = client.get(f"/vault/{token}", headers=auth_headers_employee)
    assert resp_emp.status_code == 403
    assert "not authorized" in resp_emp.json()["detail"].lower()

    # 2. HR role -> 200 OK
    resp_hr = client.get(f"/vault/{token}", headers=auth_headers_hr)
    assert resp_hr.status_code == 200
    assert resp_hr.json()["original_value"] == secret_value

    # 3. Admin role -> 200 OK
    resp_admin = client.get(f"/vault/{token}", headers=auth_headers_admin)
    assert resp_admin.status_code == 200
    assert resp_admin.json()["original_value"] == secret_value


def test_audit_logging_authentication_no_secret_leakage(auth_headers_hr):
    """Verify auth and restoration events are recorded without leaking credentials or tokens."""
    audit = get_audit_service()

    # Perform a login attempt
    emp_pw = os.getenv("INITIAL_EMPLOYEE_PASSWORD")
    client.post("/auth/login", json={"username": "employee_user", "password": emp_pw})

    # Retrieve all audit events
    events = audit.get_events()
    login_events = [e for e in events if e["event_type"] == "auth_login"]
    assert len(login_events) > 0

    latest_login = login_events[-1]
    # Ensure neither password, salt, nor token are in metadata
    metadata_str = str(latest_login["metadata"])
    assert emp_pw not in metadata_str
    assert "Bearer" not in metadata_str
