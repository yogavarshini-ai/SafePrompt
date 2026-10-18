# Architecture Document for SafePrompt Blueprint

## A. Overview
This document captures the finalized Blueprint for the SafePrompt Enterprise AI Security Gateway prototype. It consolidates design decisions, security considerations, and acceptance tests before any code is written.

---

## B. Vault Design (AES‑256‑GCM)
- **Algorithm:** AES‑256‑GCM provided by the `cryptography` library (or equivalent).
- **Key Storage:** Keys are loaded from environment variables (`VAULT_KEY`) or a protected OS key‑ring (e.g., Windows Credential Manager). Keys are **never** committed to source control.
- **Nonce/IV:** A fresh 96‑bit nonce is generated per encryption operation using a CSPRNG and stored alongside the ciphertext.
- **Key Rotation:** Periodic rotation procedure – generate a new key, re‑encrypt existing vault entries in a background job, and deprecate the old key after successful migration.
- **Backup & Recovery:** Encrypted vault file (`vault.db`) can be backed up; restoration requires the current key. If the key is lost, vault data is unrecoverable – this is documented as a risk.
- **Failure Handling:** On decryption failure (authentication tag mismatch), the operation aborts, the event is logged as a security incident, and no plaintext is returned.
- **Note:** Encryption **does not replace** RBAC; access to vault APIs is still gated by role checks.

---

## C. Request Flow & API Contracts
1. **Receive Request** – `POST /v1/prompt` with JSON body `{ "prompt": "string", "metadata": {…} }`.
2. **Authenticate** – Validate JWT or API key; extract `user_id` and `role` (HR or Employee).
3. **Detect Sensitive Data** – Run detection engine; produce list of `SensitiveItem`s `{ "type": "PII|COMP", "value": "..." }`.
4. **Policy Evaluation** – Apply policy rules; if prohibited, return `403 Forbidden` with reason.
5. **Masking** – Replace each sensitive value with a deterministic placeholder `{{TOKEN_<hash>}}` scoped to the request ID.
6. **Vault Store** – Insert `(placeholder, original_value, ttl, request_id)` into encrypted SQLite vault.
7. **Forward** – Send sanitized prompt to external AI (`POST https://api.external.ai/v1/completions`).
8. **Response Handling** – Receive AI response; if the response contains placeholders that need restoration, check user role and explicit authorization before lookup.
9. **Restoration** – If authorized, retrieve original values from vault, replace placeholders, and return the final response.
10. **Audit Logging** – Emit a structured audit event (see Section F).

### API Endpoints (proposed, not implemented)
- `POST /v1/prompt` – Main entry point for masked prompt submission.
- `GET /v1/vault/{placeholder}` – Retrieve original value (RBAC‑checked).
- `POST /v1/vault/rotate` – Trigger key rotation (admin only).
- `GET /v1/health` – Health check.

### Error Cases
- `401 Unauthorized` – Missing/invalid authentication.
- `403 Forbidden` – Policy violation or insufficient RBAC permission.
- `422 Unprocessable Entity` – Malformed request or detection failure.
- `500 Internal Server Error` – Vault encryption/decryption error (audit logged).

---

## D. RBAC Permission Matrix
| Role | Permissions |
|------|-------------|
| **Standard Employee** | • Submit prompts (`/v1/prompt`).\n• Receive masked AI responses.\n*Cannot* retrieve raw vault entries or view any PII/COMP data. |
| **HR** | • All Employee permissions.\n• Query aggregated salary trends (e.g., `/v1/reports/salary‑trend`).\n• Retrieve **anonymized** PII for approved reports.\n*Cannot* directly request raw individual compensation records. |
| **Admin** (future) | • Manage key rotation, vault backups, audit log access. |

- Default deny: if role is missing or unrecognized, the request is rejected with `401`.
- All checks are enforced **backend‑side**; the frontend must not rely on client‑side gating.

---

## E. STRIDE Threat Model
| Component | Threat | Impact | Mitigation | Test Example |
|-----------|--------|--------|------------|-------------|
| **Authentication** | Spoofing (stolen token) | Unauthorized access to vault/API | Short‑lived JWTs, signature verification, revocation list | Attempt API call with expired/modified token → `401` |
| **Request/Response Handling** | Tampering (man‑in‑the‑middle) | Modified prompts or responses | TLS everywhere, integrity‑protected AES‑GCM for vault data | Capture traffic → ensure TLS handshake fails without cert |
| **Audit Logging** | Repudiation | Users deny actions | Append‑only logs with hash chaining (e.g., SHA‑256 of previous entry) | Verify log entry chain breaks when entry altered |
| **Vault Storage** | Information Disclosure | Leakage of plaintext secrets | Encrypt with AES‑GCM, separate key storage, RBAC checks | Attempt to read `vault.db` directly → ciphertext unreadable |
| **API Service** | Denial of Service | Service unavailable | Rate limiting, request size caps, graceful degradation | Flood `/v1/prompt` → service returns 429 after threshold |
| **RBAC Enforcement** | Elevation of Privilege | HR role abused to access raw data | Strict role checks, audit all elevated requests | HR user tries `/v1/vault/{placeholder}` → `403` |

---

## F. Audit‑Event Schema
```json
{
  "event_id": "uuid",
  "timestamp": "ISO8601",
  "request_id": "uuid",
  "user_id": "string",
  "role": "HR|Employee|Admin",
  "event_type": "prompt_received|mask_applied|vault_store|vault_retrieve|policy_block|audit_failure",
  "policy_decision": "allow|block",
  "outcome": "success|error",
  "metadata": {
    "redacted_prompt": "string",   // placeholders only, no raw PII
    "placeholders": ["{{TOKEN_abc}}"],
    "error_code": "optional",
    "details": "optional free text"
  },
  "integrity_hash": "hex" // hash of the previous event + current payload
}
```
- **No raw secrets** are stored; `metadata.redacted_prompt` contains only placeholders.
- **Integrity:** Each event includes a SHA‑256 hash of the previous event’s JSON concatenated with the current payload, creating a tamper‑evident chain.
- **Access Restrictions:** Only users with `Admin` role can read full audit logs; HR can view redacted summaries.
- **Retention:** Logs are retained for 90 days (configurable) and then archived with encryption.

---

## G. Acceptance Test Plan
| Test | Description |
|------|-------------|
| **Sensitive‑Value Detection** | Submit a prompt containing a mock SSN; verify response contains a placeholder, not the raw SSN. |
| **Masking in Outbound Payload** | Intercept the call to the external AI (mock) and assert the payload does not contain any raw sensitive strings. |
| **RBAC Enforcement – Employee** | Employee role attempts to retrieve a vault entry → expect `403`. |
| **RBAC Enforcement – HR** | HR role requests an aggregated report (allowed) and attempts raw retrieval (blocked). |
| **Encryption / Decryption** | Store a known value in the vault, retrieve it, and verify it matches; tamper with ciphertext and ensure decryption fails with audit event. |
| **Invalid Auth Tag** | Modify the authentication tag of a stored entry and attempt decryption → operation aborts, audit logged. |
| **Prompt‑Injection Mitigation** | Send a crafted prompt attempting to bypass policy (e.g., `ignore_security=true`); system should block and log `policy_block`. |
| **Audit Redaction** | Verify audit logs contain placeholders only, not original PII. |
| **External AI Error Handling** | Mock external AI to return timeout; system should return a `502 Bad Gateway` with proper audit entry. |
| **Rate‑Limiting / DoS** | Flood the `/v1/prompt` endpoint; ensure the service responds with `429 Too Many Requests` after the configured threshold. |

---

## H. Open Decisions / Next Steps
- Finalize key‑management implementation (OS key‑ring vs. external secret manager).
- Choose concrete JSON schema definitions for `SensitiveItem` and request/response models.
- Define the exact format of the integrity hash chain (e.g., concatenate `event_id` + `timestamp`).
- Determine audit‑log storage location (file vs. database) and encryption at rest.
- Agree on the retention period policy for audit logs.
- Produce UI mockups for the React prototype.

*All the above architecture, flow, and security design are documented here and referenced from the project‑memory files. No code has been written yet.*
