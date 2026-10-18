# Findings for SafePrompt Project

## Verified Observations
- Workspace root c:/Users/Admin/Desktop/Safe Prompt exists.
- Files present: 	ask_plan.md, indings.md, progress.md, gemini.md, and workflow definitions under .agents/workflows/.
- No source code, configuration files, or UI assets currently in the repository.

## Approved Technology Stack (confirmed by stakeholder)
- **Backend:** Python + FastAPI
- **Frontend:** React + Tailwind CSS
- **Storage:** SQLite for prototype metadata (encryption to be designed).
- **Secrets:** Environment variables; .env excluded from VCS, .env.example with placeholders.
- **RBAC:** HR and Standard Employee roles, enforced by backend.
- **Testing:** Pytest for backend, appropriate frontend test suite.
- **Deployment:** Local development first; Docker optional later.
- **Audit Trail:** Structured events with tamper-resistance strategy.
- **Compliance:** No formal certification required; privacy and security considerations documented.

## Pending Architectural Decisions (need design documentation)
- **Vault Encryption & Key Management** – algorithm, key storage, rotation.
- **Data Flow & API Contracts** – request/response schemas for masking, vault access, and external AI calls.
- **RBAC Permission Matrix** – specific permissions per role.
- **Threat Model** – STRIDE analysis of the system.
- **Masking & Restoration Process** – exact mechanisms, audit logging, and authorization checks.
- **Audit-Event Schema** – fields, redaction rules, integrity protection.
- **Compliance Considerations** – privacy impact assessment, data retention policy.

---
*These items will be addressed during the Blueprint phase before any code is written.*
