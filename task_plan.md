# Task Plan for SafePrompt Project

## Project Goal
Enterprise AI Security Gateway to detect, mask, and manage sensitive information in prompts.

## Phases & High‑Level Tasks

### Phase 0 – Blueprint (Discovery)
- Inspect existing workspace and documentation.
- Document requirements, data flow, security constraints.
- Identify open questions **(critical: resolve before marking Blueprint complete).**
- Record proposed technology choices (see `findings.md`).
- Define vault encryption design, request flow, RBAC matrix, STRIDE threat model, audit schema, and acceptance tests (see `docs/architecture.md`).

### Phase 1 – Link
- Review dependencies (FastAPI, React, Tailwind, SQLite, Pytest, etc.).
- Set up development environment, .env handling, and CI scaffolding.

### Phase 2 – Architect
- Design and document:
  - AES‑256‑GCM vault encryption and key‑management.
  - End‑to‑end request flow and API contracts.
  - RBAC permission matrix.
  - STRIDE threat model.
  - Audit‑event schema.
  - Acceptance test plan.
- Implement core masking, tokenization, vault storage, RBAC, audit logging.
- Write unit and integration tests.

### Phase 3 – Stylize
- Refine UI/CLI, error handling, documentation, logging format.
- Build React prototype with Tailwind.

### Phase 4 – Trigger
- Run full test suite, linting, build checks.
- Produce audit‑trail verification report.
- Update `progress.md` with final status.

## Acceptance Criteria (Non‑Exhaustive)
- Sensitive data is reliably detected and masked before any outbound AI request.
- Original values are stored only in an **encrypted vault** and restored after explicit RBAC‑checked authorization.
- RBAC enforces HR vs. Standard Employee permissions.
- Audit trail records every detection, mask, restore, and access attempt with tamper‑evidence.
- No secret values are hard‑coded; all secrets come from environment variables.
- All architectural decisions are documented in `docs/architecture.md` before any code is written.

---
*The Blueprint phase remains **open** until all pending design items in `findings.md` are approved.*

## Project Goal
Enterprise AI Security Gateway to detect, mask, and manage sensitive information in prompts.

## Phases & High-Level Tasks

### Phase 0 – Blueprint (Discovery)
- Inspect existing workspace and documentation.
- Document requirements, data flow, security constraints.
- Identify open questions **(critical: resolve before marking Blueprint complete).**
- Record proposed technology choices (see indings.md).

### Phase 1 – Link
- Review dependencies, environment configuration, storage back-ends.
- Establish a minimal working baseline.

### Phase 2 – Architect
- Implement core masking, tokenization, vault storage, RBAC, audit logging.
- Write unit and integration tests.

### Phase 3 – Stylize
- Refine UI/CLI, error handling, documentation, logging format.

### Phase 4 – Trigger
- Run full test suite, linting, build checks.
- Report results and update progress.

## Acceptance Criteria (Non-Exhaustive)
- Sensitive data is correctly identified and masked before outbound requests.
- Original values are stored securely and can be restored only after authorized approval.
- RBAC enforces role-based access to restoration and vault operations.
- Audit trail records all detections, masks, restorations, and access attempts.
- No secret values are hard-coded; environment variables or secret-manager used.

---
*The Blueprint phase remains **open** until all critical requirements and architectural decisions (see indings.md) are approved.*
