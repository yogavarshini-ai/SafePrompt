# SafePrompt – Project Constitution

## 1?? Project Overview
Enterprise AI Security Gateway that:
- Detects and masks sensitive data in prompts.
- Stores original values in a **secure local lookup vault**.
- Restores values only after proper **authorization**.
- Enforces **RBAC** and protects against prompt-injection & policy-bypass.
- Maintains comprehensive **audit trails** without exposing secrets.

## 2?? Source of Truth
All functional requirements, data flows, and security specifications are defined in the *SafePrompt PDF* (provided by the stakeholder). The PDF supersedes any other informal notes.

## 3?? Core Guarantees
- **Never hard-code secrets**; use environment variables or a secret-manager abstraction.
- **Never claim a test passed** unless it has been executed and verified.
- **Assumptions & proposed features** must be clearly marked and approved before implementation.
- **Destructive changes, deployments, or major architectural shifts** require explicit user approval.

## 4?? Operational Rules
- Detect & mask sensitive data **before** any outbound AI request.
- Store masked-original pairs in an **encrypted vault** (implementation to be decided).
- Restoration requires an **authorized role** and audit logging of the request.
- RBAC must be enforced on all vault operations and restoration endpoints.
- All actions (detections, masks, restores, access attempts) are recorded in an immutable audit log.
- The system must resist **prompt-injection** and **policy-bypass** attacks through input sanitization and policy enforcement layers.

## 5?? Documentation & Change Management
- All **requirements**, **design decisions**, and **open questions** are captured in indings.md.
- The **Blueprint phase** is complete only when every critical requirement and architectural decision in indings.md is resolved and approved.
- Updates to any of the four project-memory files must be version-controlled and reviewed.

## 6?? Assumptions & Open Questions (see indings.md for details)
- Language / framework selection.
- Secret-management mechanism.
- Vault storage backend.
- RBAC implementation (OAuth2, LDAP, custom roles, …).
- Deployment environment (Docker, on-prem, serverless, …).
- Test framework / CI pipeline.
- Audit-trail storage format.
- Compliance requirements (GDPR, HIPAA, etc.).

*All of the above will be clarified during the Blueprint phase before any code is written.*
