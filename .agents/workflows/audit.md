# Audit Workflow (/audit)

## Purpose
Inspect the SafePrompt workspace and project documentation to verify that the architecture, security controls, and code quality meet the defined specifications.

## Steps
1. **Workspace Inspection**
   - Verify the actual workspace root (`C:\Users\Admin\Desktop\Safe Prompt`).
   - List all project files and ensure the four project‑memory files exist.
2. **Architecture Review**
   - Check for components handling:
     - Sensitive‑data detection and masking
     - Outbound data flow to external AI services
     - Secure vault access and storage
     - RBAC enforcement
     - Prompt‑injection and policy‑bypass safeguards
     - Secret‑management (environment variables, `.env` exclusion)
     - Audit‑trail generation and integrity protection
3. **Security & Code‑Quality Findings**
   - Identify issues with severity levels (Critical, High, Medium, Low).
   - Provide evidence, file paths, and line numbers where applicable.
   - Distinguish **verified issues** from **potential risks**.
4. **Reporting**
   - Summarize findings in a markdown report.
   - Do **not** modify application code.
   - Suggest remediation actions, but apply changes only after explicit approval.

---
*This workflow is invoked via the `/audit` command and runs independently of other workflows.*
