# Debugging Workflow (/debugging)

## Purpose
Assist in diagnosing and fixing reported issues in the SafePrompt codebase while preserving existing functionality.

## Steps
1. **Issue Inspection**
   - Identify the reported symptom and the files involved.
   - Gather relevant context (error messages, stack traces, failing test output).
2. **Reproduction**
   - Attempt to reproduce the problem locally using the provided steps or test cases.
   - Record exact commands and environment details.
3. **Root‑Cause Analysis**
   - Examine the code paths implicated.
   - Locate the minimal code fragment responsible for the failure.
4. **Proposed Fix**
   - Describe the intended change, rationale, and any security implications.
   - Ensure the fix does not introduce regressions or break existing contracts.
5. **Implementation**
   - Apply the smallest, non‑destructive edit required.
   - Update or add regression tests where appropriate.
6. **Verification**
   - Run the relevant tests and any additional sanity checks.
   - Report actual results (pass/fail, output, logs).
7. **Documentation**
   - Document the change, including references to the issue and test coverage.
   - Update `progress.md` with the outcome.

---
*This workflow is invoked via the `/debugging` command and operates independently of the `/audit` workflow.*
