# Security Audit Report – `pkg/httpapi/handlers.go`

## Scope
Only the file **`pkg/httpapi/handlers.go`** was examined.

## Findings
1. **High Risk – Password Hash Leakage (handleLogin)**
   * Lines 44‑47 return the full `user` object, which includes the `PasswordHash` field.
   * Exposing password hashes increases the attack surface for offline cracking and violates data minimisation.
2. **Medium Risk – Path Traversal (handleReportsList)**
   * The `category` parameter is used directly in a call to `filepath.Join(s.reportsPath, body.Category)` without sanitisation.
   * A malicious value such as `../secret` can expose arbitrary directories.
3. **Medium Risk – Missing Auth on Task List (handleListTasks)**
   * No authentication check; any request can retrieve all tasks.
4. **Low Risk – Wrong Status Code (handleAssignTask)**
   * Returns 403 when the user is nil, whereas 401 Unauthorized is appropriate.
5. **Low Risk – Informative Error Messages**
   * Several handlers return detailed error strings that could aid attackers.

## Recommendations
* Return a sanitized user payload in `handleLogin` (omit `PasswordHash`).
* Sanitize `body.Category`: use `filepath.Clean`, reject paths containing `..` or `/`.
* Add authentication checks to `handleListTasks` and similar endpoints.
* Use 401 for unauthenticated requests.
* Replace specific error messages with generic ones where feasible.

---
**Prepared by:** OpenCode Security Auditor
