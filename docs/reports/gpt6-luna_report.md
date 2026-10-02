Security audit report
Project: tasks-demo
Scope: All non-ignored project source, schema, deployment files, and documentation. No files changed.
Date: 2026-09-24

High risk

1. SQL injection in task creation — pkg/store/store.go:168-172
   Task name is concatenated into the INSERT statement. An authenticated caller controls this value, allowing SQL syntax injection and potentially database modification.
   Fix: use a parameter placeholder for name, as used for the other values.

2. Missing admin authorization on task assignment — pkg/httpapi/handlers.go:156-162
   The handler only rejects a missing user; any authenticated non-admin can reassign any task to any user. This contradicts the handler’s stated admin-only policy.
   Fix: reject when user == nil or !user.IsAdmin.

Other findings

3. Public exposure of all task data — pkg/httpapi/server.go:30-33; pkg/httpapi/handlers.go:100-107
   GET /api/tasks has no authentication and returns every task, including names and creator/assignee account metadata. If these are not explicitly intended as public data, unauthenticated clients can enumerate them.
   Fix: require authentication and apply any needed ownership or role-based filtering.

4. Directory traversal in public report listing — pkg/httpapi/handlers.go:226-258
   The caller-controlled category is joined to the configured reports path without validating containment. Traversal components can make the service enumerate files outside the reports directory and return their names.
   Fix: accept only a single category path segment, or resolve and verify the final path remains inside the reports root; require authentication if report names are sensitive.

5. Login has no throttling — pkg/httpapi/server.go:30-32; pkg/httpapi/handlers.go:17-35
   Repeated password guesses can be sent to the public login endpoint without rate limits or backoff.
   Fix: add per-account and per-source throttling, plus monitoring.

Review notes

- No .env file was present.
- Password hashes are omitted from JSON via json:"-"; password checks use bcrypt; SQL statements other than task-name insertion use placeholders.
- Request bodies are capped at 1 MiB.
- No tests or build were run as part of this review.
