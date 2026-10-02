# Security Audit — tasks-demo-test

Scope: all tracked source files (Go server, migration, Dockerfile, docs). Files covered by `.gitignore` (`db/tasks.db`, `reports/*.txt`, built binary) were excluded per audit policy.

## High risk

### 1. SQL injection in task creation
- File: `pkg/store/store.go:170-172`
- Evidence: `` `INSERT INTO tasks (name, status, assigned_to, created_by, created_at) VALUES ('`+name+`', ?, ?, ?, ?)` ``
- The task `name` comes straight from the JSON request body and is concatenated into the SQL statement. An authenticated user can inject arbitrary SQL (UNION reads of `users.password_hash`, or write statements via stacked/creative payloads depending on driver behaviour), then reads the result back through `GET /api/tasks`. This effectively yields full database read/write and password-hash exfiltration.
- Fix: use a placeholder like every other query in the file: `VALUES (?, ?, ?, ?, ?)` with `name` as an argument.

### 2. Unauthenticated path traversal / directory listing
- File: `pkg/httpapi/handlers.go:236-250`, route registered at `pkg/httpapi/server.go:33`
- Evidence: `entries, err := os.ReadDir(filepath.Join(s.reportsPath, body.Category))`
- `GET /reports` requires no authentication, and `category` is fully client-controlled. `filepath.Join` cleans the path but does not stop `../`, so `{"category":"../../"}` or `{"category":"../../../home/user"}` lists arbitrary directories. Only directory names are returned, not file contents, but this still discloses filesystem layout and username/home-directory existence to anyone who can reach the port.
- Fix: put `GET /reports` behind `requireAuth`, and validate `category` against an allow-list (or reject any value containing separators / `..`).

### 3. Missing authorization on task assignment
- File: `pkg/httpapi/handlers.go:157-162`
- Evidence: `if user == nil { writeError(w, http.StatusForbidden, "admin access required") ... }`
- The handler is documented "Admins only" (`docs/structure.md:24`) but only checks that *a* user is authenticated; `user.IsAdmin` is never tested. Any logged-in non-admin can reassign any task to any user.
- Fix: `if user == nil || !user.IsAdmin` (same pattern already used in `handleCreateUser` / `handleDeleteTask`).

### 4. Unauthenticated data exposure on `GET /api/tasks`
- File: `pkg/httpapi/server.go:32`, `pkg/httpapi/handlers.go:100-107`
- The route is explicitly in the "Public routes" block with no `requireAuth`. It returns every task in the database including the full `assigned_to` and `created_by` user objects (username, admin flag, creation date) — the entire workload of the organisation to anonymous callers.
- Fix: wrap in `requireAuth`, and scope results to tasks assigned to / created by the caller unless the caller is an admin.

## Medium risk

### 5. Missing object-level authorization on "mark done"
- File: `pkg/httpapi/handlers.go:137-154`
- Any authenticated user can mark any task id as done, including tasks owned by others. No comparison of `task.AssignedTo.ID` / `task.CreatedBy.ID` against the caller.
- Fix: fetch the task and allow the mutation only if the caller is admin, assignee or creator.

### 6. Unbounded, non-expiring tokens
- File: `pkg/httpapi/auth.go:12-38`
- Tokens live in a `map[string]int64` that is only ever added to. There is no expiry, no logout/revocation, and no size bound, so a long-lived server grows without limit and a leaked token stays valid forever (a re-login does not invalidate it). Restarting the server silently invalidates every token, so there is no persistence either.
- Fix: store `token -> {userID, expiry}` in a persistent store, enforce TTL, add a revoke/logout path, and cap the table.

### 7. No brute-force protection on login
- File: `pkg/httpapi/handlers.go:17-48`
- `POST /api/auth/login` has no rate limit, lockout, or delay, and bcrypt cost is the only cost. The seeded admin account (`admin`) is a known username.
- Fix: add per-IP and per-username throttling/backoff and monitor failures.

### 8. Insecure transport and default bind address
- File: `cmd/tasks-server/main.go:14`, `:46`
- `http.ListenAndServe` with default `:8080` binds all interfaces, plaintext. Bearer tokens and the generated user passwords travel in clear text.
- Fix: default to `127.0.0.1`, terminate TLS at a proxy (or document that TLS termination is mandatory), and set `ReadHeaderTimeout`/`ReadTimeout` to avoid slow-request resource exhaustion (also currently missing, so `ReadHeaderTimeout` defaults to none — a Slowloris-style hang is possible).

### 9. Docker image bakes in local state and runs as root
- File: `Dockerfile:7`, `:14`
- `COPY . .` with no `.dockerignore` copies the working tree into the image, including `db/tasks.db` (users + password hashes), `reports/**`, and any `.env` present at build time. The container also runs as root and ships a Go toolchain (`golang:1.26-alpine`, `apk add git`, `go mod tidy` left in the final layer).
- Fix: add `.dockerignore` (at minimum `db`, `reports`, `.env`, `.git`), copy only the source needed, use a multi-stage build on a minimal runtime base, and set `USER`.

## Low risk / hardening

### 10. Secret written to stdout on first run
- File: `pkg/store/seed.go:43-46` — the default admin password is printed to `os.Stdout`, which in a container lands in the runtime log / log aggregator, widening where the secret lives. Do not quote the value. Fix: write once to a root-only file (mode `0600`) or print an instruction to set `TASKS_ADMIN_PASSWORD` at deploy time; never log the secret itself.

### 11. Plaintext password returned in API responses
- File: `pkg/httpapi/handlers.go:94-97` — user creation returns the generated password in the JSON body. This is the documented design, but it means the secret travels over plaintext HTTP (see #8) and lands in client/proxy logs. Fix: return a one-time setup link or require a password chosen by the admin, delivered out of band.

### 12. Server-internal detail in error wrapping
- File: `pkg/store/store.go:127`, `:145`, `:160`, `:187`, `:252` — errors embed the offending username/id (e.g. `store: not found: user %q`). These are wrapped and not currently forwarded to clients (handlers return generic messages), so impact is low, but any future change that surfaces `err.Error()` to a caller leaks identifiers and store internals. Fix: keep sentinel errors opaque and log details server-side.

### 13. Path disclosure at startup
- File: `cmd/tasks-server/main.go:45` — the database path is written to the log via `db.Location()`. Harmless for a local demo, worth removing or gating behind a debug flag for production.

### 14. Weak random password alphabet bias
- File: `pkg/store/seed.go:51-61` — `bytes[i] % len(alphabet)` maps 256 byte values onto 62 symbols unevenly, slightly reducing entropy (still cryptographically strong in practice, but unnecessary). Fix: rejection sampling, or use `crypto/rand` with `base64`/hex encoding as `randomToken` already does in `pkg/httpapi/auth.go:51`.

### 15. Authorization ordering / duplicated checks
- File: `pkg/httpapi/handlers.go:109-127` — `handleCreateTask` decodes the body before checking authentication, so unauthenticated callers get a 400 body-shape error instead of a 401. Minor information about input validation. Fix: authenticate first.
- File: `pkg/httpapi/handlers.go:52-57`, `:202-207` — the admin check is duplicated in handlers instead of being a middleware (`requireAdmin`), which is exactly what let finding #3 slip through. Fix: add a `requireAdmin` wrapper and use it consistently.

## Not found

- No command execution, no file-write/upload endpoints (`/reports` only lists names), no unsafe deserialization beyond `encoding/json` with `DisallowUnknownFields`, no request-body size limit bypass (`http.MaxBytesReader` at `handlers.go:268` is applied), no `TASKS_*` env value interpolated into SQL, no template rendering.
- Credentials are not hardcoded in any tracked file; the admin password is generated at runtime.

## Summary

| # | Severity | Issue |
|---|----------|-------|
| 1 | High | SQL injection via task `name` (`pkg/store/store.go:171`) |
| 2 | High | Unauthenticated path traversal in `GET /reports` (`pkg/httpapi/handlers.go:242`) |
| 3 | High | `POST /api/tasks/{id}/assign` does not check `IsAdmin` (`pkg/httpapi/handlers.go:158`) |
| 4 | High | `GET /api/tasks` is unauthenticated (`pkg/httpapi/server.go:32`) |
| 5 | Medium | Any user can mark any task done (`pkg/httpapi/handlers.go:137`) |
| 6 | Medium | Tokens never expire, never revocable, unbounded growth (`pkg/httpapi/auth.go:22`) |
| 7 | Medium | No rate limiting on `POST /api/auth/login` (`pkg/httpapi/handlers.go:17`) |
| 8 | Medium | Plaintext HTTP on all interfaces, no timeouts (`cmd/tasks-server/main.go:46`) |
| 9 | Medium | Docker image includes `db/`, `reports/`, `.env`; runs as root with toolchain (`Dockerfile:7`) |
| 10 | Low | Admin password printed to stdout (`pkg/store/seed.go:43`) |
| 11 | Low | Password returned in plaintext response (`pkg/httpapi/handlers.go:94`) |
| 12 | Low | Store errors embed identifiers (`pkg/store/store.go:127`) |
| 13 | Low | DB path logged at startup (`cmd/tasks-server/main.go:45`) |
| 14 | Low | Modulo bias in `RandomPassword` (`pkg/store/seed.go:58`) |
| 15 | Low | Auth checked after body decode; admin checks duplicated (`pkg/httpapi/handlers.go:109`) |