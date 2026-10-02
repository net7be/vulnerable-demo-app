# Security audit — tasks-demo

Date: 2026-09-25
Scope: all git-tracked code files (`cmd/`, `pkg/`, `Dockerfile`, docs, tracked report files). Gitignored local artifacts (`db/`, `.env`) were excluded from repo-disclosure review but are relevant to the Docker finding (#10).

Method: full manual review of every source file, plus temporary Go probe tests (written, executed, then removed) that empirically confirmed findings #1–#4 against the real server and store.

## High risk

### 1. SQL injection in task creation — CONFIRMED
- **Where:** `pkg/store/store.go:169-172` (`CreateTask`), reachable from `POST /api/tasks` (`pkg/httpapi/handlers.go:129`) by any authenticated user.
- **Issue:** The task `name` is concatenated directly into the INSERT statement (`VALUES ('`+name+`', ?, ?, ?, ?)`) instead of being passed as a parameter. All other columns are parameterized.
- **Impact (verified):** The payload `x' || (SELECT password_hash FROM users WHERE username='victim') || '` created a task whose name contained the victim's bcrypt hash. Since `GET /api/tasks` is public (#4), an attacker can exfiltrate any column from any table (password hashes included) without ever authenticating. Arbitrary row manipulation is also possible.
- **Fix:** Parameterize the name like the other columns: `VALUES (?, ?, ?, ?, ?)`.

### 2. Unauthenticated path traversal in reports listing — CONFIRMED
- **Where:** `pkg/httpapi/handlers.go:242` (`handleReportsList`), public route `GET /reports` (`pkg/httpapi/server.go:33`).
- **Issue:** The client-controlled `category` is joined with `filepath.Join(s.reportsPath, body.Category)`. `Join` cleans the path but does not confine it, so `../` segments escape the reports directory.
- **Impact (verified):** `{"category":"current/../../../../../etc"}` returned a listing of `/etc` (120 entries) with no authentication. Exposes directory structure and file names anywhere on disk readable by the process.
- **Fix:** Validate `category` against a strict allowlist (e.g. `^[a-zA-Z0-9_-]+$`, no separators), or resolve the joined path and verify it stays within `s.reportsPath` before reading.

### 3. Missing admin check on task assignment — CONFIRMED
- **Where:** `pkg/httpapi/handlers.go:158-161` (`handleAssignTask`), route `POST /api/tasks/{id}/assign` (`pkg/httpapi/server.go:39`).
- **Issue:** The handler checks only `user == nil` (authentication), not `user.IsAdmin`, despite the "Admins only" comment and the documented admin-only contract (`docs/overview.md`, `docs/structure.md`).
- **Impact (verified):** A non-admin user's token reassigns any task to any user with HTTP 200.
- **Fix:** Use the same guard as `handleDeleteTask`: `if user == nil || !user.IsAdmin`.

### 4. Task listing is public — CONFIRMED
- **Where:** `pkg/httpapi/server.go:32`: `GET /api/tasks` is registered in the public (unauthenticated) route group.
- **Issue/Impact (verified):** No token required; returns every task with assignee/creator usernames. Also the exfiltration channel that makes finding #1 fully exploitable without credentials.
- **Fix:** Move the route behind `requireAuth` (and ideally scope results to the caller's tasks).

## Other findings

### 5. IDOR: any user can mark any task done
`pkg/httpapi/handlers.go:137-154` — no ownership/assignment check before `UpdateTaskStatus`. Any authenticated user can modify any task's status. Fix: verify the caller is the assignee, creator, or an admin.

### 6. `/reports` requires no authentication
Even without traversal, report file names and categories are exposed publicly. Put the route behind `requireAuth`.

### 7. No brute-force protection; username enumeration via timing
`pkg/httpapi/handlers.go:32-36` — login has no rate limiting, and an unknown username skips the bcrypt comparison (fast) while a known one runs it (~100 ms), enabling username enumeration by response time. Fix: run a dummy bcrypt compare for unknown users and add rate limiting/backoff.

### 8. Bearer tokens never expire and cannot be revoked
`pkg/httpapi/auth.go` — tokens live in memory indefinitely; no logout, no TTL, no cap on issued tokens (unbounded growth via repeated logins). All tokens die on restart. Fix: add expiry and an eviction policy, and a logout/revoke endpoint.

### 9. No HTTP server timeouts
`cmd/tasks-server/main.go:46` — bare `http.ListenAndServe` sets no `ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`/`IdleTimeout`, enabling slowloris-style resource exhaustion. Fix: construct an `http.Server` with timeouts.

### 10. Docker build copies local secrets/database into the image
`Dockerfile:7` — `COPY . .` with no `.dockerignore` bakes the gitignored local `db/tasks.db` (contains bcrypt password hashes), any future `.env`, reports, and `.git` into the image. The container also runs as root (no `USER` directive). Fix: add a `.dockerignore` (`.git`, `db`, `.env`, `reports`, `dist`, `target`), build in a stage that copies only what's needed, and run as a non-root user.

### 11. Modulo bias in password generation
`pkg/store/seed.go:58` — `int(bytes[i]) % 62` on a 0–255 byte biases the first 8 alphabet characters (256 % 62 = 8). Marginal for 16-char passwords, but use rejection sampling or `math/big` for uniformity.

### 12. Brittle unique-violation detection
`pkg/store/store.go:284-286` — unique-constraint detection by matching driver error text. If the driver message changes, duplicate usernames become 500s instead of 409s. Prefer checking the driver's error code.

### 13. `.gitignore` pattern does not cover tracked report files
`.gitignore` has `reports/*.txt` (top level only) while `reports/current/report1.txt` and `reports/past/*.txt` are already tracked. If real reports are ever placed in subdirectories they will be committed despite the ignore intent. Current contents are harmless placeholders. Fix: `reports/**/*.txt` plus `git rm --cached` for anything that was meant to stay local.

### 14. Default admin password printed to stdout
`pkg/store/seed.go:43-46` — by design and documented, one-time only, but it ends up in container logs. Consider requiring the admin password via environment or writing it to a protected file with restrictive permissions.

## Positive observations
- Queries elsewhere are fully parameterized; `User.PasswordHash` is hidden from JSON (`json:"-"`).
- bcrypt with default cost for password hashing; crypto-random tokens (32 bytes).
- Request bodies capped (`http.MaxBytesReader`) with `DisallowUnknownFields` and a generic "invalid JSON body" error.
- Login returns an identical error for unknown user and wrong password (no direct enumeration via message).
- Error responses are generic; internal errors are only logged server-side.

## Verification evidence (probes removed after run)
- SQL injection probe: task created with name starting `x$2a$10$…` — exfiltrated bcrypt hash confirmed.
- Traversal probe: `GET /reports` with `category: current/../../../../../etc` → 200 with 120 `/etc` entries.
- Authz probe: non-admin token on `POST /api/tasks/1/assign` → 200, task reassigned.
- Authn probe: `GET /api/tasks` without token → 200 with full task list.

No secrets were found in tracked files. No findings required redaction of values.
