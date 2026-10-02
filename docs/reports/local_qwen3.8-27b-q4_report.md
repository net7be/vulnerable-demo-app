# Security Audit — tasks-demo

- Date: 2026-09-24
- Scope: full project (all Go code, SQL migrations, Dockerfile, config, docs, reports). `.gitignore`-covered files (`db/`, `target/`, `dist/`, built binaries) were skipped; no committed secrets found (`.env` absent, `db/tasks.db` gitignored, report `.txt` files are placeholders).
- Stack: Go `net/http` JSON API, SQLite (`modernc.org/sqlite`), bcrypt, bearer tokens.

## HIGH

### 1. SQL injection in task creation
- File: `pkg/store/store.go:168-173` (`CreateTask`)
- Why: the task `name` is concatenated directly into the SQL string (`VALUES ('`+name+`', ...)`) instead of using a placeholder. Reachable unauthenticated-ish via `POST /api/tasks` by any authenticated user. A crafted name breaks out of the string and executes arbitrary SQL (data read, modification, or destruction).
- Fix: parameterize `name`:
  `VALUES (?, ?, ?, ?, ?)` with `name, StatusInProgress, assignedTo, createdBy, now()`.

### 2. Broken access control — task assignment missing admin check
- File: `pkg/httpapi/handlers.go:157-162` (`handleAssignTask`)
- Why: the handler is documented "Admins only" but only checks `user == nil` (i.e. that a user is logged in) and never `user.IsAdmin`. Any authenticated non-admin can reassign any task to any user. Compare `handleDeleteTask` (handlers.go:210), which correctly checks `user == nil || !user.IsAdmin`.
- Fix: `if user == nil || !user.IsAdmin { writeError(..., "admin access required"); return }`.

### 3. Path traversal / arbitrary directory listing on public `GET /reports`
- File: `pkg/httpapi/handlers.go:228-259` (`handleReportsList`), routed public in `pkg/httpapi/server.go:33`
- Why: the route requires no auth, and `body.Category` (user-controlled, only trimmed) is passed to `os.ReadDir(filepath.Join(s.reportsPath, body.Category))`. `filepath.Join` cleans `..` sequences, so `category` of `..`, `../..`, etc. escapes `reports/` and lists arbitrary directories on the host (filesystem structure, usernames, config names).
- Fix: (a) require auth, and (b) whitelist categories (e.g. `current`/`past`) or resolve with `filepath.Clean` and verify the result stays inside `reportsPath` before reading.

## MEDIUM

### 4. `GET /api/tasks` is public (no authentication)
- File: `pkg/httpapi/server.go:32`, handler `pkg/httpapi/handlers.go:100-107`
- Why: unauthenticated users can list every task, including assignee/creator usernames and timestamps. All mutating endpoints require auth; the read endpoint leaks the full task dataset.
- Fix: wrap `handleListTasks` in `requireAuth`.

### 5. No rate limiting / lockout on login; unbounded, non-expiring tokens
- File: `pkg/httpapi/handlers.go:17-48` (`handleLogin`), `pkg/httpapi/auth.go:12-57` (`tokenStore`)
- Why: `POST /api/auth/login` has no throttling → password brute-force is feasible. Tokens are in-memory, never expire, and can never be revoked (no logout); a stolen token is valid until process restart.
- Fix: add per-account / per-IP rate limiting, token TTL + expiration cleanup, and a revocation/logout path.

### 6. Plaintext HTTP only
- File: `cmd/tasks-server/main.go:46` (`http.ListenAndServe`)
- Why: credentials, tokens, and passwords travel unencrypted unless an external proxy terminates TLS.
- Fix: serve TLS (`ListenAndServeTLS`) or document/require a TLS-terminating reverse proxy.

## LOW / code quality

7. **`RandomPassword` modulo bias** — `pkg/store/seed.go:51-60`: `int(b) % len(alphabet)` (62) is biased; use `rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))`.
8. **Admin seed password printed to stdout** — `pkg/store/seed.go:43-46`: stdout is persisted by containers/logs; ensure this is not captured, or rotate immediately.
9. **`POST /api/users` returns the generated password in the response** — `pkg/httpapi/handlers.go:94-97`: acceptable if shown-once by design, but risky if the response is logged or intercepted.
10. **Username enumeration via `POST /api/users`** — `pkg/httpapi/handlers.go:86`: "username already exists" is admin-only, so low impact.
11. **`Dockerfile` `COPY . .`** — line 7: ships `.git`, `db/`, `reports/`, and the prebuilt binary into the image, and runs as root. Use a `.dockerignore` and a non-root `USER`.

## Positive notes
- Login compares with bcrypt and returns a generic "invalid username or password" (no user enumeration via login, no timing oracle on the error path).
- `User.PasswordHash` is excluded from JSON (`json:"-"`) so it is never serialized in responses.
- All other SQL access uses parameterized queries; the single string-build in `CreateTask` is the exception.
- `decodeBody` enforces a 1 MB cap and returns a generic "invalid JSON body".
- Error messages are largely generic and do not leak internals.

## Recommended priority order
1. Parameterize `CreateTask` (SQLi) — `pkg/store/store.go:168`.
2. Add `!user.IsAdmin` check to `handleAssignTask` — `pkg/httpapi/handlers.go:157`.
3. Auth + category whitelist on `GET /reports` — `pkg/httpapi/handlers.go:228`, `pkg/httpapi/server.go:33`.
4. Put `GET /api/tasks` behind auth.
5. Add login rate limiting and token expiration/revocation.
