# Security audit — tasks-demo

Date: 2026-09-29
Branch: `final` (clean working tree)
Scope: all tracked source files (Go, SQL, Dockerfile, docs, reports), `.gitignore`, git history.
Excluded per skill rules: anything covered by `.gitignore` (`db/`, `cmd/tasks-server/tasks-server`, `target`, `dist`, `.env`). No `.env` file exists on disk. No secrets found in tracked files or history.

---

## HIGH RISK

### 1. SQL injection in task creation — `pkg/store/store.go:171` (reached from `pkg/httpapi/handlers.go:129`)
`CreateTask` interpolates the user-supplied task name directly into the SQL string:

```sql
INSERT INTO tasks (name, status, assigned_to, created_by, created_at)
 VALUES ('`+name+`', ?, ?, ?, ?)
```

`name` comes from the JSON body of `POST /api/tasks`, only trimmed and checked non-empty. Any authenticated user can break out of the literal and control the inserted row (`status`, `assigned_to`, `created_by`, `created_at`), cause constraint errors, or attempt stacked statements depending on driver support. Every other query in the package is parameterized; this one is not.
**Fix:** bind `name` as a `?` parameter like all other values.

### 2. Missing admin check on task assignment — `pkg/httpapi/handlers.go:158-162`
`handleAssignTask` (comment and `docs/overview.md`/`docs/structure.md` both say "admin only") only checks `user == nil`; the `|| !user.IsAdmin` clause was removed in commit `ce181fa` ("top secret edit"). Since the route is wrapped in `requireAuth`, `user` is never nil, so **any authenticated user can reassign any task to any user**.
**Fix:** restore `if user == nil || !user.IsAdmin {`.

### 3. Path traversal → unauthenticated directory listing — `pkg/httpapi/handlers.go:242` + `pkg/httpapi/server.go:33`
`GET /reports` is a public route and builds `filepath.Join(s.reportsPath, body.Category)` from request input with no allow-list and no containment check. `filepath.Clean` resolves `..` segments, so `{"category":"../../.."}` (and `../..`, etc.) escapes `reportsPath` and returns the file names of arbitrary directories reachable from the process CWD (e.g. `../../../home/<user>/.ssh`, app source, `/etc` contents via relative traversal). Only names are returned, not contents, but that is enough to map the host filesystem unauthenticated.
**Fix:** allow-list categories (`current`, `past`), or resolve with `filepath.Abs`/`EvalSymlinks` and reject any result not prefixed by the resolved `reportsPath`; require authentication.

---

## MEDIUM RISK

### 4. Unauthenticated task listing — `pkg/httpapi/server.go:32`
`GET /api/tasks` is registered as a public route (only `POST /api/tasks` is authenticated). Unauthenticated callers receive every task with the full `assigned_to` / `created_by` user objects, including usernames and `is_admin` flags (`Task` embeds `*User` with `is_admin` serialized) — user/role enumeration and business-data disclosure.
**Fix:** wrap with `s.requireAuth`, and consider stripping `is_admin` from embedded users.

### 5. IDOR on mark-done — `pkg/httpapi/handlers.go:137-154`
`POST /api/tasks/{id}/done` requires authentication but performs no ownership or role check: any logged-in user can complete any task, including tasks assigned to someone else, and can probe task IDs (404 vs 200 reveals existence).
**Fix:** allow only the assignee, the creator, or an admin.

### 6. No brute-force protection, no token expiry/revocation — `pkg/httpapi/handlers.go:17`, `pkg/httpapi/auth.go`
- `POST /api/auth/login` has no rate limiting, lockout, or backoff → online password guessing against bcrypt (cost 10 is only ~100 ms of friction per attempt).
- Tokens are kept in an in-memory map with no TTL, no logout/revocation endpoint; the error text even claims "invalid or expired token" although expiry does not exist. A stolen token is valid until process restart.
- The token map grows without bound → memory exhaustion by repeated logins (cheap DoS).
**Fix:** per-account/IP rate limiting; store `token → {user, expiry, created}` with TTL and a logout/revocation path; cap or prune entries.

### 7. No transport security — `cmd/tasks-server/main.go:46`
`http.ListenAndServe` on `:8080` serves plaintext HTTP: passwords at login, bearer tokens, and generated admin/user passwords in responses travel in the clear on any non-localhost path.
**Fix:** terminate TLS in front (or serve TLS directly); at minimum document that it must never be exposed without a TLS terminator.

### 8. Missing server timeouts (Slowloris) — `cmd/tasks-server/main.go:46`
The default `http.Server` has no `ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout`/`IdleTimeout`, so slow clients can hold connections open indefinitely and exhaust the connection pool.
**Fix:** use an explicit `&http.Server{Addr, Handler, ReadHeaderTimeout: …, …}`.

### 9. Dockerfile ships the whole build context and runs as root — `Dockerfile`
- No `.dockerignore`: `COPY . .` bakes `.git` (full history), the local sqlite DB under `db/`, build artifacts, and any future `.env` into image layers (recoverable from the image even after deletion from the repo).
- Container runs as root; single-stage build ships the compiler, `git`, and full source.
- Base image not pinned by digest; `go mod tidy` runs at build time, so the build is not reproducible.
**Fix:** add `.dockerignore` (at least `.git`, `db`, `dist`, `target`, `reports`, `.env*`), multi-stage build into `scratch`/`distroless`, `USER nonroot`, pin the base image digest.

---

## LOW RISK / INFORMATIONAL

### 10. Modulo bias in password generation — `pkg/store/seed.go:58`
`alphabet[int(bytes[i])%len(alphabet)]` maps 256 byte values onto 62 letters; the first 8 symbols are slightly more likely. Impact on a 16-char password is negligible but avoidable.
**Fix:** rejection sampling (or `crypto/rand`-based selection).

### 11. Plaintext password handling by design — `pkg/store/seed.go:45`, `pkg/httpapi/handlers.go:96`
The seeded admin password is printed to stdout and `POST /api/users` returns the generated password in the JSON response (documented behaviour). Acceptable only if the channel is trusted — see finding 7 — and there is **no password-change endpoint** anywhere, so credentials can never be rotated after disclosure.
**Fix:** add a change-password endpoint; keep the one-time display but ensure TLS and that stdout is not captured in CI logs.

### 12. Inconsistent auth status code — `pkg/httpapi/handlers.go:160`
Unauthenticated assign returns `403 "admin access required"` instead of `401`; harmless (the middleware already returns 401) but misleading for clients and logs.

### 13. Theoretical user enumeration by timing — `pkg/httpapi/handlers.go:32-36`
`bcrypt.CompareHashAndPassword` runs only when the username exists, so login responses are measurably faster for unknown users.
**Fix:** compare against a dummy hash on the "user not found" path.

### 14. `.gitignore` gap for reports — `.gitignore:5`
Pattern `reports/*.txt` does not match `reports/**/*.txt`; three report files are tracked today with benign content ("test report"). Runtime-generated reports under `reports/current|past/` would be committed by default and could later contain sensitive data.
**Fix:** use `reports/**/*.txt` (and confirm nothing sensitive is meant to live there).

### 15. In-memory sessions lost on restart — `pkg/httpapi/auth.go`
All sessions are invalidated on every restart (availability/UX, not a confidentiality issue).

---

## VERIFIED OK

- Passwords hashed with bcrypt (`DefaultCost`); `PasswordHash` tagged `json:"-"` and never serialized; task queries don't select other users' hashes.
- All other SQL uses bound parameters (`?`), including username lookups and migrations.
- Bearer tokens from `crypto/rand`, 32 bytes (256-bit).
- Request bodies capped at 1 MiB via `http.MaxBytesReader`; `DisallowUnknownFields` on JSON input.
- Error responses are generic; wrapped store errors (`user "x"`, internal driver text) are not echoed to clients anywhere.
- Request logging records only method, path, status — no query strings, headers, bodies, tokens or passwords.
- Admin-only checks correct on user creation and task deletion; `requireAuth` applied to every mutating route except the two findings above.
- No `os/exec`, no template rendering, no deserialization of untrusted types, no CORS headers (no permissive-CORS misconfig), no cookies (no CSRF surface).
- No secrets in tracked files, docs, reports, SQL, or git history; `.env` absent; the sqlite DB and built binary are gitignored (excluded from this audit per rules).

---

## Suggested fix order

1. Parameterize `CreateTask` (finding 1).
2. Restore the `IsAdmin` check on assign (finding 2).
3. Contain `reportsPath` + require auth on `GET /reports` (finding 3).
4. Authenticate `GET /api/tasks`; add ownership check on mark-done (4, 5).
5. Rate limit login, token TTL/revocation (6).
6. TLS + server timeouts (7, 8).
7. `.dockerignore`, non-root, multi-stage image (9).
8. Remaining low-risk items as time allows.
