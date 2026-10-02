# Implemented structure

- pkg/store — sqlite persistence (modernc.org/sqlite, pure Go):
  - store.go — user/task models, Store interface, store.Open opens/
    creates db/tasks.db, applies migrations, sanitizes foreign keys/
    WAL.
  - migrate.go — version-tracking migration runner (embedded
    migrations/*.sql, applied in order, recorded in schema_migrations).
  - migrations/0001_initial.sql — users + tasks tables with FKs and
    indexes.
  - seed.go — creates default admin user with a random 16-char
    password, printed to console only on first init.
  - password.go — bcrypt hash/verify.
- pkg/httpapi — net/http JSON API with bearer-token auth (Go 1.22+
  routing, request logging).
- cmd/tasks-server/main.go — minimal main; env TASKS_ADDR /
  TASKS_DB_PATH.

## Endpoints

- POST /api/auth/login {username,password} → {token, user}
- GET /api/tasks, POST /api/tasks (creator is assignee by default)
- POST /api/tasks/{id}/done
- POST /api/tasks/{id}/assign (admin only)
- DELETE /api/tasks/{id} (admin only)
- POST /api/users (admin only) {username, is_admin} -> {user, password}


