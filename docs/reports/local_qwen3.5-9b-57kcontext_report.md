# Security Audit Report - tasks-demo

**Date:** Fri Oct 02 2026  
**Project:** tasks-demo-test

---

## HIGH RISK FINDINGS

### 1. SQL Injection Vulnerability in `CreateTask`

**File:** `pkg/store/store.go:172`  
**Risk:** High - Code Injection / Data Loss

```go
res, err := d.db.ExecContext(ctx,
    `INSERT INTO tasks (name, status, assigned_to, created_by, created_at)
        VALUES ('`+name+`', ?, ?, ?, ?)`,
    StatusInProgress, assignedTo, createdBy, now(),
)
```

**Issue:** The task `name` parameter is concatenated directly into the SQL query string without using a parameterized placeholder. This allows an attacker to inject arbitrary SQL through malicious input.

**Impact:** An attacker could:
- Delete or modify data in the database
- Extract sensitive information from other tables
- Potentially execute operating system commands (if SQLite extension functions are available)

**Remediation:** Replace with a parameterized query placeholder `?`:
```go
res, err := d.db.ExecContext(ctx,
    `INSERT INTO tasks (name, status, assigned_to, created_by, created_at)
        VALUES (?, ?, ?, ?, ?)`,
    name, StatusInProgress, assignedTo, createdBy, now(),
)
```

---

### 2. Error Messages Disclose Sensitive Information

**File:** `pkg/store/store.go:145-146, 154-155, 240-241`  
**Risk:** High - Information Disclosure

```go
return nil, fmt.Errorf("%w: user %q", ErrNotFound, username)
return nil, fmt.Errorf("%w: task %d", ErrNotFound, id)
return fmt.Errorf("%w: task %d", ErrNotFound, affected)
```

**Issue:** Error messages contain actual usernames and IDs when users or tasks are not found. This allows attackers to enumerate valid usernames and potentially infer internal system information.

**Impact:** 
- User enumeration attacks - attacker can iterate through possible usernames
- Internal system information leakage
- May aid in targeted attacks

**Remediation:** Use generic error messages that do not disclose specific data:
```go
return nil, fmt.Errorf("%w", ErrNotFound)
```

---

### 3. Unprotected Reports Endpoint

**File:** `pkg/httpapi/server.go:33`, `handlers.go:228`  
**Risk:** High - Unauthorized Access / Information Disclosure

```go
// Public routes (line 33 in server.go):
s.mux.Handle("GET /reports", http.HandlerFunc(s.handleReportsList))
```

**Issue:** The `/reports` endpoint is publicly accessible without authentication. This endpoint reads and lists files from the filesystem based on user-provided category names.

**Impact:** 
- Information disclosure about report files
- Potential path traversal if attacker manipulates `category` parameter (no validation against directory boundary)
- Attacker can discover what categories of reports exist and their contents

**Remediation:** Add authentication requirement:
```go
s.mux.Handle("GET /reports", s.requireAuth(http.HandlerFunc(s.handleReportsList)))
```

---

### 4. Missing Admin Validation in Task Assignment

**File:** `pkg/httpapi/handlers.go:183-187`  
**Risk:** High - Privilege Escalation / Data Integrity

```go
target, err := s.store.GetUserByUsername(r.Context(), body.AssignedTo)
if err != nil {
    writeError(w, http.StatusNotFound, "user not found")
    return
}
task, err := s.store.AssignTask(r.Context(), id, target.ID)
```

**Issue:** While the code checks if a user exists before assignment, an admin could potentially assign tasks to any existing user without verifying that the admin should have permission to do so. Additionally, there's no validation that the task belongs to the requester.

**Impact:** 
- Admin could modify task assignments arbitrarily
- Potential for privilege escalation in task management
- Data integrity issues if users don't own their tasks

**Remediation:** Add proper authorization checks and consider ownership restrictions:
```go
task, err := s.store.GetTask(r.Context(), id)
if err != nil {
    // handle error
}
if task.CreatedBy != user.ID && !user.IsAdmin {
    writeError(w, http.StatusForbidden, "cannot assign task you do not own")
    return
}
```

---

### 5. Password Exposure on User Creation Response

**File:** `pkg/httpapi/handlers.go:94-97`  
**Risk:** Medium-High - Credential Leakage

```go
writeJSON(w, http.StatusCreated, map[string]any{
    "user":     created,
    "password": password,  // Sent in response to admin
})
```

**Issue:** While this may be by design for usability (admin can immediately use the account), the password is sent as plain text in the HTTP response body.

**Impact:**
- Any interceptor or man-in-the-middle attack can capture credentials
- Logs containing these responses would expose passwords
- History of password generation is stored on disk if responses are cached

**Remediation:** Either:
1. Send password via separate secure channel (e.g., console output for admin session)
2. Require admin to enter a custom password instead
3. Send password in response but ensure proper security headers and logging protection

**Note:** Current code uses `fmt.Fprintf(out, ...)` in `seedAdmin` which goes to the console, so passwords should not be logged to disk. However, responses might still be cached or intercepted.

---

### 6. Database Path Information Disclosure

**File:** `pkg/httpapi/server.go:45`  
**Risk:** Medium - Information Disclosure

```go
log.Printf("tasks-server listening on %s (db: %s)", addr, db.Location())
```

**Issue:** The log output includes the full database file path. If this logging is exposed or captured by attackers, it reveals the database location.

**Impact:** 
- Attacker knows where the database file is located
- Makes targeted attacks on the database file possible if server has write access to that directory
- Information about deployment structure

**Remediation:** Mask the database path in logs:
```go
log.Printf("tasks-server listening on %s", addr)
// Or log relative to app root without full disclosure
```

---

### 7. No Rate Limiting on Authentication Endpoints

**File:** `pkg/httpapi/auth.go`, `handlers.go:17`  
**Risk:** Medium - Brute Force Attacks

**Issue:** The `/api/auth/login` endpoint has no rate limiting or account lockout mechanism.

**Impact:**
- Attackers can perform unlimited brute-force password attacks
- Password spraying attacks (testing common passwords across multiple accounts)
- Denial of service through excessive login attempts

**Remediation:** Implement rate limiting:
```go
// Add middleware for rate limiting
s.mux.Handle("POST /api/auth/login", rateLimiter(http.HandlerFunc(s.handleLogin)))
```

---

## MEDIUM RISK FINDINGS

### 8. No Input Sanitization for JSON Fields

**File:** `pkg/httpapi/handlers.go:67-71`  
**Risk:** Medium - Injection Potential

```go
body.Username = strings.TrimSpace(body.Username)
if body.Username == "" {
    writeError(w, http.StatusBadRequest, "username is required")
    return
}
```

**Issue:** Only `TrimSpace` and empty check are performed. No validation against:
- Maximum length limits
- Special characters that might have significance
- SQL injection attempts (though store layer should protect)

**Impact:** While the store layer uses prepared statements for most queries, user input should still be validated at API boundaries.

---

### 9. Missing Security Headers

**File:** `pkg/httpapi/server.go`  
**Risk:** Medium - Information Disclosure / CSRF

**Issue:** No security headers are set on responses:
- No `X-Content-Type-Options: nosniff`
- No `X-Frame-Options` (if there's a frontend)
- No `Cache-Control` headers for sensitive responses
- No `Content-Security-Policy`

**Remediation:** Add security headers middleware:
```go
func addSecurityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        // Additional headers as needed
        next.ServeHTTP(w, r)
    })
}
```

---

## LOW RISK FINDINGS

### 10. No Timeout Configuration for HTTP Server

**File:** `cmd/tasks-server/main.go:46`  
**Risk:** Low - Denial of Service

**Issue:** `http.ListenAndServe(addr, ...)` has no timeout configuration.

**Impact:** Potential for slowloris-style DoS attacks.

**Remediation:** Consider using a production HTTP server library like `gorilla/mux` with proper timeouts, or configure net/http server with timeouts if possible.

---

### 11. In-Memory Token Storage Without Cleanup

**File:** `pkg/httpapi/auth.go:12-38`  
**Risk:** Low - Memory Growth

**Issue:** The token store uses an in-memory map that grows indefinitely as new tokens are issued, with no expiration or cleanup mechanism.

**Impact:** Over time, server memory will grow linearly with the number of active users/sessions.

**Remediation:** Implement token expiration with a background cleanup routine:
```go
type tokenStore struct {
    mu     sync.Mutex
    tokens map[string]tokenEntry
}

type tokenEntry struct {
    userID   int64
    expiresAt time.Time
}
```

---

## RECOMMENDATIONS SUMMARY

| Priority | Issue | File | Line | Fix |
|----------|-------|------|------|-----|
| **HIGH** | SQL Injection | pkg/store/store.go | 172 | Use parameterized ? placeholder |
| **HIGH** | Info Disclosure - Usernames | pkg/store/store.go | 145,154 | Remove sensitive data from errors |
| **HIGH** | Unprotected Endpoint | pkg/httpapi/server.go | 33 | Add requireAuth middleware |
| **MEDIUM** | Password Response | pkg/httpapi/handlers.go | 94-97 | Review security implications |
| **MEDIUM** | Missing Security Headers | pkg/httpapi/server.go | - | Add security headers middleware |
| **MEDIUM** | No Rate Limiting | pkg/httpapi/auth.go | 17 | Implement rate limiter |

---

## COMPLIANCE NOTES

- This application does not implement any logging redaction for sensitive data
- Password verification uses bcrypt correctly with DefaultCost
- Token generation uses crypto/rand (secure)
- Database connection is serialized to prevent locking issues

---

**Report Generated By:** Security Audit Tool  
**Reviewed Files:** All Go source files in project root
