# Security Audit Report

## Executive Summary
The tasks-server application has several high-risk security vulnerabilities related to authentication, authorization, input validation, and information disclosure.

---

## High Risk Findings

### 1. Plaintext Password Disclosure in Admin User Creation Response
**File:** `pkg/httpapi/handlers.go:94-97`  
**Risk:** **High** - Sensitive Credential Exposure

When a non-admin user creates another user, the plaintext password is returned in the JSON response. This leaks credentials to any client that receives this response.

```go
writeJSON(w, http.StatusCreated, map[string]any{
    "user":     created,
    "password": password,  // Plaintext password exposed!
})
```

**Remediation:** Never return plaintext passwords in API responses. Instead:
- Return a message prompting the user to change their password on first login
- Or provide a one-time reset token that requires confirmation before allowing access

---

### 2. SQL Injection in Task Name Creation
**File:** `pkg/store/store.go:170`  
**Risk:** **High** - SQL Injection Vulnerability

The task name is directly interpolated into a SQL query without sanitization, enabling SQL injection attacks.

```go
`INSERT INTO tasks (name, status, assigned_to, created_by, created_at)
 VALUES ('`+name+`', ?, ?, ?, ?)`,
```

**Remediation:** Use parameterized queries for all user input. The `name` should be a query parameter, not interpolated:

```go
VALUES (?, ?, ?, ?, ?),
StatusInProgress, assignedTo, createdBy, now(),
```

---

### 3. Information Disclosure in Database Path Logging
**File:** `pkg/httpapi/server.go:45`  
**Risk:** **High** - Sensitive Configuration Exposure

The database file path is logged in plaintext, potentially exposing sensitive file system information.

```go
log.Printf("tasks-server listening on %s (db: %s)", addr, db.Location())
```

**Remediation:** Log only the directory or a sanitized identifier instead of the full path. If debugging access is needed, restrict logging to local development environments only.

---

### 4. Error Message Information Disclosure
**File:** `pkg/store/store.go:129`, `136-137`, `145-146`  
**Risk:** **Medium/High** - Sensitive Data in Errors

Error messages leak database state information, including unique constraint failures and not found errors.

```go
return nil, fmt.Errorf("%w: username %q", ErrExists, username)  // Exposes username
return nil, fmt.Errorf("%w: user %d", ErrNotFound, id)          // Exposes user IDs
```

**Remediation:** Use generic error messages in API responses. Store sensitive data in error types but never expose them directly to clients.

---

### 5. In-Memory Token Storage Without Expiration
**File:** `pkg/httpapi/auth.go:12-38`  
**Risk:** **Medium** - Security by Design Weakness

Tokens are stored indefinitely in memory with no expiration mechanism. If tokens are compromised, they remain valid forever. Additionally, there's a race condition between token lookup and storage (double-spending vulnerability).

**Remediation:**
1. Implement token expiration with configurable TTL
2. Add a database or persistent store for tokens (especially critical across server restarts)
3. Consider adding blacklisting capability for revoked tokens

---

### 6. Path Traversal Vulnerability in Reports Endpoint
**File:** `pkg/httpapi/handlers.go:242`  
**Risk:** **High** - Arbitrary File Access

The category parameter is used directly in a file path operation without validation, enabling path traversal attacks.

```go
entries, err := os.ReadDir(filepath.Join(s.reportsPath, body.Category))
```

**Remediation:** Validate and sanitize the `Category` parameter:

```go
// Allow only predefined categories or validate against allowed prefix
if !strings.HasPrefix(body.Category, "reports/") || strings.Contains(body.Category, "..") {
    writeError(w, http.StatusBadRequest, "invalid category")
    return
}
```

---

### 7. Hardcoded Default Admin Credentials
**File:** `pkg/store/seed.go:10`  
**Risk:** **High** - Default Secret Exposure

A hardcoded admin username ("admin") exists with password generated at runtime but predictable naming scheme. This creates a common attack vector where attackers assume default credentials.

```go
const defaultAdminUsername = "admin"
```

**Remediation:** Either:
- Do not create the admin user by default (require explicit setup)
- Use a more unique default username
- Require password reset on first login for all users, including admins
- Document clearly that default credentials should be changed immediately

---

### 8. Weak Random Password Generation
**File:** `pkg/store/seed.go:51-60`  
**Risk:** **Medium** - Insufficient Entropy

The random password uses only alphanumeric characters (62 total) which provides less entropy than recommended for security-sensitive values.

```go
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345789"
```

**Remediation:** Include symbols and special characters in the alphabet pool, or use a cryptographically strong random password library like `golang.org/x/crypto/pbkdf2` with salt.

---

### 9. No Rate Limiting on Authentication Endpoints
**File:** `pkg/httpapi/server.go:31`, `pkg/httpapi/handlers.go:17-48`  
**Risk:** **Medium** - Brute Force Vulnerability

The login endpoint is vulnerable to brute force attacks with no rate limiting or account lockout mechanism.

**Remediation:** Implement rate limiting (e.g., 5 attempts per minute per IP) and temporary account lockouts after repeated failures.

---

### 10. Missing Input Validation on Task Assignment
**File:** `pkg/httpapi/handlers.go:183`  
**Risk:** **Medium** - Authorization Bypass Potential

The target username for task assignment is retrieved without verifying the current user has permission to assign that specific task. Only admin checks are performed.

```go
target, err := s.store.GetUserByUsername(r.Context(), body.AssignedTo)
// No verification that user can access or modify this task
```

**Remediation:** Verify the requesting user is an admin OR owns/has proper permission to reassign the specific task before allowing the operation.

---

## Additional Observations

### Code Quality Issues
- No CSRF protection on state-changing endpoints
- Missing Content Security Policy headers
- No HTTPS enforcement (in production)
- SQLite database file is exposed in `.gitignore` but already exists as `db/tasks.db` - consider removing or encrypting if it contains test data

---

## Summary

| Severity | Count |
|----------|-------|
| High     | 4    |
| Medium   | 5    |

**Immediate Action Required:** Address SQL injection vulnerability, fix password disclosure in responses, and implement proper path validation to prevent file traversal attacks.

**Short-term Improvements:** Add token expiration, implement rate limiting, and sanitize error messages.

**Long-term Recommendations:** Implement comprehensive authorization framework, add security headers, and consider using established OAuth providers instead of custom authentication.
