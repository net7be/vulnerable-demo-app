# Security Audit Report - Tasks Server

## Summary

Multiple critical security vulnerabilities were identified in the tasks-server application. The following issues require immediate attention:

---

## High Risk Findings

### 1. Password Hash Stored in API Response (CRITICAL)

**File:** `pkg/httpapi/auth.go:47-48`  
**Risk:** HIGH - Authentication credentials exposed to attackers

When a user logs in successfully, the full `User` struct including `PasswordHash` is returned in the JSON response. While bcrypt hashing makes rainbow table attacks difficult, exposing password hashes:
- Enables offline brute-force attacks by malicious actors
- Violates security best practices (never return sensitive data)
- May violate regulatory compliance requirements

**Impact:** Attackers can attempt to crack user passwords offline using computational resources.

**Remediation:** 
```go
// Option 1: Redact password_hash in response struct tag
type User struct {
    ID           int64  `json:"id"`
    Username     string `json:"username"`
    IsAdmin      bool   `json:"is_admin"`
    CreatedAt    string `json:"created_at"`
    PasswordHash string `json:"-"` // Already marked for exclusion - ensure handlers don't include it
}
```

**Current Status:** The struct has `json:"-"` on PasswordHash, but the response still includes user data. Verify this is working correctly and ensure no other handler leaks password hashes.

---

### 2. In-Memory Token Store (CRITICAL)

**File:** `pkg/httpapi/auth.go:12-38`  
**Risk:** HIGH - Session tokens persist in memory, vulnerable to server compromise

The application uses an in-memory map (`tokenStore`) to store authentication tokens:
- Tokens persist until server restart (no TTL)
- No token revocation capability
- Server memory dump exposure risk
- If server is compromised, all tokens are compromised
- No support for multiple sessions or logout functionality

**Impact:** 
- All authenticated sessions remain valid indefinitely
- Attacker with server access can view all active sessions
- No way to invalidate stolen credentials mid-session

**Remediation:**
1. Implement JWT tokens with expiration times (e.g., 24 hours)
2. Add refresh token mechanism
3. Consider short-lived access tokens + long-lived refresh tokens
4. Store tokens in Redis/external store for distributed deployment support

---

### 3. No Rate Limiting or Brute Force Protection (HIGH)

**File:** `pkg/httpapi/handlers.go:17-48`  
**Risk:** HIGH - Authentication endpoints vulnerable to brute force attacks

The login endpoint accepts unlimited authentication attempts:
```go
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
    // No rate limiting, no attempt tracking
}
```

**Impact:**
- Attackers can brute-force user passwords
- Default admin account is particularly vulnerable
- Can lead to account takeover and unauthorized access

**Remediation:**
1. Implement rate limiting (e.g., 5 attempts per minute per IP)
2. Add exponential backoff after failed attempts
3. Consider temporary account lockout after multiple failures
4. Monitor for suspicious authentication patterns

---

### 4. Insecure Admin User Creation (MEDIUM-HIGH)

**File:** `pkg/store/seed.go:10,27-46`  
**Risk:** MEDIUM - Hardcoded admin username with plaintext password exposure

```go
const defaultAdminUsername = "admin"

// On first run:
fmt.Fprintf(out, "  username: %s\n", defaultAdminUsername)
fmt.Fprintf(out, "  password: %s\n", password)
```

**Impact:**
- Fixed admin username ("admin") makes guessing easier
- Password printed to console (stdout) on server startup
- Console output may be logged or visible in process list
- If stdout is captured by logging systems, credentials are stored insecurely

**Remediation:**
1. Use a random, cryptographically secure username instead of "admin"
2. Never print passwords to stdout - write to secure file or use environment variables
3. Require password change on first login
4. Log credentials only to secured configuration storage

---

### 5. Path Traversal Vulnerability in Reports Endpoint (HIGH)

**File:** `pkg/httpapi/handlers.go:228-259`  
**Risk:** HIGH - Unvalidated user input for file system operations

```go
func (s *Server) handleReportsList(w http.ResponseWriter, r *http.Request) {
    var body struct {
        Category string `json:"category"`
    }
    // ...
    entries, err := os.ReadDir(filepath.Join(s.reportsPath, body.Category))
```

**Impact:**
- Attacker can use `../../../` or absolute paths to read arbitrary files
- Can expose sensitive data from any path on the server's filesystem
- No validation that Category is within the reports directory
- Could leak database files, source code, configuration files, etc.

**Remediation:**
```go
// Validate and sanitize the category parameter
category = strings.Trim(category, "/") // Remove slashes
if !strings.HasPrefix(filepath.Join(s.reportsPath, category), s.reportsPath) {
    writeError(w, http.StatusBadRequest, "invalid category path")
    return
}

// Better: use a whitelist of allowed categories
allowedCategories := map[string]bool{
    "reports": true,
    // ... other allowed categories
}
if !allowedCategories[category] {
    writeError(w, http.StatusBadRequest, "invalid category")
    return
}
```

---

### 6. SQL Injection Risk in Task Creation (MEDIUM)

**File:** `pkg/store/store.go:168-182`  
**Risk:** MEDIUM - Manual string concatenation for user input in SQL query

```go
func (d *DB) CreateTask(ctx context.Context, name string, assignedTo, createdBy int64) (*Task, error) {
    res, err := d.db.ExecContext(ctx,
        `INSERT INTO tasks (name, status, assigned_to, created_by, created_at)
         VALUES ('`+name+`', ?, ?, ?, ?)`,  // WARNING: name is manually concatenated
        StatusInProgress, assignedTo, createdBy, now(),
    )
```

**Impact:**
- While wrapped in quotes making it less dangerous, this could still allow injection of SQL comments and other tricks
- If `name` contains characters that affect SQL parsing, unexpected behavior may occur
- Violates principle of using parameterized queries consistently

**Remediation:**
Use only parameterized queries. For string fields:
```go
res, err := d.db.ExecContext(ctx,
    `INSERT INTO tasks (name, status, assigned_to, created_by, created_at)
     VALUES (?, ?, ?, ?, ?)`,  // Note: no manual concatenation
    name, StatusInProgress, assignedTo, createdBy, now(),
)
```

---

### 7. Information Disclosure in Error Messages (MEDIUM)

**File:** `pkg/store/store.go`  
**Risk:** MEDIUM - Error messages leak internal system information

Multiple locations return error messages with specific details:
- `ErrNotFound`: Exposes internal error types
- Line 129: `"create user: %w: username %q"` - leaks that usernames are being checked
- Line 145: `"get user by username: %w: user %q"` - confirms existence of database table

**Impact:**
- Helps attackers understand the system's internal structure
- Can aid in reconnaissance and attack planning
- May leak existence/non-existence of resources (timing attacks)

**Remediation:** Use generic error messages that don't reveal system internals:
```go
return fmt.Errorf("invalid credentials")  // Instead of exposing table/column names
return ErrNotFound                       // Instead of embedding in string with user details
```

---

### 8. No Input Validation on Task Name (MEDIUM)

**File:** `pkg/httpapi/handlers.go:109-135`  
**Risk:** MEDIUM - Missing validation on task name input

```go
func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
    var body struct {
        Name string `json:"name"`
    }
    body.Name = strings.TrimSpace(body.Name)
    if body.Name == "" {  // Only checks for empty after trim
```

**Impact:**
- No length limits on task names (potential DoS via extremely long input)
- No validation of special characters
- Could lead to database size exhaustion or storage issues

**Remediation:**
```go
if body.Name == "" || len(body.Name) > 256 {
    writeError(w, http.StatusBadRequest, "task name must be between 1 and 256 characters")
    return
}
// Consider sanitizing or validating against a whitelist of allowed characters
```

---

### 9. Missing HTTPS Enforcement (MEDIUM)

**File:** `cmd/tasks-server/main.go:45-47`  
**Risk:** MEDIUM - API served over unencrypted HTTP by default

```go
return http.ListenAndServe(addr, httpapi.New(db, reportsPath))
```

**Impact:**
- All authentication tokens transmitted in plaintext
- User passwords and task data exposed to network eavesdropping
- Man-in-the-middle attacks possible

**Remediation:**
1. Default to HTTPS configuration
2. Provide clear instructions for TLS/SSL setup
3. Consider requiring HTTPS for all API endpoints
4. Use reverse proxy with TLS termination if self-hosting

---

## Additional Observations

### 10. No Account Enumeration Protection

Login endpoint does not differentiate between "invalid username" and "invalid password":
```go
if err != nil || !store.CheckPassword(user.PasswordHash, body.Password) {
    writeError(w, http.StatusUnauthorized, "invalid username or password")
}
```
**Remediation:** Always return the same error message regardless of whether the username exists.

---

### 11. No Password Complexity Requirements

No validation on user-provided passwords during creation.
**Remediation:** Implement minimum length (e.g., 8 characters), character requirements, and avoid common password dictionaries.

---

## Risk Summary Table

| ID | Finding | Risk Level | Impact |
|----|---------|------------|--------|
| 1 | Password hash in API response | HIGH | Credential compromise via offline attacks |
| 2 | In-memory token store (no TTL) | HIGH | All sessions compromised on server breach |
| 3 | No rate limiting on auth | HIGH | Brute force password guessing possible |
| 4 | Plaintext password printed to console | MEDIUM-HIGH | Credentials logged/exposed on startup |
| 5 | Path traversal in reports API | HIGH | Arbitrary file system access |
| 6 | SQL injection risk (manual concat) | MEDIUM | Potential query manipulation |
| 7 | Information disclosure errors | MEDIUM | System reconnaissance aid |
| 8 | No input validation on task names | MEDIUM | DoS via large payloads |
| 9 | No HTTPS enforcement | MEDIUM | All data transmitted in plaintext |
| 10 | Account enumeration possible | LOW | User discovery by attackers |
| 11 | No password complexity rules | LOW | Weak passwords accepted |

---

## Recommendations (Prioritized)

### Immediate Actions:
1. **Fix path traversal vulnerability** in reports API - prevent filesystem access abuse
2. **Implement rate limiting** on authentication endpoints
3. **Change admin username** from "admin" and remove plaintext password logging
4. **Remove password hash** from login response or ensure JSON tag exclusion works

### Short-term:
5. Replace in-memory token store with JWT tokens with expiration
6. Use parameterized queries for ALL database operations
7. Implement generic error messages that don't leak system information
8. Add input validation (length, special characters) on all user inputs

### Long-term:
9. Require HTTPS/TLS for API communication
10. Implement account lockout after failed login attempts
11. Add password complexity requirements
12. Consider implementing audit logging for admin actions

---

## Conclusion

The tasks-server application has several critical security vulnerabilities that expose sensitive data and allow potential unauthorized access. The most severe issues are the in-memory token store (no session expiration), path traversal vulnerability, lack of rate limiting on authentication, and hardcoded admin credentials printed to console. Immediate remediation is recommended for all high-risk findings before deploying to production environments.
