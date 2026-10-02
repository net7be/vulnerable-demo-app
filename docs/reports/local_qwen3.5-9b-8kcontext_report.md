# Security Audit Report - Tasks Demo API

**Date:** September 28, 2026  
**Project:** tasks-demo  
**Auditor:** Automated Security Analysis

---

## Executive Summary

The tasks-demo project is a Go-based REST API for task management with in-memory token authentication and SQLite storage. The audit identified **10 security issues** ranging from critical to low severity. Key findings include:

- **CRITICAL:** SQL injection vulnerability in task creation
- **CRITICAL:** Server-side path traversal in reports endpoint
- **HIGH:** Hardcoded default admin password
- **MEDIUM:** Missing input validation and sanitization
- **MEDIUM:** In-memory token store with no expiration
- **LOW:** Information disclosure through error messages

---

## Detailed Findings

### CRITICAL - SQL Injection in Task Creation

**Location:** `pkg/store/store.go:170`

```go
`INSERT INTO tasks (name, status, assigned_to, created_by, created_at)
    VALUES ('`+name+`', ?, ?, ?, ?)`,
```

**Description:** User-controlled input (`name`) is directly interpolated into SQL without parameterization, allowing SQL injection attacks.

**Impact:**
- Database manipulation and data corruption
- Authentication bypass (extracting password hashes)
- Data exfiltration
- Potential database server compromise

**Remediation:**
```go
`INSERT INTO tasks (name, status, assigned_to, created_by, created_at)
    VALUES (?, ?, ?, ?, ?)`,
    name, StatusInProgress, assignedTo, createdBy, now(),
```

---

### CRITICAL - Server-Side Path Traversal in Reports Endpoint

**Location:** `pkg/httpapi/handlers.go:219-226`

```go
if !strings.HasPrefix(filePath, reportsPath) {
    return nil, fmt.Errorf("invalid file path")
}
```

**Description:** The prefix check is insufficient to prevent path traversal. An attacker could use `../../../etc/passwd` style paths to read arbitrary files on the filesystem.

**Impact:**
- Unauthorized access to sensitive system files
- Data exfiltration
- Potential remote code execution if configuration files are readable

**Remediation:**
```go
absPath, err := filepath.Abs(filePath)
if err != nil {
    return nil, fmt.Errorf("resolve path: %w", err)
}
absReportsPath, err := filepath.Abs(reportsPath)
if err != nil {
    return nil, fmt.Errorf("resolve reports path: %w", err)
}
if !strings.HasPrefix(absPath, absReportsPath+"/") && absPath != absReportsPath {
    return nil, fmt.Errorf("access denied")
}
```

---

### HIGH - Hardcoded Default Admin Password

**Location:** `pkg/store/seed.go:28`

```go
username := "admin"
password := "admin123" // Default password for initial setup
```

**Description:** A hardcoded default admin password is used for the initial seed user. This creates a known credential that attackers can exploit.

**Impact:**
- Immediate unauthorized access to administrative functions
- Full system compromise (admin has all permissions)
- Credential stuffing attack vector

**Remediation:**
1. Force password change on first login
2. Disable default admin after initial setup
3. Use environment variable for initial credentials
4. Send password reset email to registered administrators

---

### MEDIUM - Missing Input Validation and Sanitization

**Location:** Multiple handlers in `pkg/httpapi/handlers.go`

**Description:** Several endpoints lack proper input validation:
- Task name length not validated (could be empty or excessively long)
- No validation on status values
- No rate limiting on authentication endpoints
- No request size limits

**Impact:**
- Denial of service through resource exhaustion
- Potential for buffer overflow if backend doesn't validate
- Spam/abuse prevention bypassed

**Affected Endpoints:**
- `POST /api/tasks` - task name validation missing
- `PUT /api/tasks/:id/status` - status value not validated
- `POST /api/login` - no rate limiting
- `POST /api/register` - no username validation

---

### MEDIUM - In-Memory Token Store with No Expiration

**Location:** `pkg/httpapi/auth.go:16`

```go
type TokenStore map[string]string // maps JWT to user ID
```

**Description:** Tokens are stored in-memory without expiration. On server restart, all sessions persist indefinitely.

**Impact:**
- Compromised credentials remain valid until server restart
- No way to invalidate tokens remotely
- Session fixation vulnerabilities
- Memory exhaustion with large number of concurrent users

**Remediation:**
```go
type TokenStore struct {
    tokens map[string]TokenInfo  // JWT -> { userID, expiry }
    mu     sync.RWMutex
}

type TokenInfo struct {
    UserID   int64
    Expiry   time.Time
}

// Validate checks if token is valid and not expired
func (s *TokenStore) Validate(token string) (*User, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    info, ok := s.tokens[token]
    if !ok || time.Now().After(info.Expiry) {
        return nil, ErrInvalidToken
    }
    
    user, err := storeDB.GetUserByID(ctx, info.UserID)
    if err != nil {
        return nil, ErrUserNotFound
    }
    
    return user, nil
}
```

---

### MEDIUM - No CORS Configuration

**Location:** `pkg/httpapi/server.go` (no CORS middleware found)

**Description:** Cross-Origin Resource Sharing is not explicitly configured. Default behavior may block legitimate cross-origin requests or allow excessive cross-origin access if misconfigured.

**Impact:**
- CSRF attacks from malicious origins
- Information disclosure to untrusted domains
- Browser security controls bypassed

**Remediation:**
Add CORS middleware with explicit allowed origins, methods, and headers.

---

### LOW - Information Disclosure Through Error Messages

**Location:** Throughout codebase (e.g., `pkg/store/store.go:145`, `pkg/store/store.go:161`)

```go
return nil, fmt.Errorf("%w: user %q", ErrNotFound, username)
```

**Description:** Detailed error messages reveal information about internal state (usernames, IDs).

**Impact:**
- Information leakage to attackers
- ReDoS attacks through predictable error patterns
- User enumeration vulnerabilities

**Remediation:** Use generic error messages for production:
```go
return nil, fmt.Errorf("%w", ErrNotFound)
```

---

### LOW - Missing Security Headers

**Location:** `pkg/httpapi/server.go` (no security headers configured)

**Description:** Essential HTTP security headers are not set.

**Impact:**
- Clickjacking attacks possible without X-Frame-Options
- Cache poisoning with missing Content-Security-Policy
- XSS attacks facilitated by missing CSP
- Information leakage via missing HSTS

**Remediation:** Add middleware to set:
```go
Headers: {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}
```

---

### LOW - No Password Complexity Requirements

**Location:** `pkg/httpapi/handlers.go:28-49`

**Description:** User registration accepts any password without complexity requirements.

**Impact:**
- Dictionary attacks more effective
- Credential stuffing success rate increases
- Weak passwords easily compromised

**Remediation:** Add validation function:
```go
func validatePassword(password string) error {
    if len(password) < 8 {
        return errors.New("password must be at least 8 characters")
    }
    // Check for uppercase, lowercase, digit, special character
    hasUpper, hasLower, hasDigit, hasSpecial := ...
    if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
        return errors.New("password must contain uppercase, lowercase, digit, and special character")
    }
    return nil
}
```

---

### LOW - No Activity Logging/Auditing

**Location:** `cmd/tasks-server/main.go` (logging configured but not comprehensive)

```go
logger := zap.L() // Basic logging
```

**Description:** Only basic logging is configured. Security-critical events are not logged:
- Authentication failures/successes
- Permission denials
- Admin actions
- Database access patterns

**Impact:**
- Difficulty detecting and investigating security incidents
- Compliance requirements may not be met
- No audit trail for forensic analysis

**Remediation:** Add middleware to log:
- All authentication events
- All admin operations
- Failed authorization attempts
- Suspicious patterns (rate limiting triggers, etc.)

---

## Risk Assessment Matrix

| Severity | Count | Priority |
|----------|-------|----------|
| CRITICAL | 2     | Immediate action required |
| HIGH     | 1     | Fix within 7 days |
| MEDIUM   | 3     | Fix within 30 days |
| LOW      | 4     | Address in next sprint |

---

## Recommendations Summary

### Immediate Actions (This Sprint)
1. **Fix SQL injection** in task creation - highest priority
2. **Patch path traversal** in reports endpoint
3. **Remove or secure** default admin password

### Short-term (Next 2 Sprints)
4. Add input validation to all handlers
5. Implement token expiration
6. Add CORS configuration with allowed origins

### Medium-term (Next Month)
7. Add security headers middleware
8. Implement rate limiting on auth endpoints
9. Add password complexity requirements
10. Enhance logging for security events

---

## Compliance Notes

This application may require additional security controls to meet:
- **OWASP Top 10** compliance (currently failing multiple categories)
- **SOC 2** Type II (insufficient audit logging)
- **PCI-DSS** (if handling card data, not applicable currently)
- **GDPR** (user data handling lacks consent management)

---

## Testing Recommendations

Before deploying fixes:
1. Run automated security scanning (Snyk, SonarQube)
2. Conduct penetration testing
3. Perform code review of all changes
4. Test in isolated environment matching production configuration

---

*Report generated automatically by security audit tool.*
