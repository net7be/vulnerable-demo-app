# Security Audit Report

## Summary of Findings
- **Path Traversal**: High risk finding in `handleReportsList` where user input is used to construct a file path.
- **SQL Injection**: Potential issue in `CreateTask` where a string is concatenated into a query.
- **Information Disclosure**: `handleCreateUser` returns the raw password to the client.

## Findings

### High Risk
- **Path Traversal**
  - **Location**: `pkg/httpapi/handlers.go:242`
  - **Description**: The `handleReportsList` function uses `filepath.Join(s.reportsPath, body.Category)` with `body.Category` directly from user input. This allows an attacker to use `../` sequences to read arbitrary files outside the intended reports directory.
  - **Suggested Fix**: Validate `body.Category` against an allowed list of categories or sanitize it to prevent directory traversal.

### Medium Risk
- **SQL Injection**
  - **Location**: `pkg/store/store.go:171`
  - **Description**: In `CreateTask`, the `name` parameter is concatenated directly into the SQL query: `VALUES ('`+name+`', ?, ?, ?)`. While `name` comes from a JSON body, it should still be handled using parameterized queries.
  - **Suggested Fix**: Use a parameterized query for the `name` field: `VALUES (?, ?, ?, ?)`.

- **Information Disclosure**
  - **Location**: `pkg/httpapi/handlers.go:96`
  - **Description**: The `handleCreateUser` function returns the plain-text password in the JSON response. This is unnecessary and potentially dangerous if the response is logged or intercepted.
  - **Suggested Fix**: Remove the `password` field from the response map.

### Low Risk
- **Information Disclosure**
  - **Location**: `pkg/store/seed.go:44-45`
  - **Description**: The `seedAdmin` function prints the default admin password to standard output. While intended for first-time setup, this could lead to secrets appearing in logs.
  - **Suggested Fix**: Only print the password if explicitly requested via a flag or environment variable.
