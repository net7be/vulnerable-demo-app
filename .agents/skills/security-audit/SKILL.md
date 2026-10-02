---
name: security-audit
description: Audit current changes, a path, or the full project for security or obvious code quality issue
disable-model-invocation: true
---

# security-audit - Review code for security issues and obvious code quality issues

Unless told differently, read every single code file. Ignore anything from `.gitignore`. Don't edit any source file from the project.

- Look for missing authentication or authorization, client-controlled ownership, injection of any kind (in query parameters or commands, URLs, etc.) without parameterized or sanitized queries, unsafe parsing or deserialization, sensitive-data exposure, secret handling, insecure defaults, trust-boundary mistakes and path traversal.
- Check error messages to make sure they don't disclose too much information on the system
- Look at all the user entry points such as API endpoints or methods directly invokable from UI or CLI and check for any of these possibly leaking more data than they should.
- Report any such place allowing the upload of arbitrary data.

If a possible secret is found, never quote its value, paste the matching source line, or include raw command output containing it. Report only the redacted secret category, file, line, risk, and remediation. Redact sensitive values from all audit evidence before responding.

Do not use full local filesystem paths in the report, always make them relative to project root.

List all findings, explain why they matter and suggest a fix or resolution but keep those as short as possible.

Use a simple classification of "High risk" first and then all the rest.

Save a copy of the full report in a temporary directory, formatted in markdown.

## Specific unintended information disclosure files to look for
Ignore any of these if they're covered by a relevant `.gitignore` file.

- `.env` files and similar that contain secrets
- config files that contain secrets
- doc files that contain secrets
- Database dumps and account creation information
- Full database file (e.g. sqlite)
- Log files
- Test fixtures

Don't attempt to convert PDF or doc, docx files into text nor to OCR images.
