# Security Fixes — Audit & Remediation Report

**Date:** 2026-03-01
**Triggered by:** Community security review (credit: Reddit user dexgh0st)
**Auditor:** Automated + manual review

---

## Summary

| Severity | Found | Fixed | Status |
|----------|-------|-------|--------|
| 🔴 Critical | 3 | 3 | ✅ Remediated |
| 🟠 High | 5 | 5 | ✅ Remediated |
| 🟡 Medium | 4 | 4 | ✅ Remediated |
| **Total** | **12** | **12** | **All fixed** |

---

## 🔴 Critical Issues

### CRIT-01: Command Injection via Container Image Names
**File:** `sentinel/k8s_scanner.py` — `_run_in_container()`
**CWE:** CWE-78 (OS Command Injection)

**Before:**
```python
subprocess.run(
    [runtime, "run", "--rm", "--entrypoint", "/bin/sh", image, "-c", cmd],
    capture_output=True, text=True, timeout=120,
)
```
Image names from K8s API responses were passed directly to subprocess without validation. A malicious image name containing shell metacharacters could execute arbitrary commands.

**Fix:**
- Added `validate_image_name()` from `sentinel/sanitize.py` — rejects shell metacharacters
- Added container hardening flags: `--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--memory 512m`, `--cpus 0.5`
- Image names validated against strict regex before subprocess call

---

### CRIT-02: Authentication Bypass in Slack & Teams Integrations
**Files:** `sentinel/integrations/slack.py`, `sentinel/integrations/teams.py`
**CWE:** CWE-287 (Improper Authentication)

**Before:**
```python
if not secret:
    logger.warning("SLACK_SIGNING_SECRET not set — skipping verification")
    return True  # ← ALLOWS UNAUTHENTICATED REQUESTS
```
When signing secrets weren't configured, signature verification returned `True`, allowing anyone to send commands.

**Fix:**
- Changed to `return False` — deny by default
- Changed log level from `warning` to `error`
- Server rejects requests with 401 when verification fails
- Both Slack and Teams integrations now require valid signatures

---

### CRIT-03: Source Code Sent to Claude via deep_scan.py
**File:** `sentinel/deep_scan.py` — `_build_code_context()`
**CWE:** CWE-200 (Exposure of Sensitive Information)

**Before:**
```python
# Sent 11 lines of surrounding source code per usage to Claude
entry = f"--- {usage.file}:{usage.line} ---\n{usage.snippet}\n"
```
The deep scan feature sent actual source code snippets (up to 12,000 characters) to the Claude API, violating the project's core security promise of "no source code sent externally."

**Fix:**
- Replaced `_build_code_context()` with `_build_sanitized_context()` — sends ONLY file names, line numbers, and single-line import statements
- Added `contains_source_code()` assertion before every Claude API call
- Added audit logging of all data sent to Claude at `~/.sentinel/audit.log`
- Original function preserved for local-only display, clearly marked as DEPRECATED and NEVER for external use

---

## 🟠 High Issues

### HIGH-01: Git Clone URL Injection
**File:** `sentinel/scanner.py` — `clone_repo()`
**CWE:** CWE-20 (Improper Input Validation)

**Before:** Accepted any URL including `git://`, `ssh://`, `file://` schemes and URLs with shell metacharacters.

**Fix:**
- Added `validate_url()` — HTTPS only, known hosts (github.com, gitlab.com, bitbucket.org)
- Rejects URLs starting with `-` (flag injection)
- Rejects shell metacharacters
- Added `--` separator in git command to prevent flag injection

---

### HIGH-02: No Input Validation on API Endpoints
**File:** `sentinel/server.py`
**CWE:** CWE-20 (Improper Input Validation)

**Fix:** Added `validate_cve_id()` validation at all API entry points. Malformed CVE IDs return 400 Bad Request.

---

### HIGH-03: Temp Directory Security
**File:** `sentinel/scanner.py`
**CWE:** CWE-377 (Insecure Temporary File)

**Fix:** Added try/finally cleanup guarantee and restrictive permissions (0o700) on temp directories.

---

### HIGH-04: Missing CORS Restrictions
**File:** `sentinel/server.py`
**CWE:** CWE-346 (Origin Validation Error)

**Fix:** Added CORS middleware with restrictive default origins (not `*`). Configurable via `SENTINEL_CORS_ORIGINS` environment variable.

---

### HIGH-05: Missing Security Headers
**File:** `sentinel/server.py`
**CWE:** CWE-693 (Protection Mechanism Failure)

**Fix:** Added middleware for:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'none'`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `X-XSS-Protection: 1; mode=block`

---

## 🟡 Medium Issues

### MED-01: Slack response_url SSRF
**File:** `sentinel/integrations/slack.py`
**CWE:** CWE-918 (Server-Side Request Forgery)

**Fix:** Validated that `response_url` is on a Slack domain (`hooks.slack.com`) before posting.

---

### MED-02: Error Message Information Leakage
**File:** `sentinel/server.py`
**CWE:** CWE-209 (Information Exposure Through Error Messages)

**Fix:** Generic error messages for client-facing responses. Detailed errors only logged server-side.

---

### MED-03: API Key Leakage in Logs
**Files:** Various
**CWE:** CWE-532 (Information Exposure Through Log Files)

**Fix:** Added `sanitize_log_output()` utility that redacts API keys, tokens, JWTs, and credentials from log output. Applied across all modules.

---

### MED-04: Config File Permissions
**File:** `sentinel/config.py`
**CWE:** CWE-276 (Incorrect Default Permissions)

**Fix:** Verified config file at `~/.sentinel/config.json` is created with `0o600` permissions (owner read/write only).

---

## New Security Infrastructure

### sentinel/sanitize.py (NEW)
Centralized input validation module:
- `validate_cve_id()` — strict CVE format
- `validate_image_name()` — container image validation
- `validate_url()` — HTTPS-only URL validation
- `sanitize_log_output()` — secret redaction for logs

### Audit Logging
All Claude API calls now logged to `~/.sentinel/audit.log` with:
- Timestamp
- Action type
- CVE ID
- Data length and preview (first 200 chars)
- No source code ever in audit log

### SECURITY.md (NEW)
Project security policy documenting:
- Vulnerability reporting process
- Security design principles
- Configuration requirements
- Known limitations

---

## Verification

All 150 existing tests continue to pass after remediation.
No functional regressions introduced.

```
========================= 150 passed, 2 warnings =========================
```
