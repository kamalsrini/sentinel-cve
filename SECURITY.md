# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in Sentinel, please report it responsibly:

- **Email:** security@notabotkamal.substack.com
- **Do not** open a public GitHub issue for security vulnerabilities
- We aim to respond within 48 hours and provide a fix within 7 days for critical issues

## Security Design Principles

### 1. No Source Code Exfiltration
Sentinel **never sends source code** to external APIs (including Claude). Only sanitized metadata is sent:
- File names and line numbers
- Import statement names (single line)
- Function/module names
- Call graph edges (caller → callee)
- Package names and versions

This is enforced by:
- `SanitizedContext` class with `contains_source_code()` assertion
- Audit logging of all Claude API calls at `~/.sentinel/audit.log`
- `--local-only` flag for fully air-gapped analysis

### 2. Deny by Default
- Missing API secrets = **request rejected** (not bypassed)
- Missing authentication = **401 Unauthorized**
- Unknown hosts = **rejected** for git clone operations
- Non-HTTPS URLs = **rejected**

### 3. Input Validation
All user input passes through `sentinel/sanitize.py`:
- `validate_cve_id()` — strict CVE-YYYY-NNNNN format
- `validate_image_name()` — rejects shell metacharacters
- `validate_url()` — HTTPS only, known hosts only, no flag injection

### 4. Container Isolation
When scanning container images, Sentinel runs containers with:
- `--network none` — no network access
- `--read-only` — no filesystem writes
- `--cap-drop ALL` — drop all Linux capabilities
- `--security-opt no-new-privileges` — prevent privilege escalation
- `--memory 512m --cpus 0.5` — resource limits

### 5. Least Privilege
- K8s scanning uses read-only RBAC (see `config/k8s-rbac.yaml`)
- ServiceNow integration uses minimum required API scopes
- Config files stored with `0o600` permissions

## Security Configuration

### Required Environment Variables (for server mode)
```bash
SLACK_SIGNING_SECRET=<your-slack-signing-secret>    # Required for Slack integration
SLACK_BOT_TOKEN=<your-slack-bot-token>              # Required for Slack posting
TEAMS_WEBHOOK_SECRET=<your-teams-secret>            # Required for Teams integration
TELEGRAM_BOT_TOKEN=<your-telegram-bot-token>        # Required for Telegram integration
ANTHROPIC_API_KEY=<your-api-key>                    # Required for Claude analysis
```

**Warning:** The server will reject requests to Slack/Teams/Telegram endpoints if the corresponding secrets are not configured. This is intentional — security by default.

### Allowed Git Hosts
By default, `sentinel scan` only clones from:
- github.com
- gitlab.com
- bitbucket.org

To add custom hosts, set `SENTINEL_ALLOWED_GIT_HOSTS=github.com,gitlab.internal.com`

## Known Limitations

1. **Regex-based parsing** for some languages (JS/Go/Java imports) may miss edge cases
2. **Source code detection heuristic** errs on the side of caution — may block clean text that looks like code
3. **Execution path analysis** is static — dynamic dispatch, reflection, and plugins may bypass detection
4. **Version matching** depends on OSV/NVD data accuracy

## Dependencies

Sentinel's own dependencies are regularly audited. Run `sentinel scan .` to check Sentinel against itself.
