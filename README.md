# 🛡️ Sentinel — CVE Explainer CLI

**"Does this CVE even affect me?"** — answered in seconds, not hours.

Sentinel takes a CVE ID, fetches data from NVD, OSV.dev, and MITRE, then uses Claude to produce a clear, actionable 5-section vulnerability briefing.

## Install

```bash
cd sentinel/
pip install -e .
```

## Configure

```bash
# Required: Anthropic API key
sentinel config set api-key sk-ant-...

# Optional: NVD API key (higher rate limits)
sentinel config set nvd-key xxxxxxxx-xxxx-...

# Or use environment variables
export ANTHROPIC_API_KEY=sk-ant-...
export NVD_API_KEY=xxxxxxxx-xxxx-...
```

## Usage

```bash
# Explain a CVE (5-section report with colored terminal output)
sentinel cve CVE-2024-3094

# Choose output persona (see Personas below)
sentinel cve CVE-2024-3094 --format exec       # Executive / CISO summary
sentinel cve CVE-2024-3094 -f engineer          # Deep technical advisory
sentinel cve CVE-2024-3094 -f devops            # Infrastructure-focused
sentinel cve CVE-2024-3094 -f security          # Default 5-section report

# Also works with scan
sentinel scan . --cve CVE-2024-3094 --format exec

# JSON output
sentinel cve CVE-2024-3094 --json

# Markdown output
sentinel cve CVE-2024-3094 --markdown

# Brief one-paragraph summary
sentinel cve CVE-2024-3094 --brief

# Skip cache, fetch fresh data
sentinel cve CVE-2024-3094 --no-cache

# Verbose mode (show timing and source details)
sentinel cve CVE-2024-3094 -v
```

## Output Personas (`--format` / `-f`)

### `security` (default) — Security Analyst
The classic 5-section vulnerability briefing:

| Section | What it answers |
|---|---|
| 🔍 **What it is** | Plain-English explanation |
| 💥 **How to exploit** | Attack vector, PoC summary, difficulty |
| 🚨 **Who should panic** | Affected software, versions, ecosystems |
| 🛡️ **How to patch safely** | Remediation steps, patch links |
| ✅ **What to test** | Verification steps after patching |

### `exec` — Executive / CISO
A 10-second read for busy executives. Traffic light severity, business impact, one action item. No jargon.

```
🔴 CRITICAL — CVE-2024-3094 (XZ Backdoor)

A backdoor was planted in a core Linux compression library used across most servers.
Attackers can intercept and modify data on any system running xz 5.6.0-5.6.1.
Immediate downgrade required — estimated 15-30 min per server, no downtime expected.

Risk: Supply chain compromise — high severity, active exploitation
Impact: All Linux infrastructure running affected versions
Action needed: Downgrade xz to 5.4.6. Verify with `xz --version`.
```

### `engineer` — Software Engineer
Deep technical dive with exact versions, upgrade commands, grep patterns, and test steps:

| Section | Focus |
|---|---|
| 📦 **Affected Libraries & Versions** | Exact version ranges, dependency chains |
| 🔧 **Code-Level Remediation** | Specific upgrade commands, config changes |
| 🔍 **What to Grep For** | Patterns to search your codebase |
| 🧪 **How to Test the Fix** | Verification commands, regression tests |
| ⚠️ **Breaking Changes** | Deprecations, behavioral differences |

### `devops` — DevOps / SRE
Infrastructure-focused with containers, K8s, CI/CD, and monitoring:

| Section | Focus |
|---|---|
| 🏗️ **Affected Infrastructure** | Base images, containers, cloud services |
| 🚀 **Deployment Impact** | Rolling update strategy, downtime assessment |
| 🔄 **Rollback Plan** | How to revert if the patch causes issues |
| 📊 **Monitoring & Detection** | Logs, alerts, exploitation detection |
| 🚨 **Incident Response Steps** | Step-by-step if actively exploited |

## Cache Management

```bash
sentinel cache clear    # Clear all cached data
```

## Config

Config stored at `~/.sentinel/config.json`. Cache at `~/.sentinel/cache.db`.

```bash
sentinel config set api-key <key>
sentinel config set nvd-key <key>
sentinel config set model <model-name>
sentinel config get api-key
```

## 🌐 Webhook Server & Integrations

Sentinel includes a FastAPI server that accepts commands from Slack, Microsoft Teams, Telegram, and a generic REST API.

### Start the Server

```bash
sentinel server start                    # Default port 8080
sentinel server start --port 9090        # Custom port
sentinel server start --workers 4        # Multiple workers
sentinel server status                   # Check if running
```

### REST API

```bash
# Explain a CVE
curl -X POST http://localhost:8080/api/cve \
  -H "Content-Type: application/json" \
  -d '{"cve_id": "CVE-2024-3094"}'

# Scan a repo
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/user/repo", "cve_id": "CVE-2024-3094"}'

# Health check
curl http://localhost:8080/health
```

### Slack Integration

```bash
sentinel setup slack   # Interactive setup guide
```

1. Create a Slack app using `config/slack-manifest.yml`
2. Set environment variables:
   ```bash
   export SLACK_SIGNING_SECRET=<signing-secret>
   export SLACK_BOT_TOKEN=xoxb-<bot-token>
   ```
3. Set slash command URL to `https://<your-domain>/slack/commands`
4. Set events URL to `https://<your-domain>/slack/events`
5. Use: `/sentinel cve CVE-2024-3094` or `@Sentinel cve CVE-2024-3094`

### Microsoft Teams Integration

```bash
sentinel setup teams   # Interactive setup guide
```

1. Create an outgoing webhook in your Teams channel pointing to `https://<your-domain>/teams/webhook`
2. Set environment variables:
   ```bash
   export TEAMS_WEBHOOK_SECRET=<base64-hmac-secret>
   ```
3. Mention the bot: `@Sentinel cve CVE-2024-3094`

### Telegram Integration

```bash
sentinel setup telegram   # Interactive setup guide
```

1. Create a bot via @BotFather
2. Set environment variables:
   ```bash
   export TELEGRAM_BOT_TOKEN=<bot-token>
   ```
3. Set webhook: `curl -X POST "https://api.telegram.org/bot<TOKEN>/setWebhook" -d '{"url":"https://<YOUR_DOMAIN>/telegram/webhook"}'`
4. Send commands: `/cve CVE-2024-3094`, `/scan <repo> --cve CVE-XXXX`

### Docker Deployment

```bash
cd docker/
# Set env vars in .env file or export them
docker compose up -d

# With nginx reverse proxy:
docker compose --profile with-nginx up -d
```

### Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/api/cve` | POST | REST API — explain a CVE |
| `/api/scan` | POST | REST API — scan a repo |
| `/slack/commands` | POST | Slack slash commands |
| `/slack/events` | POST | Slack Events API |
| `/teams/webhook` | POST | Teams outgoing webhook |
| `/telegram/webhook` | POST | Telegram bot webhook |
