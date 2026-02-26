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

## Output Sections

| Section | What it answers |
|---|---|
| 🔍 **What it is** | Plain-English explanation |
| 💥 **How to exploit** | Attack vector, PoC summary, difficulty |
| 🚨 **Who should panic** | Affected software, versions, ecosystems |
| 🛡️ **How to patch safely** | Remediation steps, patch links |
| ✅ **What to test** | Verification steps after patching |

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
