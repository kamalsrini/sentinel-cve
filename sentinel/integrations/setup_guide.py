"""Interactive setup guides for Slack, Teams, and Telegram integrations."""

from __future__ import annotations

import click


def setup_slack() -> None:
    """Walk through Slack app creation."""
    click.echo("""
🔧 Slack Setup — Sentinel CVE Explainer
========================================

1. Go to https://api.slack.com/apps
2. Click "Create New App" → "From an app manifest"
3. Paste the manifest from config/slack-manifest.yml (update your domain)
4. Install to your workspace
5. Copy the values below into your environment:

   export SLACK_SIGNING_SECRET=<from Basic Information → Signing Secret>
   export SLACK_BOT_TOKEN=xoxb-<from OAuth & Permissions → Bot User OAuth Token>

6. Set your slash command Request URL to:
   https://<your-domain>/slack/commands

7. Set Event Subscriptions Request URL to:
   https://<your-domain>/slack/events

8. Start the server:
   sentinel server start --port 8080

Done! Try `/sentinel cve CVE-2024-3094` in Slack.
""")


def setup_teams() -> None:
    """Walk through Teams app setup."""
    click.echo("""
🔧 Microsoft Teams Setup — Sentinel CVE Explainer
====================================================

Option A: Outgoing Webhook (simpler)
-------------------------------------
1. In your Teams channel, click ⋯ → Connectors → Outgoing Webhook
2. Name: "Sentinel", Callback URL: https://<your-domain>/teams/webhook
3. Copy the HMAC secret provided
4. Set environment:
   export TEAMS_WEBHOOK_SECRET=<base64 secret from Teams>

Option B: Bot Framework (richer)
---------------------------------
1. Register a bot at https://dev.botframework.com
2. Use the Teams app manifest from config/teams-manifest.json
3. Set environment:
   export TEAMS_WEBHOOK_SECRET=<your-app-password>

Then start the server:
   sentinel server start --port 8080

Mention @Sentinel in your channel: `@Sentinel cve CVE-2024-3094`
""")


def setup_telegram() -> None:
    """Walk through Telegram bot setup."""
    click.echo("""
🔧 Telegram Setup — Sentinel CVE Explainer
=============================================

1. Message @BotFather on Telegram
2. Send /newbot, follow the prompts
3. Copy the bot token
4. Set environment:
   export TELEGRAM_BOT_TOKEN=<your-bot-token>

5. Set the webhook (replace YOUR_DOMAIN and TOKEN):
   curl -X POST "https://api.telegram.org/bot<TOKEN>/setWebhook" \\
     -H "Content-Type: application/json" \\
     -d '{"url": "https://<YOUR_DOMAIN>/telegram/webhook"}'

6. Start the server:
   sentinel server start --port 8080

Done! Send /cve CVE-2024-3094 to your bot.
""")
