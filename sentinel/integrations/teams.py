"""Microsoft Teams integration — outgoing webhook and bot framework support."""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)


def get_webhook_secret() -> str:
    return os.environ.get("TEAMS_WEBHOOK_SECRET", "")


def get_webhook_url() -> str:
    """Outgoing connector/webhook URL for posting messages."""
    return os.environ.get("TEAMS_WEBHOOK_URL", "")


def verify_hmac(body: bytes, auth_header: str) -> bool:
    """Verify Teams outgoing webhook HMAC signature.

    Teams sends: Authorization: HMAC <base64-hmac>
    The HMAC is SHA256 of the raw body using the base64-decoded shared secret.
    """
    secret = get_webhook_secret()
    if not secret:
        logger.warning("TEAMS_WEBHOOK_SECRET not set — skipping verification")
        return True

    if not auth_header.startswith("HMAC "):
        return False
    provided = auth_header[5:]

    secret_bytes = base64.b64decode(secret)
    computed = base64.b64encode(
        hmac.new(secret_bytes, body, hashlib.sha256).digest()
    ).decode()
    return hmac.compare_digest(computed, provided)


def parse_command(text: str) -> dict[str, Any]:
    """Parse a command from a Teams message.

    Teams outgoing webhooks strip the bot mention, so the text may look like:
        "cve CVE-2024-3094"
    Or from a full bot mention:
        "<at>Sentinel</at> cve CVE-2024-3094"
    """
    # Strip HTML at-mentions
    cleaned = re.sub(r"<at>[^<]*</at>\s*", "", text).strip()
    if not cleaned:
        return {"action": "help"}

    parts = cleaned.split()
    action = parts[0].lower()

    if action == "cve" and len(parts) >= 2:
        cve_id = parts[1].upper()
        if re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
            brief = "--brief" in parts
            return {"action": "cve", "cve_id": cve_id, "brief": brief}
        return {"action": "error", "message": f"Invalid CVE ID: {parts[1]}"}

    if action == "scan" and len(parts) >= 2:
        repo_url = parts[1]
        cve_id = None
        if "--cve" in parts:
            idx = parts.index("--cve")
            if idx + 1 < len(parts):
                cve_id = parts[idx + 1].upper()
        return {"action": "scan", "repo_url": repo_url, "cve_id": cve_id}

    if action == "help":
        return {"action": "help"}

    return {"action": "error", "message": f"Unknown command: {action}"}


def help_card() -> dict[str, Any]:
    """Return a Teams Adaptive Card with usage help."""
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock", "text": "🛡️ Sentinel — CVE Explainer", "size": "Large", "weight": "Bolder"},
                    {"type": "TextBlock", "text": (
                        "**Commands:**\n"
                        "- `cve CVE-2024-3094` — Explain a CVE\n"
                        "- `cve CVE-2024-3094 --brief` — Brief summary\n"
                        "- `scan <repo-url> --cve CVE-XXXX` — Scan a repo\n"
                        "- `help` — This message"
                    ), "wrap": True},
                ],
            },
        }],
    }


async def post_to_webhook(card: dict[str, Any], webhook_url: str | None = None) -> None:
    """Post an Adaptive Card to a Teams webhook URL."""
    url = webhook_url or get_webhook_url()
    if not url:
        logger.error("TEAMS_WEBHOOK_URL not set")
        return
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, json=card)
        if resp.status_code not in (200, 201):
            logger.error("Teams webhook POST failed: %s %s", resp.status_code, resp.text)
