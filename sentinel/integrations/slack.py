"""Slack integration — slash commands, events API, signature verification."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)


def get_signing_secret() -> str:
    return os.environ.get("SLACK_SIGNING_SECRET", "")


def get_bot_token() -> str:
    return os.environ.get("SLACK_BOT_TOKEN", "")


def verify_signature(body: bytes, timestamp: str, signature: str) -> bool:
    """Verify Slack request signature using HMAC-SHA256."""
    secret = get_signing_secret()
    if not secret:
        logger.warning("SLACK_SIGNING_SECRET not set — skipping verification")
        return True

    # Reject old timestamps (> 5 min)
    try:
        if abs(time.time() - int(timestamp)) > 300:
            return False
    except (ValueError, TypeError):
        return False

    sig_basestring = f"v0:{timestamp}:{body.decode('utf-8')}"
    computed = "v0=" + hmac.new(
        secret.encode(), sig_basestring.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed, signature)


def parse_command(text: str) -> dict[str, Any]:
    """Parse a Sentinel slash command text.

    Examples:
        "cve CVE-2024-3094"             → {"action": "cve", "cve_id": "CVE-2024-3094"}
        "scan https://github.com/x/y --cve CVE-2024-3094" → {"action": "scan", "repo_url": "...", "cve_id": "..."}
    """
    text = text.strip()
    if not text:
        return {"action": "help"}

    parts = text.split()
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

    return {"action": "error", "message": f"Unknown command: {action}. Try `cve CVE-XXXX` or `scan <repo>`"}


def help_blocks() -> list[dict[str, Any]]:
    """Return Slack blocks with usage help."""
    return [
        {"type": "header", "text": {"type": "plain_text", "text": "🛡️ Sentinel — CVE Explainer", "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn", "text": (
            "*Commands:*\n"
            "• `/sentinel cve CVE-2024-3094` — Explain a CVE\n"
            "• `/sentinel cve CVE-2024-3094 --brief` — Brief summary\n"
            "• `/sentinel scan <repo-url> --cve CVE-XXXX` — Scan a repo\n"
            "• `/sentinel help` — This message"
        )}},
    ]


async def post_response(response_url: str, blocks: list[dict[str, Any]], text: str = "") -> None:
    """Post a response back to Slack via response_url."""
    async with httpx.AsyncClient(timeout=30) as client:
        payload: dict[str, Any] = {"response_type": "in_channel", "blocks": blocks}
        if text:
            payload["text"] = text
        resp = await client.post(response_url, json=payload)
        if resp.status_code != 200:
            logger.error("Slack response_url POST failed: %s %s", resp.status_code, resp.text)


async def post_to_channel(channel: str, blocks: list[dict[str, Any]], text: str = "", thread_ts: str | None = None) -> None:
    """Post a message to a Slack channel via Web API."""
    token = get_bot_token()
    if not token:
        logger.error("SLACK_BOT_TOKEN not set")
        return
    async with httpx.AsyncClient(timeout=30) as client:
        payload: dict[str, Any] = {
            "channel": channel,
            "blocks": blocks,
            "text": text or "Sentinel CVE Report",
        }
        if thread_ts:
            payload["thread_ts"] = thread_ts
        resp = await client.post(
            "https://slack.com/api/chat.postMessage",
            json=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        data = resp.json()
        if not data.get("ok"):
            logger.error("Slack API error: %s", data.get("error"))
