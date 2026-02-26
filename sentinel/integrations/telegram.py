"""Telegram bot integration — webhook handler, command parsing, message posting."""

from __future__ import annotations

import logging
import os
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

BOT_API = "https://api.telegram.org"


def get_bot_token() -> str:
    return os.environ.get("TELEGRAM_BOT_TOKEN", "")


def parse_update(update: dict[str, Any]) -> dict[str, Any]:
    """Parse a Telegram webhook update into a command.

    Returns dict with keys: action, chat_id, message_id, and command-specific fields.
    """
    message = update.get("message") or update.get("edited_message") or {}
    callback = update.get("callback_query")

    if callback:
        data = callback.get("data", "")
        chat_id = callback.get("message", {}).get("chat", {}).get("id")
        msg_id = callback.get("message", {}).get("message_id")
        return {"action": "callback", "data": data, "chat_id": chat_id, "message_id": msg_id, "callback_id": callback.get("id")}

    text = message.get("text", "").strip()
    chat_id = message.get("chat", {}).get("id")
    msg_id = message.get("message_id")
    user_id = message.get("from", {}).get("id")

    base = {"chat_id": chat_id, "message_id": msg_id, "user_id": user_id}

    if not text:
        return {**base, "action": "ignore"}

    # /cve CVE-2024-3094
    m = re.match(r"^/cve(?:@\w+)?\s+(CVE-\d{4}-\d{4,})\s*(.*)$", text, re.IGNORECASE)
    if m:
        cve_id = m.group(1).upper()
        flags = m.group(2)
        brief = "--brief" in flags
        return {**base, "action": "cve", "cve_id": cve_id, "brief": brief}

    # /scan <url> [--cve CVE-XXXX]
    m = re.match(r"^/scan(?:@\w+)?\s+(\S+)\s*(.*)$", text, re.IGNORECASE)
    if m:
        repo_url = m.group(1)
        rest = m.group(2)
        cve_id = None
        cve_m = re.search(r"--cve\s+(CVE-\d{4}-\d{4,})", rest, re.IGNORECASE)
        if cve_m:
            cve_id = cve_m.group(1).upper()
        return {**base, "action": "scan", "repo_url": repo_url, "cve_id": cve_id}

    # /start or /help
    if re.match(r"^/(start|help)(?:@\w+)?", text):
        return {**base, "action": "help"}

    return {**base, "action": "ignore"}


def help_text() -> str:
    return (
        "🛡️ *Sentinel — CVE Explainer*\n\n"
        "*Commands:*\n"
        "/cve CVE\\-2024\\-3094 — Explain a CVE\n"
        "/cve CVE\\-2024\\-3094 \\-\\-brief — Brief summary\n"
        "/scan <repo\\-url> \\-\\-cve CVE\\-XXXX — Scan a repo\n"
        "/help — This message"
    )


def cve_keyboard(cve_id: str) -> dict[str, Any]:
    """Inline keyboard for CVE results."""
    return {
        "inline_keyboard": [
            [
                {"text": "📋 Full details", "callback_data": f"cve_full:{cve_id}"},
                {"text": "🔍 Scan my repo", "callback_data": f"scan_prompt:{cve_id}"},
            ],
            [
                {"text": "🌐 View on NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
            ],
        ]
    }


async def send_message(
    chat_id: int | str,
    text: str,
    parse_mode: str = "MarkdownV2",
    reply_to: int | None = None,
    reply_markup: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Send a message via Telegram Bot API."""
    token = get_bot_token()
    if not token:
        logger.error("TELEGRAM_BOT_TOKEN not set")
        return {}
    url = f"{BOT_API}/bot{token}/sendMessage"
    payload: dict[str, Any] = {"chat_id": chat_id, "text": text}
    if parse_mode:
        payload["parse_mode"] = parse_mode
    if reply_to:
        payload["reply_parameters"] = {"message_id": reply_to}
    if reply_markup:
        payload["reply_markup"] = reply_markup

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, json=payload)
        data = resp.json()
        if not data.get("ok"):
            logger.error("Telegram API error: %s", data.get("description"))
            # Fallback: try without parse mode
            if parse_mode:
                payload.pop("parse_mode", None)
                resp = await client.post(url, json=payload)
                data = resp.json()
        return data


async def answer_callback(callback_id: str, text: str = "") -> None:
    """Answer a callback query."""
    token = get_bot_token()
    if not token:
        return
    url = f"{BOT_API}/bot{token}/answerCallbackQuery"
    async with httpx.AsyncClient(timeout=10) as client:
        await client.post(url, json={"callback_query_id": callback_id, "text": text})
