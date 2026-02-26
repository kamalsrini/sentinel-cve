"""Sentinel FastAPI server — webhook endpoints for Slack, Teams, Telegram, and REST API."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from collections import defaultdict
from typing import Any

from fastapi import BackgroundTasks, FastAPI, Request, Response
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

app = FastAPI(title="Sentinel CVE Explainer", version="0.1.0")

# ── Rate limiting ──────────────────────────────────────────────────────────

_rate_limits: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 10  # requests per window


def _check_rate_limit(key: str) -> bool:
    """Return True if under rate limit."""
    now = time.time()
    _rate_limits[key] = [t for t in _rate_limits[key] if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_limits[key]) >= RATE_LIMIT_MAX:
        return False
    _rate_limits[key].append(now)
    return True


# ── Core processing ────────────────────────────────────────────────────────

async def _process_cve(cve_id: str, brief: bool = False) -> dict[str, Any]:
    """Run CVE explainer and return result dict."""
    from sentinel.fetcher import fetch_cve_data
    from sentinel.synthesizer import analyze_cve
    from sentinel.cache import cache_get, cache_set

    cache_key = f"analysis:{cve_id}:{'brief' if brief else 'full'}"
    cached = await cache_get(cache_key, category="analysis")
    if cached:
        return {"cve_id": cve_id, "analysis": cached["analysis"], "sources": cached["sources"]}

    cve_data = await fetch_cve_data(cve_id)
    sources = cve_data.get("sources", {})
    raw_context = cve_data.get("raw_context", "")
    analysis = await analyze_cve(raw_context, brief=brief)

    await cache_set(cache_key, {"analysis": analysis, "sources": sources}, category="analysis")
    return {"cve_id": cve_id, "analysis": analysis, "sources": sources}


async def _process_scan(repo_url: str, cve_id: str | None = None) -> dict[str, Any]:
    """Run scan and return result dict."""
    from sentinel.scanner import scan_repo

    result = await scan_repo(repo_url, cve_id=cve_id)
    return {"scan": result.to_dict(), "cve_id": cve_id, "path": repo_url}


# ── Health ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinel"}


# ── REST API ───────────────────────────────────────────────────────────────

@app.post("/api/cve")
async def api_cve(request: Request) -> JSONResponse:
    body = await request.json()
    cve_id = body.get("cve_id", "").upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        return JSONResponse({"error": f"Invalid CVE ID: {cve_id}"}, status_code=400)
    if not _check_rate_limit(f"api:{request.client.host if request.client else 'unknown'}"):
        return JSONResponse({"error": "Rate limit exceeded"}, status_code=429)
    try:
        result = await _process_cve(cve_id, brief=body.get("brief", False))
        return JSONResponse({"cve_id": cve_id, "sections": result["analysis"].get("sections", {}), "sources": list(result.get("sources", {}).keys())})
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=404)
    except Exception as e:
        logger.exception("API CVE error")
        return JSONResponse({"error": "Internal error"}, status_code=500)


@app.post("/api/scan")
async def api_scan(request: Request) -> JSONResponse:
    body = await request.json()
    repo_url = body.get("repo_url", "")
    cve_id = body.get("cve_id")
    if not repo_url:
        return JSONResponse({"error": "repo_url is required"}, status_code=400)
    if cve_id:
        cve_id = cve_id.upper()
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
            return JSONResponse({"error": f"Invalid CVE ID: {cve_id}"}, status_code=400)
    if not _check_rate_limit(f"api:{request.client.host if request.client else 'unknown'}"):
        return JSONResponse({"error": "Rate limit exceeded"}, status_code=429)
    try:
        result = await _process_scan(repo_url, cve_id)
        return JSONResponse(result)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=404)
    except Exception as e:
        logger.exception("API scan error")
        return JSONResponse({"error": "Internal error"}, status_code=500)


# ── Slack ──────────────────────────────────────────────────────────────────

async def _slack_background(command: dict[str, Any], response_url: str) -> None:
    """Process a Slack command in the background and post results."""
    from sentinel.integrations.slack import post_response, help_blocks
    from sentinel.formatters import format_slack_blocks, format_slack_scan_blocks

    try:
        action = command["action"]
        if action == "cve":
            result = await _process_cve(command["cve_id"], brief=command.get("brief", False))
            blocks = format_slack_blocks(result)
            await post_response(response_url, blocks, text=f"Sentinel report for {command['cve_id']}")
        elif action == "scan":
            result = await _process_scan(command["repo_url"], command.get("cve_id"))
            blocks = format_slack_scan_blocks(result)
            await post_response(response_url, blocks, text="Sentinel scan results")
        elif action == "help":
            await post_response(response_url, help_blocks())
        elif action == "error":
            await post_response(response_url, [{"type": "section", "text": {"type": "mrkdwn", "text": f"❌ {command['message']}"}}])
    except Exception as e:
        logger.exception("Slack background task error")
        try:
            await post_response(response_url, [{"type": "section", "text": {"type": "mrkdwn", "text": f"❌ Error: {e}"}}])
        except Exception:
            pass


@app.post("/slack/commands")
async def slack_commands(request: Request, background_tasks: BackgroundTasks) -> Response:
    """Handle Slack slash commands. Must respond within 3 seconds."""
    from sentinel.integrations.slack import verify_signature, parse_command

    body = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")

    if not verify_signature(body, timestamp, signature):
        return JSONResponse({"error": "Invalid signature"}, status_code=401)

    form = await request.form()
    text = str(form.get("text", ""))
    response_url = str(form.get("response_url", ""))
    user_id = str(form.get("user_id", ""))

    if not _check_rate_limit(f"slack:{user_id}"):
        return JSONResponse({"response_type": "ephemeral", "text": "⏳ Rate limit exceeded. Please wait a minute."})

    command = parse_command(text)
    background_tasks.add_task(_slack_background, command, response_url)

    # Fast 200 acknowledgment
    return JSONResponse({"response_type": "in_channel", "text": f"🔍 Looking up... `{text}`"})


@app.post("/slack/events")
async def slack_events(request: Request, background_tasks: BackgroundTasks) -> Response:
    """Handle Slack Events API (app_mention)."""
    from sentinel.integrations.slack import verify_signature, parse_command, post_to_channel
    from sentinel.formatters import format_slack_blocks

    body = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")

    if not verify_signature(body, timestamp, signature):
        return JSONResponse({"error": "Invalid signature"}, status_code=401)

    data = await request.json()

    # URL verification challenge
    if data.get("type") == "url_verification":
        return JSONResponse({"challenge": data.get("challenge", "")})

    event = data.get("event", {})
    if event.get("type") != "app_mention":
        return Response(status_code=200)

    # Strip bot mention from text
    text = re.sub(r"<@\w+>\s*", "", event.get("text", "")).strip()
    channel = event.get("channel", "")
    thread_ts = event.get("thread_ts") or event.get("ts")

    command = parse_command(text)

    async def _events_bg() -> None:
        try:
            if command["action"] == "cve":
                result = await _process_cve(command["cve_id"], brief=command.get("brief", False))
                blocks = format_slack_blocks(result)
                await post_to_channel(channel, blocks, thread_ts=thread_ts)
            elif command["action"] == "help":
                from sentinel.integrations.slack import help_blocks
                await post_to_channel(channel, help_blocks(), thread_ts=thread_ts)
        except Exception as e:
            logger.exception("Slack events background error")
            await post_to_channel(channel, [{"type": "section", "text": {"type": "mrkdwn", "text": f"❌ Error: {e}"}}], thread_ts=thread_ts)

    background_tasks.add_task(_events_bg)
    return Response(status_code=200)


# ── Teams ──────────────────────────────────────────────────────────────────

@app.post("/teams/webhook")
async def teams_webhook(request: Request) -> Response:
    """Handle Teams outgoing webhook / bot messages."""
    from sentinel.integrations.teams import verify_hmac, parse_command, help_card
    from sentinel.formatters import format_teams_card, format_teams_scan_card

    body = await request.body()
    auth_header = request.headers.get("Authorization", "")

    if not verify_hmac(body, auth_header):
        return JSONResponse({"error": "Invalid HMAC"}, status_code=401)

    data = await request.json()
    text = data.get("text", "")
    command = parse_command(text)

    try:
        action = command["action"]
        if action == "cve":
            result = await _process_cve(command["cve_id"], brief=command.get("brief", False))
            card = format_teams_card(result)
            return JSONResponse(card)
        elif action == "scan":
            result = await _process_scan(command["repo_url"], command.get("cve_id"))
            card = format_teams_scan_card(result)
            return JSONResponse(card)
        elif action == "help":
            return JSONResponse(help_card())
        elif action == "error":
            return JSONResponse({"type": "message", "text": f"❌ {command['message']}"})
        else:
            return JSONResponse(help_card())
    except ValueError as e:
        return JSONResponse({"type": "message", "text": f"❌ {e}"})
    except Exception as e:
        logger.exception("Teams webhook error")
        return JSONResponse({"type": "message", "text": f"❌ Internal error: {e}"})


# ── Telegram ───────────────────────────────────────────────────────────────

@app.post("/telegram/webhook")
async def telegram_webhook(request: Request, background_tasks: BackgroundTasks) -> Response:
    """Handle Telegram bot webhook updates."""
    from sentinel.integrations.telegram import parse_update, send_message, help_text, cve_keyboard, answer_callback
    from sentinel.formatters import format_telegram_md, format_telegram_scan_md

    data = await request.json()
    parsed = parse_update(data)
    action = parsed.get("action")
    chat_id = parsed.get("chat_id")

    if action == "ignore" or not chat_id:
        return Response(status_code=200)

    user_id = parsed.get("user_id", chat_id)
    if not _check_rate_limit(f"tg:{user_id}"):
        background_tasks.add_task(send_message, chat_id, "⏳ Rate limit exceeded\\. Please wait a minute\\.", "MarkdownV2", parsed.get("message_id"))
        return Response(status_code=200)

    async def _tg_bg() -> None:
        try:
            if action == "cve":
                result = await _process_cve(parsed["cve_id"], brief=parsed.get("brief", False))
                text = format_telegram_md(result)
                keyboard = cve_keyboard(parsed["cve_id"])
                await send_message(chat_id, text, reply_to=parsed.get("message_id"), reply_markup=keyboard)
            elif action == "scan":
                result = await _process_scan(parsed["repo_url"], parsed.get("cve_id"))
                text = format_telegram_scan_md(result)
                await send_message(chat_id, text, reply_to=parsed.get("message_id"))
            elif action == "help":
                await send_message(chat_id, help_text(), reply_to=parsed.get("message_id"))
            elif action == "callback":
                cb_data = parsed.get("data", "")
                if cb_data.startswith("cve_full:"):
                    cve_id = cb_data.split(":", 1)[1]
                    result = await _process_cve(cve_id, brief=False)
                    text = format_telegram_md(result)
                    await send_message(chat_id, text)
                await answer_callback(parsed.get("callback_id", ""), "Processing...")
        except ValueError as e:
            await send_message(chat_id, f"❌ {str(e)}", parse_mode="")
        except Exception as e:
            logger.exception("Telegram background error")
            await send_message(chat_id, f"❌ Error: {str(e)}", parse_mode="")

    background_tasks.add_task(_tg_bg)
    return Response(status_code=200)
