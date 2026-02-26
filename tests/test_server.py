"""Tests for Sentinel server, integrations, and formatters."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from sentinel.server import app
from sentinel.integrations.slack import parse_command as slack_parse, verify_signature as slack_verify
from sentinel.integrations.teams import parse_command as teams_parse, verify_hmac as teams_verify
from sentinel.integrations.telegram import parse_update as tg_parse
from sentinel.formatters import (
    format_slack_blocks,
    format_teams_card,
    format_telegram_md,
    format_plain,
    format_slack_scan_blocks,
    format_teams_scan_card,
    format_telegram_scan_md,
    format_plain_scan,
)

client = TestClient(app)


# ── Health ─────────────────────────────────────────────────────────────────

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "sentinel"


# ── Slack command parsing ──────────────────────────────────────────────────

def test_slack_parse_cve():
    result = slack_parse("cve CVE-2024-3094")
    assert result["action"] == "cve"
    assert result["cve_id"] == "CVE-2024-3094"


def test_slack_parse_cve_brief():
    result = slack_parse("cve CVE-2024-3094 --brief")
    assert result["action"] == "cve"
    assert result["brief"] is True


def test_slack_parse_scan():
    result = slack_parse("scan https://github.com/user/repo --cve CVE-2024-3094")
    assert result["action"] == "scan"
    assert result["repo_url"] == "https://github.com/user/repo"
    assert result["cve_id"] == "CVE-2024-3094"


def test_slack_parse_help():
    result = slack_parse("")
    assert result["action"] == "help"


def test_slack_parse_invalid_cve():
    result = slack_parse("cve NOTACVE")
    assert result["action"] == "error"


def test_slack_parse_unknown():
    result = slack_parse("foobar")
    assert result["action"] == "error"


# ── Slack signature verification ──────────────────────────────────────────

def test_slack_verify_valid():
    secret = "test_secret_123"
    body = b"token=xxx&command=/sentinel&text=cve+CVE-2024-3094"
    ts = str(int(time.time()))
    sig_base = f"v0:{ts}:{body.decode('utf-8')}"
    expected = "v0=" + hmac.new(secret.encode(), sig_base.encode(), hashlib.sha256).hexdigest()
    with patch.dict("os.environ", {"SLACK_SIGNING_SECRET": secret}):
        assert slack_verify(body, ts, expected) is True


def test_slack_verify_invalid():
    with patch.dict("os.environ", {"SLACK_SIGNING_SECRET": "secret"}):
        assert slack_verify(b"body", str(int(time.time())), "v0=bad") is False


def test_slack_verify_old_timestamp():
    with patch.dict("os.environ", {"SLACK_SIGNING_SECRET": "secret"}):
        assert slack_verify(b"body", "1000000000", "v0=anything") is False


# ── Teams parsing ──────────────────────────────────────────────────────────

def test_teams_parse_cve():
    result = teams_parse("cve CVE-2024-3094")
    assert result["action"] == "cve"
    assert result["cve_id"] == "CVE-2024-3094"


def test_teams_parse_with_mention():
    result = teams_parse("<at>Sentinel</at> cve CVE-2024-3094")
    assert result["action"] == "cve"
    assert result["cve_id"] == "CVE-2024-3094"


def test_teams_parse_scan():
    result = teams_parse("scan https://github.com/x/y --cve CVE-2024-1234")
    assert result["action"] == "scan"
    assert result["repo_url"] == "https://github.com/x/y"
    assert result["cve_id"] == "CVE-2024-1234"


def test_teams_parse_help():
    result = teams_parse("")
    assert result["action"] == "help"


# ── Teams HMAC verification ───────────────────────────────────────────────

def test_teams_verify_valid():
    import base64
    secret = base64.b64encode(b"my_secret_key").decode()
    body = b'{"text":"cve CVE-2024-3094"}'
    computed = base64.b64encode(hmac.new(b"my_secret_key", body, hashlib.sha256).digest()).decode()
    with patch.dict("os.environ", {"TEAMS_WEBHOOK_SECRET": secret}):
        assert teams_verify(body, f"HMAC {computed}") is True


def test_teams_verify_invalid():
    import base64
    secret = base64.b64encode(b"key").decode()
    with patch.dict("os.environ", {"TEAMS_WEBHOOK_SECRET": secret}):
        assert teams_verify(b"body", "HMAC badhmac") is False


# ── Telegram parsing ──────────────────────────────────────────────────────

def test_telegram_parse_cve():
    update = {"message": {"text": "/cve CVE-2024-3094", "chat": {"id": 123}, "message_id": 1, "from": {"id": 456}}}
    result = tg_parse(update)
    assert result["action"] == "cve"
    assert result["cve_id"] == "CVE-2024-3094"
    assert result["chat_id"] == 123


def test_telegram_parse_cve_with_bot_name():
    update = {"message": {"text": "/cve@SentinelBot CVE-2024-3094", "chat": {"id": 123}, "message_id": 1, "from": {"id": 456}}}
    result = tg_parse(update)
    assert result["action"] == "cve"
    assert result["cve_id"] == "CVE-2024-3094"


def test_telegram_parse_scan():
    update = {"message": {"text": "/scan https://github.com/x/y --cve CVE-2024-1234", "chat": {"id": 123}, "message_id": 1, "from": {"id": 456}}}
    result = tg_parse(update)
    assert result["action"] == "scan"
    assert result["repo_url"] == "https://github.com/x/y"
    assert result["cve_id"] == "CVE-2024-1234"


def test_telegram_parse_help():
    update = {"message": {"text": "/help", "chat": {"id": 123}, "message_id": 1, "from": {"id": 456}}}
    result = tg_parse(update)
    assert result["action"] == "help"


def test_telegram_parse_callback():
    update = {"callback_query": {"id": "cb1", "data": "cve_full:CVE-2024-3094", "message": {"chat": {"id": 123}, "message_id": 1}}}
    result = tg_parse(update)
    assert result["action"] == "callback"
    assert result["data"] == "cve_full:CVE-2024-3094"


def test_telegram_parse_ignore():
    update = {"message": {"text": "hello", "chat": {"id": 123}, "message_id": 1, "from": {"id": 456}}}
    result = tg_parse(update)
    assert result["action"] == "ignore"


# ── Formatters ─────────────────────────────────────────────────────────────

_SAMPLE_RESULT = {
    "cve_id": "CVE-2024-3094",
    "analysis": {
        "sections": {
            "what_it_is": "A backdoor in xz-utils.",
            "how_to_exploit": "Supply chain attack.",
            "who_should_panic": "Anyone using xz 5.6.0-5.6.1.",
            "how_to_patch": "Downgrade to 5.4.x.",
            "what_to_test": "Check xz --version.",
        }
    },
    "sources": {"nvd": {}, "osv": {}},
}

_SAMPLE_SCAN = {
    "scan": {
        "status": "AFFECTED",
        "details": [{"dependency": "xz-utils", "your_version": "5.6.0", "fix_version": "5.4.6", "status": "AFFECTED"}],
        "vulnerabilities": [],
    },
    "cve_id": "CVE-2024-3094",
    "path": ".",
}


def test_format_slack_blocks():
    blocks = format_slack_blocks(_SAMPLE_RESULT)
    assert len(blocks) > 0
    assert blocks[0]["type"] == "header"
    assert "CVE-2024-3094" in blocks[0]["text"]["text"]


def test_format_slack_scan_blocks():
    blocks = format_slack_scan_blocks(_SAMPLE_SCAN)
    assert len(blocks) > 0
    assert "Scan" in blocks[0]["text"]["text"]


def test_format_teams_card():
    card = format_teams_card(_SAMPLE_RESULT)
    assert "attachments" in card
    content = card["attachments"][0]["content"]
    assert content["type"] == "AdaptiveCard"
    assert any("CVE-2024-3094" in b.get("text", "") for b in content["body"])


def test_format_teams_scan_card():
    card = format_teams_scan_card(_SAMPLE_SCAN)
    assert "attachments" in card


def test_format_telegram_md():
    text = format_telegram_md(_SAMPLE_RESULT)
    assert "CVE\\-2024\\-3094" in text
    assert "Sentinel" in text


def test_format_telegram_scan_md():
    text = format_telegram_scan_md(_SAMPLE_SCAN)
    assert "Scan" in text


def test_format_plain():
    text = format_plain(_SAMPLE_RESULT)
    assert "CVE-2024-3094" in text
    assert "WHAT IT IS" in text


def test_format_plain_scan():
    text = format_plain_scan(_SAMPLE_SCAN)
    assert "CVE-2024-3094" in text


# ── API endpoints ──────────────────────────────────────────────────────────

def test_api_cve_invalid():
    resp = client.post("/api/cve", json={"cve_id": "NOTACVE"})
    assert resp.status_code == 400


def test_api_scan_missing_url():
    resp = client.post("/api/scan", json={})
    assert resp.status_code == 400


def test_api_scan_invalid_cve():
    resp = client.post("/api/scan", json={"repo_url": "https://github.com/x/y", "cve_id": "BAD"})
    assert resp.status_code == 400
