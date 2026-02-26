"""SQLite caching layer for Sentinel.

Stores CVE data and analysis results at ~/.sentinel/cache.db with TTL-based expiration.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import aiosqlite

from sentinel.config import SENTINEL_DIR

DB_PATH = SENTINEL_DIR / "cache.db"

# TTLs in seconds
CVE_DATA_TTL = 24 * 3600       # 24 hours
ANALYSIS_TTL = 7 * 24 * 3600   # 7 days

_INIT_SQL = """\
CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    category TEXT NOT NULL,
    created_at REAL NOT NULL
);
"""


async def _get_db() -> aiosqlite.Connection:
    """Open (and initialize) the cache database."""
    SENTINEL_DIR.mkdir(parents=True, exist_ok=True)
    db = await aiosqlite.connect(str(DB_PATH))
    await db.execute(_INIT_SQL)
    await db.commit()
    return db


async def cache_get(key: str, category: str = "data") -> Any | None:
    """Retrieve a cached value if it exists and hasn't expired.

    Args:
        key: Cache key (e.g. "nvd:CVE-2024-3094").
        category: "data" (24h TTL) or "analysis" (7d TTL).

    Returns:
        The cached value (deserialized from JSON), or None.
    """
    ttl = ANALYSIS_TTL if category == "analysis" else CVE_DATA_TTL
    db = await _get_db()
    try:
        cursor = await db.execute(
            "SELECT value, created_at FROM cache WHERE key = ? AND category = ?",
            (key, category),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        value, created_at = row
        if time.time() - created_at > ttl:
            await db.execute("DELETE FROM cache WHERE key = ? AND category = ?", (key, category))
            await db.commit()
            return None
        return json.loads(value)
    finally:
        await db.close()


async def cache_set(key: str, value: Any, category: str = "data") -> None:
    """Store a value in the cache.

    Args:
        key: Cache key.
        value: JSON-serializable value.
        category: "data" or "analysis".
    """
    db = await _get_db()
    try:
        await db.execute(
            "INSERT OR REPLACE INTO cache (key, value, category, created_at) VALUES (?, ?, ?, ?)",
            (key, json.dumps(value), category, time.time()),
        )
        await db.commit()
    finally:
        await db.close()


async def cache_clear() -> int:
    """Clear all cached entries. Returns number of rows deleted."""
    if not DB_PATH.exists():
        return 0
    db = await _get_db()
    try:
        cursor = await db.execute("DELETE FROM cache")
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()
