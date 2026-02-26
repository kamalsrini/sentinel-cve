"""Configuration management for Sentinel.

Stores config at ~/.sentinel/config.json. Falls back to environment variables.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

SENTINEL_DIR = Path.home() / ".sentinel"
CONFIG_PATH = SENTINEL_DIR / "config.json"

# Mapping of config keys to environment variable names
ENV_MAP: dict[str, str] = {
    "api-key": "ANTHROPIC_API_KEY",
    "nvd-key": "NVD_API_KEY",
    "model": "SENTINEL_MODEL",
}

DEFAULT_MODEL = "claude-sonnet-4-20250514"


def _ensure_dir() -> None:
    """Create ~/.sentinel/ if it doesn't exist."""
    SENTINEL_DIR.mkdir(parents=True, exist_ok=True)


def _load_config() -> dict[str, Any]:
    """Load config from disk."""
    if CONFIG_PATH.exists():
        return json.loads(CONFIG_PATH.read_text())
    return {}


def _save_config(cfg: dict[str, Any]) -> None:
    """Persist config to disk."""
    _ensure_dir()
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2) + "\n")
    # Restrict permissions
    CONFIG_PATH.chmod(0o600)


def config_get(key: str) -> str | None:
    """Get a config value. Checks config file first, then env vars."""
    cfg = _load_config()
    val = cfg.get(key)
    if val:
        return val
    env_name = ENV_MAP.get(key)
    if env_name:
        return os.environ.get(env_name)
    return None


def config_set(key: str, value: str) -> None:
    """Set a config value and persist to disk."""
    cfg = _load_config()
    cfg[key] = value
    _save_config(cfg)


def get_api_key() -> str | None:
    """Get the Anthropic API key."""
    return config_get("api-key")


def get_nvd_key() -> str | None:
    """Get the NVD API key (optional, for higher rate limits)."""
    return config_get("nvd-key")


def get_model() -> str:
    """Get the Claude model to use."""
    return config_get("model") or DEFAULT_MODEL
