"""Input sanitization and validation utilities for Sentinel.

All user input MUST pass through these validators before processing.
"""

from __future__ import annotations

import os
import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Strict CVE ID format: CVE-YYYY-NNNNN (4+ digit sequence number)
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Container image name: alphanumeric start, then alphanumeric/._-/:@
_IMAGE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-/:@]{0,255}$")

# Shell metacharacters that should never appear in image names
_SHELL_METACHARACTERS = set(";&|`$(){}[]!#~<>\\'\"\n\r\t")

# Allowed git hosting domains
_ALLOWED_GIT_HOSTS = {
    "github.com",
    "gitlab.com",
    "bitbucket.org",
}

# Additional hosts can be configured via environment variable
_extra_hosts = os.environ.get("SENTINEL_ALLOWED_GIT_HOSTS", "")
if _extra_hosts:
    _ALLOWED_GIT_HOSTS.update(h.strip() for h in _extra_hosts.split(",") if h.strip())

# Patterns that look like secrets/tokens
_SECRET_PATTERNS = [
    re.compile(r"(sk-[a-zA-Z0-9]{20,})", re.IGNORECASE),
    re.compile(r"(ghp_[a-zA-Z0-9]{36,})", re.IGNORECASE),
    re.compile(r"(xoxb-[a-zA-Z0-9\-]+)", re.IGNORECASE),
    re.compile(r"(xoxp-[a-zA-Z0-9\-]+)", re.IGNORECASE),
    re.compile(r"(AKIA[A-Z0-9]{16})", re.IGNORECASE),
    re.compile(r"(eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})", re.IGNORECASE),  # JWT
    re.compile(r"(https?://)([^:]+):([^@]+)@"),  # user:pass@host
    re.compile(r"((?:api[_-]?key|token|secret|password|credential|auth)\s*[=:]\s*)\S+", re.IGNORECASE),
]


def validate_cve_id(cve_id: str) -> str:
    """Validate and normalize a CVE ID.

    Args:
        cve_id: The CVE ID string to validate.

    Returns:
        Normalized (uppercased) CVE ID.

    Raises:
        ValueError: If the CVE ID format is invalid.
    """
    if not cve_id or not isinstance(cve_id, str):
        raise ValueError("CVE ID is required")
    normalized = cve_id.strip().upper()
    if not _CVE_PATTERN.match(normalized):
        raise ValueError(
            f"Invalid CVE ID format: '{cve_id}'. "
            f"Expected format: CVE-YYYY-NNNNN (e.g., CVE-2024-3094)"
        )
    return normalized


def validate_image_name(image: str) -> str:
    """Validate a container image name.

    Args:
        image: Container image reference (e.g., nginx:1.25, registry.io/app:v1).

    Returns:
        The validated image name.

    Raises:
        ValueError: If the image name is invalid or contains dangerous characters.
    """
    if not image or not isinstance(image, str):
        raise ValueError("Image name is required")
    image = image.strip()
    # Check for shell metacharacters
    bad_chars = set(image) & _SHELL_METACHARACTERS
    if bad_chars:
        raise ValueError(
            f"Image name contains forbidden characters: {bad_chars}"
        )
    if not _IMAGE_NAME_PATTERN.match(image):
        raise ValueError(
            f"Invalid container image name: '{image}'. "
            f"Must match: [a-zA-Z0-9][a-zA-Z0-9._-/:@]{{0,255}}"
        )
    return image


def validate_url(url: str, allow_hosts: set[str] | None = None) -> str:
    """Validate a URL for git cloning — HTTPS only, known hosts.

    Args:
        url: The URL to validate.
        allow_hosts: Optional set of allowed hostnames. Defaults to major git hosts.

    Returns:
        The validated URL.

    Raises:
        ValueError: If the URL is invalid, not HTTPS, or from an unknown host.
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL is required")
    url = url.strip()
    # Reject URLs starting with - (flag injection)
    if url.startswith("-"):
        raise ValueError("URL must not start with '-'")
    # Reject shell metacharacters
    bad_chars = set(url) & {";", "&", "|", "`", "$", "(", ")", "{", "}", "!", "#", "~"}
    if bad_chars:
        raise ValueError(f"URL contains forbidden characters: {bad_chars}")
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError(f"Cannot parse URL: '{url}'")
    # Must be HTTPS
    if parsed.scheme not in ("https",):
        raise ValueError(
            f"Only HTTPS URLs are allowed (got '{parsed.scheme}://'). "
            f"git://, ssh://, file:// and http:// are rejected for security."
        )
    if not parsed.hostname:
        raise ValueError(f"URL has no hostname: '{url}'")
    # Check allowed hosts
    hosts = allow_hosts or _ALLOWED_GIT_HOSTS
    if parsed.hostname not in hosts:
        raise ValueError(
            f"Host '{parsed.hostname}' is not in the allowed list: {sorted(hosts)}. "
            f"Set SENTINEL_ALLOWED_GIT_HOSTS to add custom hosts."
        )
    return url


def sanitize_log_output(text: str) -> str:
    """Redact secrets and tokens from text before logging.

    Args:
        text: Text that may contain secrets.

    Returns:
        Text with secrets redacted.
    """
    if not text:
        return text
    result = text
    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 3:
            # URL credential pattern
            result = pattern.sub(r"\1***:***@", result)
        elif pattern.groups >= 2:
            # key=value pattern
            result = pattern.sub(r"\1[REDACTED]", result)
        else:
            result = pattern.sub("[REDACTED]", result)
    return result
