from __future__ import annotations

import html
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RedactionResult:
    text: str
    count: int


SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?im)^(\s*authorization\s*:\s*bearer\s+)([^\s]+).*$"), r"\1[REDACTED]"),
    (re.compile(r"(?im)^(\s*authorization\s*:\s*basic\s+)([^\s]+).*$"), r"\1[REDACTED]"),
    (re.compile(r"(?im)^(\s*(?:cookie|set-cookie)\s*:\s*)(.+)$"), r"\1[REDACTED]"),
    (re.compile(r"(?im)^(\s*(?:x-api-key|x-csrf-token|csrf-token)\s*:\s*)(.+)$"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)\bbasic\s+[A-Za-z0-9._~+/=-]+"), "Basic [REDACTED]"),
    (re.compile(r"(?i)(api[_-]?key|session[_-]?id|csrf[_-]?token|access[_-]?token|refresh[_-]?token|oauth[_-]?token)([\"'\s:=]+)([A-Za-z0-9._~+/=-]{8,})"), r"\1\2[REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "[JWT_REDACTED]"),
    (re.compile(r"(?i)([?&](?:token|access_token|refresh_token|api_key|key|session|sessionid|csrf)=)([^&#\s]+)"), r"\1[REDACTED]"),
]


def redact_with_count(text: str) -> RedactionResult:
    total = 0
    redacted = text
    for pattern, replacement in SECRET_PATTERNS:
        redacted, count = pattern.subn(replacement, redacted)
        total += count
    return RedactionResult(redacted, total)


def redact(text: str) -> str:
    return redact_with_count(text).text


def escape_html(text: str) -> str:
    return html.escape(text, quote=True)


def safe_path(root: Path, candidate: str | Path) -> Path:
    root = root.resolve()
    path = Path(candidate)
    if not path.is_absolute():
        path = root / path
    resolved = path.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"path traversal rejected: {candidate}")
    return resolved