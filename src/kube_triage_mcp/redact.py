"""Scrub secrets out of anything we hand to a model.

Logs are where credentials leak: connection strings, bearer tokens, keys
printed on startup. We redact before the text leaves the server.
"""

from __future__ import annotations

import re

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:aws-key]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[REDACTED:jwt]"),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)(\w+://[^:/\s]+:)[^@\s]+(@)"), r"\1[REDACTED]\2"),
    (
        re.compile(r"(?i)\b(gh[pousr]_[A-Za-z0-9]{20,}|xox[abpr]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,})"),
        "[REDACTED:token]",
    ),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "[REDACTED:private-key]",
    ),
    (
        re.compile(
            r"""(?i)\b([\w.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)[\w.-]*)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;]+)"""
        ),
        r"\1\2[REDACTED]",
    ),
]


def redact(text: str) -> tuple[str, int]:
    """Return (clean_text, number_of_redactions)."""
    total = 0
    for rx, repl in _PATTERNS:
        text, n = rx.subn(repl, text)
        total += n
    return text, total
