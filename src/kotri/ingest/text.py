"""Helpers for composing a Finding's raw_message from scanner report fields.

raw_message is what the triage model reads, so parsers put the evidence that decides
true vs false positive in it (matched code, attack, response evidence, CWE) after the
scanner's own description. The text is untrusted; the prompt fences it as data.
"""

from __future__ import annotations

from collections.abc import Iterable

# Keeps one verbose field (a response body as ZAP evidence) from crowding out the rest
# when the prompt later truncates the whole message.
MAX_DETAIL_CHARS = 500
_TRUNCATION_MARKER = "... [truncated]"


def clip(value: object, limit: int = MAX_DETAIL_CHARS) -> str:
    """Return value stripped and cut to limit characters; "" if it isn't a string."""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if len(text) <= limit:
        return text
    return text[: limit - len(_TRUNCATION_MARKER)].rstrip() + _TRUNCATION_MARKER


def compose_message(summary: str, details: Iterable[tuple[str, str]]) -> str:
    """The summary, then a "Label: value" line per non-empty detail.

    A multi-line value starts on the line after its label so the structure stays clear.
    """
    lines = [
        f"{label}:\n{value}" if "\n" in value else f"{label}: {value}"
        for label, value in details
        if value
    ]
    return "\n\n".join(part for part in (summary, "\n".join(lines)) if part)
