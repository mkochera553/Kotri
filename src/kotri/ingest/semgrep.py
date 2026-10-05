"""Semgrep JSON -> list[Finding]."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from kotri.ingest.jsonshape import dict_items, load_report
from kotri.ingest.models import Finding, Severity, SourceTool, make_finding_id
from kotri.ingest.text import clip, compose_message

logger = logging.getLogger(__name__)

_NO_CODE_PLACEHOLDERS = frozenset({"requires login"})

_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _normalize_severity(raw: object) -> Severity:
    return _SEVERITY_MAP.get(str(raw).upper(), Severity.CRITICAL) # Finding severity defaults to critical if tool outputs unrecognized severity string.


def _values(value: object) -> str:
    """A metadata field that is a string or a list of strings, joined onto one line."""
    items = [value] if isinstance(value, str) else value if isinstance(value, list) else []
    return clip("; ".join(item.strip() for item in items if isinstance(item, str) and item.strip()))


def _build_message(message: str, extra: dict[str, Any]) -> str:
    """The rule message plus the rule metadata and matched code that help judge it.

    Without a Semgrep login `lines` is a placeholder rather than code, so it is dropped.
    """
    metadata = extra.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    code = clip(extra.get("lines"))
    if code.lower() in _NO_CODE_PLACEHOLDERS:
        code = ""
    return compose_message(
        message,
        [
            ("CWE", _values(metadata.get("cwe"))),
            ("OWASP", _values(metadata.get("owasp"))),
            ("Rule confidence", _values(metadata.get("confidence"))),
            ("Likelihood", _values(metadata.get("likelihood"))),
            ("Impact", _values(metadata.get("impact"))),
            ("Matched code", code),
        ],
    )


def _parse_result(result: dict[str, Any]) -> Finding | None:
    """Build a Finding from one Semgrep result, or None if it's malformed."""
    try:
        rule = result["check_id"]
        location = f"{result['path']}:{result['start']['line']}"
        extra = result["extra"]
        severity = _normalize_severity(extra["severity"])
        message = extra["message"]
        if not isinstance(rule, str) or not isinstance(message, str):
            raise TypeError("check_id and message must be strings")
    except (KeyError, TypeError) as exc:
        logger.warning("skipping malformed Semgrep result: %s", exc)
        return None

    return Finding(
        id=make_finding_id(SourceTool.SEMGREP, rule, location),
        source_tool=SourceTool.SEMGREP,
        rule=rule,
        location=location,
        severity=severity,
        raw_message=_build_message(message, extra),
    )


def parse_semgrep(path: Path) -> list[Finding]:
    """Parse a Semgrep JSON report into normalized Findings.

    Results missing expected fields or holding the wrong types are skipped and
    logged rather than aborting the whole parse. A file that isn't a JSON object
    raises ValueError.
    """
    data = load_report(path)

    findings: list[Finding] = []
    for result in dict_items(data.get("results", []), "Semgrep results"):
        finding = _parse_result(result)
        if finding is not None:
            findings.append(finding)
    return findings
