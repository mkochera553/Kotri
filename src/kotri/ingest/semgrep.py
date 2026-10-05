"""Semgrep JSON -> list[Finding]."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from kotri.ingest.jsonshape import dict_items, load_report
from kotri.ingest.models import Finding, Severity, SourceTool, make_finding_id

logger = logging.getLogger(__name__)

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


def _parse_result(result: dict[str, Any]) -> Finding | None:
    """Build a Finding from one Semgrep result, or None if it's malformed."""
    try:
        rule = result["check_id"]
        location = f"{result['path']}:{result['start']['line']}"
        severity = _normalize_severity(result["extra"]["severity"])
        raw_message = result["extra"]["message"]
        if not isinstance(rule, str) or not isinstance(raw_message, str):
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
        raw_message=raw_message,
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
