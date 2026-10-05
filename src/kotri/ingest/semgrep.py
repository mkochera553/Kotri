"""Semgrep JSON -> list[Finding]."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

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


def _normalize_severity(raw: str) -> Severity:
    return _SEVERITY_MAP.get(raw.upper(), Severity.CRITICAL) # Finding severity defaults to critical if tool outputs unrecognized severity string.


def _parse_result(result: dict[str, Any]) -> Finding | None:
    """Build a Finding from one Semgrep result, or None if it's malformed."""
    try:
        rule = result["check_id"]
        location = f"{result['path']}:{result['start']['line']}"
        severity = _normalize_severity(result["extra"]["severity"])
        raw_message = result["extra"]["message"]
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

    Results missing expected fields are skipped and logged rather than
    aborting the whole parse.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    findings: list[Finding] = []
    for result in data.get("results", []):
        finding = _parse_result(result)
        if finding is not None:
            findings.append(finding)
    return findings
