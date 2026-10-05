"""Semgrep JSON -> list[Finding]."""

from __future__ import annotations

import json
from pathlib import Path

from kotri.ingest.models import Finding, Severity, SourceTool, make_finding_id

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


def parse_semgrep(path: Path) -> list[Finding]:
    """Parse a Semgrep JSON report into normalized Findings."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    findings: list[Finding] = []
    for result in data.get("results", []):
        rule = result["check_id"]
        location = f"{result['path']}:{result['start']['line']}"
        severity = _normalize_severity(result["extra"]["severity"])
        raw_message = result["extra"]["message"]

        findings.append(
            Finding(
                id=make_finding_id(SourceTool.SEMGREP, rule, location),
                source_tool=SourceTool.SEMGREP,
                rule=rule,
                location=location,
                severity=severity,
                raw_message=raw_message,
            )
        )
    return findings
