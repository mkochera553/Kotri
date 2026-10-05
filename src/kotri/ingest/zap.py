"""ZAP JSON -> list[Finding]."""

from __future__ import annotations

import json
import re
from pathlib import Path

from kotri.ingest.models import Finding, Severity, SourceTool, make_finding_id

_RISKCODE_MAP = {
    "0": Severity.INFO,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
}

_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


def _normalize_severity(riskcode: str) -> Severity:
    return _RISKCODE_MAP.get(riskcode, Severity.CRITICAL) # Finding severity defaults to critical if tool outputs unrecognized severity string.


def _strip_html(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", _TAG_RE.sub(" ", text)).strip()


def parse_zap(path: Path) -> list[Finding]:
    """Parse a ZAP JSON report into normalized Findings, one per alert instance."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    findings: list[Finding] = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            rule = alert["alert"]
            severity = _normalize_severity(alert["riskcode"])
            raw_message = _strip_html(alert.get("desc", ""))

            for instance in alert.get("instances", []):
                uri = instance["uri"]
                param = instance.get("param", "")
                location = f"{uri}#{param}" if param else uri
                findings.append(
                    Finding(
                        id=make_finding_id(SourceTool.ZAP, rule, location),
                        source_tool=SourceTool.ZAP,
                        rule=rule,
                        location=location,
                        severity=severity,
                        raw_message=raw_message,
                    )
                )
    return findings
