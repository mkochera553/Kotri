"""ZAP JSON -> list[Finding]."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from kotri.ingest.jsonshape import dict_items, load_report
from kotri.ingest.models import Finding, Severity, SourceTool, make_finding_id

logger = logging.getLogger(__name__)

_RISKCODE_MAP = {
    "0": Severity.INFO,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
}

_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


def _normalize_severity(riskcode: object) -> Severity:
    # str() because some ZAP report formats emit riskcode as a number, not "2".
    return _RISKCODE_MAP.get(str(riskcode), Severity.CRITICAL) # Finding severity defaults to critical if tool outputs unrecognized severity string.


def _strip_html(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", _TAG_RE.sub(" ", text)).strip()


def _parse_instance(
    instance: dict[str, Any], rule: str, severity: Severity, raw_message: str
) -> Finding | None:
    """Build a Finding from one ZAP alert instance, or None if it's malformed."""
    try:
        uri = instance["uri"]
        if not isinstance(uri, str):
            raise TypeError("uri must be a string")
    except (KeyError, TypeError) as exc:
        logger.warning("skipping malformed ZAP instance: %s", exc)
        return None

    param = instance.get("param", "")
    location = f"{uri}#{param}" if param else uri
    return Finding(
        id=make_finding_id(SourceTool.ZAP, rule, location),
        source_tool=SourceTool.ZAP,
        rule=rule,
        location=location,
        severity=severity,
        raw_message=raw_message,
    )


def parse_zap(path: Path) -> list[Finding]:
    """Parse a ZAP JSON report into normalized Findings, one per alert instance.

    Alerts or instances missing expected fields or holding the wrong types are
    skipped and logged rather than aborting the whole parse. A file that isn't a
    JSON object raises ValueError.
    """
    data = load_report(path)

    findings: list[Finding] = []
    for site in dict_items(data.get("site", []), "ZAP sites"):
        for alert in dict_items(site.get("alerts", []), "ZAP alerts"):
            try:
                rule = alert["alert"]
                if not isinstance(rule, str):
                    raise TypeError("alert name must be a string")
                severity = _normalize_severity(alert["riskcode"])
                raw_message = _strip_html(alert.get("desc", ""))
            except (KeyError, TypeError) as exc:
                logger.warning("skipping malformed ZAP alert: %s", exc)
                continue

            for instance in dict_items(alert.get("instances", []), "ZAP instances"):
                finding = _parse_instance(instance, rule, severity, raw_message)
                if finding is not None:
                    findings.append(finding)
    return findings
