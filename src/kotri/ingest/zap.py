"""ZAP JSON -> list[Finding]."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from kotri.ingest.jsonshape import dict_items, load_report
from kotri.ingest.models import Finding, Severity, SourceTool, make_finding_id
from kotri.ingest.text import clip, compose_message

logger = logging.getLogger(__name__)

_RISKCODE_MAP = {
    "0": Severity.INFO,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
}
# ZAP's own confidence in the alert; "false positive" is a value ZAP itself can assign.
_CONFIDENCE_LABELS = {"0": "false positive", "1": "low", "2": "medium", "3": "high", "4": "confirmed"}

_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


def _normalize_severity(riskcode: object) -> Severity:
    # str() because some ZAP report formats emit riskcode as a number, not "2".
    return _RISKCODE_MAP.get(str(riskcode), Severity.CRITICAL) # Finding severity defaults to critical if tool outputs unrecognized severity string.


def _strip_html(text: str) -> str:
    return _WHITESPACE_RE.sub(" ", _TAG_RE.sub(" ", text)).strip()


def _html_text(value: object) -> str:
    return _strip_html(value) if isinstance(value, str) else ""


def _cwe(alert: dict[str, Any]) -> str:
    """"CWE-601" from a ZAP cweid, or "" when ZAP reports none (0 or -1)."""
    cweid = str(alert.get("cweid", "")).strip()
    return f"CWE-{cweid}" if cweid.isascii() and cweid.isdigit() and int(cweid) > 0 else ""


def _build_message(description: str, alert: dict[str, Any], instance: dict[str, Any]) -> str:
    """The alert description plus the instance evidence a triager would look at.

    attack and evidence are kept verbatim: they often contain the payload or markup that
    shows whether the alert is real, so HTML stripping would destroy the signal. Alert
    level otherinfo is HTML-wrapped like desc; instance level otherinfo is plain text.
    """
    otherinfo = clip(instance.get("otherinfo")) or clip(_html_text(alert.get("otherinfo")))
    return compose_message(
        description,
        [
            ("Method", clip(instance.get("method"))),
            ("Attack", clip(instance.get("attack"))),
            ("Evidence", clip(instance.get("evidence"))),
            ("Other info", otherinfo),
            ("CWE", _cwe(alert)),
            ("ZAP confidence", _CONFIDENCE_LABELS.get(str(alert.get("confidence")), "")),
        ],
    )


def _parse_instance(
    instance: dict[str, Any], alert: dict[str, Any], rule: str, severity: Severity, description: str
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
        raw_message=_build_message(description, alert, instance),
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
                description = _strip_html(alert.get("desc", ""))
            except (KeyError, TypeError) as exc:
                logger.warning("skipping malformed ZAP alert: %s", exc)
                continue

            for instance in dict_items(alert.get("instances", []), "ZAP instances"):
                finding = _parse_instance(instance, alert, rule, severity, description)
                if finding is not None:
                    findings.append(finding)
    return findings
