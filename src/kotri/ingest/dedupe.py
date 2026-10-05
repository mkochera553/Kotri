"""Collapse Findings that report the same issue at the same location."""

from __future__ import annotations

from kotri.ingest.models import Finding


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Keep the first Finding for each (source_tool, rule, location) seen.

    This covers both dedupe rules from the spec: same Semgrep rule and file
    location, or same ZAP alert and URL, since both map onto `rule` + `location`.
    """
    seen: set[tuple[str, str, str]] = set()
    deduped: list[Finding] = []
    for finding in findings:
        key = (finding.source_tool.value, finding.rule, finding.location)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
