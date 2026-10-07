"""Ranked Markdown report of triaged findings.

Rule, location and the model's text all originate outside this program, so they are
rendered as code spans or blockquotes with HTML escaped and cannot add headings or
markup of their own.
"""

from __future__ import annotations

import re

from kotri.ingest.models import Severity
from kotri.llm.prompts import single_line
from kotri.llm.schema import Verdict
from kotri.pipeline import PipelineResult, TriagedFinding

SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
# Within one severity, confirmed issues come before undecided ones, then dismissals.
_VERDICT_RANK = {
    Verdict.LIKELY_TRUE_POSITIVE: 0,
    Verdict.NEEDS_REVIEW: 1,
    Verdict.LIKELY_FALSE_POSITIVE: 2,
}
_MAX_INLINE_CHARS = 300


def _is_triaged(item: TriagedFinding) -> bool:
    return item.outcome is not None and item.outcome.result is not None


def _sort_key(item: TriagedFinding) -> tuple[int, int, int, str]:
    """Ascending sort key that puts the highest adjusted severity first."""
    assert item.outcome is not None and item.outcome.result is not None
    result = item.outcome.result
    return (
        -SEVERITY_RANK[result.adjusted_severity],
        _VERDICT_RANK[result.verdict],
        -SEVERITY_RANK[item.finding.severity],
        item.finding.id,
    )


def _code(text: str) -> str:
    """text as a one-line Markdown code span that the text cannot close early."""
    line = single_line(text, _MAX_INLINE_CHARS) or " "
    longest = max((len(run) for run in re.findall(r"`+", line)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if line.startswith("`") or line.endswith("`") or line == " " else ""
    return f"{fence}{pad}{line}{pad}{fence}"


def _quote(text: str) -> str:
    """text as an HTML-escaped blockquote."""
    escaped = text.replace("&", "&amp;").replace("<", "&lt;")
    return "\n".join(f"> {line}" if line else ">" for line in escaped.splitlines())


def _header(result: PipelineResult, triaged: list[TriagedFinding]) -> list[str]:
    stats = result.stats
    seconds = sum(i.outcome.latency_s for i in result.items if i.outcome is not None)
    lines = [
        "# Kotri triage report",
        "",
        f"- Model: {_code(result.model)}",
        f"- Findings: {len(result.items)} ({len(triaged)} triaged, "
        f"{len(result.items) - len(triaged)} not triaged, "
        f"{result.duplicates_dropped} duplicates dropped)",
        f"- Parse retries: {stats.retries} of {stats.calls} "
        f"({stats.retry_rate:.1%}); parse failures: {stats.failures} "
        f"({stats.failure_rate:.1%}); runtime errors: {stats.transport_errors}",
        f"- Total triage time: {seconds:.1f}s",
    ]
    if result.aborted:
        lines += [
            "",
            "> **Incomplete run:** the runtime failed repeatedly, so the remaining "
            "findings were not triaged.",
        ]
    return lines


def _summary(triaged: list[TriagedFinding]) -> list[str]:
    counts = {severity: 0 for severity in SEVERITY_RANK}
    false_positives = 0
    for item in triaged:
        result = item.outcome.result  # type: ignore[union-attr]
        counts[result.adjusted_severity] += 1
        false_positives += result.verdict is Verdict.LIKELY_FALSE_POSITIVE
    lines = ["## Summary", "", "| Adjusted severity | Findings |", "| --- | ---: |"]
    for severity in sorted(counts, key=SEVERITY_RANK.__getitem__, reverse=True):
        lines.append(f"| {severity.value} | {counts[severity]} |")
    lines += ["", f"Likely false positives among them: {false_positives}"]
    return lines


def _ranked_entry(rank: int, item: TriagedFinding) -> list[str]:
    finding = item.finding
    result = item.outcome.result  # type: ignore[union-attr]
    changed = result.adjusted_severity is not finding.severity
    scanner = f"{finding.source_tool.value} ({finding.severity.value})"
    lines = [
        f"### {rank}. [{result.adjusted_severity.value.upper()}] {_code(finding.rule)}",
        "",
        f"- Location: {_code(finding.location)}",
        f"- Verdict: {result.verdict.value}",
        f"- Scanner: {scanner}" + (" - severity adjusted by the model" if changed else ""),
        "",
        "Rationale:",
        "",
        _quote(result.exploitability_rationale),
    ]
    if result.suggested_fix:
        lines += ["", "Suggested fix:", "", _quote(result.suggested_fix)]
    return lines


def _untriaged_entry(item: TriagedFinding) -> str:
    finding = item.finding
    reason = single_line(item.error or "no result", _MAX_INLINE_CHARS)
    reason = reason.replace("&", "&amp;").replace("<", "&lt;")
    return (
        f"- {_code(finding.rule)} at {_code(finding.location)} - "
        f"{finding.source_tool.value}, scanner severity {finding.severity.value}: {reason}"
    )


def render_report(result: PipelineResult) -> str:
    """Markdown report: findings ranked by the model's adjusted severity, highest first.

    Findings with no triage result (parse failure, runtime error, aborted run) have no
    adjusted severity to rank by, so they are listed last with the scanner's severity.
    """
    triaged = sorted((i for i in result.items if _is_triaged(i)), key=_sort_key)
    untriaged = [i for i in result.items if not _is_triaged(i)]

    sections = [_header(result, triaged), _summary(triaged)]
    ranked = ["## Ranked findings", ""]
    if triaged:
        for rank, item in enumerate(triaged, start=1):
            ranked += [*_ranked_entry(rank, item), ""]
    else:
        ranked += ["No findings were triaged.", ""]
    sections.append(ranked[:-1])

    if untriaged:
        sections.append(
            ["## Not triaged", "", *(_untriaged_entry(i) for i in untriaged)]
        )
    return "\n\n".join("\n".join(section) for section in sections) + "\n"
