from collections.abc import Callable

from kotri.ingest.models import Finding, Severity
from kotri.llm.client import ParseStats, TriageOutcome
from kotri.llm.schema import Verdict
from kotri.pipeline import PipelineResult, TriagedFinding
from kotri.report import render_report


def _headings(report: str) -> list[str]:
    return [line for line in report.splitlines() if line.startswith("### ")]


def test_ranked_by_adjusted_severity_not_scanner_severity(
    make_finding: Callable[..., Finding], make_outcome: Callable[..., TriageOutcome]
) -> None:
    # The scanner called "low-rule" critical, but the model downgraded it.
    items = [
        TriagedFinding(
            make_finding(id="a", rule="low-rule", severity=Severity.CRITICAL),
            make_outcome("a", adjusted_severity=Severity.LOW),
        ),
        TriagedFinding(
            make_finding(id="b", rule="high-rule", severity=Severity.LOW),
            make_outcome("b", adjusted_severity=Severity.HIGH),
        ),
        TriagedFinding(
            make_finding(id="c", rule="crit-rule", severity=Severity.MEDIUM),
            make_outcome("c", adjusted_severity=Severity.CRITICAL),
        ),
    ]
    report = render_report(PipelineResult(model="m", items=items))
    headings = _headings(report)
    assert [("crit-rule" in h, "high-rule" in h, "low-rule" in h) for h in headings] == [
        (True, False, False),
        (False, True, False),
        (False, False, True),
    ]
    assert headings[0].startswith("### 1. [CRITICAL]")
    assert "severity adjusted by the model" in report


def test_ties_break_on_verdict_then_id(
    make_finding: Callable[..., Finding], make_outcome: Callable[..., TriageOutcome]
) -> None:
    items = [
        TriagedFinding(
            make_finding(id="a", rule="fp"),
            make_outcome("a", verdict=Verdict.LIKELY_FALSE_POSITIVE),
        ),
        TriagedFinding(
            make_finding(id="b", rule="review"),
            make_outcome("b", verdict=Verdict.NEEDS_REVIEW),
        ),
        TriagedFinding(make_finding(id="c", rule="tp"), make_outcome("c")),
    ]
    headings = _headings(render_report(PipelineResult(model="m", items=items)))
    assert ["tp" in headings[0], "review" in headings[1], "fp" in headings[2]] == [True] * 3


def test_untriaged_findings_are_listed_last_not_ranked(
    make_finding: Callable[..., Finding], make_outcome: Callable[..., TriageOutcome]
) -> None:
    items = [
        TriagedFinding(make_finding(id="a", rule="broken", severity=Severity.CRITICAL), error="down"),
        TriagedFinding(make_finding(id="b", rule="fine"), make_outcome("b", adjusted_severity=Severity.INFO)),
    ]
    report = render_report(PipelineResult(model="m", items=items))
    assert len(_headings(report)) == 1
    assert report.index("## Ranked findings") < report.index("## Not triaged")
    not_triaged = report.split("## Not triaged")[1]
    assert "broken" in not_triaged and "scanner severity critical" in not_triaged
    assert "down" in not_triaged
    assert "broken" not in report.split("## Not triaged")[0]


def test_header_and_summary_counts(
    make_finding: Callable[..., Finding], make_outcome: Callable[..., TriageOutcome]
) -> None:
    items = [
        TriagedFinding(make_finding(id="a"), make_outcome("a")),
        TriagedFinding(
            make_finding(id="b"),
            make_outcome("b", verdict=Verdict.LIKELY_FALSE_POSITIVE, adjusted_severity=Severity.INFO),
        ),
    ]
    stats = ParseStats(calls=2, retries=1, recovered=1)
    report = render_report(
        PipelineResult(model="qwen2.5:7b", items=items, stats=stats, duplicates_dropped=4)
    )
    assert "`qwen2.5:7b`" in report
    assert "2 triaged, 0 not triaged, 4 duplicates dropped" in report
    assert "Parse retries: 1 of 2 (50.0%)" in report
    assert "| high | 1 |" in report and "| info | 1 |" in report and "| critical | 0 |" in report
    assert "Likely false positives among them: 1" in report
    assert "Total triage time: 1.0s" in report


def test_aborted_run_is_flagged(make_finding: Callable[..., Finding]) -> None:
    items = [TriagedFinding(make_finding(id="a"), error="down")]
    report = render_report(PipelineResult(model="m", items=items, aborted=True))
    assert "Incomplete run" in report
    assert "No findings were triaged." in report


def test_empty_result_renders(make_finding: Callable[..., Finding]) -> None:
    report = render_report(PipelineResult(model="m"))
    assert "# Kotri triage report" in report
    assert "No findings were triaged." in report
    assert "## Not triaged" not in report


def test_untrusted_text_cannot_inject_markup(
    make_finding: Callable[..., Finding], make_outcome: Callable[..., TriageOutcome]
) -> None:
    finding = make_finding(id="a", rule="evil`\n# fake heading", location="http://x/`` `<b>")
    outcome = make_outcome(
        "a",
        exploitability_rationale="line one\n# Heading\n<script>alert(1)</script>",
        suggested_fix="a & b <img src=x>",
    )
    report = render_report(PipelineResult(model="m", items=[TriagedFinding(finding, outcome)]))
    assert "\n# fake heading" not in report
    assert "\n# Heading" not in report
    assert "<script>" not in report and "<img" not in report
    assert "&lt;script>" in report
    assert "> # Heading" in report
    assert len(_headings(report)) == 1
    # Both the rule and location code spans use a fence longer than their inner backticks.
    assert "```http://x/`` `<b>```" in report
    assert "``evil` # fake heading``" in report


def test_missing_fix_is_omitted(
    make_finding: Callable[..., Finding], make_outcome: Callable[..., TriageOutcome]
) -> None:
    item = TriagedFinding(make_finding(id="a"), make_outcome("a", suggested_fix=""))
    assert "Suggested fix" not in render_report(PipelineResult(model="m", items=[item]))
