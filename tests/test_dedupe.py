from pathlib import Path

from kotri.ingest.dedupe import dedupe_findings
from kotri.ingest.models import Finding, Severity, SourceTool, make_finding_id
from kotri.ingest.semgrep import parse_semgrep

FIXTURE = Path(__file__).parent / "fixtures" / "semgrep_sample.json"


def _finding(rule: str, location: str) -> Finding:
    return Finding(
        id=make_finding_id(SourceTool.SEMGREP, rule, location),
        source_tool=SourceTool.SEMGREP,
        rule=rule,
        location=location,
        severity=Severity.MEDIUM,
        raw_message="msg",
    )


def test_dedupe_drops_same_rule_and_location():
    findings = [
        _finding("rule-a", "file.ts:1"),
        _finding("rule-a", "file.ts:1"),
        _finding("rule-b", "file.ts:1"),
    ]

    deduped = dedupe_findings(findings)

    assert len(deduped) == 2
    assert {f.rule for f in deduped} == {"rule-a", "rule-b"}


def test_dedupe_keeps_first_occurrence_order():
    first = _finding("rule-a", "file.ts:1")
    duplicate = _finding("rule-a", "file.ts:1")

    deduped = dedupe_findings([first, duplicate])

    assert deduped == [first]


def test_dedupe_on_parsed_semgrep_fixture_removes_known_duplicate():
    findings = parse_semgrep(FIXTURE)
    deduped = dedupe_findings(findings)

    assert len(findings) == 4
    assert len(deduped) == 3
