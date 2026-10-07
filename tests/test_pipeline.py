from collections.abc import Callable
from pathlib import Path

import pytest

from kotri.ingest.models import Finding
from kotri.llm.client import LLMError, ParseStats, TriageOutcome
from kotri.pipeline import (
    MAX_CONSECUTIVE_TRANSPORT_ERRORS,
    dedupe,
    load_findings,
    run_pipeline,
    triage_all,
)

FIXTURES = Path(__file__).parent / "fixtures"


class FakeTriager:
    """Returns a scripted outcome (or raises a scripted error) per finding id."""

    def __init__(self, script: dict[str, TriageOutcome | Exception]) -> None:
        self.model = "fake-model"
        self.stats = ParseStats()
        self.script = script
        self.seen: list[str] = []

    def triage(self, finding: Finding) -> TriageOutcome:
        self.seen.append(finding.id)
        scripted = self.script[finding.id]
        if isinstance(scripted, Exception):
            self.stats.transport_errors += 1
            raise scripted
        self.stats.calls += 1
        return scripted


def test_dedupe_keeps_first_of_each_id(make_finding: Callable[..., Finding]) -> None:
    a, a_again, b = make_finding(id="a"), make_finding(id="a", rule="other"), make_finding(id="b")
    kept, dropped = dedupe([a, a_again, b])
    assert kept == [a, b]
    assert dropped == 1


def test_load_findings_combines_both_tools() -> None:
    findings = load_findings(FIXTURES / "semgrep_sample.json", FIXTURES / "zap_sample.json")
    tools = {f.source_tool.value for f in findings}
    assert tools == {"semgrep", "zap"}


def test_load_findings_with_no_inputs_is_empty() -> None:
    assert load_findings() == []


def test_triage_all_collects_outcomes_in_order(
    make_finding: Callable[..., Finding], make_outcome: Callable[..., TriageOutcome]
) -> None:
    findings = [make_finding(id="a"), make_finding(id="b")]
    triager = FakeTriager({"a": make_outcome("a"), "b": make_outcome("b")})
    result = triage_all(findings, triager, duplicates_dropped=3)
    assert [i.finding.id for i in result.items] == ["a", "b"]
    assert all(i.outcome is not None and i.error is None for i in result.items)
    assert result.model == "fake-model"
    assert result.duplicates_dropped == 3
    assert result.stats.calls == 2
    assert not result.aborted


def test_stats_are_a_snapshot(
    make_finding: Callable[..., Finding], make_outcome: Callable[..., TriageOutcome]
) -> None:
    triager = FakeTriager({"a": make_outcome("a")})
    result = triage_all([make_finding(id="a")], triager)
    triager.stats.calls += 10
    assert result.stats.calls == 1


def test_parse_failure_is_recorded_with_its_error(
    make_finding: Callable[..., Finding], make_outcome: Callable[..., TriageOutcome]
) -> None:
    triager = FakeTriager({"a": make_outcome("a", result=None)})
    (item,) = triage_all([make_finding(id="a")], triager).items
    assert item.outcome is not None and item.outcome.parse_failed
    assert item.error == "bad json"


def test_runtime_error_is_recorded_and_run_continues(
    make_finding: Callable[..., Finding], make_outcome: Callable[..., TriageOutcome]
) -> None:
    triager = FakeTriager({"a": LLMError("timed out"), "b": make_outcome("b")})
    result = triage_all([make_finding(id="a"), make_finding(id="b")], triager)
    first, second = result.items
    assert first.outcome is None and first.error == "timed out"
    assert second.outcome is not None
    assert not result.aborted


def test_repeated_runtime_errors_abort_the_run(make_finding: Callable[..., Finding]) -> None:
    count = MAX_CONSECUTIVE_TRANSPORT_ERRORS + 2
    findings = [make_finding(id=str(n)) for n in range(count)]
    triager = FakeTriager({f.id: LLMError("down") for f in findings})
    result = triage_all(findings, triager)
    assert result.aborted
    assert len(triager.seen) == MAX_CONSECUTIVE_TRANSPORT_ERRORS
    assert len(result.items) == count
    assert all(i.outcome is None and i.error for i in result.items)


def test_a_success_resets_the_error_streak(
    make_finding: Callable[..., Finding], make_outcome: Callable[..., TriageOutcome]
) -> None:
    findings = [make_finding(id=str(n)) for n in range(2 * MAX_CONSECUTIVE_TRANSPORT_ERRORS)]
    script: dict[str, TriageOutcome | Exception] = {}
    for n, f in enumerate(findings):
        script[f.id] = make_outcome(f.id) if n % 2 else LLMError("flaky")
    result = triage_all(findings, FakeTriager(script))
    assert not result.aborted


def test_run_pipeline_dedupes_before_triage(
    tmp_path: Path, make_outcome: Callable[..., TriageOutcome]
) -> None:
    sample = FIXTURES / "semgrep_sample.json"
    parsed = load_findings(sample)
    unique = {f.id for f in parsed}  # the sample itself repeats a finding
    triager = FakeTriager({f.id: make_outcome(f.id) for f in parsed})
    copy = tmp_path / "copy.json"
    copy.write_bytes(sample.read_bytes())

    result = run_pipeline(triager, semgrep=sample, zap=None)
    assert len(result.items) == len(unique)
    assert result.duplicates_dropped == len(parsed) - len(unique)
    assert sorted(triager.seen) == sorted(unique)  # one triage call per unique finding

    # The same report passed twice would double every finding without dedupe.
    findings, dropped = dedupe(parsed + load_findings(copy))
    assert len(findings) == len(unique)
    assert dropped == 2 * len(parsed) - len(unique)


def test_run_pipeline_propagates_unreadable_scan(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError):
        run_pipeline(FakeTriager({}), semgrep=bad)
