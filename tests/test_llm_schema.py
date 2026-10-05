from pathlib import Path

import pytest

from kotri.ingest.models import Severity
from kotri.llm.schema import TriageParseError, Verdict, parse_triage_output

FIXTURE = Path(__file__).parent / "fixtures" / "triage_valid.json"


def test_parse_valid_output():
    result = parse_triage_output(FIXTURE.read_text(encoding="utf-8"))

    assert result.verdict == Verdict.LIKELY_TRUE_POSITIVE
    assert result.adjusted_severity == Severity.HIGH
    assert "forge tokens" in result.exploitability_rationale
    assert result.suggested_fix.startswith("Load the secret")


def test_parse_strips_markdown_fence():
    text = "```json\n" + FIXTURE.read_text(encoding="utf-8") + "\n```"
    assert parse_triage_output(text).verdict == Verdict.LIKELY_TRUE_POSITIVE


def test_parse_extracts_object_from_surrounding_prose():
    text = "Sure! Here is my answer: " + FIXTURE.read_text(encoding="utf-8") + " Hope it helps."
    assert parse_triage_output(text).adjusted_severity == Severity.HIGH


def test_parse_normalizes_enum_casing_and_spacing():
    text = (
        '{"verdict": "Likely False Positive", "adjusted_severity": "LOW",'
        ' "exploitability_rationale": "Test file only.", "suggested_fix": ""}'
    )
    result = parse_triage_output(text)

    assert result.verdict == Verdict.LIKELY_FALSE_POSITIVE
    assert result.adjusted_severity == Severity.LOW
    assert result.suggested_fix == ""


def test_parse_ignores_extra_keys():
    text = (
        '{"verdict": "needs_review", "adjusted_severity": "info",'
        ' "exploitability_rationale": "Unclear.", "suggested_fix": "", "confidence": 0.4}'
    )
    assert parse_triage_output(text).verdict == Verdict.NEEDS_REVIEW


@pytest.mark.parametrize(
    "text",
    [
        "",
        "not json at all",
        "[1, 2, 3]",
        '{"verdict": "likely_true_positive"}',  # missing fields
        '{"verdict": "maybe", "adjusted_severity": "high",'
        ' "exploitability_rationale": "x", "suggested_fix": ""}',  # bad verdict
        '{"verdict": "needs_review", "adjusted_severity": "severe",'
        ' "exploitability_rationale": "x", "suggested_fix": ""}',  # bad severity
        '{"verdict": "needs_review", "adjusted_severity": "low",'
        ' "exploitability_rationale": "   ", "suggested_fix": ""}',  # blank rationale
    ],
)
def test_parse_rejects_invalid_output(text: str) -> None:
    with pytest.raises(TriageParseError):
        parse_triage_output(text)
