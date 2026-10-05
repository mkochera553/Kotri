import json
from pathlib import Path

import pytest

from kotri.ingest.models import Severity
from kotri.llm.schema import (
    MAX_FIX_CHARS,
    MAX_RATIONALE_CHARS,
    TriageParseError,
    Verdict,
    parse_triage_output,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "triage_valid.json"


def test_parse_valid_output() -> None:
    result = parse_triage_output(FIXTURE.read_text(encoding="utf-8"))

    assert result.verdict == Verdict.LIKELY_TRUE_POSITIVE
    assert result.adjusted_severity == Severity.HIGH
    assert "forge tokens" in result.exploitability_rationale
    assert result.suggested_fix.startswith("Load the secret")


def test_parse_strips_markdown_fence() -> None:
    text = "```json\n" + FIXTURE.read_text(encoding="utf-8") + "\n```"
    assert parse_triage_output(text).verdict == Verdict.LIKELY_TRUE_POSITIVE


def test_parse_extracts_object_from_surrounding_prose() -> None:
    text = "Sure! Here is my answer: " + FIXTURE.read_text(encoding="utf-8") + " Hope it helps."
    assert parse_triage_output(text).adjusted_severity == Severity.HIGH


def test_parse_extracts_object_followed_by_trailing_prose() -> None:
    text = FIXTURE.read_text(encoding="utf-8") + "\n\nLet me know if you need more."
    assert parse_triage_output(text).verdict == Verdict.LIKELY_TRUE_POSITIVE


def test_parse_extracts_object_after_fence_and_trailing_prose() -> None:
    text = "```json\n" + FIXTURE.read_text(encoding="utf-8") + "\n```\nDone."
    assert parse_triage_output(text).verdict == Verdict.LIKELY_TRUE_POSITIVE


def test_parse_skips_stray_braces_in_prose() -> None:
    text = "Note {see below} {x}: " + FIXTURE.read_text(encoding="utf-8") + " (cf. {1})"
    assert parse_triage_output(text).adjusted_severity == Severity.HIGH


def _answer(verdict: str, severity: str, rationale: str) -> str:
    return json.dumps(
        {
            "verdict": verdict,
            "adjusted_severity": severity,
            "exploitability_rationale": rationale,
            "suggested_fix": "",
        }
    )


def test_parse_prefers_the_final_answer_over_a_draft_in_a_think_block() -> None:
    draft = _answer("likely_false_positive", "low", "draft")
    final = _answer("likely_true_positive", "high", "final")

    result = parse_triage_output(f"<think>maybe {draft}</think>\n{final}")

    assert result.verdict == Verdict.LIKELY_TRUE_POSITIVE
    assert result.exploitability_rationale == "final"


def test_parse_takes_the_last_valid_object_when_there_are_several() -> None:
    first = _answer("likely_false_positive", "low", "first")
    last = _answer("likely_true_positive", "high", "last")

    result = parse_triage_output(f"Example: {first}\nAnswer: {last}")

    assert result.exploitability_rationale == "last"


def test_parse_skips_empty_object_in_prose_before_the_answer() -> None:
    text = "Use {} for empty. " + _answer("needs_review", "low", "ok")
    assert parse_triage_output(text).verdict == Verdict.NEEDS_REVIEW


def test_parse_falls_back_to_an_earlier_valid_object_if_a_later_one_is_invalid() -> None:
    valid = _answer("needs_review", "low", "valid")
    assert parse_triage_output(f'{valid} then {{"verdict": "x"}}').exploitability_rationale == "valid"


def test_parse_error_describes_the_last_object_when_none_validate() -> None:
    text = '{"verdict": "needs_review"} {"adjusted_severity": "low"}'

    with pytest.raises(TriageParseError) as excinfo:
        parse_triage_output(text)

    assert "verdict" in str(excinfo.value)  # the last object is missing verdict, not severity
    assert "adjusted_severity\n  Field required" not in str(excinfo.value)


def test_parse_normalizes_enum_casing_and_spacing() -> None:
    text = (
        '{"verdict": "Likely False Positive", "adjusted_severity": "LOW",'
        ' "exploitability_rationale": "Test file only.", "suggested_fix": ""}'
    )
    result = parse_triage_output(text)

    assert result.verdict == Verdict.LIKELY_FALSE_POSITIVE
    assert result.adjusted_severity == Severity.LOW
    assert result.suggested_fix == ""


def test_parse_ignores_extra_keys() -> None:
    text = (
        '{"verdict": "needs_review", "adjusted_severity": "info",'
        ' "exploitability_rationale": "Unclear.", "suggested_fix": "", "confidence": 0.4}'
    )
    assert parse_triage_output(text).verdict == Verdict.NEEDS_REVIEW


def _reply(**overrides: object) -> str:
    fields = {
        "verdict": "needs_review",
        "adjusted_severity": "low",
        "exploitability_rationale": "Unclear.",
        "suggested_fix": "",
    }
    fields.update(overrides)
    return json.dumps({k: v for k, v in fields.items() if v is not _OMIT})


_OMIT = object()


def test_missing_suggested_fix_defaults_to_empty() -> None:
    assert parse_triage_output(_reply(suggested_fix=_OMIT)).suggested_fix == ""


def test_null_suggested_fix_becomes_empty() -> None:
    assert parse_triage_output(_reply(suggested_fix=None)).suggested_fix == ""


def test_overlong_rationale_is_truncated_not_rejected() -> None:
    result = parse_triage_output(_reply(exploitability_rationale="word " * 1000))

    assert 0 < len(result.exploitability_rationale) <= MAX_RATIONALE_CHARS


def test_overlong_fix_is_truncated_not_rejected() -> None:
    result = parse_triage_output(_reply(suggested_fix="x" * (MAX_FIX_CHARS * 2)))
    assert len(result.suggested_fix) == MAX_FIX_CHARS


def test_text_at_the_limit_is_untouched() -> None:
    text = "y" * MAX_RATIONALE_CHARS
    assert parse_triage_output(_reply(exploitability_rationale=text)).exploitability_rationale == text


@pytest.mark.parametrize("severity", ["informational", "Informational", "INFORMATIONAL"])
def test_informational_maps_to_info(severity: str) -> None:
    assert parse_triage_output(_reply(adjusted_severity=severity)).adjusted_severity == Severity.INFO


@pytest.mark.parametrize(
    "overrides",
    [
        {"exploitability_rationale": _OMIT},  # still required
        {"exploitability_rationale": None},
        {"exploitability_rationale": "  "},
        {"verdict": _OMIT},
        {"adjusted_severity": _OMIT},
        {"suggested_fix": 5},  # wrong type is still an error, not coerced
    ],
)
def test_loosening_does_not_accept_substantive_errors(overrides: dict) -> None:
    with pytest.raises(TriageParseError):
        parse_triage_output(_reply(**overrides))


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
