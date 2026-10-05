from typing import Any

import pytest

from kotri.ingest.text import MAX_DETAIL_CHARS, clip, compose_message


@pytest.mark.parametrize("value", [None, 5, ["a"], {"a": 1}, b"bytes"])
def test_clip_returns_empty_for_non_strings(value: Any) -> None:
    assert clip(value) == ""


def test_clip_strips_and_leaves_short_text_alone() -> None:
    assert clip("  hello \n") == "hello"
    assert clip("x" * MAX_DETAIL_CHARS) == "x" * MAX_DETAIL_CHARS


def test_clip_truncates_to_the_limit_and_marks_the_cut() -> None:
    clipped = clip("word " * 1000)

    assert len(clipped) <= MAX_DETAIL_CHARS
    assert clipped.endswith("... [truncated]")
    assert clip("y" * 100, limit=40).endswith("... [truncated]")
    assert len(clip("y" * 100, limit=40)) == 40


def test_compose_message_appends_labelled_details_after_the_summary() -> None:
    message = compose_message("Summary.", [("A", "1"), ("B", "2")])
    assert message == "Summary.\n\nA: 1\nB: 2"


def test_compose_message_skips_empty_details() -> None:
    assert compose_message("Summary.", [("A", ""), ("B", "2"), ("C", "")]) == "Summary.\n\nB: 2"


def test_compose_message_without_details_is_just_the_summary() -> None:
    assert compose_message("Summary.", []) == "Summary."
    assert compose_message("Summary.", [("A", "")]) == "Summary."


def test_compose_message_puts_multiline_values_on_their_own_lines() -> None:
    message = compose_message("S", [("Code", "line1\nline2"), ("After", "x")])
    assert message == "S\n\nCode:\nline1\nline2\nAfter: x"


def test_compose_message_with_empty_summary_has_no_leading_blank_line() -> None:
    assert compose_message("", [("A", "1")]) == "A: 1"
    assert compose_message("", []) == ""
