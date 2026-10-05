from kotri.ingest.models import Finding, Severity, SourceTool
from kotri.llm.prompts import (
    MAX_LOCATION_CHARS,
    MAX_MESSAGE_CHARS,
    build_messages,
    build_retry_messages,
    truncate,
)


def _finding(raw_message: str = "A hardcoded JWT secret was found.") -> Finding:
    return Finding(
        id="abc123",
        source_tool=SourceTool.SEMGREP,
        rule="jwt-hardcode",
        location="lib/insecurity.ts:54",
        severity=Severity.HIGH,
        raw_message=raw_message,
    )


def test_build_messages_includes_finding_fields():
    system, user = build_messages(_finding())

    assert system["role"] == "system"
    assert "JSON" in system["content"]
    assert user["role"] == "user"
    for expected in ("semgrep", "jwt-hardcode", "lib/insecurity.ts:54", "high", "hardcoded JWT secret"):
        assert expected in user["content"]


def test_build_messages_tolerates_braces_in_scanner_text():
    messages = build_messages(_finding('payload {"a": {0}} {x}'))
    assert '{"a": {0}} {x}' in messages[1]["content"]


def test_build_messages_truncates_oversized_scanner_text() -> None:
    huge = "A" * (MAX_MESSAGE_CHARS * 10)
    user = build_messages(_finding(huge))[1]["content"]

    assert "... [truncated]" in user
    assert "A" * MAX_MESSAGE_CHARS not in user  # marker counts toward the limit
    assert len(user) < MAX_MESSAGE_CHARS + 500  # template overhead only
    assert user.rstrip().endswith(">>>")  # closing delimiter survives truncation


def test_build_messages_truncates_long_location() -> None:
    finding = _finding().model_copy(update={"location": "http://x/" + "p" * 5000})
    user = build_messages(finding)[1]["content"]

    assert "... [truncated]" in user
    assert "p" * MAX_LOCATION_CHARS not in user


def test_build_messages_leaves_short_text_untouched() -> None:
    user = build_messages(_finding())[1]["content"]
    assert "[truncated]" not in user


def test_truncate_respects_limit_exactly() -> None:
    assert truncate("abc", 3) == "abc"
    assert len(truncate("a" * 100, 40)) == 40


def test_build_retry_messages_appends_bad_reply_and_error():
    original = build_messages(_finding())
    retry = build_retry_messages(original, "oops", "missing verdict")

    assert retry[: len(original)] == original
    assert retry[-2] == {"role": "assistant", "content": "oops"}
    assert retry[-1]["role"] == "user"
    assert "missing verdict" in retry[-1]["content"]
    assert len(original) == 2  # input list is not mutated
