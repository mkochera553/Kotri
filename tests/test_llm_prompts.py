from kotri.ingest.models import Finding, Severity, SourceTool
from kotri.llm.prompts import build_messages, build_retry_messages


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


def test_build_retry_messages_appends_bad_reply_and_error():
    original = build_messages(_finding())
    retry = build_retry_messages(original, "oops", "missing verdict")

    assert retry[: len(original)] == original
    assert retry[-2] == {"role": "assistant", "content": "oops"}
    assert retry[-1]["role"] == "user"
    assert "missing verdict" in retry[-1]["content"]
    assert len(original) == 2  # input list is not mutated
