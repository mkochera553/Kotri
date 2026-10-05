import json
import logging
from pathlib import Path
from typing import Any

import pytest

from kotri.ingest.models import Severity, SourceTool
from kotri.ingest.semgrep import parse_semgrep
from kotri.ingest.text import MAX_DETAIL_CHARS

FIXTURE = Path(__file__).parents[1] / "fixtures" / "semgrep_sample.json"


def test_parse_semgrep_returns_one_finding_per_result():
    findings = parse_semgrep(FIXTURE)
    assert len(findings) == 4


def test_parse_semgrep_maps_fields():
    findings = parse_semgrep(FIXTURE)
    jwt_finding = next(f for f in findings if "jwt-hardcode" in f.rule)

    assert jwt_finding.source_tool == SourceTool.SEMGREP
    assert jwt_finding.location == "lib/insecurity.ts:54"
    assert jwt_finding.severity == Severity.HIGH
    assert "hardcoded JWT secret" in jwt_finding.raw_message


def test_parse_semgrep_severity_mapping():
    findings = parse_semgrep(FIXTURE)
    by_rule = {f.rule: f for f in findings}

    assert by_rule["javascript.lang.security.audit.hardcoded-hmac-key.hardcoded-hmac-key"].severity == Severity.MEDIUM
    assert by_rule["javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing"].severity == Severity.LOW


def test_parse_semgrep_duplicate_results_get_same_id():
    findings = parse_semgrep(FIXTURE)
    hmac_findings = [f for f in findings if "hardcoded-hmac-key" in f.rule]

    assert len(hmac_findings) == 2
    assert hmac_findings[0].id == hmac_findings[1].id


def test_parse_semgrep_skips_malformed_result_without_crashing(tmp_path: Path) -> None:
    malformed = {
        "results": [
            {
                "check_id": "javascript.lang.security.audit.hardcoded-hmac-key.hardcoded-hmac-key",
                "path": "lib/insecurity.ts",
                "start": {"line": 42, "col": 1, "offset": 900},
                "extra": {"message": "missing severity key below"},
            },
            {
                "check_id": "javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret",
                "path": "lib/insecurity.ts",
                "start": {"line": 54, "col": 1, "offset": 1200},
                "extra": {
                    "message": "A hardcoded JWT secret was found.",
                    "severity": "ERROR",
                },
            },
        ]
    }
    path = tmp_path / "malformed.json"
    path.write_text(json.dumps(malformed), encoding="utf-8")

    findings = parse_semgrep(path)

    assert len(findings) == 1
    assert "jwt-hardcode" in findings[0].rule


def _result(**extra_overrides: Any) -> dict[str, Any]:
    return {
        "check_id": "rule-a",
        "path": "app.ts",
        "start": {"line": 1},
        "extra": {"message": "msg", "severity": "ERROR", **extra_overrides},
    }


def _write(tmp_path: Path, report: Any) -> Path:
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ERROR", Severity.HIGH),
        ("WARNING", Severity.MEDIUM),
        ("INFO", Severity.LOW),
        ("error", Severity.HIGH),
        ("EXPERIMENT", Severity.CRITICAL),  # unrecognized falls back to critical
        (3, Severity.CRITICAL),  # wrong type is unrecognized, not a crash
        (None, Severity.CRITICAL),
    ],
)
def test_parse_semgrep_severity_values(tmp_path: Path, raw: Any, expected: Severity) -> None:
    findings = parse_semgrep(_write(tmp_path, {"results": [_result(severity=raw)]}))
    assert [f.severity for f in findings] == [expected]


@pytest.mark.parametrize(
    "bad_result",
    [
        {**_result(), "check_id": 7},  # non-string rule
        {**_result(), "check_id": None},
        _result(message=None),
        _result(message=["a"]),
        {**_result(), "extra": ["not", "a", "dict"]},
        {**_result(), "extra": None},
        {**_result(), "start": "line 1"},
        {**_result(), "start": None},
        "not an object",
        None,
        ["check_id"],
    ],
)
def test_parse_semgrep_skips_wrong_typed_results_and_keeps_the_rest(
    tmp_path: Path, bad_result: Any, caplog: pytest.LogCaptureFixture
) -> None:
    good = _result()
    with caplog.at_level(logging.WARNING, logger="kotri.ingest"):
        findings = parse_semgrep(_write(tmp_path, {"results": [bad_result, good]}))

    assert [f.rule for f in findings] == ["rule-a"]
    assert caplog.records  # the skip is logged, not silent


@pytest.mark.parametrize("report", [[], "text", 5, None])
def test_parse_semgrep_rejects_a_report_that_is_not_an_object(tmp_path: Path, report: Any) -> None:
    with pytest.raises(ValueError, match="JSON object"):
        parse_semgrep(_write(tmp_path, report))


@pytest.mark.parametrize("results", [None, {}, "x", 5])
def test_parse_semgrep_tolerates_non_list_results(
    tmp_path: Path, results: Any, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="kotri.ingest"):
        assert parse_semgrep(_write(tmp_path, {"results": results})) == []
    assert caplog.records


def _only_message(tmp_path: Path, **extra: Any) -> str:
    (finding,) = parse_semgrep(_write(tmp_path, {"results": [_result(**extra)]}))
    return finding.raw_message


def test_parse_semgrep_message_includes_metadata_and_matched_code() -> None:
    jwt = next(f for f in parse_semgrep(FIXTURE) if "jwt-hardcode" in f.rule)

    assert jwt.raw_message.startswith("A hardcoded JWT secret was found.")
    assert "CWE: CWE-798: Use of Hard-coded Credentials" in jwt.raw_message
    assert (
        "OWASP: A07:2021 - Identification and Authentication Failures; "
        "A07:2025 - Authentication Failures"
    ) in jwt.raw_message
    assert "Rule confidence: HIGH" in jwt.raw_message
    assert "Likelihood: HIGH" in jwt.raw_message
    assert "Impact: MEDIUM" in jwt.raw_message
    assert "Matched code: const secret = 'hardcoded-jwt-secret'" in jwt.raw_message


def test_parse_semgrep_drops_the_requires_login_placeholder() -> None:
    hmac = next(f for f in parse_semgrep(FIXTURE) if "hardcoded-hmac-key" in f.rule)

    assert hmac.raw_message == "A hardcoded HMAC key was found. Store it in a secret manager instead."


@pytest.mark.parametrize("placeholder", ["requires login", "Requires Login", "  requires login\n", ""])
def test_parse_semgrep_placeholder_lines_are_not_matched_code(tmp_path: Path, placeholder: str) -> None:
    assert _only_message(tmp_path, lines=placeholder) == "msg"


def test_parse_semgrep_multiline_code_starts_on_its_own_line(tmp_path: Path) -> None:
    message = _only_message(tmp_path, lines="if (x) {\n  y();\n}")
    assert message == "msg\n\nMatched code:\nif (x) {\n  y();\n}"


def test_parse_semgrep_metadata_accepts_strings_and_ignores_junk(tmp_path: Path) -> None:
    metadata = {"cwe": "CWE-79", "owasp": ["A03", 7, None, " "], "impact": ["HIGH"], "confidence": 5}
    message = _only_message(tmp_path, metadata=metadata)

    assert message == "msg\n\nCWE: CWE-79\nOWASP: A03\nImpact: HIGH"


@pytest.mark.parametrize("metadata", [None, "x", ["cwe"], 5])
def test_parse_semgrep_ignores_a_non_object_metadata(tmp_path: Path, metadata: Any) -> None:
    assert _only_message(tmp_path, metadata=metadata) == "msg"


def test_parse_semgrep_clips_each_metadata_field_and_the_code(tmp_path: Path) -> None:
    message = _only_message(tmp_path, lines="c" * 5000, metadata={"cwe": ["w" * 5000]})

    assert len(message) < 2 * MAX_DETAIL_CHARS + 100
    assert message.count("... [truncated]") == 2


def test_parse_semgrep_details_do_not_change_the_finding_id(tmp_path: Path) -> None:
    plain = parse_semgrep(_write(tmp_path, {"results": [_result()]}))[0]
    rich = parse_semgrep(_write(tmp_path, {"results": [_result(lines="code", metadata={"cwe": "x"})]}))[0]

    assert plain.id == rich.id
    assert plain.raw_message != rich.raw_message


def test_parse_semgrep_missing_results_key_is_an_empty_scan(tmp_path: Path) -> None:
    assert parse_semgrep(_write(tmp_path, {"errors": []})) == []
