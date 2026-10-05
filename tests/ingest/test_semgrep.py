import json
import logging
from pathlib import Path
from typing import Any

import pytest

from kotri.ingest.models import Severity, SourceTool
from kotri.ingest.semgrep import parse_semgrep

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


def test_parse_semgrep_missing_results_key_is_an_empty_scan(tmp_path: Path) -> None:
    assert parse_semgrep(_write(tmp_path, {"errors": []})) == []
