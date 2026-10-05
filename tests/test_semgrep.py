import json
from pathlib import Path

from kotri.ingest.models import Severity, SourceTool
from kotri.ingest.semgrep import parse_semgrep

FIXTURE = Path(__file__).parent / "fixtures" / "semgrep_sample.json"


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
