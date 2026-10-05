import json
from pathlib import Path

from kotri.ingest.models import Severity, SourceTool
from kotri.ingest.zap import parse_zap

FIXTURE = Path(__file__).parents[1] / "fixtures" / "zap_sample.json"


def test_parse_zap_flattens_instances_to_findings():
    findings = parse_zap(FIXTURE)
    # 2 instances for CSP + 1 for clickjacking + 2 for off-site redirect
    assert len(findings) == 5


def test_parse_zap_maps_fields():
    findings = parse_zap(FIXTURE)
    csp_findings = [f for f in findings if f.rule == "Content Security Policy (CSP) Header Not Set"]

    assert len(csp_findings) == 2
    first = csp_findings[0]
    assert first.source_tool == SourceTool.ZAP
    assert first.location == "http://host.docker.internal:3000/"
    assert first.severity == Severity.MEDIUM
    assert "<p>" not in first.raw_message
    assert "added layer of security" in first.raw_message


def test_parse_zap_distinct_instances_get_distinct_ids():
    findings = parse_zap(FIXTURE)
    csp_findings = [f for f in findings if f.rule == "Content Security Policy (CSP) Header Not Set"]

    assert csp_findings[0].id != csp_findings[1].id


def test_parse_zap_distinct_params_on_same_uri_get_distinct_locations_and_ids():
    findings = parse_zap(FIXTURE)
    redirect_findings = [f for f in findings if f.rule == "Off-site Redirect"]

    assert len(redirect_findings) == 2
    assert redirect_findings[0].location != redirect_findings[1].location
    assert redirect_findings[0].id != redirect_findings[1].id


def test_parse_zap_skips_malformed_alert_without_crashing(tmp_path: Path) -> None:
    malformed = {
        "site": [
            {
                "alerts": [
                    {
                        "alert": "Missing riskcode entirely, not just unrecognized",
                        "desc": "<p>this alert has no riskcode key</p>",
                        "instances": [{"uri": "http://host.docker.internal:3000/broken"}],
                    },
                    {
                        "alert": "Missing Anti-clickjacking Header",
                        "riskcode": "2",
                        "desc": "<p>valid alert</p>",
                        "instances": [{"uri": "http://host.docker.internal:3000/"}],
                    },
                ]
            }
        ]
    }
    path = tmp_path / "malformed.json"
    path.write_text(json.dumps(malformed), encoding="utf-8")

    findings = parse_zap(path)

    assert len(findings) == 1
    assert findings[0].rule == "Missing Anti-clickjacking Header"


def test_parse_zap_skips_malformed_instance_without_crashing(tmp_path: Path) -> None:
    malformed = {
        "site": [
            {
                "alerts": [
                    {
                        "alert": "Missing Anti-clickjacking Header",
                        "riskcode": "2",
                        "desc": "<p>valid alert</p>",
                        "instances": [
                            {"method": "GET"},
                            {"uri": "http://host.docker.internal:3000/"},
                        ],
                    }
                ]
            }
        ]
    }
    path = tmp_path / "malformed.json"
    path.write_text(json.dumps(malformed), encoding="utf-8")

    findings = parse_zap(path)

    assert len(findings) == 1
    assert findings[0].location == "http://host.docker.internal:3000/"
