import json
import logging
from pathlib import Path
from typing import Any

import pytest

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


def _alert(**overrides: Any) -> dict[str, Any]:
    return {
        "alert": "Alert A",
        "riskcode": "2",
        "desc": "<p>d</p>",
        "instances": [{"uri": "http://h/"}],
        **overrides,
    }


def _report(*alerts: Any) -> dict[str, Any]:
    return {"site": [{"alerts": list(alerts)}]}


def _write(tmp_path: Path, report: Any) -> Path:
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("riskcode", "expected"),
    [
        ("0", Severity.INFO),
        ("1", Severity.LOW),
        ("2", Severity.MEDIUM),
        ("3", Severity.HIGH),
        (0, Severity.INFO),  # some report formats emit a number, not a string
        (2, Severity.MEDIUM),
        (3, Severity.HIGH),
        ("9", Severity.CRITICAL),  # unrecognized falls back to critical
        (None, Severity.CRITICAL),
    ],
)
def test_parse_zap_riskcode_values(tmp_path: Path, riskcode: Any, expected: Severity) -> None:
    findings = parse_zap(_write(tmp_path, _report(_alert(riskcode=riskcode))))
    assert [f.severity for f in findings] == [expected]


@pytest.mark.parametrize(
    "bad_alert",
    [
        _alert(alert=None),
        _alert(alert=["x"]),
        _alert(desc=None),  # re.sub on a non-string
        _alert(desc=5),
        "not an object",
        None,
    ],
)
def test_parse_zap_skips_wrong_typed_alerts_and_keeps_the_rest(
    tmp_path: Path, bad_alert: Any, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="kotri.ingest"):
        findings = parse_zap(_write(tmp_path, _report(bad_alert, _alert())))

    assert [f.rule for f in findings] == ["Alert A"]
    assert caplog.records


@pytest.mark.parametrize(
    "bad_instance",
    [{"uri": None}, {"uri": 7}, {"uri": ["u"]}, "http://h/", None, 3],
)
def test_parse_zap_skips_wrong_typed_instances_and_keeps_the_rest(
    tmp_path: Path, bad_instance: Any
) -> None:
    alert = _alert(instances=[bad_instance, {"uri": "http://ok/"}])
    findings = parse_zap(_write(tmp_path, _report(alert)))
    assert [f.location for f in findings] == ["http://ok/"]


@pytest.mark.parametrize("instances", [None, "x", {}, 5])
def test_parse_zap_tolerates_non_list_instances(tmp_path: Path, instances: Any) -> None:
    findings = parse_zap(_write(tmp_path, _report(_alert(instances=instances), _alert(alert="B"))))
    assert [f.rule for f in findings] == ["B"]  # Alert A has no usable instances


def test_parse_zap_tolerates_a_non_string_param(tmp_path: Path) -> None:
    alert = _alert(instances=[{"uri": "http://h/", "param": None}, {"uri": "http://h/", "param": 4}])
    findings = parse_zap(_write(tmp_path, _report(alert)))
    assert [f.location for f in findings] == ["http://h/", "http://h/#4"]


@pytest.mark.parametrize("sites", [None, {}, "x", [None, "x", 5]])
def test_parse_zap_tolerates_malformed_sites(tmp_path: Path, sites: Any) -> None:
    assert parse_zap(_write(tmp_path, {"site": sites})) == []


@pytest.mark.parametrize("alerts", [None, "x", {}])
def test_parse_zap_tolerates_non_list_alerts(tmp_path: Path, alerts: Any) -> None:
    assert parse_zap(_write(tmp_path, {"site": [{"alerts": alerts}]})) == []


@pytest.mark.parametrize("report", [[], "text", 5, None])
def test_parse_zap_rejects_a_report_that_is_not_an_object(tmp_path: Path, report: Any) -> None:
    with pytest.raises(ValueError, match="JSON object"):
        parse_zap(_write(tmp_path, report))
