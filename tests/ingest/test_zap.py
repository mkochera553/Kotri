import json
import logging
from pathlib import Path
from typing import Any

import pytest

from kotri.ingest.models import Severity, SourceTool
from kotri.ingest.text import MAX_DETAIL_CHARS
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


def _messages(tmp_path: Path, alert: dict[str, Any]) -> list[str]:
    return [f.raw_message for f in parse_zap(_write(tmp_path, _report(alert)))]


def test_parse_zap_message_includes_instance_evidence() -> None:
    redirect = [f for f in parse_zap(FIXTURE) if f.rule == "Off-site Redirect"]
    with_evidence = next(f for f in redirect if f.location.endswith("#to"))

    assert with_evidence.raw_message.startswith("The response contains a redirect")
    assert "Method: GET" in with_evidence.raw_message
    assert "CWE: CWE-601" in with_evidence.raw_message
    assert "ZAP confidence: medium" in with_evidence.raw_message
    assert "Other info: The 302 response contained user input" in with_evidence.raw_message


def test_parse_zap_keeps_attack_and_evidence_verbatim_including_markup() -> None:
    finding = next(f for f in parse_zap(FIXTURE) if f.location.endswith("#to"))

    assert "Attack: https://evil.example/<script>" in finding.raw_message
    assert "Evidence: Location: https://evil.example/<script>" in finding.raw_message


def test_parse_zap_instance_without_evidence_gets_no_empty_labels() -> None:
    finding = next(f for f in parse_zap(FIXTURE) if f.location.endswith("#redirectUrl"))

    for label in ("Attack:", "Evidence:", "Other info:"):
        assert label not in finding.raw_message
    assert "Method: GET" in finding.raw_message


def test_parse_zap_alert_level_otherinfo_is_html_stripped_and_used_as_fallback() -> None:
    finding = next(f for f in parse_zap(FIXTURE) if f.rule == "Missing Anti-clickjacking Header")

    assert "Other info: Alert level note." in finding.raw_message
    assert "<p>" not in finding.raw_message


def test_parse_zap_instance_otherinfo_wins_over_alert_otherinfo(tmp_path: Path) -> None:
    alert = _alert(otherinfo="<p>alert</p>", instances=[{"uri": "http://h/", "otherinfo": "instance"}])
    (message,) = _messages(tmp_path, alert)

    assert "Other info: instance" in message
    assert "alert" not in message.replace("Alert A", "")


@pytest.mark.parametrize("cweid", ["0", "-1", "", "abc", "²", None, 0, [1]])
def test_parse_zap_omits_the_cwe_line_when_zap_reports_none(tmp_path: Path, cweid: Any) -> None:
    (message,) = _messages(tmp_path, _alert(cweid=cweid))
    assert "CWE" not in message


def test_parse_zap_formats_numeric_cweid(tmp_path: Path) -> None:
    assert "CWE: CWE-79" in _messages(tmp_path, _alert(cweid=79))[0]
    assert "CWE: CWE-79" in _messages(tmp_path, _alert(cweid=" 79 "))[0]


@pytest.mark.parametrize(
    ("confidence", "label"),
    [("0", "false positive"), ("1", "low"), ("2", "medium"), ("3", "high"), (4, "confirmed")],
)
def test_parse_zap_confidence_labels(tmp_path: Path, confidence: Any, label: str) -> None:
    assert f"ZAP confidence: {label}" in _messages(tmp_path, _alert(confidence=confidence))[0]


@pytest.mark.parametrize("confidence", ["9", None, "high", []])
def test_parse_zap_omits_unknown_confidence(tmp_path: Path, confidence: Any) -> None:
    assert "confidence" not in _messages(tmp_path, _alert(confidence=confidence))[0]


def test_parse_zap_ignores_non_string_detail_fields(tmp_path: Path) -> None:
    instance = {"uri": "http://h/", "method": 5, "attack": ["a"], "evidence": None, "otherinfo": {}}
    assert _messages(tmp_path, _alert(instances=[instance])) == ["d"]


def test_parse_zap_clips_long_evidence(tmp_path: Path) -> None:
    instance = {"uri": "http://h/", "evidence": "e" * 50_000}
    (message,) = _messages(tmp_path, _alert(instances=[instance]))

    assert len(message) < MAX_DETAIL_CHARS + 100
    assert message.endswith("... [truncated]")


def test_parse_zap_details_do_not_change_the_finding_id(tmp_path: Path) -> None:
    bare = parse_zap(_write(tmp_path, _report(_alert(instances=[{"uri": "http://h/"}]))))[0]
    rich = parse_zap(_write(tmp_path, _report(_alert(instances=[{"uri": "http://h/", "evidence": "x"}]))))[0]

    assert bare.id == rich.id


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
