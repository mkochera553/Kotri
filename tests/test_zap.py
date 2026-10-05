from pathlib import Path

from kotri.ingest.models import Severity, SourceTool
from kotri.ingest.zap import parse_zap

FIXTURE = Path(__file__).parent / "fixtures" / "zap_sample.json"


def test_parse_zap_flattens_instances_to_findings():
    findings = parse_zap(FIXTURE)
    # 2 instances for the CSP alert + 1 instance for clickjacking
    assert len(findings) == 3


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
