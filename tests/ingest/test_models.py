import pytest
from pydantic import ValidationError

from kotri.ingest.models import Finding, Severity, SourceTool, make_finding_id


def test_make_finding_id_is_deterministic():
    id_a = make_finding_id(SourceTool.SEMGREP, "rule-a", "file.ts:1")
    id_b = make_finding_id(SourceTool.SEMGREP, "rule-a", "file.ts:1")

    assert id_a == id_b


def test_make_finding_id_differs_on_any_component():
    base = make_finding_id(SourceTool.SEMGREP, "rule-a", "file.ts:1")

    assert make_finding_id(SourceTool.ZAP, "rule-a", "file.ts:1") != base
    assert make_finding_id(SourceTool.SEMGREP, "rule-b", "file.ts:1") != base
    assert make_finding_id(SourceTool.SEMGREP, "rule-a", "file.ts:2") != base


def test_make_finding_id_does_not_collide_across_field_boundary():
    # Naively joining with "tool:rule:location" would make these two equal,
    # since "a:b" + ":" + "c" == "a" + ":" + "b:c".
    shifted_rule = make_finding_id(SourceTool.SEMGREP, "a:b", "c")
    shifted_location = make_finding_id(SourceTool.SEMGREP, "a", "b:c")

    assert shifted_rule != shifted_location


def test_finding_rejects_invalid_severity():
    with pytest.raises(ValidationError):
        Finding(
            id="abc123",
            source_tool=SourceTool.SEMGREP,
            rule="rule-a",
            location="file.ts:1",
            severity="not-a-real-severity",
            raw_message="msg",
        )
