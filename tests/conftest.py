"""Fixtures shared across the test suite.

Directories under tests/ mirror the packages under src/kotri/. Sample data used by more
than one package lives in tests/fixtures/.
"""

from collections.abc import Callable
from typing import Any

import pytest

from kotri.ingest.models import Finding, Severity, SourceTool
from kotri.llm.client import TriageOutcome
from kotri.llm.schema import TriageResult, Verdict


@pytest.fixture
def make_finding() -> Callable[..., Finding]:
    """Build a Finding with realistic defaults; pass keyword overrides to change fields."""

    def _make(**overrides: Any) -> Finding:
        fields: dict[str, Any] = {
            "id": "abc123",
            "source_tool": SourceTool.SEMGREP,
            "rule": "jwt-hardcode",
            "location": "lib/insecurity.ts:54",
            "severity": Severity.HIGH,
            "raw_message": "A hardcoded JWT secret was found.",
        }
        return Finding(**{**fields, **overrides})

    return _make


@pytest.fixture
def make_outcome() -> Callable[..., TriageOutcome]:
    """Build a successful TriageOutcome; pass keyword overrides for the triage result.

    Pass result=None for a parse failure.
    """

    def _make(finding_id: str = "abc123", **overrides: Any) -> TriageOutcome:
        if "result" in overrides and overrides["result"] is None:
            return TriageOutcome(finding_id, None, True, 2, 0.5, error="bad json")
        fields: dict[str, Any] = {
            "verdict": Verdict.LIKELY_TRUE_POSITIVE,
            "adjusted_severity": Severity.HIGH,
            "exploitability_rationale": "Exploitable with a crafted request.",
            "suggested_fix": "Validate the input.",
        }
        result = TriageResult(**{**fields, **overrides})
        return TriageOutcome(finding_id, result, False, 1, 0.5)

    return _make
