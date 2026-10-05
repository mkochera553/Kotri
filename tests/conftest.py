"""Fixtures shared across the test suite.

Directories under tests/ mirror the packages under src/kotri/. Sample data used by more
than one package lives in tests/fixtures/.
"""

from collections.abc import Callable
from typing import Any

import pytest

from kotri.ingest.models import Finding, Severity, SourceTool


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
