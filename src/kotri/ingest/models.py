"""The Finding model: the single normalized shape every parser returns."""

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel


class SourceTool(str, Enum):
    SEMGREP = "semgrep"
    ZAP = "zap"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    id: str
    source_tool: SourceTool
    rule: str
    location: str
    severity: Severity
    raw_message: str


def make_finding_id(source_tool: SourceTool, rule: str, location: str) -> str:
    """Deterministic id so re-running a scan yields stable Finding ids."""
    digest = hashlib.sha256(f"{source_tool.value}:{rule}:{location}".encode("utf-8"))
    return digest.hexdigest()[:16]
