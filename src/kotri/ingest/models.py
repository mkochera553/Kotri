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
    """Deterministic id so re-running a scan yields stable Finding ids.

    Each component is length-prefixed before hashing so that, e.g., a rule
    ending in ":3000" can't shift into the next field and collide with a
    different (rule, location) pair.
    """
    digest = hashlib.sha256()
    for part in (source_tool.value, rule, location):
        encoded = part.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()[:16]
