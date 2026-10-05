"""The JSON shape the LLM's triage output must validate against.

LLM output is untrusted: nothing here trusts the model to return clean JSON.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from kotri.ingest.models import Severity


class Verdict(str, Enum):
    LIKELY_TRUE_POSITIVE = "likely_true_positive"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    NEEDS_REVIEW = "needs_review"


class TriageParseError(ValueError):
    """The model's reply was not valid JSON matching TriageResult."""


def _normalize_enum_text(value: Any) -> Any:
    """Tolerate casing/spacing drift ("Likely True Positive", "HIGH") from small models."""
    if isinstance(value, str):
        return re.sub(r"[\s\-]+", "_", value.strip().lower())
    return value


class TriageResult(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    verdict: Verdict
    adjusted_severity: Severity
    exploitability_rationale: str = Field(min_length=1, max_length=1000)
    suggested_fix: str = Field(max_length=2000)

    @field_validator("verdict", "adjusted_severity", mode="before")
    @classmethod
    def _normalize_enums(cls, value: Any) -> Any:
        return _normalize_enum_text(value)


_FENCE_RE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.DOTALL | re.IGNORECASE)


def _extract_json_text(text: str) -> str:
    """Strip markdown fences or surrounding prose so only the JSON object remains."""
    text = text.strip()
    fence = _FENCE_RE.match(text)
    if fence:
        text = fence.group(1)
    if not text.startswith("{"):
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            text = text[start : end + 1]
    return text


def parse_triage_output(text: str) -> TriageResult:
    """Parse and validate raw model output, raising TriageParseError on any failure."""
    try:
        return TriageResult.model_validate_json(_extract_json_text(text))
    except ValidationError as exc:
        raise TriageParseError(str(exc)) from exc
