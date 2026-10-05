"""The JSON shape the LLM's triage output must validate against.

LLM output is untrusted: nothing here trusts the model to return clean JSON.
"""

from __future__ import annotations

import json
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


MAX_RATIONALE_CHARS = 1000
MAX_FIX_CHARS = 2000
# ZAP reports "Informational"; models that echo that wording mean our "info".
_SEVERITY_ALIASES = {"informational": "info"}


def _clip(value: Any, limit: int) -> Any:
    """Strip and truncate over-long free text; the length isn't a correctness signal."""
    if isinstance(value, str):
        return value.strip()[:limit].rstrip()
    return value


class TriageResult(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    verdict: Verdict
    adjusted_severity: Severity
    exploitability_rationale: str = Field(min_length=1)
    suggested_fix: str = ""

    @field_validator("verdict", "adjusted_severity", mode="before")
    @classmethod
    def _normalize_enums(cls, value: Any) -> Any:
        return _normalize_enum_text(value)

    @field_validator("adjusted_severity", mode="before")
    @classmethod
    def _alias_severity(cls, value: Any) -> Any:
        normalized = _normalize_enum_text(value)  # don't rely on validator ordering
        return _SEVERITY_ALIASES.get(normalized, normalized)

    @field_validator("exploitability_rationale", mode="before")
    @classmethod
    def _clip_rationale(cls, value: Any) -> Any:
        return _clip(value, MAX_RATIONALE_CHARS)

    @field_validator("suggested_fix", mode="before")
    @classmethod
    def _clip_fix(cls, value: Any) -> Any:
        # "No fix needed" is allowed to be empty; small models often send null for it.
        return "" if value is None else _clip(value, MAX_FIX_CHARS)


_DECODER = json.JSONDecoder()


def _json_objects(text: str) -> list[str]:
    """Every top-level JSON object in text, in order, skipping fences and prose.

    Stray braces in prose are skipped, and objects nested inside a decoded object are
    not returned separately.
    """
    objects: list[str] = []
    start = text.find("{")
    while start != -1:
        try:
            _, end = _DECODER.raw_decode(text, start)
        except ValueError:
            start = text.find("{", start + 1)
        else:
            objects.append(text[start:end])
            start = text.find("{", end)
    return objects


def parse_triage_output(text: str) -> TriageResult:
    """Parse and validate raw model output, raising TriageParseError on any failure.

    If the reply holds several JSON objects (a draft in a reasoning model's think
    block, an example before the answer, or `{}` in prose), the last one that
    validates wins, since the final answer comes last. If none validates, the error
    is for the last object, or for the whole text when no object decodes.
    """
    text = text.strip()
    candidates = _json_objects(text) or [text]

    last_error: ValidationError | None = None
    for candidate in reversed(candidates):
        try:
            return TriageResult.model_validate_json(candidate)
        except ValidationError as exc:
            if last_error is None:  # the first failure seen is the last candidate's
                last_error = exc
    raise TriageParseError(str(last_error)) from last_error
