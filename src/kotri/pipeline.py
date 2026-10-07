"""normalize -> dedupe -> triage -> collect results."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Protocol

from kotri.ingest.models import Finding
from kotri.ingest.semgrep import parse_semgrep
from kotri.ingest.zap import parse_zap
from kotri.llm.client import LLMError, ParseStats, TriageOutcome

logger = logging.getLogger(__name__)

# A dead runtime would otherwise cost every remaining finding a full retry cycle.
MAX_CONSECUTIVE_TRANSPORT_ERRORS = 3
_NOT_ATTEMPTED = "not attempted: run aborted after repeated runtime errors"


class Triager(Protocol):
    """What the pipeline needs from the LLM layer; LLMClient satisfies it."""

    model: str
    stats: ParseStats

    def triage(self, finding: Finding) -> TriageOutcome: ...


@dataclass
class TriagedFinding:
    finding: Finding
    # None when the runtime failed or the run aborted first; error says why.
    outcome: TriageOutcome | None = None
    error: str | None = None


@dataclass
class PipelineResult:
    model: str
    items: list[TriagedFinding] = field(default_factory=list)
    stats: ParseStats = field(default_factory=ParseStats)
    duplicates_dropped: int = 0
    aborted: bool = False


def load_findings(semgrep: Path | None = None, zap: Path | None = None) -> list[Finding]:
    """Parse whichever scan reports were given into one Finding list."""
    findings: list[Finding] = []
    if semgrep is not None:
        findings.extend(parse_semgrep(semgrep))
    if zap is not None:
        findings.extend(parse_zap(zap))
    return findings


def dedupe(findings: Iterable[Finding]) -> tuple[list[Finding], int]:
    """Drop repeated findings, keeping the first of each id; returns (kept, dropped).

    Ids hash (tool, rule, location), so the same alert reported twice, or in two
    scans of the same target, collapses to one triage call.
    """
    seen: set[str] = set()
    kept: list[Finding] = []
    dropped = 0
    for finding in findings:
        if finding.id in seen:
            dropped += 1
        else:
            seen.add(finding.id)
            kept.append(finding)
    return kept, dropped


def triage_all(
    findings: list[Finding], triager: Triager, duplicates_dropped: int = 0
) -> PipelineResult:
    """Triage each finding in order and collect the outcomes.

    A parse failure is an ordinary outcome. A runtime error is recorded on that
    finding and the run continues, until several in a row show the runtime is down.
    """
    result = PipelineResult(model=triager.model, duplicates_dropped=duplicates_dropped)
    consecutive_errors = 0
    total = len(findings)

    for index, finding in enumerate(findings, start=1):
        if consecutive_errors >= MAX_CONSECUTIVE_TRANSPORT_ERRORS:
            result.aborted = True
            result.items.append(TriagedFinding(finding, error=_NOT_ATTEMPTED))
            continue

        logger.info("triaging %d/%d: %s %s", index, total, finding.rule, finding.location)
        try:
            outcome = triager.triage(finding)
        except LLMError as exc:
            consecutive_errors += 1
            logger.error("triage failed for %s: %s", finding.id, exc)
            result.items.append(TriagedFinding(finding, error=str(exc)))
        else:
            consecutive_errors = 0
            result.items.append(TriagedFinding(finding, outcome=outcome, error=outcome.error))

    result.stats = replace(triager.stats)  # snapshot; the client keeps counting
    return result


def run_pipeline(
    triager: Triager, semgrep: Path | None = None, zap: Path | None = None
) -> PipelineResult:
    """Parse the given scans, dedupe, and triage every finding."""
    findings, dropped = dedupe(load_findings(semgrep, zap))
    return triage_all(findings, triager, dropped)
