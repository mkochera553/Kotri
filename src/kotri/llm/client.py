"""OpenAI-compatible chat client for the local inference runtime.

Findings must never leave this machine, so the client only talks to a
loopback host, ignores proxy environment variables, and refuses redirects.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from kotri.ingest.models import Finding
from kotri.llm.prompts import Message, build_messages, build_retry_messages
from kotri.llm.schema import TriageParseError, TriageResult, parse_triage_output

logger = logging.getLogger(__name__)

ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
# Caps generation so a looping model can't run until the timeout. Replies asked for
# in the prompt are far smaller; a reply cut off at the cap fails to parse and is
# retried/recorded like any other parse failure.
DEFAULT_MAX_TOKENS = 1024


class LLMError(RuntimeError):
    """The runtime could not be reached or returned an unusable response."""


def validate_base_url(base_url: str) -> str:
    """Return base_url without a trailing slash, or raise if it isn't loopback."""
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"base_url must be http(s), got {base_url!r}")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(
            f"base_url host {parsed.hostname!r} is not local; findings must not "
            f"leave this machine (allowed: {sorted(ALLOWED_HOSTS)})"
        )
    return base_url.rstrip("/")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect could send the request body to a non-local host."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _build_opener() -> urllib.request.OpenerDirector:
    # An empty ProxyHandler stops HTTP(S)_PROXY from routing requests elsewhere.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


@dataclass
class ParseStats:
    """How often model output failed to parse; a quality metric for small models.

    Only triages that got a model reply count toward calls, so the rates measure the
    model. Invariants: retries == recovered + failures, and calls - retries is the
    number that parsed first try. Transport errors are tracked separately.
    """

    calls: int = 0
    retries: int = 0
    recovered: int = 0
    failures: int = 0
    transport_errors: int = 0

    @property
    def retry_rate(self) -> float:
        return self.retries / self.calls if self.calls else 0.0

    @property
    def failure_rate(self) -> float:
        return self.failures / self.calls if self.calls else 0.0


@dataclass
class TriageOutcome:
    finding_id: str
    result: TriageResult | None
    parse_failed: bool
    attempts: int
    latency_s: float
    error: str | None = None


class LLMClient:
    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        timeout: float = 120.0,
        max_retries: int = 2,
        backoff: float = 1.0,
        temperature: float = 0.0,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        opener: urllib.request.OpenerDirector | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = validate_base_url(base_url)
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff = backoff
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.stats = ParseStats()
        self._opener = opener or _build_opener()
        self._sleep = sleep

    @classmethod
    def from_config(cls, llm_config: Mapping[str, Any], model: str) -> LLMClient:
        """Build a client from the `llm:` section of config.yaml."""
        return cls(
            llm_config["base_url"],
            model,
            timeout=llm_config.get("timeout_seconds", 120.0),
            max_retries=llm_config.get("max_retries", 2),
            max_tokens=llm_config.get("max_tokens", DEFAULT_MAX_TOKENS),
        )

    def chat(self, messages: list[Message]) -> str:
        """Send one chat completion and return the reply text.

        Connection errors, timeouts, 429s and 5xx responses are retried with
        exponential backoff; anything else raises LLMError immediately.
        """
        payload = json.dumps(
            {
                "model": self.model,
                "messages": messages,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
                "stream": False,
                "response_format": {"type": "json_object"},
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            if attempt:
                delay = self.backoff * 2 ** (attempt - 1)
                logger.warning(
                    "LLM request failed (%s); retry %d/%d in %.1fs",
                    last_error, attempt, self.max_retries, delay,
                )
                self._sleep(delay)
            try:
                with self._opener.open(request, timeout=self.timeout) as response:
                    body = response.read()
            except urllib.error.HTTPError as exc:
                exc.close()
                if exc.code not in _RETRYABLE_STATUS:
                    raise LLMError(f"runtime returned HTTP {exc.code}") from exc
                last_error = exc
                continue
            except OSError as exc:  # URLError, timeouts, connection resets
                last_error = exc
                continue
            return self._extract_content(body)

        raise LLMError(
            f"runtime unreachable after {self.max_retries + 1} attempts: {last_error}"
        ) from last_error

    @staticmethod
    def _extract_content(body: bytes) -> str:
        try:
            content = json.loads(body)["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"unexpected response shape from runtime: {exc!r}") from exc
        if not isinstance(content, str):
            raise LLMError("runtime returned no message content")
        return content

    def triage(self, finding: Finding) -> TriageOutcome:
        """Ask the model to triage one finding.

        Output that fails validation is retried once with the error fed back;
        a second failure is recorded as a parse failure, not raised. Transport
        problems still raise LLMError, since they aren't a model-quality signal;
        they are counted in stats.transport_errors and leave the other counters alone.
        """
        try:
            outcome = self._triage(finding)
        except LLMError:
            self.stats.transport_errors += 1
            raise
        self._record(outcome)
        return outcome

    def _triage(self, finding: Finding) -> TriageOutcome:
        start = time.perf_counter()
        messages = build_messages(finding)

        reply = self.chat(messages)
        try:
            result = parse_triage_output(reply)
            return self._outcome(finding, result, 1, start)
        except TriageParseError as first_error:
            logger.warning(
                "unparseable triage output for %s from %s; retrying once",
                finding.id, self.model,
            )
            retry_messages = build_retry_messages(messages, reply, str(first_error))

        reply = self.chat(retry_messages)
        try:
            result = parse_triage_output(reply)
        except TriageParseError as exc:
            logger.error(
                "triage parse failure for %s from %s after retry", finding.id, self.model
            )
            return self._outcome(finding, None, 2, start, error=str(exc))
        return self._outcome(finding, result, 2, start)

    def _record(self, outcome: TriageOutcome) -> None:
        """Update parse stats from a completed triage."""
        self.stats.calls += 1
        if outcome.attempts > 1:
            self.stats.retries += 1
            if outcome.parse_failed:
                self.stats.failures += 1
            else:
                self.stats.recovered += 1

    def _outcome(
        self,
        finding: Finding,
        result: TriageResult | None,
        attempts: int,
        start: float,
        error: str | None = None,
    ) -> TriageOutcome:
        return TriageOutcome(
            finding_id=finding.id,
            result=result,
            parse_failed=result is None,
            attempts=attempts,
            latency_s=time.perf_counter() - start,
            error=error,
        )

    def log_parse_stats(self) -> None:
        """Log the parse-retry/failure summary; call once at the end of a run."""
        s = self.stats
        logger.info(
            "%s parse stats: %d calls, %d retried (%.1f%%), %d recovered, %d failed (%.1f%%), "
            "%d transport errors",
            self.model, s.calls, s.retries, s.retry_rate * 100,
            s.recovered, s.failures, s.failure_rate * 100, s.transport_errors,
        )
