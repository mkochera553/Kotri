import http.client
import io
import json
import logging
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from urllib.response import addinfourl

import pytest

from kotri.ingest.models import Finding, Severity, SourceTool
from kotri.llm.client import (
    DEFAULT_MAX_TOKENS,
    LLMClient,
    LLMError,
    _build_opener,
    _NoRedirect,
    validate_base_url,
)

FIXTURES = Path(__file__).parent / "fixtures"
CHAT_BODY = (FIXTURES / "chat_completion.json").read_bytes()
VALID_REPLY = (FIXTURES / "triage_valid.json").read_text(encoding="utf-8")
BASE_URL = "http://127.0.0.1:11434/v1"


class FakeResponse(io.BytesIO):
    def __enter__(self) -> "FakeResponse":
        return self


class FakeOpener:
    """Plays back a script of response bodies / exceptions; records requests."""

    def __init__(self, script: list) -> None:
        self.script = list(script)
        self.requests: list = []
        self.timeouts: list = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        self.timeouts.append(timeout)
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        return FakeResponse(step)


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(BASE_URL, code, "err", {}, io.BytesIO(b""))


def _client(script: list, **kwargs) -> tuple[LLMClient, FakeOpener]:
    opener = FakeOpener(script)
    client = LLMClient(BASE_URL, "test-model", opener=opener, sleep=lambda _: None, **kwargs)
    return client, opener


def _finding() -> Finding:
    return Finding(
        id="abc123",
        source_tool=SourceTool.SEMGREP,
        rule="jwt-hardcode",
        location="lib/insecurity.ts:54",
        severity=Severity.HIGH,
        raw_message="A hardcoded JWT secret was found.",
    )


def _scripted_chat(client: LLMClient, replies: list[str]) -> list:
    """Replace client.chat so triage tests never touch transport."""
    calls: list = []

    def fake_chat(messages):
        calls.append(messages)
        return replies.pop(0)

    client.chat = fake_chat  # type: ignore[method-assign]
    return calls


# --- localhost-only check ---------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:11434/v1",
        "http://localhost:11434/v1/",
        "http://[::1]:11434/v1",
        "http://LOCALHOST:11434/v1",
    ],
)
def test_validate_base_url_accepts_loopback(url: str) -> None:
    assert not validate_base_url(url).endswith("/")


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/v1",
        "http://192.168.1.10:11434/v1",
        "http://0.0.0.0:11434/v1",
        "http://127.0.0.1.evil.com/v1",
        "http://127.0.0.1@evil.com/v1",
        "http://localhost.evil.com/v1",
        "ftp://127.0.0.1/v1",
        "127.0.0.1:11434/v1",
        "http://127.0.0.1:abc/v1",  # port is validated lazily by urlparse
        "http://localhost:99999/v1",
        "",
    ],
)
def test_validate_base_url_rejects_non_loopback(url: str) -> None:
    with pytest.raises(ValueError):
        validate_base_url(url)


def test_client_constructor_rejects_remote_host() -> None:
    with pytest.raises(ValueError):
        LLMClient("https://api.example.com/v1", "m")


# --- transport: timeouts and retries ----------------------------------------


def test_chat_returns_message_content_and_sends_expected_request() -> None:
    client, opener = _client([CHAT_BODY], timeout=7.5)

    assert client.chat([{"role": "user", "content": "hi"}]) == '{"ok": true}'

    request = opener.requests[0]
    body = json.loads(request.data)
    assert request.full_url == f"{BASE_URL}/chat/completions"
    assert body["model"] == "test-model"
    assert body["temperature"] == 0.0
    assert body["response_format"] == {"type": "json_object"}
    assert body["max_tokens"] == DEFAULT_MAX_TOKENS
    assert opener.timeouts == [7.5]


def test_chat_sends_configured_max_tokens() -> None:
    client, opener = _client([CHAT_BODY], max_tokens=256)
    client.chat([])
    assert json.loads(opener.requests[0].data)["max_tokens"] == 256


def test_chat_retries_transient_errors_then_succeeds() -> None:
    sleeps: list[float] = []
    opener = FakeOpener([TimeoutError("slow"), _http_error(503), CHAT_BODY])
    client = LLMClient(BASE_URL, "m", opener=opener, backoff=1.0, sleep=sleeps.append)

    assert client.chat([]) == '{"ok": true}'
    assert len(opener.requests) == 3
    assert sleeps == [1.0, 2.0]


def test_chat_retries_connection_errors() -> None:
    client, opener = _client([urllib.error.URLError("refused"), CHAT_BODY])
    assert client.chat([]) == '{"ok": true}'
    assert len(opener.requests) == 2


@pytest.mark.parametrize(
    "error",
    [
        http.client.IncompleteRead(b"{", 100),
        http.client.BadStatusLine("garbage"),
        http.client.RemoteDisconnected("closed"),
    ],
)
def test_chat_retries_dropped_connections(error: Exception) -> None:
    client, opener = _client([error, CHAT_BODY])
    assert client.chat([]) == '{"ok": true}'
    assert len(opener.requests) == 2


def test_chat_wraps_persistent_http_exceptions_in_llm_error() -> None:
    client, opener = _client([http.client.IncompleteRead(b"")] * 3, max_retries=2)

    with pytest.raises(LLMError, match="3 attempts"):
        client.chat([])
    assert len(opener.requests) == 3


def test_chat_raises_after_exhausting_retries() -> None:
    client, opener = _client([TimeoutError()] * 3, max_retries=2)

    with pytest.raises(LLMError, match="3 attempts"):
        client.chat([])
    assert len(opener.requests) == 3


def test_chat_does_not_retry_client_errors() -> None:
    client, opener = _client([_http_error(404), CHAT_BODY])

    with pytest.raises(LLMError, match="404"):
        client.chat([])
    assert len(opener.requests) == 1


def test_chat_treats_redirect_status_as_non_retryable_error() -> None:
    client, opener = _client([_http_error(302), CHAT_BODY])

    with pytest.raises(LLMError, match="302"):
        client.chat([])
    assert len(opener.requests) == 1


class _ScriptedHTTP(urllib.request.BaseHandler):
    """Stands in for the socket layer so the real opener chain runs without network.

    handler_order 200 puts it after ProxyHandler (100) but before the real HTTPHandler (500).
    """

    handler_order = 200

    def __init__(self, code: int = 200, location: str | None = None) -> None:
        self.code = code
        self.location = location
        self.opened: list[urllib.request.Request] = []

    def http_open(self, request: urllib.request.Request) -> addinfourl:
        self.opened.append(request)
        headers = Message()
        if self.location:
            headers["Location"] = self.location
        response = addinfourl(io.BytesIO(CHAT_BODY), headers, request.full_url, self.code)
        response.msg = "scripted"  # http.client responses expose the reason phrase as .msg
        return response


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_default_opener_does_not_follow_redirects(code: int) -> None:
    transport = _ScriptedHTTP(code, location="http://remote.example.com/steal")
    opener = _build_opener()
    opener.add_handler(transport)
    request = urllib.request.Request(
        f"{BASE_URL}/chat/completions", data=b"{}", method="POST"
    )

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        opener.open(request, timeout=1)

    assert excinfo.value.code == code
    assert [r.full_url for r in transport.opened] == [f"{BASE_URL}/chat/completions"]


def test_default_opener_ignores_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"):
        monkeypatch.setenv(name, "http://proxy.example.com:3128")
    transport = _ScriptedHTTP()
    opener = _build_opener()
    opener.add_handler(transport)
    request = urllib.request.Request(f"{BASE_URL}/chat/completions")

    opener.open(request, timeout=1).close()

    assert request.host == "127.0.0.1:11434"  # a proxy would have rewritten this
    assert transport.opened == [request]


def test_client_uses_hardened_opener_by_default() -> None:
    client = LLMClient(BASE_URL, "m")
    handlers = client._opener.handlers  # type: ignore[attr-defined]

    assert any(isinstance(h, _NoRedirect) for h in handlers)
    assert not any(type(h) is urllib.request.HTTPRedirectHandler for h in handlers)


@pytest.mark.parametrize(
    "body",
    [b"not json", b"{}", b'{"choices": []}', b'{"choices": [{"message": {"content": null}}]}'],
)
def test_chat_rejects_malformed_response(body: bytes) -> None:
    client, _ = _client([body])
    with pytest.raises(LLMError):
        client.chat([])


def test_from_config_reads_llm_section() -> None:
    client = LLMClient.from_config(
        {"base_url": BASE_URL, "timeout_seconds": 30, "max_retries": 5, "models": ["a"]}, "a"
    )
    assert (client.model, client.timeout, client.max_retries) == ("a", 30, 5)
    assert client.max_tokens == DEFAULT_MAX_TOKENS  # absent key falls back to the default

    configured = LLMClient.from_config({"base_url": BASE_URL, "max_tokens": 64}, "a")
    assert configured.max_tokens == 64


# --- triage: parse retry and metrics ----------------------------------------


def test_triage_success_on_first_try() -> None:
    client, _ = _client([])
    calls = _scripted_chat(client, [VALID_REPLY])

    outcome = client.triage(_finding())

    assert outcome.result is not None and not outcome.parse_failed
    assert outcome.attempts == 1
    assert outcome.finding_id == "abc123"
    assert len(calls) == 1
    assert (client.stats.calls, client.stats.retries, client.stats.failures) == (1, 0, 0)


def test_triage_retries_once_on_parse_failure_and_recovers(caplog) -> None:
    client, _ = _client([])
    calls = _scripted_chat(client, ["I think it's bad.", VALID_REPLY])

    with caplog.at_level(logging.WARNING, logger="kotri.llm.client"):
        outcome = client.triage(_finding())

    assert outcome.result is not None
    assert outcome.attempts == 2
    assert len(calls) == 2
    assert calls[1][-2] == {"role": "assistant", "content": "I think it's bad."}
    assert (client.stats.retries, client.stats.recovered, client.stats.failures) == (1, 1, 0)
    assert "retrying once" in caplog.text


def test_triage_records_parse_failure_after_second_bad_reply() -> None:
    client, _ = _client([])
    calls = _scripted_chat(client, ["nope", "still nope"])

    outcome = client.triage(_finding())  # must not raise

    assert outcome.result is None and outcome.parse_failed
    assert outcome.attempts == 2
    assert outcome.error
    assert len(calls) == 2  # exactly one retry
    assert (client.stats.retries, client.stats.recovered, client.stats.failures) == (1, 0, 1)


def test_parse_stats_rates_and_summary_log(caplog) -> None:
    client, _ = _client([])
    _scripted_chat(client, [VALID_REPLY, "bad", VALID_REPLY, "bad", "bad"])

    client.triage(_finding())  # ok
    client.triage(_finding())  # retried, recovered
    client.triage(_finding())  # retried, failed

    assert client.stats.retry_rate == pytest.approx(2 / 3)
    assert client.stats.failure_rate == pytest.approx(1 / 3)
    with caplog.at_level(logging.INFO, logger="kotri.llm.client"):
        client.log_parse_stats()
    assert "3 calls" in caplog.text and "2 retried" in caplog.text


def test_triage_propagates_transport_errors() -> None:
    client, _ = _client([TimeoutError()] * 3)
    with pytest.raises(LLMError):
        client.triage(_finding())


def test_transport_error_is_counted_separately_from_parse_stats() -> None:
    client, _ = _client([TimeoutError()] * 3)

    with pytest.raises(LLMError):
        client.triage(_finding())

    assert client.stats.transport_errors == 1
    assert (client.stats.calls, client.stats.retries) == (0, 0)
    assert (client.stats.recovered, client.stats.failures) == (0, 0)
    assert client.stats.failure_rate == 0.0  # no denominator inflation


def test_transport_error_on_retry_leaves_parse_counters_reconciled() -> None:
    client, _ = _client([])

    def fake_chat(messages):
        if len(messages) == 2:
            return "not json"  # first attempt: unparseable
        raise LLMError("runtime went away")  # retry attempt: transport failure

    client.chat = fake_chat  # type: ignore[method-assign]

    with pytest.raises(LLMError):
        client.triage(_finding())

    stats = client.stats
    assert stats.transport_errors == 1
    assert (stats.calls, stats.retries, stats.recovered, stats.failures) == (0, 0, 0, 0)


def test_parse_stats_invariants_hold_across_mixed_outcomes() -> None:
    client, _ = _client([])
    replies = [VALID_REPLY, "bad", VALID_REPLY, "bad", "bad"]

    def fake_chat(messages):
        return replies.pop(0)

    client.chat = fake_chat  # type: ignore[method-assign]
    for _ in range(3):
        client.triage(_finding())

    s = client.stats
    assert s.retries == s.recovered + s.failures
    assert s.calls - s.retries == 1  # parsed first try
