from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from kotri import cli
from kotri.ingest.models import Finding, Severity
from kotri.llm.client import LLMError, ParseStats, TriageOutcome

FIXTURES = Path(__file__).parent / "fixtures"
CONFIG = """\
llm:
  base_url: http://127.0.0.1:11434/v1
  models:
    - first-model
    - second-model
"""


class FakeClient:
    """Stands in for LLMClient; never touches the network."""

    instances: list["FakeClient"] = []

    def __init__(self, model: str, outcome: Callable[[Finding], TriageOutcome]) -> None:
        self.model = model
        self.stats = ParseStats()
        self._outcome = outcome
        self.logged = False
        FakeClient.instances.append(self)

    def triage(self, finding: Finding) -> TriageOutcome:
        self.stats.calls += 1
        return self._outcome(finding)

    def log_parse_stats(self) -> None:
        self.logged = True


@pytest.fixture
def fake_client(
    monkeypatch: pytest.MonkeyPatch, make_outcome: Callable[..., TriageOutcome]
) -> type[FakeClient]:
    FakeClient.instances = []

    def from_config(llm_config: Mapping[str, Any], model: str) -> FakeClient:
        # Severity depends on the id so the report has something to sort.
        return FakeClient(
            model,
            lambda f: make_outcome(
                f.id, adjusted_severity=Severity.CRITICAL if f.id[0] < "8" else Severity.LOW
            ),
        )

    monkeypatch.setattr(cli.LLMClient, "from_config", staticmethod(from_config))
    return FakeClient


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(CONFIG, encoding="utf-8")
    return path


def test_one_command_writes_a_ranked_report(
    fake_client: type[FakeClient], config_path: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "out" / "report.md"  # parent directory does not exist yet
    code = cli.main([
        "--semgrep", str(FIXTURES / "semgrep_sample.json"),
        "--zap", str(FIXTURES / "zap_sample.json"),
        "--config", str(config_path),
        "--output", str(output),
    ])
    assert code == 0
    report = output.read_text(encoding="utf-8")
    assert report.startswith("# Kotri triage report")
    assert "## Ranked findings" in report
    assert "### 1. [CRITICAL]" in report
    assert str(output) in capsys.readouterr().out
    (client,) = fake_client.instances
    assert client.logged


def test_runtime_failure_exits_1_but_still_writes_the_report(
    monkeypatch: pytest.MonkeyPatch, config_path: Path, tmp_path: Path
) -> None:
    def always_down(finding: Finding) -> TriageOutcome:
        raise LLMError("connection refused")

    monkeypatch.setattr(
        cli.LLMClient, "from_config", staticmethod(lambda cfg, model: FakeClient(model, always_down))
    )
    output = tmp_path / "report.md"
    code = cli.main([
        "--zap", str(FIXTURES / "zap_sample.json"),
        "--config", str(config_path),
        "--output", str(output),
    ])
    assert code == 1
    assert "connection refused" in output.read_text(encoding="utf-8")


def test_output_that_is_a_directory_exits_2_before_triage(
    fake_client: type[FakeClient], config_path: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = cli.main([
        "--semgrep", str(FIXTURES / "semgrep_sample.json"),
        "--config", str(config_path),
        "--output", str(tmp_path),
    ])
    assert code == 2
    assert "is a directory" in capsys.readouterr().err
    (client,) = fake_client.instances
    assert client.stats.calls == 0  # no model time was spent


def test_unwritable_report_exits_2_not_a_traceback(
    fake_client: type[FakeClient],
    config_path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def deny(self: Path, *args: Any, **kwargs: Any) -> int:
        raise PermissionError("locked")

    monkeypatch.setattr(Path, "write_text", deny)
    code = cli.main([
        "--semgrep", str(FIXTURES / "semgrep_sample.json"),
        "--config", str(config_path),
        "--output", str(tmp_path / "report.md"),
    ])
    assert code == 2
    err = capsys.readouterr().err
    assert "cannot write report" in err and "locked" in err


def test_model_defaults_to_first_in_config_and_can_be_overridden(
    fake_client: type[FakeClient], config_path: Path, tmp_path: Path
) -> None:
    base = ["--semgrep", str(FIXTURES / "semgrep_sample.json"), "--config", str(config_path)]
    cli.main([*base, "--output", str(tmp_path / "a.md")])
    cli.main([*base, "--model", "second-model", "--output", str(tmp_path / "b.md")])
    assert [c.model for c in fake_client.instances] == ["first-model", "second-model"]


def test_requires_an_input(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2
    assert "--semgrep or --zap" in capsys.readouterr().err


def test_bad_config_exits_2_without_writing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "report.md"
    code = cli.main([
        "--semgrep", str(FIXTURES / "semgrep_sample.json"),
        "--config", str(tmp_path / "missing.yaml"),
        "--output", str(output),
    ])
    assert code == 2
    assert "cannot read config" in capsys.readouterr().err
    assert not output.exists()


def test_remote_base_url_in_config_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(CONFIG.replace("127.0.0.1:11434", "example.com"), encoding="utf-8")
    code = cli.main(["--zap", str(FIXTURES / "zap_sample.json"), "--config", str(config)])
    assert code == 2
    assert "not local" in capsys.readouterr().err


def test_unreadable_scan_exits_2(
    fake_client: type[FakeClient], config_path: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = cli.main([
        "--semgrep", str(tmp_path / "missing.json"),
        "--config", str(config_path),
        "--output", str(tmp_path / "report.md"),
    ])
    assert code == 2
    assert "kotri:" in capsys.readouterr().err
