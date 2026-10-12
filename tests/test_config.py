from pathlib import Path

import pytest

from kotri.config import ConfigError, load_config

VALID = """\
llm:
  base_url: http://127.0.0.1:11434/v1
  timeout_seconds: 30
  models:
    - llama3.1:8b
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_llm_section(tmp_path: Path) -> None:
    llm = load_config(_write(tmp_path, VALID))
    assert llm["models"] == ["llama3.1:8b"]
    assert llm["timeout_seconds"] == 30


def test_example_config_is_valid() -> None:
    example = Path(__file__).parents[1] / "config.example.yaml"
    assert load_config(example)["models"]


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "nope.yaml")


def test_invalid_yaml(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(_write(tmp_path, "llm: [unclosed"))


@pytest.mark.parametrize("text", ["", "- a\n- b\n", "other: 1\n", "llm: text\n"])
def test_missing_llm_section(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError, match="llm:"):
        load_config(_write(tmp_path, text))


def test_remote_base_url_is_rejected(tmp_path: Path) -> None:
    text = VALID.replace("127.0.0.1:11434", "api.example.com")
    with pytest.raises(ConfigError, match="not local"):
        load_config(_write(tmp_path, text))


def test_base_url_must_be_a_string(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="base_url"):
        load_config(_write(tmp_path, "llm:\n  models: [a]\n"))


def _with(extra: str) -> str:
    return f"llm:\n  base_url: http://localhost:11434/v1\n  models: [a]\n  {extra}\n"


@pytest.mark.parametrize(
    "extra",
    [
        "timeout_seconds: 0.5",
        "timeout_seconds: 120",
        "max_retries: 0",
        "max_retries: 5",
        "max_tokens: 1024",
        "timeout_seconds: 30\n  max_retries: 2\n  max_tokens: 512",
    ],
)
def test_valid_numeric_settings_are_accepted(tmp_path: Path, extra: str) -> None:
    assert load_config(_write(tmp_path, _with(extra)))["models"] == ["a"]


@pytest.mark.parametrize(
    ("extra", "key"),
    [
        ("timeout_seconds: '120'", "timeout_seconds"),
        ("timeout_seconds:", "timeout_seconds"),  # null
        ("timeout_seconds: 0", "timeout_seconds"),
        ("timeout_seconds: -5", "timeout_seconds"),
        ("timeout_seconds: .nan", "timeout_seconds"),
        ("timeout_seconds: .inf", "timeout_seconds"),
        ("timeout_seconds: true", "timeout_seconds"),
        ("max_retries: -1", "max_retries"),
        ("max_retries: 1.5", "max_retries"),
        ("max_retries: '2'", "max_retries"),
        ("max_retries: false", "max_retries"),
        ("max_tokens:", "max_tokens"),  # null
        ("max_tokens: 0", "max_tokens"),
        ("max_tokens: 10.5", "max_tokens"),
        ("max_tokens: lots", "max_tokens"),
    ],
)
def test_bad_numeric_settings_are_rejected(tmp_path: Path, extra: str, key: str) -> None:
    with pytest.raises(ConfigError, match=f"llm.{key}"):
        load_config(_write(tmp_path, _with(extra)))


@pytest.mark.parametrize("models", ["[]", "a", "[1]", "['']"])
def test_models_must_be_nonempty_list_of_names(tmp_path: Path, models: str) -> None:
    text = f"llm:\n  base_url: http://localhost:11434/v1\n  models: {models}\n"
    with pytest.raises(ConfigError, match="models"):
        load_config(_write(tmp_path, text))
