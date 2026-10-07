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


@pytest.mark.parametrize("models", ["[]", "a", "[1]", "['']"])
def test_models_must_be_nonempty_list_of_names(tmp_path: Path, models: str) -> None:
    text = f"llm:\n  base_url: http://localhost:11434/v1\n  models: {models}\n"
    with pytest.raises(ConfigError, match="models"):
        load_config(_write(tmp_path, text))
