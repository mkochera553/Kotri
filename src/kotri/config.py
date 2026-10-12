"""Load and validate config.yaml (copy config.example.yaml to create one)."""

from __future__ import annotations

import math
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from kotri.llm.client import validate_base_url


class ConfigError(ValueError):
    """config.yaml is missing, unreadable or doesn't have the expected shape."""


def load_config(path: Path) -> dict[str, Any]:
    """Read config.yaml and return its `llm:` section as a validated dict.

    The base URL is checked against the localhost allow-list here so a bad config
    fails before any scan is read.
    """
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from exc

    llm = data.get("llm") if isinstance(data, dict) else None
    if not isinstance(llm, dict):
        raise ConfigError(f"{path} needs an `llm:` section (see config.example.yaml)")
    _check_llm(llm, path)
    return llm


def _check_llm(llm: Mapping[str, Any], path: Path) -> None:
    base_url = llm.get("base_url")
    if not isinstance(base_url, str):
        raise ConfigError(f"{path}: llm.base_url must be a string")
    try:
        validate_base_url(base_url)
    except ValueError as exc:
        raise ConfigError(f"{path}: {exc}") from exc

    models = llm.get("models")
    if (
        not isinstance(models, list)
        or not models
        or not all(isinstance(m, str) and m for m in models)
    ):
        raise ConfigError(f"{path}: llm.models must be a non-empty list of model names")

    _check_number(llm, "timeout_seconds", path, integer=False, minimum=0, exclusive=True)
    _check_number(llm, "max_retries", path, integer=True, minimum=0)
    _check_number(llm, "max_tokens", path, integer=True, minimum=0, exclusive=True)


def _check_number(
    llm: Mapping[str, Any],
    key: str,
    path: Path,
    *,
    integer: bool,
    minimum: int,
    exclusive: bool = False,
) -> None:
    """If `key` is set it must be a number (an integer if `integer`) above/at `minimum`.

    A key that is absent uses the client's default; one that is present but null or the
    wrong type is an error, since passing it on would crash the client mid-run.
    """
    if key not in llm:
        return
    value = llm[key]
    kind = "an integer" if integer else "a number"
    is_number = isinstance(value, int) if integer else isinstance(value, (int, float))
    # bool is an int subclass, but `max_retries: true` is a typo, not a count.
    if isinstance(value, bool) or not is_number or not math.isfinite(value):
        raise ConfigError(f"{path}: llm.{key} must be {kind}, got {value!r}")
    if value < minimum or (exclusive and value == minimum):
        bound = f"greater than {minimum}" if exclusive else f"at least {minimum}"
        raise ConfigError(f"{path}: llm.{key} must be {bound}, got {value!r}")
