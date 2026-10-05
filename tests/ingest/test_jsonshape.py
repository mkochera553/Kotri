import json
import logging
from pathlib import Path
from typing import Any

import pytest

from kotri.ingest.jsonshape import dict_items, load_report


def test_load_report_returns_the_top_level_object(tmp_path: Path) -> None:
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"results": []}), encoding="utf-8")
    assert load_report(path) == {"results": []}


@pytest.mark.parametrize("payload", ["[]", '"text"', "7", "null", "true"])
def test_load_report_rejects_non_object_top_level(tmp_path: Path, payload: str) -> None:
    path = tmp_path / "r.json"
    path.write_text(payload, encoding="utf-8")

    with pytest.raises(ValueError, match="JSON object") as excinfo:
        load_report(path)
    assert str(path) in str(excinfo.value)


def test_load_report_propagates_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "r.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        load_report(path)


def test_dict_items_yields_objects_and_skips_the_rest(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="kotri.ingest.jsonshape"):
        items = list(dict_items([{"a": 1}, "x", None, [1], {"b": 2}], "things"))

    assert items == [{"a": 1}, {"b": 2}]
    assert caplog.text.count("skipping things entry") == 3


@pytest.mark.parametrize("value", [None, {}, "x", 5])
def test_dict_items_yields_nothing_for_a_non_list(value: Any, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="kotri.ingest.jsonshape"):
        assert list(dict_items(value, "things")) == []
    assert "skipping things: expected a list" in caplog.text


def test_dict_items_empty_list_is_silent(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="kotri.ingest.jsonshape"):
        assert list(dict_items([], "things")) == []
    assert not caplog.records
