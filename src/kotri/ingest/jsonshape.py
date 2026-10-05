"""Shape checks shared by the scanner parsers.

Scanner reports are untrusted input: a field can be null, a list can hold strings, and
a truncated or wrong file can be valid JSON of the wrong type. These helpers turn those
cases into a logged skip, or a clear ValueError when nothing in the file is usable.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def load_report(path: Path) -> dict[str, Any]:
    """Read a JSON report whose top level must be an object, else raise ValueError."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(
            f"{path}: expected a JSON object at the top level, got {type(data).__name__}"
        )
    return data


def dict_items(value: Any, what: str) -> Iterator[dict[str, Any]]:
    """Yield the object elements of a JSON list, logging and skipping anything else.

    `what` names the field in log messages. A value that isn't a list yields nothing.
    """
    if not isinstance(value, list):
        logger.warning("skipping %s: expected a list, got %s", what, type(value).__name__)
        return
    for item in value:
        if isinstance(item, dict):
            yield item
        else:
            logger.warning("skipping %s entry: expected an object, got %s", what, type(item).__name__)
