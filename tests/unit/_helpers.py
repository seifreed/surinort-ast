"""Miscellaneous shared helpers for unit tests."""

from __future__ import annotations

import json


def extract_json(text: str) -> dict[str, object]:
    """Parse the outermost ``{...}`` JSON object embedded in ``text``.

    Used by the SARIF tests to pull a JSON payload out of mixed CLI/console
    output that may contain surrounding text.
    """
    start = text.find("{")
    end = text.rfind("}")
    return json.loads(text[start : end + 1])
