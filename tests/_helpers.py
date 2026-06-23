"""Shared test helpers usable from both unit and integration suites."""

from __future__ import annotations

import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def temp_rules_file(rules: Sequence[str]) -> Iterator[Path]:
    """Write ``rules`` (one per line) to a temporary ``.rules`` file.

    Yields the path and removes the file on exit, replacing the repeated
    ``NamedTemporaryFile`` + ``try/finally`` boilerplate across the tests.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        f.write("".join(rule + "\n" for rule in rules))
        path = Path(f.name)
    try:
        yield path
    finally:
        path.unlink(missing_ok=True)
