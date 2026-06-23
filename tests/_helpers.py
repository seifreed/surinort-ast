"""Shared test helpers usable from both unit and integration suites."""

from __future__ import annotations

import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import TypeVar

from surinort_ast.core.nodes import Option, Rule

_OptionT = TypeVar("_OptionT", bound=Option)


def first_option(rule: Rule, option_type: type[_OptionT]) -> _OptionT | None:
    """Return the first option of ``option_type`` on ``rule``, or None."""
    return next((opt for opt in rule.options if isinstance(opt, option_type)), None)


def iter_rule_lines(path: Path) -> Iterator[tuple[int, str]]:
    """Yield ``(line_number, stripped_line)`` for the meaningful lines of a rules file.

    Skips blank lines and ``#`` comments, replacing the repeated
    open-strip-skip loop across the parsing tests.
    """
    with path.open(encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                yield line_num, stripped


@contextmanager
def temp_file(content: str, suffix: str = ".rules") -> Iterator[Path]:
    """Write ``content`` verbatim to a temporary file and yield its path.

    Removes the file on exit, replacing the repeated ``NamedTemporaryFile`` +
    ``try/finally`` boilerplate across the tests.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as f:
        f.write(content)
        path = Path(f.name)
    try:
        yield path
    finally:
        path.unlink(missing_ok=True)


@contextmanager
def temp_rules_file(rules: Sequence[str]) -> Iterator[Path]:
    """Write ``rules`` (one per line) to a temporary ``.rules`` file."""
    with temp_file("".join(rule + "\n" for rule in rules)) as path:
        yield path


@contextmanager
def temp_output_path(suffix: str = ".rules") -> Iterator[Path]:
    """Yield a path to an empty temporary file for tests that write output to it."""
    with temp_file("", suffix=suffix) as path:
        yield path
