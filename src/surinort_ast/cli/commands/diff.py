"""Command: diff"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from ...analysis import semantic_diff
from ...api import parse_file
from ...core.enums import Dialect
from ..shared import DialectOption, cli_error_handler, console


def diff_command(
    before: Annotated[Path, typer.Argument(help="Original rule file")],
    after: Annotated[Path, typer.Argument(help="Changed rule file")],
    dialect: DialectOption = Dialect.SURICATA,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output the semantic diff as JSON"),
    ] = False,
) -> None:
    """Compare two single-rule files semantically."""
    with cli_error_handler():
        before_rules = parse_file(before, dialect=dialect)
        after_rules = parse_file(after, dialect=dialect)
        if len(before_rules) != 1 or len(after_rules) != 1:
            raise ValueError("diff expects exactly one parsed rule in each input file")
        result = semantic_diff(before_rules[0], after_rules[0])
        if json_output:
            console.print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        else:
            console.print(result)
