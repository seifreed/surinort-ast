"""
Command: to-json

Convert IDS rules to JSON format.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from ...api import to_json
from ...core.enums import Dialect
from ..shared import (
    cli_error_handler,
    load_rules,
    status_console,
    write_output,
)


def to_json_command(
    file: Annotated[
        Path | None,
        typer.Argument(help="Rule file to convert (or - for stdin)"),
    ] = None,
    dialect: Annotated[
        Dialect,
        typer.Option("--dialect", "-d", help="IDS rule dialect"),
    ] = Dialect.SURICATA,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file (default: stdout)"),
    ] = None,
    compact: Annotated[
        bool,
        typer.Option("--compact", "-c", help="Compact JSON output"),
    ] = False,
) -> None:
    """
    Convert IDS rules to JSON format.

    Examples:

        surinort to-json rules.txt -o rules.json

        cat rules.txt | surinort to-json - --compact
    """
    with cli_error_handler():
        rules, _, _ = load_rules(file, dialect)

        # Convert to JSON
        output_data = {
            "rules": [json.loads(to_json(rule, indent=None if compact else 2)) for rule in rules],
            "count": len(rules),
            "dialect": dialect.value,
        }

        result = json.dumps(output_data, indent=None if compact else 2)
        write_output(result, output)

        status_console.print(f"[green]Success:[/green] Converted {len(rules)} rule(s) to JSON")
