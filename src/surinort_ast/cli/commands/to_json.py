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

from ...api import parse_file, to_json
from ...core.enums import Dialect
from ..shared import (
    cli_error_handler,
    err_console,
    parse_rules_from_content,
    read_input,
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
        # Read input
        if file and str(file) == "-":
            file = None

        content = read_input(file)

        # Parse rules
        if file:
            rules = parse_file(file, dialect=dialect)
        else:
            # Parse from stdin using shared helper
            rules = parse_rules_from_content(content, dialect)

        if not rules:
            err_console.print("Error: No valid rules found")
            raise typer.Exit(1) from None

        # Convert to JSON
        output_data = {
            "rules": [json.loads(to_json(rule, indent=None if compact else 2)) for rule in rules],
            "count": len(rules),
            "dialect": dialect.value,
        }

        result = json.dumps(output_data, indent=None if compact else 2)
        write_output(result, output)

        status_console.print(f"[green]Success:[/green] Converted {len(rules)} rule(s) to JSON")
