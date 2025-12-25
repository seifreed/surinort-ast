"""
Command: from-json

Convert JSON back to IDS rules.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from ...api import from_json, print_rule
from ...exceptions import SerializationError
from ..shared import console, err_console, read_input, write_output


def from_json_command(
    file: Annotated[
        Path | None,
        typer.Argument(help="JSON file to convert (or - for stdin)"),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file (default: stdout)"),
    ] = None,
    stable: Annotated[
        bool,
        typer.Option("--stable", "-s", help="Use stable/canonical formatting"),
    ] = False,
) -> None:
    """
    Convert JSON back to IDS rules.

    Examples:

        surinort from-json rules.json -o rules.txt

        cat rules.json | surinort from-json -
    """
    try:
        # Read input
        if file and str(file) == "-":
            file = None

        content = read_input(file)

        # Parse JSON
        data = json.loads(content)

        # Handle both single rule and multi-rule format
        if isinstance(data, dict) and "rules" in data:
            rules_data = data["rules"]
        elif isinstance(data, list):
            rules_data = data
        else:
            rules_data = [data]

        # Convert from JSON
        rules = []
        for rule_data in rules_data:
            rules.append(from_json(rule_data))

        if not rules:
            err_console.print("Error: No valid rules found in JSON")
            raise typer.Exit(1) from None

        # Format rules
        formatted_lines = []
        for rule in rules:
            formatted_lines.append(print_rule(rule, stable=stable))

        result = "\n".join(formatted_lines) + "\n"
        write_output(result, output)

        console.print(f"[green]Success:[/green] Converted {len(rules)} rule(s) from JSON")

    except json.JSONDecodeError as e:
        err_console.print(f"JSON decode error: {e}")
        raise typer.Exit(1) from None
    except SerializationError as e:
        err_console.print(f"Serialization error: {e}")
        raise typer.Exit(1) from None
    except Exception as e:
        err_console.print(f"Unexpected error: {e}")
        raise typer.Exit(1) from None
