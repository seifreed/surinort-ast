"""
Command: schema

Generate JSON Schema for Rule AST.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from ...api import to_json_schema
from ..shared import console, err_console, write_output


def schema_command(
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file (default: stdout)"),
    ] = None,
) -> None:
    """
    Generate JSON Schema for Rule AST.

    Examples:

        surinort schema

        surinort schema -o rule-schema.json
    """
    try:
        schema_dict = to_json_schema()
        result = json.dumps(schema_dict, indent=2)
        write_output(result, output)

        console.print("[green]Success:[/green] Generated JSON Schema")

    except Exception as e:
        err_console.print(f"Error: {e}")
        raise typer.Exit(1) from None
