"""
Command: schema

Generate JSON Schema for Rule AST.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import json

import typer

from ...api import to_json_schema
from ..shared import OutputOption, err_console, status_console, write_output


def schema_command(
    output: OutputOption = None,
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

        status_console.print("[green]Success:[/green] Generated JSON Schema")

    except Exception as e:
        err_console.print(f"Error: {e}")
        raise typer.Exit(1) from None
