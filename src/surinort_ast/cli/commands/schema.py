"""
Command: schema

Generate JSON Schema for Rule AST.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import json
from time import perf_counter

import typer

from ...api import to_json_schema
from ..shared import (
    OutputOption,
    err_console,
    log_cli_failure,
    log_cli_success,
    status_console,
    write_output,
)


def schema_command(
    output: OutputOption = None,
) -> None:
    """
    Generate JSON Schema for Rule AST.

    Examples:

        surinort schema

        surinort schema -o rule-schema.json
    """
    started_at = perf_counter()
    try:
        schema_dict = to_json_schema()
        result = json.dumps(schema_dict, indent=2)
        write_output(result, output)

        status_console.print("[green]Success:[/green] Generated JSON Schema")
        log_cli_success("cli.schema", started_at)

    except Exception as e:
        log_cli_failure("cli.schema", e, started_at=started_at)
        err_console.print(f"Error: {e}")
        raise typer.Exit(1) from None
