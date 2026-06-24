"""
Command: fmt

Format IDS rules with consistent style.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from ...api import print_rule
from ...core.enums import Dialect
from ..shared import (
    DialectOption,
    OutputOption,
    cli_error_handler,
    console,
    count_rule_blocks,
    err_console,
    load_rules,
    parsing_progress,
    status_console,
    write_output,
)


def _handle_check_mode(content: str, result: str) -> None:
    """Handle --check mode validation."""
    if content.strip() == result.strip():
        console.print("[green]File is already formatted[/green]")
        raise typer.Exit(0)
    err_console.print("File would be reformatted")
    raise typer.Exit(1) from None


def _handle_in_place_mode(file: Path | None, in_place: bool) -> Path | None:
    """Handle --in-place mode validation and return output path."""
    if in_place:
        if not file:
            err_console.print("Error: Cannot use --in-place with stdin")
            raise typer.Exit(1) from None
        return file
    return None


def fmt_command(
    file: Annotated[
        Path | None,
        typer.Argument(help="Rule file to format (or - for stdin)"),
    ] = None,
    dialect: DialectOption = Dialect.SURICATA,
    output: OutputOption = None,
    stable: Annotated[
        bool,
        typer.Option("--stable", "-s", help="Use stable/canonical formatting"),
    ] = False,
    check: Annotated[
        bool,
        typer.Option("--check", "-c", help="Check if file is formatted (exit 1 if not)"),
    ] = False,
    in_place: Annotated[
        bool,
        typer.Option("--in-place", "-i", help="Format file in-place"),
    ] = False,
) -> None:
    """
    Format IDS rules with consistent style.

    Examples:

        surinort fmt rules.txt

        surinort fmt rules.txt --stable -o formatted.rules

        surinort fmt rules.txt --check
    """
    with cli_error_handler():
        # --in-place rewrites the input file, so an explicit --output target is
        # contradictory. Reject the combination rather than silently ignoring
        # --output and writing back to the input file.
        if in_place and output is not None:
            err_console.print("Error: --in-place and --output are mutually exclusive")
            raise typer.Exit(1) from None

        # Read and parse input
        with parsing_progress("Formatting rules..."):
            rules, content, file = load_rules(file, dialect)

        # Refuse to format when any rule failed to parse: emitting only the
        # formatted survivors would silently drop the unparseable rules — and
        # with --in-place that permanently destroys them in the user's file.
        input_rule_count = count_rule_blocks(content)
        if len(rules) < input_rule_count:
            dropped = input_rule_count - len(rules)
            err_console.print(
                f"Error: {dropped} rule(s) could not be parsed; refusing to format "
                "to avoid dropping them. Fix the rule(s) and retry."
            )
            raise typer.Exit(1) from None

        # Format rules
        formatted_lines = []
        for rule in rules:
            formatted_lines.append(print_rule(rule, stable=stable))

        result = "\n".join(formatted_lines) + "\n"

        # Check mode
        if check:
            _handle_check_mode(content, result)

        # In-place mode
        if in_place:
            output = _handle_in_place_mode(file, in_place)

        # Reaching here means check mode was off (--check exits in
        # _handle_check_mode), so always report success.
        write_output(result, output)
        status_console.print(f"[green]Success:[/green] Formatted {len(rules)} rule(s)")
