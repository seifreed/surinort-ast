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
from rich.progress import Progress, SpinnerColumn, TextColumn

from ...api import parse_file, print_rule
from ...core.enums import Dialect
from ...exceptions import ParseError
from ..shared import console, err_console, parse_rules_from_content, read_input, write_output


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
    dialect: Annotated[
        Dialect,
        typer.Option("--dialect", "-d", help="IDS rule dialect"),
    ] = Dialect.SURICATA,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file (default: stdout)"),
    ] = None,
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
    try:
        # Read input
        if file and str(file) == "-":
            file = None

        content = read_input(file)

        # Parse and format
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Formatting rules...", total=None)

            if file:
                rules = parse_file(file, dialect=dialect)
            else:
                # Parse from stdin using shared helper
                rules = parse_rules_from_content(content, dialect)

        if not rules:
            err_console.print("Error: No valid rules found")
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

        write_output(result, output)

        if not check:
            console.print(f"[green]Success:[/green] Formatted {len(rules)} rule(s)")

    except ParseError as e:
        err_console.print(f"Parse error: {e}")
        raise typer.Exit(1) from None
    except typer.Exit:
        # Let typer.Exit exceptions pass through unchanged
        raise
    except Exception as e:
        err_console.print(f"Unexpected error: {e}")
        raise typer.Exit(1) from None
