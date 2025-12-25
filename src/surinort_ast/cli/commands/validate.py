"""
Command: validate

Validate IDS rules and report issues.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ...api import parse_file, validate_rule
from ...core.enums import DiagnosticLevel, Dialect
from ...exceptions import ParseError
from ..shared import console, err_console, validate_file_path


def validate_command(
    file: Annotated[
        Path,
        typer.Argument(help="Rule file to validate"),
    ],
    dialect: Annotated[
        Dialect,
        typer.Option("--dialect", "-d", help="IDS rule dialect"),
    ] = Dialect.SURICATA,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Treat warnings as errors"),
    ] = False,
    lua_dir: Annotated[
        Path | None,
        typer.Option("--lua-dir", help="Base directory for custom Lua scripts"),
    ] = None,
) -> None:
    """
    Validate IDS rules and report issues.

    Examples:

        surinort validate rules.txt

        surinort validate rules.txt --strict
    """
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Validating rules...", total=None)
            rules = parse_file(file, dialect=dialect)

        # Validate all rules
        all_diagnostics = []
        error_count = 0
        warning_count = 0

        # Optional Lua script existence checks
        lua_warnings: list[tuple[int, str]] = []

        for idx, rule in enumerate(rules, 1):
            diagnostics = validate_rule(rule)
            for diag in diagnostics:
                all_diagnostics.append((idx, diag))
                if diag.level == DiagnosticLevel.ERROR:
                    error_count += 1
                elif diag.level == DiagnosticLevel.WARNING:
                    warning_count += 1

            # If requested, check lua/luajit script paths exist
            if lua_dir:
                try:
                    from surinort_ast.core.nodes import LuajitOption, LuaOption

                    for opt in rule.options:
                        if isinstance(opt, (LuaOption, LuajitOption)):
                            # Securely validate Lua script path to prevent path traversal
                            try:
                                script_path = validate_file_path(
                                    lua_dir / opt.script_name,
                                    must_exist=False,
                                    allowed_base=lua_dir,
                                    allow_symlinks=True,  # Allow symlinks for Lua scripts
                                )
                                if not script_path.exists():
                                    lua_warnings.append(
                                        (
                                            idx,
                                            f"Lua script not found: {opt.script_name} (looked in {lua_dir})",
                                        )
                                    )
                            except ValueError as e:
                                # Path traversal attempt detected
                                lua_warnings.append(
                                    (
                                        idx,
                                        f"Invalid Lua script path: {opt.script_name} - {e}",
                                    )
                                )
                except Exception:
                    # Do not fail validation on optional check
                    pass

        # Display results
        if all_diagnostics:
            table = Table(title="Validation Diagnostics")
            table.add_column("Rule", style="cyan")
            table.add_column("Level", style="magenta")
            table.add_column("Code", style="yellow")
            table.add_column("Message")

            for rule_idx, diag in all_diagnostics:
                level_color = {
                    DiagnosticLevel.ERROR: "red",
                    DiagnosticLevel.WARNING: "yellow",
                    DiagnosticLevel.INFO: "blue",
                }.get(diag.level, "white")

                table.add_row(
                    str(rule_idx),
                    f"[{level_color}]{diag.level.value.upper()}[/{level_color}]",
                    diag.code or "-",
                    diag.message,
                )

            console.print(table)

        # Add Lua warnings to output table if any
        if lua_warnings:
            table = Table(title="Lua Script Checks")
            table.add_column("Rule", style="cyan")
            table.add_column("Message")
            for r_idx, msg in lua_warnings:
                table.add_row(str(r_idx), msg)
            console.print(table)

        # Summary
        console.print()
        console.print(f"[cyan]Total rules:[/cyan] {len(rules)}")
        console.print(f"[red]Errors:[/red] {error_count}")
        console.print(f"[yellow]Warnings:[/yellow] {warning_count + len(lua_warnings)}")

        # Exit code
        if error_count > 0 or (strict and (warning_count + len(lua_warnings)) > 0):
            raise typer.Exit(1) from None
        console.print("\n[green]Validation passed[/green]")

    except ParseError as e:
        err_console.print(f"Parse error: {e}")
        raise typer.Exit(1) from None
    except Exception as e:
        err_console.print(f"Unexpected error: {e}")
        raise typer.Exit(1) from None
