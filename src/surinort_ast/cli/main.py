"""
Command-line interface for surinort-ast.

Provides commands for parsing, formatting, validating, and converting IDS rules.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import json
import sys
import traceback
from collections import Counter
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ..api import (
    from_json,
    parse_file,
    parse_rule,
    print_rule,
    to_json,
    to_json_schema,
    validate_rule,
)
from ..core.enums import DiagnosticLevel, Dialect
from ..exceptions import ParseError, SerializationError
from ..version import __version__

# ============================================================================
# CLI Setup
# ============================================================================

app = typer.Typer(
    name="surinort-ast",
    help="Parser and AST for Suricata/Snort IDS rules",
    no_args_is_help=True,
    add_completion=True,
)

console = Console()
err_console = Console(stderr=True, style="bold red")


# ============================================================================
# Global Options
# ============================================================================


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"surinort-ast version {__version__}")
        raise typer.Exit()


# ============================================================================
# Helper Functions
# ============================================================================


def read_input(file_path: Path | None) -> str:
    """Read input from file or stdin."""
    if file_path:
        if not file_path.exists():
            err_console.print(f"Error: File not found: {file_path}")
            raise typer.Exit(1) from None
        return file_path.read_text(encoding="utf-8")
    # Read from stdin
    if sys.stdin.isatty():
        err_console.print("Error: No input provided. Use a file or pipe input.")
        raise typer.Exit(1) from None
    return sys.stdin.read()


def write_output(content: str, output: Path | None) -> None:
    """Write output to file or stdout."""
    if output:
        output.write_text(content, encoding="utf-8")
        console.print(f"[green]Output written to:[/green] {output}")
    else:
        console.print(content)


# ============================================================================
# Commands
# ============================================================================


@app.command()
def parse(
    file: Annotated[
        Path | None,
        typer.Argument(
            help="Rule file to parse (or - for stdin)",
            exists=False,
        ),
    ] = None,
    dialect: Annotated[
        Dialect,
        typer.Option("--dialect", "-d", help="IDS rule dialect"),
    ] = Dialect.SURICATA,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file (default: stdout)"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output as JSON"),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show detailed parsing info"),
    ] = False,
) -> None:
    """
    Parse IDS rules from file or stdin.

    Examples:

        surinort parse rules.txt

        cat rules.txt | surinort parse -

        surinort parse rules.txt --json -o output.json
    """
    try:
        # Read input
        if file and str(file) == "-":
            file = None

        content = read_input(file)

        # Parse rules
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Parsing rules...", total=None)

            if file:
                rules = parse_file(file, dialect=dialect)
            else:
                # Parse line by line from stdin
                rules = []
                for raw_line in content.splitlines():
                    line = raw_line.strip()
                    if line and not line.startswith("#"):
                        try:
                            rules.append(parse_rule(line, dialect=dialect))
                        except ParseError:
                            if verbose:
                                err_console.print(f"[yellow]Warning:[/yellow] Failed to parse: {line[:50]}...")

        if not rules:
            err_console.print("Error: No valid rules found")
            raise typer.Exit(1) from None

        # Output results
        if json_output:
            output_data = {
                "rules": [json.loads(to_json(rule)) for rule in rules],
                "count": len(rules),
                "dialect": dialect.value,
            }
            result = json.dumps(output_data, indent=2)
        else:
            result = f"Successfully parsed {len(rules)} rule(s)\n\n"
            if verbose:
                for idx, rule in enumerate(rules, 1):
                    result += f"[Rule {idx}]\n"
                    result += print_rule(rule) + "\n\n"

        write_output(result, output)

        console.print(f"[green]Success:[/green] Parsed {len(rules)} rule(s)")

    except ParseError as e:
        err_console.print(f"Parse error: {e}")
        raise typer.Exit(1) from None
    except Exception as e:
        err_console.print(f"Unexpected error: {e}")
        if verbose:
            err_console.print(traceback.format_exc())
        raise typer.Exit(1) from None


@app.command()
def fmt(
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
                rules = []
                for raw_line in content.splitlines():
                    line = raw_line.strip()
                    if line and not line.startswith("#"):
                        rules.append(parse_rule(line, dialect=dialect))

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
            if content.strip() == result.strip():
                console.print("[green]File is already formatted[/green]")
                raise typer.Exit(0)
            err_console.print("File would be reformatted")
            raise typer.Exit(1) from None

        # In-place mode
        if in_place:
            if not file:
                err_console.print("Error: Cannot use --in-place with stdin")
                raise typer.Exit(1) from None
            output = file

        write_output(result, output)

        if not check:
            console.print(f"[green]Success:[/green] Formatted {len(rules)} rule(s)")

    except ParseError as e:
        err_console.print(f"Parse error: {e}")
        raise typer.Exit(1) from None
    except Exception as e:
        err_console.print(f"Unexpected error: {e}")
        raise typer.Exit(1) from None


@app.command()
def validate(
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

        for idx, rule in enumerate(rules, 1):
            diagnostics = validate_rule(rule)
            for diag in diagnostics:
                all_diagnostics.append((idx, diag))
                if diag.level == DiagnosticLevel.ERROR:
                    error_count += 1
                elif diag.level == DiagnosticLevel.WARNING:
                    warning_count += 1

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

        # Summary
        console.print()
        console.print(f"[cyan]Total rules:[/cyan] {len(rules)}")
        console.print(f"[red]Errors:[/red] {error_count}")
        console.print(f"[yellow]Warnings:[/yellow] {warning_count}")

        # Exit code
        if error_count > 0 or (strict and warning_count > 0):
            raise typer.Exit(1) from None
        console.print("\n[green]Validation passed[/green]")

    except ParseError as e:
        err_console.print(f"Parse error: {e}")
        raise typer.Exit(1) from None
    except Exception as e:
        err_console.print(f"Unexpected error: {e}")
        raise typer.Exit(1) from None


@app.command(name="to-json")
def to_json_cmd(
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
    try:
        # Read input
        if file and str(file) == "-":
            file = None

        content = read_input(file)

        # Parse rules
        if file:
            rules = parse_file(file, dialect=dialect)
        else:
            rules = []
            for raw_line in content.splitlines():
                line = raw_line.strip()
                if line and not line.startswith("#"):
                    rules.append(parse_rule(line, dialect=dialect))

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

        console.print(f"[green]Success:[/green] Converted {len(rules)} rule(s) to JSON")

    except ParseError as e:
        err_console.print(f"Parse error: {e}")
        raise typer.Exit(1) from None
    except Exception as e:
        err_console.print(f"Unexpected error: {e}")
        raise typer.Exit(1) from None


@app.command(name="from-json")
def from_json_cmd(
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


@app.command()
def stats(
    file: Annotated[
        Path,
        typer.Argument(help="Rule file to analyze"),
    ],
    dialect: Annotated[
        Dialect,
        typer.Option("--dialect", "-d", help="IDS rule dialect"),
    ] = Dialect.SURICATA,
) -> None:
    """
    Show statistics about IDS rules.

    Examples:

        surinort stats rules.txt

        surinort stats rules.txt --dialect snort3
    """
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Analyzing rules...", total=None)
            rules = parse_file(file, dialect=dialect)

        if not rules:
            err_console.print("Error: No valid rules found")
            raise typer.Exit(1) from None

        # Collect statistics
        action_counts = Counter(rule.action for rule in rules)
        protocol_counts = Counter(rule.header.protocol for rule in rules)
        direction_counts = Counter(rule.header.direction for rule in rules)

        # Display statistics
        console.print(Panel.fit(
            f"[bold cyan]Rule Statistics[/bold cyan]\n\n"
            f"File: {file}\n"
            f"Dialect: {dialect.value}\n"
            f"Total Rules: {len(rules)}",
            border_style="cyan"
        ))

        # Actions table
        actions_table = Table(title="Actions", show_header=True)
        actions_table.add_column("Action", style="cyan")
        actions_table.add_column("Count", style="green", justify="right")
        actions_table.add_column("Percentage", style="yellow", justify="right")

        for action, count in action_counts.most_common():
            percentage = (count / len(rules)) * 100
            actions_table.add_row(
                action.value,
                str(count),
                f"{percentage:.1f}%"
            )

        console.print()
        console.print(actions_table)

        # Protocols table
        protocols_table = Table(title="Protocols", show_header=True)
        protocols_table.add_column("Protocol", style="cyan")
        protocols_table.add_column("Count", style="green", justify="right")
        protocols_table.add_column("Percentage", style="yellow", justify="right")

        for protocol, count in protocol_counts.most_common():
            percentage = (count / len(rules)) * 100
            protocols_table.add_row(
                protocol.value,
                str(count),
                f"{percentage:.1f}%"
            )

        console.print()
        console.print(protocols_table)

        # Directions table
        directions_table = Table(title="Directions", show_header=True)
        directions_table.add_column("Direction", style="cyan")
        directions_table.add_column("Count", style="green", justify="right")
        directions_table.add_column("Percentage", style="yellow", justify="right")

        for direction, count in direction_counts.most_common():
            percentage = (count / len(rules)) * 100
            directions_table.add_row(
                direction.value,
                str(count),
                f"{percentage:.1f}%"
            )

        console.print()
        console.print(directions_table)

    except ParseError as e:
        err_console.print(f"Parse error: {e}")
        raise typer.Exit(1) from None
    except Exception as e:
        err_console.print(f"Unexpected error: {e}")
        raise typer.Exit(1) from None


@app.command()
def schema(
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


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Show version and exit",
            callback=version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """
    Surinort-AST: Parser and AST for Suricata/Snort IDS rules.

    A high-performance, type-safe parser for IDS/IPS rule languages.
    """
    pass


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    app()
