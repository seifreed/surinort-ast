"""
Command: parse

Parse IDS rules from file or stdin and display or convert to JSON.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import json
import traceback
from pathlib import Path
from typing import Annotated

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn

from ...api import parse_file, print_rule, to_json
from ...api._internal import _get_parser
from ...core.enums import Dialect
from ...exceptions import ParseError
from ..shared import console, err_console, read_input, write_output


def parse_command(
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
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Use strict resource limits for untrusted input"),
    ] = False,
    permissive: Annotated[
        bool,
        typer.Option("--permissive", help="Use permissive limits for trusted input"),
    ] = False,
    workers: Annotated[
        int,
        typer.Option("--workers", "-w", help="Parallel workers (>=1)", min=1),
    ] = 1,
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
                rules = parse_file(file, dialect=dialect, workers=workers)
            else:
                # Parse from stdin using shared helper
                from ...parsing.transformer import RuleTransformer

                parser = _get_parser(dialect)
                transformer = RuleTransformer(dialect=dialect)
                rules = []

                # Parse line by line with verbose warnings
                for raw_line in content.splitlines():
                    line = raw_line.strip()
                    if line and not line.startswith("#"):
                        try:
                            tree = parser.parse(line)
                            rule = transformer.transform(tree)
                            rules.append(rule.model_copy(update={"raw_text": line}))
                        except Exception:
                            if verbose:
                                err_console.print(
                                    f"[yellow]Warning:[/yellow] Failed to parse: {line[:50]}..."
                                )

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
