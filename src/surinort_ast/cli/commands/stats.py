"""
Command: stats

Show statistics about IDS rules.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ...analysis import CoverageAnalyzer
from ...api import coverage_report_to_sarif, parse_file
from ...core.enums import Dialect
from ...exceptions import ParseError
from ..shared import console, err_console, write_output


def _resolve_output_format(output_format: str) -> str:
    fmt = output_format.lower()
    if fmt not in {"text", "sarif"}:
        err_console.print("Error: --format must be one of: text, sarif")
        raise typer.Exit(1) from None
    return fmt


def _emit_sarif_if_requested(
    rules: list[Any], fmt: str, output: Path | None, sarif_out: Path | None
) -> bool:
    if sarif_out is None and fmt != "sarif":
        return False

    report = CoverageAnalyzer().analyze(rules)
    sarif_json = coverage_report_to_sarif(report)
    if sarif_out is not None:
        sarif_out.write_text(sarif_json, encoding="utf-8")
        console.print(f"[green]SARIF report written:[/green] {sarif_out}")
    if fmt == "sarif":
        write_output(sarif_json, output)
        return True
    return False


def _build_count_table(title: str, item_name: str, counts: Counter[Any], total: int) -> Table:
    table = Table(title=title, show_header=True)
    table.add_column(item_name, style="cyan")
    table.add_column("Count", style="green", justify="right")
    table.add_column("Percentage", style="yellow", justify="right")

    for value, count in counts.most_common():
        percentage = (count / total) * 100
        table.add_row(value.value, str(count), f"{percentage:.1f}%")
    return table


def _display_stats(file: Path, dialect: Dialect, rules: list[Any]) -> None:
    action_counts = Counter(rule.action for rule in rules)
    protocol_counts = Counter(rule.header.protocol for rule in rules)
    direction_counts = Counter(rule.header.direction for rule in rules)

    console.print(
        Panel.fit(
            f"[bold cyan]Rule Statistics[/bold cyan]\n\n"
            f"File: {file}\n"
            f"Dialect: {dialect.value}\n"
            f"Total Rules: {len(rules)}",
            border_style="cyan",
        )
    )

    console.print()
    console.print(_build_count_table("Actions", "Action", action_counts, len(rules)))
    console.print()
    console.print(_build_count_table("Protocols", "Protocol", protocol_counts, len(rules)))
    console.print()
    console.print(_build_count_table("Directions", "Direction", direction_counts, len(rules)))


def stats_command(
    file: Annotated[
        Path,
        typer.Argument(help="Rule file to analyze"),
    ],
    dialect: Annotated[
        Dialect,
        typer.Option("--dialect", "-d", help="IDS rule dialect"),
    ] = Dialect.SURICATA,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: text, sarif"),
    ] = "text",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file (default: stdout)"),
    ] = None,
    sarif_out: Annotated[
        Path | None,
        typer.Option("--sarif-out", help="Write SARIF report to file"),
    ] = None,
) -> None:
    """
    Show statistics about IDS rules.

    Examples:

        surinort stats rules.txt

        surinort stats rules.txt --dialect snort3
    """
    try:
        fmt = _resolve_output_format(output_format)

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

        if _emit_sarif_if_requested(rules, fmt, output, sarif_out):
            return
        _display_stats(file, dialect, rules)

    except ParseError as e:
        err_console.print(f"Parse error: {e}")
        raise typer.Exit(1) from None
    except typer.Exit:
        raise
    except Exception as e:
        err_console.print(f"Unexpected error: {e}")
        raise typer.Exit(1) from None
