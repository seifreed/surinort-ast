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
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ...analysis import CoverageAnalyzer
from ...api import coverage_report_to_sarif, parse_file
from ...core.enums import Dialect
from ..shared import (
    cli_error_handler,
    emit_sarif_report,
    err_console,
    parsing_progress,
    render_text_output,
    resolve_output_format,
)


def _resolve_output_format(output_format: str) -> str:
    return resolve_output_format(output_format, ("text", "sarif"))


def _emit_sarif_if_requested(
    rules: list[Any], fmt: str, output: Path | None, sarif_out: Path | None
) -> bool:
    return emit_sarif_report(
        lambda: coverage_report_to_sarif(CoverageAnalyzer().analyze(rules)),
        fmt,
        output,
        sarif_out,
    )


def _build_count_table(title: str, item_name: str, counts: Counter[Any], total: int) -> Table:
    table = Table(title=title, show_header=True)
    table.add_column(item_name, style="cyan")
    table.add_column("Count", style="green", justify="right")
    table.add_column("Percentage", style="yellow", justify="right")

    for value, count in counts.most_common():
        percentage = (count / total) * 100
        table.add_row(value.value, str(count), f"{percentage:.1f}%")
    return table


def _display_stats(file: Path, dialect: Dialect, rules: list[Any], target: Console) -> None:
    action_counts = Counter(rule.action for rule in rules)
    protocol_counts = Counter(rule.header.protocol for rule in rules)
    direction_counts = Counter(rule.header.direction for rule in rules)

    target.print(
        Panel.fit(
            f"[bold cyan]Rule Statistics[/bold cyan]\n\n"
            f"File: {file}\n"
            f"Dialect: {dialect.value}\n"
            f"Total Rules: {len(rules)}",
            border_style="cyan",
        )
    )

    target.print()
    target.print(_build_count_table("Actions", "Action", action_counts, len(rules)))
    target.print()
    target.print(_build_count_table("Protocols", "Protocol", protocol_counts, len(rules)))
    target.print()
    target.print(_build_count_table("Directions", "Direction", direction_counts, len(rules)))


def _emit_stats_text(file: Path, dialect: Dialect, rules: list[Any], output: Path | None) -> None:
    """Render the statistics tables to ``output`` when given, else to the console."""
    render_text_output(lambda target: _display_stats(file, dialect, rules, target), output)


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
    with cli_error_handler():
        fmt = _resolve_output_format(output_format)

        with parsing_progress("Analyzing rules..."):
            rules = parse_file(file, dialect=dialect)

        if not rules:
            err_console.print("Error: No valid rules found")
            raise typer.Exit(1) from None

        if _emit_sarif_if_requested(rules, fmt, output, sarif_out):
            return
        _emit_stats_text(file, dialect, rules, output)
