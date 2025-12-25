"""
Command: stats

Show statistics about IDS rules.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Annotated

import typer
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ...api import parse_file
from ...core.enums import Dialect
from ...exceptions import ParseError
from ..shared import console, err_console


def stats_command(
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
        console.print(
            Panel.fit(
                f"[bold cyan]Rule Statistics[/bold cyan]\n\n"
                f"File: {file}\n"
                f"Dialect: {dialect.value}\n"
                f"Total Rules: {len(rules)}",
                border_style="cyan",
            )
        )

        # Actions table
        actions_table = Table(title="Actions", show_header=True)
        actions_table.add_column("Action", style="cyan")
        actions_table.add_column("Count", style="green", justify="right")
        actions_table.add_column("Percentage", style="yellow", justify="right")

        for action, count in action_counts.most_common():
            percentage = (count / len(rules)) * 100
            actions_table.add_row(action.value, str(count), f"{percentage:.1f}%")

        console.print()
        console.print(actions_table)

        # Protocols table
        protocols_table = Table(title="Protocols", show_header=True)
        protocols_table.add_column("Protocol", style="cyan")
        protocols_table.add_column("Count", style="green", justify="right")
        protocols_table.add_column("Percentage", style="yellow", justify="right")

        for protocol, count in protocol_counts.most_common():
            percentage = (count / len(rules)) * 100
            protocols_table.add_row(protocol.value, str(count), f"{percentage:.1f}%")

        console.print()
        console.print(protocols_table)

        # Directions table
        directions_table = Table(title="Directions", show_header=True)
        directions_table.add_column("Direction", style="cyan")
        directions_table.add_column("Count", style="green", justify="right")
        directions_table.add_column("Percentage", style="yellow", justify="right")

        for direction, count in direction_counts.most_common():
            percentage = (count / len(rules)) * 100
            directions_table.add_row(direction.value, str(count), f"{percentage:.1f}%")

        console.print()
        console.print(directions_table)

    except ParseError as e:
        err_console.print(f"Parse error: {e}")
        raise typer.Exit(1) from None
    except Exception as e:
        err_console.print(f"Unexpected error: {e}")
        raise typer.Exit(1) from None
