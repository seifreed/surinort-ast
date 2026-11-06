"""
Command: conflicts

Detect conflicts (duplicate SIDs, conflicting actions, shadowing, overlapping,
missing flowbits dependencies) across a set of IDS rules.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from pathlib import Path
from time import perf_counter
from typing import Annotated

import typer

from ...analysis import ConflictDetectorConfig, Severity, detect_conflicts
from ...api import parse_file
from ...core.enums import Dialect
from ...exceptions import ParseError
from ..shared import (
    DialectOption,
    OutputOption,
    err_console,
    log_cli_failure,
    log_cli_success,
    parsing_progress,
    resolve_output_format,
    write_output,
)


def conflicts_command(
    file: Annotated[Path, typer.Argument(help="Rule file to analyze")],
    dialect: DialectOption = Dialect.SURICATA,
    output_format: Annotated[
        str, typer.Option("--format", help="Output format: text, json, markdown")
    ] = "text",
    min_severity: Annotated[
        Severity, typer.Option("--min-severity", help="Minimum severity to report")
    ] = Severity.INFO,
    output: OutputOption = None,
) -> None:
    """
    Detect conflicts across IDS rules.

    Examples:

        surinort conflicts rules.txt

        surinort conflicts rules.txt --min-severity high --format json
    """
    started_at = perf_counter()
    try:
        fmt = resolve_output_format(output_format, ("text", "json", "markdown"))
    except typer.Exit:
        log_cli_failure(
            "cli.conflicts", "InvalidOutputFormat", expected=True, started_at=started_at
        )
        raise

    try:
        with parsing_progress("Detecting conflicts..."):
            rules = parse_file(file, dialect=dialect)
            report = detect_conflicts(rules, ConflictDetectorConfig(min_severity=min_severity))

        if fmt == "json":
            rendered = report.to_json()
        elif fmt == "markdown":
            rendered = report.to_markdown()
        else:
            rendered = report.to_text(verbose=True)

        write_output(rendered, output)
        log_cli_success(
            "cli.conflicts",
            started_at,
            rule_count=len(rules),
            conflict_count=len(report.conflicts),
        )

    except ParseError as e:
        log_cli_failure(
            "cli.conflicts", e, expected=True, event_name="cli_parse_failed", started_at=started_at
        )
        err_console.print(f"Parse error: {e}")
        raise typer.Exit(1) from None
    except Exception as e:
        log_cli_failure("cli.conflicts", e, started_at=started_at)
        err_console.print(f"Unexpected error: {e}")
        raise typer.Exit(1) from None
