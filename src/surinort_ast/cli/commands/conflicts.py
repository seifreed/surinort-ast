"""
Command: conflicts

Detect conflicts (duplicate SIDs, conflicting actions, shadowing, overlapping,
missing flowbits dependencies) across a set of IDS rules.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from pathlib import Path
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
    fmt = resolve_output_format(output_format, ("text", "json", "markdown"))

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

    except ParseError as e:
        err_console.print(f"Parse error: {e}")
        raise typer.Exit(1) from None
    except Exception as e:
        err_console.print(f"Unexpected error: {e}")
        raise typer.Exit(1) from None
