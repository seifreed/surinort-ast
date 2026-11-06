"""
Command-line interface for surinort-ast.

Provides commands for parsing, formatting, validating, and converting IDS rules.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from typing import Annotated, Literal

import typer

from ..observability import configure_logging
from ..version import __version__
from .commands import (
    analyze_command,
    conflicts_command,
    diff_command,
    fmt_command,
    from_json_command,
    info_command,
    list_plugins_command,
    load_command,
    optimize_command,
    parse_command,
    schema_command,
    stats_command,
    to_json_command,
    validate_command,
)
from .shared import console, read_input, validate_file_path, write_output

# Re-export helpers for backward compatibility with tests
__all__ = ["app", "read_input", "validate_file_path", "version_callback", "write_output"]

# ============================================================================
# CLI Setup
# ============================================================================

app = typer.Typer(
    name="surinort-ast",
    help="Parser and AST for Suricata/Snort IDS rules",
    no_args_is_help=True,
    add_completion=True,
)


# ============================================================================
# Global Options
# ============================================================================


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"surinort-ast version {__version__}")
        raise typer.Exit()


# ============================================================================
# Register Commands
# ============================================================================

app.command(name="parse")(parse_command)
app.command(name="fmt")(fmt_command)
app.command(name="validate")(validate_command)
app.command(name="to-json")(to_json_command)
app.command(name="from-json")(from_json_command)
app.command(name="stats")(stats_command)
app.command(name="conflicts")(conflicts_command)
app.command(name="diff")(diff_command)
app.command(name="optimize")(optimize_command)
app.command(name="schema")(schema_command)

# Plugin management subcommand group
plugins_app = typer.Typer(name="plugins", help="Manage plugins")
app.add_typer(plugins_app)

plugins_app.command(name="list")(list_plugins_command)
plugins_app.command(name="info")(info_command)
plugins_app.command(name="load")(load_command)
plugins_app.command(name="analyze")(analyze_command)


# ============================================================================
# Main Callback
# ============================================================================


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
    log_level: Annotated[
        str,
        typer.Option("--log-level", envvar="SURINORT_LOG_LEVEL", help="Logging level"),
    ] = "WARNING",
    log_format: Annotated[
        Literal["text", "json"],
        typer.Option("--log-format", envvar="SURINORT_LOG_FORMAT", help="Log output format"),
    ] = "text",
) -> None:
    """
    Surinort-AST: Parser and AST for Suricata/Snort IDS rules.

    A high-performance, type-safe parser for IDS/IPS rule languages.
    """
    _ = version
    try:
        configure_logging(level=log_level, log_format=log_format)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--log-level") from exc


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    app()
