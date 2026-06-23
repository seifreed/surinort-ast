"""
Command: validate

Validate IDS rules and report issues.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from ...analysis.findings import Finding, FindingLevel, diagnostics_to_findings
from ...api import parse_file, to_sarif, validate_rule
from ...core.enums import DiagnosticLevel, Dialect
from ..shared import (
    DialectOption,
    OutputOption,
    SarifOutOption,
    cli_error_handler,
    console,
    emit_sarif_report,
    parsing_progress,
    render_text_output,
    resolve_output_format,
    validate_file_path,
)


def _check_lua_scripts(rules: list[Any], lua_dir: Path | None) -> list[tuple[int, str]]:
    """Check Lua script paths exist if lua_dir is provided."""
    lua_warnings: list[tuple[int, str]] = []

    if not lua_dir:
        return lua_warnings

    from surinort_ast.core.nodes import LuajitOption, LuaOption

    for idx, rule in enumerate(rules, 1):
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

    return lua_warnings


def _collect_diagnostics(rules: list[Any]) -> tuple[list[tuple[int, Any]], int, int]:
    """Collect validation diagnostics from all rules."""
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

    return all_diagnostics, error_count, warning_count


def _display_diagnostics(all_diagnostics: list[tuple[int, Any]], target: Console) -> None:
    """Display validation diagnostics in a table."""
    if not all_diagnostics:
        return

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

    target.print(table)


def _build_validation_findings(
    file: Path,
    all_diagnostics: list[tuple[int, Any]],
    lua_warnings: list[tuple[int, str]],
) -> list[Finding]:
    """Build the SARIF findings list for a validation run."""
    findings = diagnostics_to_findings(
        [diag for _, diag in all_diagnostics], default_file_path=str(file)
    )
    for idx, message in lua_warnings:
        findings.append(
            Finding(
                rule_id="SURINORT_LUA_SCRIPT_NOT_FOUND",
                level=FindingLevel.WARNING,
                message=f"Rule {idx}: {message}",
                category="validation",
                description=message,
            )
        )
    if not findings:
        findings.append(
            Finding(
                rule_id="SURINORT_VALIDATION_OK",
                level=FindingLevel.NOTE,
                message="Validation completed with no diagnostics",
                category="validation",
            )
        )
    return findings


def _display_validation_summary(
    rules: list[Any],
    all_diagnostics: list[tuple[int, Any]],
    lua_warnings: list[tuple[int, str]],
    error_count: int,
    warning_count: int,
    target: Console,
) -> None:
    """Display diagnostics and the rule/error/warning counts."""
    _display_diagnostics(all_diagnostics, target)
    _display_lua_warnings(lua_warnings, target)
    target.print()
    target.print(f"[cyan]Total rules:[/cyan] {len(rules)}")
    target.print(f"[red]Errors:[/red] {error_count}")
    target.print(f"[yellow]Warnings:[/yellow] {warning_count + len(lua_warnings)}")


def _emit_validation_text(
    rules: list[Any],
    all_diagnostics: list[tuple[int, Any]],
    lua_warnings: list[tuple[int, str]],
    error_count: int,
    warning_count: int,
    output: Path | None,
) -> None:
    """Render the validation summary to ``output`` when given, else to the console."""
    render_text_output(
        lambda target: _display_validation_summary(
            rules, all_diagnostics, lua_warnings, error_count, warning_count, target
        ),
        output,
    )


def _emit_validation_report(
    file: Path,
    fmt: str,
    output: Path | None,
    sarif_out: Path | None,
    rules: list[Any],
    all_diagnostics: list[tuple[int, Any]],
    lua_warnings: list[tuple[int, str]],
    error_count: int,
    warning_count: int,
) -> None:
    """Emit the validation report as text and/or SARIF."""
    emitted_as_sarif = emit_sarif_report(
        lambda: to_sarif(_build_validation_findings(file, all_diagnostics, lua_warnings)),
        fmt,
        output,
        sarif_out,
    )
    if not emitted_as_sarif:
        _emit_validation_text(
            rules, all_diagnostics, lua_warnings, error_count, warning_count, output
        )


def _display_lua_warnings(lua_warnings: list[tuple[int, str]], target: Console) -> None:
    """Display Lua script warnings in a table."""
    if not lua_warnings:
        return

    table = Table(title="Lua Script Checks")
    table.add_column("Rule", style="cyan")
    table.add_column("Message")
    for r_idx, msg in lua_warnings:
        table.add_row(str(r_idx), msg)
    target.print(table)


def validate_command(
    file: Annotated[
        Path,
        typer.Argument(help="Rule file to validate"),
    ],
    dialect: DialectOption = Dialect.SURICATA,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Treat warnings as errors"),
    ] = False,
    lua_dir: Annotated[
        Path | None,
        typer.Option("--lua-dir", help="Base directory for custom Lua scripts"),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: text, sarif"),
    ] = "text",
    output: OutputOption = None,
    sarif_out: SarifOutOption = None,
) -> None:
    """
    Validate IDS rules and report issues.

    Examples:

        surinort validate rules.txt

        surinort validate rules.txt --strict
    """
    with cli_error_handler():
        fmt = resolve_output_format(output_format, ("text", "sarif"))

        with parsing_progress("Validating rules..."):
            # Use the streaming path so syntactically invalid rules surface as
            # error rules carrying a PARSE_ERROR diagnostic. The default
            # (non-streaming) parse silently drops unparseable lines whenever at
            # least one rule parses, which would let validation pass a file that
            # contains a malformed rule.
            rules = list(parse_file(file, dialect=dialect, stream=True))

        # Validate all rules
        all_diagnostics, error_count, warning_count = _collect_diagnostics(rules)

        # Optional Lua script existence checks
        lua_warnings = _check_lua_scripts(rules, lua_dir)

        _emit_validation_report(
            file,
            fmt,
            output,
            sarif_out,
            rules,
            all_diagnostics,
            lua_warnings,
            error_count,
            warning_count,
        )

        # Exit code
        if error_count > 0 or (strict and (warning_count + len(lua_warnings)) > 0):
            raise typer.Exit(1) from None
        if fmt == "text":
            console.print("\n[green]Validation passed[/green]")
