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
from typing import Annotated, Any

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn

from ...analysis.findings import Finding, FindingLevel, diagnostics_to_findings
from ...api import parse_file, print_rule, to_json, to_sarif
from ...api._internal import _get_parser
from ...core.enums import Dialect
from ...exceptions import ParseError
from ..shared import console, err_console, read_input, write_output


def _parse_stdin_rules(content: str, dialect: Dialect, verbose: bool) -> list[Any]:
    """Parse rules from stdin content."""
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
                    err_console.print(f"[yellow]Warning:[/yellow] Failed to parse: {line[:50]}...")
    return rules


def _format_output(rules: list[Any], json_output: bool, dialect: Dialect, verbose: bool) -> str:
    """Format output based on output mode."""
    if json_output:
        output_data = {
            "rules": [json.loads(to_json(rule)) for rule in rules],
            "count": len(rules),
            "dialect": dialect.value,
        }
        return json.dumps(output_data, indent=2)

    result = f"Successfully parsed {len(rules)} rule(s)\n\n"
    if verbose:
        for idx, rule in enumerate(rules, 1):
            result += f"[Rule {idx}]\n"
            result += print_rule(rule) + "\n\n"
    return result


def _build_parse_findings(rules: list[Any], file_path: str | None) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        findings.extend(
            diagnostics_to_findings(list(rule.diagnostics), default_file_path=file_path)
        )

    if not findings:
        findings.append(
            Finding(
                rule_id="SURINORT_PARSE_SUCCESS",
                level=FindingLevel.NOTE,
                message=f"Parsed {len(rules)} rule(s) successfully",
                category="parse",
                description="Parsing completed with no diagnostics.",
            )
        )
    return findings


def _resolve_output_format(output_format: str, json_output: bool) -> str:
    fmt = output_format.lower()
    if fmt not in {"text", "json", "sarif"}:
        err_console.print("Error: --format must be one of: text, json, sarif")
        raise typer.Exit(1) from None
    if json_output:
        return "json"
    return fmt


def _emit_parse_sarif(
    rules: list[Any], file: Path | None, output: Path | None, fmt: str, sarif_out: Path | None
) -> bool:
    if sarif_out is None and fmt != "sarif":
        return False

    parse_findings = _build_parse_findings(rules, str(file) if file else None)
    sarif_json = to_sarif(parse_findings)
    if sarif_out is not None:
        sarif_out.write_text(sarif_json, encoding="utf-8")
        console.print(f"[green]SARIF report written:[/green] {sarif_out}")
    if fmt == "sarif":
        write_output(sarif_json, output)
        return True
    return False


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
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: text, json, sarif"),
    ] = "text",
    sarif_out: Annotated[
        Path | None,
        typer.Option("--sarif-out", help="Write SARIF report to file"),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show detailed parsing info"),
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
        fmt = _resolve_output_format(output_format, json_output)

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
                # Parse from stdin
                rules = _parse_stdin_rules(content, dialect, verbose)

        if not rules:
            err_console.print("Error: No valid rules found")
            raise typer.Exit(1) from None

        # Optional SARIF generation
        if _emit_parse_sarif(rules, file, output, fmt, sarif_out):
            return

        # Output text/json results
        result = _format_output(rules, fmt == "json", dialect, verbose)
        write_output(result, output)

        if fmt == "text":
            console.print(f"[green]Success:[/green] Parsed {len(rules)} rule(s)")

    except ParseError as e:
        err_console.print(f"Parse error: {e}")
        raise typer.Exit(1) from None
    except Exception as e:
        err_console.print(f"Unexpected error: {e}")
        if verbose:
            err_console.print(traceback.format_exc())
        raise typer.Exit(1) from None
