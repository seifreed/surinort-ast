"""
Plugin management CLI commands.

Provides commands for listing, inspecting, and managing surinort-ast plugins.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer

from ..shared import console

if TYPE_CHECKING:
    from surinort_ast.core.nodes import Rule

# ============================================================================
# Plugin List Command
# ============================================================================


def list_plugins_command() -> None:
    """
    List all installed plugins.

    Displays all registered plugins organized by type (parsers, serializers,
    analyzers, queries) in a formatted table.

    Example:
        surinort plugins list
    """
    from surinort_ast.plugins import get_registry

    try:
        registry = get_registry()
        plugins = registry.list_plugins()

        # Display results
        console.print("\n[bold cyan]Installed Plugins[/bold cyan]\n")

        for plugin_type, plugin_names in plugins.items():
            if plugin_names:
                console.print(f"[bold green]{plugin_type.title()}:[/bold green]")
                for name in plugin_names:
                    console.print(f"  • {name}")
                console.print()
            else:
                console.print(
                    f"[bold yellow]{plugin_type.title()}:[/bold yellow] [dim]None[/dim]\n"
                )

        # Summary
        total = sum(len(names) for names in plugins.values())
        console.print(f"[bold]Total:[/bold] {total} plugins")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1) from e


# ============================================================================
# Plugin Info Command
# ============================================================================


def info_command(
    name: Annotated[str, typer.Argument(help="Plugin name")],
    plugin_type: Annotated[
        str,
        typer.Option(
            "--type",
            "-t",
            help="Plugin type (parser, serializer, analyzer, query)",
        ),
    ] = "serializer",
) -> None:
    """
    Show detailed information about a plugin.

    Displays plugin metadata, version, and capabilities.

    Example:
        surinort plugins info yaml --type serializer
    """
    from surinort_ast.plugins import get_registry

    try:
        from surinort_ast.plugins.interfaces import (
            AnalysisPlugin,
            ParserPlugin,
            QueryPlugin,
            SerializerPlugin,
        )

        registry = get_registry()

        # Get plugin based on type
        plugin: ParserPlugin | SerializerPlugin | AnalysisPlugin | QueryPlugin | None
        if plugin_type == "parser":
            plugin = registry.get_parser(name)
        elif plugin_type == "serializer":
            plugin = registry.get_serializer(name)
        elif plugin_type == "analyzer":
            plugin = registry.get_analyzer(name)
        elif plugin_type == "query":
            plugin = registry.get_query(name)
        else:
            console.print(
                f"[bold red]Error:[/bold red] Invalid plugin type '{plugin_type}'. "
                f"Must be one of: parser, serializer, analyzer, query"
            )
            raise typer.Exit(1)

        if plugin is None:
            console.print(
                f"[bold red]Error:[/bold red] Plugin '{name}' not found in {plugin_type}s"
            )
            raise typer.Exit(1)

        # Display plugin info
        console.print(f"\n[bold cyan]Plugin: {name}[/bold cyan]\n")
        console.print(f"[bold]Type:[/bold] {plugin_type}")
        console.print(f"[bold]Class:[/bold] {type(plugin).__name__}")
        console.print(f"[bold]Module:[/bold] {type(plugin).__module__}")

        # Try to get name and version
        if hasattr(plugin, "name"):
            console.print(f"[bold]Name:[/bold] {plugin.name}")
        if hasattr(plugin, "version"):
            console.print(f"[bold]Version:[/bold] {plugin.version}")

        # Type-specific info
        if plugin_type == "serializer" and hasattr(plugin, "get_format_name"):
            console.print(f"[bold]Format:[/bold] {plugin.get_format_name()}")

        console.print()

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1) from e


# ============================================================================
# Plugin Load Command
# ============================================================================


def load_command(
    directory: Annotated[
        Path,
        typer.Argument(help="Directory containing plugin files"),
    ],
    pattern: Annotated[
        str,
        typer.Option(
            "--pattern",
            "-p",
            help="File pattern to match",
        ),
    ] = "*_plugin.py",
) -> None:
    """
    Load plugins from a directory.

    Scans the specified directory for plugin files and loads them into
    the plugin registry.

    Example:
        surinort plugins load ./local_plugins
        surinort plugins load ./plugins --pattern "*.py"
    """
    from surinort_ast.plugins import PluginLoader

    try:
        if not directory.exists():
            console.print(f"[bold red]Error:[/bold red] Directory not found: {directory}")
            raise typer.Exit(1)

        if not directory.is_dir():
            console.print(f"[bold red]Error:[/bold red] Not a directory: {directory}")
            raise typer.Exit(1)

        console.print(f"[bold cyan]Loading plugins from:[/bold cyan] {directory}")
        console.print(f"[bold cyan]Pattern:[/bold cyan] {pattern}\n")

        loader = PluginLoader(auto_load=False)
        count = loader.load_directory(directory, pattern=pattern)

        # Display results
        console.print(f"\n[bold green]Loaded {count} plugins successfully[/bold green]")

        # Show loaded plugins
        loaded = loader.get_loaded_plugins()
        if loaded:
            console.print("\n[bold]Loaded plugins:[/bold]")
            for plugin_name in sorted(loaded):
                console.print(f"  ✓ {plugin_name}")

        # Show failures
        failed = loader.get_failed_plugins()
        if failed:
            console.print("\n[bold red]Failed plugins:[/bold red]")
            for plugin_name, error in failed.items():
                console.print(f"  ✗ {plugin_name}: {error}")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1) from e


# ============================================================================
# Plugin Analyze Command
# ============================================================================


def analyze_command(
    input_file: Annotated[
        Path,
        typer.Argument(help="Input rule file to analyze"),
    ],
    analyzer: Annotated[
        str,
        typer.Option(
            "--analyzer",
            "-a",
            help="Analyzer plugin to use",
        ),
    ] = "security_auditor",
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Output file for analysis results (JSON format)",
        ),
    ] = None,
) -> None:
    """
    Analyze rules using an analyzer plugin.

    Runs the specified analyzer plugin on rules and displays results.

    Example:
        surinort plugins analyze rules.rules --analyzer security_auditor
        surinort plugins analyze rules.rules -a security_auditor -o results.json
    """
    import json

    from surinort_ast.parsing import parse_rules_file
    from surinort_ast.plugins import get_registry

    try:
        if not input_file.exists():
            console.print(f"[bold red]Error:[/bold red] File not found: {input_file}")
            raise typer.Exit(1)

        # Get analyzer plugin
        registry = get_registry()
        analyzer_plugin = registry.get_analyzer(analyzer)

        if analyzer_plugin is None:
            console.print(f"[bold red]Error:[/bold red] Analyzer '{analyzer}' not found")
            console.print("\nAvailable analyzers:")
            for name in registry.list_analyzers():
                console.print(f"  • {name}")
            raise typer.Exit(1)

        # Parse rules
        console.print(f"[bold cyan]Parsing rules from:[/bold cyan] {input_file}")
        rules = parse_rules_file(input_file)
        console.print(f"[bold green]Parsed {len(rules)} rules[/bold green]\n")

        # Analyze each rule
        console.print(f"[bold cyan]Analyzing with:[/bold cyan] {analyzer}\n")
        all_results = []

        for i, rule in enumerate(rules, 1):
            results = analyzer_plugin.analyze(rule)
            all_results.append(
                {
                    "rule_index": i,
                    "sid": _extract_sid(rule),
                    "results": results,
                }
            )

            # Display summary
            score = results.get("score", "N/A")
            issues = results.get("issues", [])
            console.print(f"Rule {i} (SID: {_extract_sid(rule)}): Score {score}")
            if issues:
                for issue in issues:
                    severity = issue.get("severity", "unknown")
                    message = issue.get("message", "")
                    console.print(f"  [{severity}] {message}")

        # Output results
        if output:
            with Path(output).open("w") as f:
                json.dump(all_results, f, indent=2)
            console.print(f"\n[bold green]Results saved to:[/bold green] {output}")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1) from e


def _extract_sid(rule: Rule) -> str | None:
    """Extract SID from rule options."""
    from surinort_ast.core.nodes import SidOption

    for opt in rule.options:
        if isinstance(opt, SidOption):
            return str(opt.value)
    return None


# ============================================================================
# Export Commands
# ============================================================================

__all__ = [
    "analyze_command",
    "info_command",
    "list_plugins_command",
    "load_command",
]

# All code in this module is released under GNU General Public License v3.0
# Copyright (c) Marc Rivero López
# For full license text, see: https://www.gnu.org/licenses/gpl-3.0.html
