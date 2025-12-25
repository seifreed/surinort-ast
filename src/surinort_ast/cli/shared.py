"""
Shared utilities and setup for CLI commands.

Provides common helpers, console setup, and utilities used across all commands.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console

# ============================================================================
# Console Setup
# ============================================================================

console = Console()
err_console = Console(stderr=True, style="bold red")


# ============================================================================
# Helper Functions
# ============================================================================


def validate_file_path(
    path: Path,
    must_exist: bool = True,
    allowed_base: Path | None = None,
    allow_symlinks: bool = False,
) -> Path:
    """
    Validate and sanitize file path for security.

    Prevents path traversal attacks (CWE-22) by validating the resolved path
    against security constraints. This function protects against:
    - Symlink attacks
    - Path traversal via .. sequences
    - Absolute paths outside allowed directories

    Args:
        path: Path to validate
        must_exist: Whether path must exist
        allowed_base: Base directory that must contain the resolved path.
                     If None, no directory restriction is applied.
        allow_symlinks: Whether to allow symlinks (default: False for security)

    Returns:
        Resolved absolute path

    Raises:
        ValueError: If path is invalid, unsafe, or outside allowed_base

    Security Notes:
        - Always validates the RESOLVED path, not the original input
        - Error messages are sanitized to prevent path disclosure
        - Symlinks are rejected by default to prevent attacks
    """
    try:
        # Resolve to absolute path
        resolved = path.resolve(strict=must_exist)
    except (OSError, RuntimeError) as e:
        # Sanitize error message - only show filename, not full path
        raise ValueError(f"Invalid path: {path.name}") from e

    # Check if it's a symlink and reject if not allowed
    if not allow_symlinks and path.is_symlink():
        raise ValueError(f"Symlinks not allowed: {path.name}")

    # Validate against allowed base directory
    if allowed_base is not None:
        try:
            allowed_resolved = allowed_base.resolve()
        except (OSError, RuntimeError) as e:
            raise ValueError("Invalid allowed base directory") from e

        # Use is_relative_to() to check if resolved path is under allowed_base
        # This is the secure way to prevent path traversal
        if not resolved.is_relative_to(allowed_resolved):
            raise ValueError(f"Path outside allowed directory: {path.name}")

    return resolved


def read_input(file_path: Path | None) -> str:
    """Read input from file or stdin."""
    if file_path:
        if not file_path.exists():
            err_console.print(f"Error: File not found: {file_path}")
            raise typer.Exit(1) from None
        return file_path.read_text(encoding="utf-8")
    # Read from stdin
    if sys.stdin.isatty():
        err_console.print("Error: No input provided. Use a file or pipe input.")
        raise typer.Exit(1) from None
    return sys.stdin.read()


def write_output(content: str, output: Path | None) -> None:
    """Write output to file or stdout."""
    if output:
        output.write_text(content, encoding="utf-8")
        console.print(f"[green]Output written to:[/green] {output}")
    else:
        console.print(content)


def parse_rules_from_content(content: str, dialect, parser=None, transformer=None):
    """
    Parse rules from text content line by line.

    This helper extracts the common pattern of parsing rules from stdin content
    that is duplicated across parse, fmt, and to_json commands.

    Args:
        content: Text content containing rules (one per line)
        dialect: Dialect enum for the parser
        parser: Optional pre-initialized parser (will create if None)
        transformer: Optional pre-initialized transformer (will create if None)

    Returns:
        List of parsed Rule objects

    Note:
        This function silently skips malformed rules, comments, and empty lines.
    """
    from ..api._internal import _get_parser
    from ..parsing.transformer import RuleTransformer

    if parser is None:
        parser = _get_parser(dialect)
    if transformer is None:
        transformer = RuleTransformer(dialect=dialect)

    rules = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            try:
                tree = parser.parse(line)
                rule = transformer.transform(tree)
                rules.append(rule.model_copy(update={"raw_text": line}))
            except Exception:
                # Silently skip malformed rules
                pass

    return rules
