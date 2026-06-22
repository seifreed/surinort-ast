"""
Shared utilities and setup for CLI commands.

Provides common helpers, console setup, and utilities used across all commands.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import logging
import sys
import traceback
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

import typer
from lark.exceptions import LarkError
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..core.enums import Dialect
from ..core.nodes import Rule
from ..exceptions import ParseError

# ============================================================================
# Console Setup
# ============================================================================

logger = logging.getLogger(__name__)
console = Console()
err_console = Console(stderr=True, style="bold red")
# Status/progress messages go to stderr so stdout stays clean for piped output.
status_console = Console(stderr=True)


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


@contextmanager
def cli_error_handler(verbose: bool = False) -> Iterator[None]:
    """Translate command failures into a clean CLI exit (code 1).

    Wraps a command body so error reporting and exit codes stay consistent
    across commands: a :class:`ParseError` reports a parse error, any other
    exception reports an unexpected error (with a traceback when ``verbose``),
    and a ``typer.Exit`` raised inside the body propagates unchanged so commands
    can still set their own exit codes.
    """
    try:
        yield
    except ParseError as e:
        err_console.print(f"Parse error: {e}")
        raise typer.Exit(1) from None
    except typer.Exit:
        raise
    except Exception as e:
        err_console.print(f"Unexpected error: {e}")
        if verbose:
            err_console.print(traceback.format_exc())
        raise typer.Exit(1) from None


@contextmanager
def parsing_progress(label: str) -> Iterator[None]:
    """Show a transient spinner labelled ``label`` while the wrapped block runs."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(label, total=None)
        yield


def resolve_output_format(value: str, allowed: Sequence[str]) -> str:
    """Lower-case and validate an ``--format`` value against the allowed set.

    Args:
        value: Raw ``--format`` option value.
        allowed: Accepted format names, in display order.

    Returns:
        The normalized (lower-cased) format.

    Raises:
        typer.Exit: With code 1 if the value is not in ``allowed``.
    """
    fmt = value.lower()
    if fmt not in allowed:
        err_console.print(f"Error: --format must be one of: {', '.join(allowed)}")
        raise typer.Exit(1) from None
    return fmt


def emit_sarif(sarif_json: str, fmt: str, output: Path | None, sarif_out: Path | None) -> bool:
    """Write and/or print a SARIF report.

    Writes ``sarif_json`` to ``sarif_out`` when given, and streams it to
    ``output``/stdout when ``fmt == "sarif"``.

    Returns:
        True if the SARIF report was emitted as the primary output
        (``fmt == "sarif"``), so the caller can skip its text rendering.
    """
    if sarif_out is not None:
        sarif_out.write_text(sarif_json, encoding="utf-8")
        console.print(f"[green]SARIF report written:[/green] {sarif_out}")
    if fmt == "sarif":
        write_output(sarif_json, output)
        return True
    return False


def emit_sarif_report(
    build: Callable[[], str],
    fmt: str,
    output: Path | None,
    sarif_out: Path | None,
) -> bool:
    """Build and emit a SARIF report only when one is requested.

    Skips building entirely when no SARIF output is wanted (no ``--sarif-out``
    and ``fmt != "sarif"``), so ``build`` runs lazily. When SARIF is requested,
    ``build`` produces the SARIF JSON and it is emitted via :func:`emit_sarif`.

    Returns:
        True if the SARIF report was emitted as the primary output, so the
        caller can skip its text rendering.
    """
    if sarif_out is None and fmt != "sarif":
        return False
    return emit_sarif(build(), fmt, output, sarif_out)


def read_input(file_path: Path | None) -> str:
    """Read input from file or stdin."""
    if file_path:
        if not file_path.exists():
            err_console.print(f"Error: File not found: {file_path}")
            raise typer.Exit(1) from None
        try:
            return file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            err_console.print(f"Error: File is not valid UTF-8 text: {file_path}")
            raise typer.Exit(1) from None
        except OSError as exc:
            detail = exc.strerror or str(exc)
            err_console.print(f"Error: Cannot read file {file_path}: {detail}")
            raise typer.Exit(1) from None
    # Read from stdin
    if sys.stdin.isatty():
        err_console.print("Error: No input provided. Use a file or pipe input.")
        raise typer.Exit(1) from None
    # Read raw bytes and decode as UTF-8 to match the file-input behavior.
    # Using ``sys.stdin.read()`` directly would rely on the system locale
    # encoding (e.g. cp1252 on Windows) and would corrupt any non-ASCII
    # rule piped in. Fall back to the text stream when no binary buffer is
    # available (e.g. an embedded or wrapped stdin replacement).
    if not hasattr(sys.stdin, "buffer"):
        text: str = sys.stdin.read()
        return text
    data = sys.stdin.buffer.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        err_console.print("Error: Stdin is not valid UTF-8 text")
        raise typer.Exit(1) from None


def write_output(content: str, output: Path | None) -> None:
    """Write output to file or stdout."""
    if output:
        output.write_text(content, encoding="utf-8")
        console.print(f"[green]Output written to:[/green] {output}")
        return

    if not content.endswith("\n"):
        sys.stdout.write(content + "\n")
    else:
        sys.stdout.write(content)


def parse_rules_from_content(
    content: str,
    dialect,
    parser=None,
    transformer=None,
    on_error: Callable[[str, LarkError], None] | None = None,
) -> list[Rule]:
    """
    Parse rules from text content line by line.

    This helper extracts the common pattern of parsing rules from stdin content
    that is shared across the parse, fmt, and to_json commands.

    Args:
        content: Text content containing rules (one per line)
        dialect: Dialect enum for the parser
        parser: Optional pre-initialized parser (will create if None)
        transformer: Optional pre-initialized transformer (will create if None)
        on_error: Optional callback invoked as ``on_error(line, exc)`` for each
            line that fails to parse. When omitted, failures are debug-logged.

    Returns:
        List of parsed Rule objects

    Note:
        This function skips malformed rules, comments, and empty lines.
    """
    from ..api._internal import _get_parser
    from ..parsing.transformer import RuleTransformer

    if parser is None:
        parser = _get_parser(dialect)
    if transformer is None:
        transformer = RuleTransformer(dialect=dialect)

    rules: list[Rule] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            try:
                tree = parser.parse(line)
                rule = transformer.transform(tree)
                rules.append(rule.model_copy(update={"raw_text": line}))
            except LarkError as exc:
                if on_error is not None:
                    on_error(line, exc)
                else:
                    logger.debug("Skipping malformed rule from stream input: %s", exc)

    return rules


def load_rules(
    file: Path | None,
    dialect: Dialect,
    *,
    workers: int = 1,
    on_error: Callable[[str, LarkError], None] | None = None,
) -> tuple[list[Rule], str, Path | None]:
    """Read input from a file or stdin and parse it into rules.

    Treats a ``-`` argument as stdin. A real file path is parsed with
    :func:`parse_file`; stdin content is parsed line by line with
    :func:`parse_rules_from_content`. Exits with code 1 when no rules parse.

    Args:
        file: Rule file path, ``Path("-")`` for stdin, or ``None`` for stdin.
        dialect: Dialect for the parser.
        workers: Parallel workers for file parsing.
        on_error: Optional per-line error callback for stdin parsing.

    Returns:
        ``(rules, content, file)`` where ``content`` is the raw input text and
        ``file`` is normalized to ``None`` for stdin input.
    """
    from ..api import parse_file

    if file is not None and str(file) == "-":
        file = None

    content = read_input(file)
    if file is not None:
        rules = parse_file(file, dialect=dialect, workers=workers)
    else:
        rules = parse_rules_from_content(content, dialect, on_error=on_error)

    if not rules:
        err_console.print("Error: No valid rules found")
        raise typer.Exit(1) from None

    return rules, content, file
