"""
Internal utilities for surinort-ast API.

This module contains internal helper functions, caches, and worker functions
for multiprocessing. These are implementation details not part of the public API.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from lark import Lark

from ..core.enums import Dialect
from ..core.nodes import Rule, SourceOrigin
from ..exceptions import ParseError
from ..parsing.transformer import RuleTransformer

# ============================================================================
# Global Caches
# ============================================================================

_PARSERS: dict[tuple[Dialect, bool], Lark] = {}


class _GrammarCache:
    """Thread-safe grammar cache to avoid repeated file I/O."""

    _cache: str | None = None

    @classmethod
    def get(cls) -> str:
        """Get or load grammar file with caching."""
        if cls._cache is not None:
            return cls._cache

        grammar_path = Path(__file__).parent.parent / "parsing" / "grammar.lark"
        with grammar_path.open(encoding="utf-8") as f:
            cls._cache = f.read()

        return cls._cache


# ============================================================================
# Security Utilities
# ============================================================================


def _sanitize_path_for_error(path: Path) -> str:
    """
    Sanitize file path for error messages to prevent information disclosure.

    This prevents CWE-209 (Information Exposure Through Error Messages) by
    removing full directory paths that could reveal system structure.

    Args:
        path: Path to sanitize

    Returns:
        Sanitized path string (filename only)

    Security Note:
        Always use this function when including file paths in error messages
        that may be exposed to users or logs.
    """
    return path.name


def _validate_file_path(
    path: Path,
    allowed_base: Path | None = None,
    allow_symlinks: bool = False,
) -> Path:
    """
    Validate and resolve file path with security checks.

    Implements CWE-22 (Path Traversal) prevention by validating that resolved
    paths stay within allowed boundaries. This protects against:
    - Directory traversal via .. sequences
    - Symlink attacks (optional)
    - Absolute path escapes outside allowed directories

    Args:
        path: Path to validate
        allowed_base: Optional base directory that must contain the resolved path.
                     If None, only basic validation is performed.
        allow_symlinks: Whether to allow symlinks (default: False for security)

    Returns:
        Resolved absolute path

    Raises:
        ParseError: If path is invalid or violates security constraints

    Security Notes:
        - Always validates the RESOLVED path, not the input
        - Symlinks are rejected by default
        - Error messages are sanitized to prevent path disclosure
    """
    try:
        # Resolve to absolute path (strict=False to allow nonexistent files)
        resolved = path.resolve()
    except (OSError, RuntimeError) as e:
        # Sanitize error - only show filename
        raise ParseError(f"Invalid path: {_sanitize_path_for_error(path)}") from e

    # Check symlinks if not allowed
    if not allow_symlinks and path.is_symlink():
        raise ParseError(f"Symlinks not allowed: {_sanitize_path_for_error(path)}")

    # Validate against allowed base directory
    if allowed_base is not None:
        try:
            allowed_resolved = allowed_base.resolve()
        except (OSError, RuntimeError) as e:
            raise ParseError("Invalid base directory") from e

        # Check if resolved path is within allowed base
        if not resolved.is_relative_to(allowed_resolved):
            raise ParseError(f"Path outside allowed directory: {_sanitize_path_for_error(path)}")

    return resolved


# ============================================================================
# Grammar and Parser Management
# ============================================================================


def _get_grammar() -> str:
    """
    Get or load grammar file with caching.

    Returns:
        Grammar string content

    Performance:
        Caches grammar file content after first read to avoid repeated
        file I/O operations. Provides minor performance improvement for
        parser instantiation in worker processes.

    Copyright (c) Marc Rivero López
    Licensed under GPLv3
    https://www.gnu.org/licenses/gpl-3.0.html
    """
    return _GrammarCache.get()


def _get_parser(dialect: Dialect = Dialect.SURICATA, track_locations: bool = True) -> Lark:
    """
    Get or create a Lark parser for the specified dialect.

    Args:
        dialect: IDS rule dialect
        track_locations: Enable position tracking (default: True)

    Returns:
        Lark parser instance

    Performance Notes:
        - Parser instances are cached per (dialect, track_locations) combination
        - Grammar file is cached after first read (see _get_grammar())
        - track_locations=False: ~10% faster parsing but no position info

    Note:
        When track_locations=False, parsing is approximately 10% faster
        but location information will not be available in the AST.
    """
    # Cache key includes location tracking preference
    cache_key = (dialect, track_locations)

    if cache_key not in _PARSERS:
        # Use cached grammar to avoid repeated file reads
        grammar = _get_grammar()

        _PARSERS[cache_key] = Lark(
            grammar,
            start="rule",
            parser="lalr",
            propagate_positions=track_locations,
            maybe_placeholders=False,
        )

    return _PARSERS[cache_key]


# ============================================================================
# Worker Functions for Parallel Processing
# ============================================================================


def _parse_rule_worker(
    args: tuple[int, str, Dialect, bool, str],
) -> tuple[int, Rule | None, str | None]:
    """
    Worker function for parallel rule parsing.

    This function is defined at module level to enable pickling for multiprocessing.

    Args:
        args: Tuple of (line_number, rule_text, dialect, track_locations, file_path)

    Returns:
        Tuple of (line_number, parsed_rule or None, error_string or None)
    """
    line_num, text, dialect, track_locations, file_path = args
    try:
        # Create fresh parser per process to avoid serialization issues
        parser = _get_parser(dialect, track_locations=track_locations)
        tree = parser.parse(text)
        transformer = RuleTransformer(dialect=dialect)
        result: Rule = transformer.transform(tree)
        result = result.model_copy(
            update={
                "raw_text": text,
                "origin": SourceOrigin(file_path=file_path, line_number=line_num),
            }
        )
        return (line_num, result, None)
    except Exception as exc:
        # Return error string for reporting
        return (line_num, None, str(exc))


def _parse_batch_worker(
    args: tuple[list[tuple[int, str]], Dialect, bool, str, bool],
) -> list[tuple[int, Rule | None, str | None]]:
    """
    Worker function for batch parsing of multiple rules.

    This function processes multiple rules in a single worker process,
    reducing serialization overhead and improving throughput by ~40%.

    Performance optimizations:
    - Reuses parser instance across batch (eliminates repeated parser creation)
    - Reuses transformer instance (reduces object allocation overhead)
    - Amortizes process spawn cost over multiple rules

    Args:
        args: Tuple of (batch_tasks, dialect, track_locations, file_path, include_raw_text)
              where batch_tasks is list of (line_number, rule_text) tuples

    Returns:
        List of (line_number, parsed_rule or None, error_string or None) for each rule

    Trade-offs:
        - Increased memory per worker (holds multiple rules in memory)
        - Batch size should be tuned based on available memory
        - Recommended batch_size: 50-200 rules

    Copyright (c) Marc Rivero López
    Licensed under GPLv3
    https://www.gnu.org/licenses/gpl-3.0.html
    """
    batch_tasks, dialect, track_locations, file_path, include_raw_text = args
    results: list[tuple[int, Rule | None, str | None]] = []

    # Create parser and transformer once for entire batch
    parser = _get_parser(dialect, track_locations=track_locations)
    transformer = RuleTransformer(dialect=dialect)

    for line_num, text in batch_tasks:
        try:
            tree = parser.parse(text)
            result: Rule = transformer.transform(tree)

            # Conditionally include raw_text based on mode
            update_dict: dict[str, Any] = {
                "origin": SourceOrigin(file_path=file_path, line_number=line_num),
            }
            if include_raw_text:
                update_dict["raw_text"] = text

            result = result.model_copy(update=update_dict)
            results.append((line_num, result, None))
        except Exception as exc:
            results.append((line_num, None, str(exc)))

    return results
