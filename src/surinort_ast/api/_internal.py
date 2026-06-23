"""
Internal utilities for surinort-ast API.

This module contains internal helper functions, caches, and worker functions
for multiprocessing. These are implementation details not part of the public API.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from lark import Lark

from ..core.enums import Dialect
from ..core.nodes import Rule, SourceOrigin
from ..core.path_security import PathSecurityError, validate_path
from ..exceptions import ParseError
from ..parsing.helpers import normalize_rule_text
from ..parsing.transformer import RuleTransformer

# ============================================================================
# Global Caches
# ============================================================================

_PARSERS: dict[tuple[Dialect, bool], Lark] = {}

# Backwards-compatible grammar cache handle for tests that clear `_GRAMMAR_CACHE`
# directly. `_GrammarCache` uses the same underlying storage.
_GRAMMAR_CACHE: str | None = None


class _GrammarCache:
    """Thread-safe grammar cache to avoid repeated file I/O."""

    _cache: str | None = None

    @classmethod
    def get(cls) -> str:
        """Get or load grammar file with caching."""
        module = sys.modules[__name__]
        grammar_cache = getattr(module, "_GRAMMAR_CACHE", None)

        # Sync with module-level cache for test overrides
        if grammar_cache is None and cls._cache is not None:
            # Explicit reset requested
            cls._cache = None

        if grammar_cache is not None and cls._cache != grammar_cache:
            cls._cache = grammar_cache

        if cls._cache is not None:
            return cls._cache

        grammar_path = Path(__file__).parent.parent / "parsing" / "grammar.lark"
        with grammar_path.open(encoding="utf-8") as f:
            cls._cache = f.read()
            module.__dict__["_GRAMMAR_CACHE"] = cls._cache

        return cls._cache

    @classmethod
    def clear(cls) -> None:
        """Clear cached grammar (used by tests to force reload)."""
        module = sys.modules[__name__]
        cls._cache = None
        module.__dict__["_GRAMMAR_CACHE"] = None


# ============================================================================
# Security Utilities
# ============================================================================


def _validate_file_path(
    path: Path,
    allowed_base: Path | None = None,
    allow_symlinks: bool = False,
) -> Path:
    """
    Validate and resolve a file path, raising ``ParseError`` on failure.

    Thin API-layer wrapper over :func:`surinort_ast.core.path_security.validate_path`
    that translates the neutral security error into the API's ``ParseError``.
    """
    try:
        return validate_path(path, allowed_base=allowed_base, allow_symlinks=allow_symlinks)
    except PathSecurityError as e:
        raise ParseError(str(e)) from e


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
            # Normalize before parsing so the parallel path accepts the same
            # rules as the sequential path (see parse_rule) and stores the same
            # normalized raw_text for consistent round-tripping.
            normalized = normalize_rule_text(text.strip())
            tree = parser.parse(normalized)
            result: Rule = transformer.transform(tree)

            # Conditionally include raw_text based on mode
            update_dict: dict[str, Any] = {
                "origin": SourceOrigin(file_path=file_path, line_number=line_num),
            }
            if include_raw_text:
                update_dict["raw_text"] = normalized

            result = result.model_copy(update=update_dict)
            results.append((line_num, result, None))
        except Exception as exc:
            results.append((line_num, None, str(exc)))

    return results
