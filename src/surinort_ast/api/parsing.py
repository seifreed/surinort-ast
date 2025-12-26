"""
Parsing functions for surinort-ast.

This module provides functions for parsing IDS rules from text, files,
and collections with support for parallel processing.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from lark.exceptions import LarkError

from ..core.enums import Dialect
from ..core.nodes import Rule, SourceOrigin
from ..exceptions import ParseError
from ..parsing.transformer import RuleTransformer
from ._internal import (
    _get_parser,
    _parse_batch_worker,
    _sanitize_path_for_error,
    _validate_file_path,
)


def parse_rule(
    text: str,
    dialect: Dialect = Dialect.SURICATA,
    track_locations: bool = True,
    include_raw_text: bool = True,
    parser: Any | None = None,
) -> Rule:
    """
    Parse a single IDS rule from text.

    Args:
        text: Rule text to parse
        dialect: Rule dialect (Suricata, Snort2, Snort3)
        track_locations: Enable position tracking (default: True).
                         Disable for ~10% performance improvement when
                         location information is not needed.
        include_raw_text: Store original rule text in Rule.raw_text (default: True).
                         Set to False for ~50% memory reduction when raw text not needed.
        parser: Optional custom parser implementation (must implement IParser protocol).
                If None, uses default Lark-based parser. This enables dependency injection
                and parser swapping for testing or alternative implementations.

    Returns:
        Parsed Rule AST

    Raises:
        ParseError: If parsing fails

    Example:
        >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
        >>> print(rule.header.protocol)
        Protocol.TCP

        >>> # Fast parsing without location tracking
        >>> rule = parse_rule(rule_text, track_locations=False)

        >>> # Memory-efficient parsing without raw text storage
        >>> rule = parse_rule(rule_text, include_raw_text=False)

        >>> # Custom parser injection (for testing or alternative implementations)
        >>> from surinort_ast.parsing.factory import ParserFactory
        >>> custom_parser = ParserFactory.create(dialect=Dialect.SNORT3, strict=True)
        >>> rule = parse_rule(rule_text, parser=custom_parser)

        >>> # Mock parser for testing
        >>> class MockParser:
        ...     def parse(self, text: str, file_path: str | None = None, line_offset: int = 0):
        ...         # Custom implementation
        ...         return mock_rule
        ...
        >>> rule = parse_rule(rule_text, parser=MockParser())

    Performance Notes:
        - include_raw_text=False: ~50% memory reduction
        - track_locations=False: ~10% faster parsing
        - Custom parser injection enables optimization for specific use cases
    """
    # Use injected parser if provided (dependency injection pattern)
    if parser is not None:
        # Custom parser provided - use it directly
        rule: Rule = parser.parse(text.strip())

        # Apply include_raw_text preference
        if not include_raw_text and rule.raw_text is not None:
            rule = rule.model_copy(update={"raw_text": None})
        elif include_raw_text and rule.raw_text is None:
            rule = rule.model_copy(update={"raw_text": text})

        return rule

    # Default path: use built-in Lark parser
    try:
        lark_parser = _get_parser(dialect, track_locations=track_locations)
        tree = lark_parser.parse(text.strip())
        transformer = RuleTransformer(dialect=dialect)
        result: Rule = transformer.transform(tree)

        # Add raw text only if requested (memory optimization)
        update_dict: dict[str, Any] = {}
        if include_raw_text:
            update_dict["raw_text"] = text
        else:
            update_dict["raw_text"] = None

        return result.model_copy(update=update_dict)

    except LarkError as e:
        raise ParseError(f"Failed to parse rule: {e}") from e
    except Exception as e:
        raise ParseError(f"Unexpected error during parsing: {e}") from e


def parse_rules(
    texts: Sequence[str],
    dialect: Dialect = Dialect.SURICATA,
    track_locations: bool = True,
    include_raw_text: bool = True,
) -> tuple[list[Rule], list[tuple[int, str]]]:
    """
    Parse multiple rules, collecting errors.

    Args:
        texts: List of rule texts
        dialect: Rule dialect
        track_locations: Enable position tracking (default: True).
                         Disable for ~10% performance improvement when
                         location information is not needed.
        include_raw_text: Store original rule text in Rule.raw_text (default: True).
                         Set to False for ~50% memory reduction when raw text not needed.

    Returns:
        Tuple of (successful rules, errors as (index, error_message))

    Example:
        >>> rules, errors = parse_rules([
        ...     'alert tcp any any -> any 80 (msg:"Test1"; sid:1;)',
        ...     'invalid rule',
        ...     'alert tcp any any -> any 443 (msg:"Test2"; sid:2;)',
        ... ])
        >>> print(f"Parsed {len(rules)}, failed {len(errors)}")

        >>> # Fast batch parsing
        >>> rules, errors = parse_rules(rule_list, track_locations=False)

        >>> # Memory-efficient batch parsing
        >>> rules, errors = parse_rules(rule_list, include_raw_text=False)

    Performance Notes:
        - include_raw_text=False: ~50% memory reduction
        - track_locations=False: ~10% faster parsing
    """
    rules: list[Rule] = []
    errors: list[tuple[int, str]] = []

    for idx, text in enumerate(texts):
        try:
            rule = parse_rule(
                text,
                dialect=dialect,
                track_locations=track_locations,
                include_raw_text=include_raw_text,
            )
            rules.append(rule)
        except ParseError as e:
            errors.append((idx, str(e)))

    return rules, errors


def parse_file(
    path: Path | str,
    dialect: Dialect = Dialect.SURICATA,
    track_locations: bool = True,
    workers: int | None = None,
    allowed_base: Path | None = None,
    allow_symlinks: bool = False,
    batch_size: int = 100,
    include_raw_text: bool = True,
    stream: bool = False,
) -> list[Rule] | Any:
    """
    Parse all rules from a file.

    Args:
        path: Path to file containing rules
        dialect: Rule dialect
        track_locations: Enable position tracking (default: True).
                         Disable for ~10% performance improvement when
                         location information is not needed.
        workers: Number of parallel workers for parsing (default: 1).
                Parallel processing is used when workers > 1.
                When workers > 1, batch processing is automatically enabled.
        allowed_base: Optional base directory for path validation.
                     If specified, the file path must be within this directory.
                     Recommended for untrusted input to prevent path traversal.
        allow_symlinks: Whether to allow symlinks (default: False).
                       Only enable if you trust the symlink source.
        batch_size: Number of rules per batch in parallel mode (default: 100).
                   Larger batches reduce overhead but increase memory per worker.
                   Recommended range: 50-200. Ignored when workers=1.
                   Performance impact: ~40% throughput improvement vs per-rule processing.
        include_raw_text: Store original rule text in Rule.raw_text (default: True).
                         Set to False for ~50% memory reduction when raw text not needed.
                         Lightweight mode is useful for large-scale rule analysis.
        stream: Enable streaming mode for memory-efficient processing (default: False).
               Returns an iterator instead of a list. Ideal for very large files.

    Returns:
        List of parsed Rule ASTs (if stream=False), or Iterator[Rule] (if stream=True)

    Raises:
        ParseError: If file cannot be read, parsed, or violates security constraints
        FileNotFoundError: If file doesn't exist

    Example:
        >>> rules = parse_file("/etc/suricata/rules/local.rules")
        >>> print(f"Parsed {len(rules)} rules")

        >>> # Fast parsing without location tracking
        >>> rules = parse_file("rules.rules", track_locations=False)

        >>> # High-throughput parallel parsing with batching
        >>> rules = parse_file("large.rules", workers=8, batch_size=150)

        >>> # Memory-efficient lightweight mode (no raw text storage)
        >>> rules = parse_file("huge.rules", include_raw_text=False)

        >>> # Secure parsing with path validation
        >>> rules = parse_file(
        ...     user_provided_path,
        ...     allowed_base=Path("/safe/rules/directory")
        ... )

        >>> # Streaming mode for very large files
        >>> for rule in parse_file("huge.rules", stream=True):
        ...     process(rule)  # Constant memory usage

    Performance Notes:
        - Parallel batching (workers > 1): ~40% higher throughput
        - Lightweight mode (include_raw_text=False): ~50% memory reduction
        - No location tracking (track_locations=False): ~10% faster parsing
        - Combined optimizations can yield 2-3x overall performance improvement

    Security Notes:
        - Use allowed_base parameter when parsing user-provided paths
        - Symlinks are rejected by default
        - Error messages are sanitized to prevent path disclosure

    Trade-offs:
        - batch_size: Larger values increase memory but reduce overhead
        - include_raw_text=False: Saves memory but loses original rule text
        - track_locations=False: Faster but loses position information
    """
    file_path = Path(path)

    # Security: Validate file path against traversal attacks (CWE-22)
    file_path = _validate_file_path(
        file_path, allowed_base=allowed_base, allow_symlinks=allow_symlinks
    )

    # Streaming mode - return iterator for memory-efficient processing
    if stream:
        from ..streaming import stream_parse_file

        return stream_parse_file(
            file_path,
            dialect=dialect,
            track_locations=track_locations,
            include_raw_text=include_raw_text,
        )

    if not file_path.exists():
        # Sanitized error message
        raise FileNotFoundError(f"File not found: {_sanitize_path_for_error(file_path)}")

    if not file_path.is_file():
        # Sanitized error message
        raise ParseError(f"Not a file: {_sanitize_path_for_error(file_path)}")

    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except Exception as e:
        # Sanitized error message
        raise ParseError(f"Failed to read file {_sanitize_path_for_error(file_path)}: {e}") from e

    # Filter candidate lines
    tasks: list[tuple[int, str]] = []
    for line_num, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if line and not line.startswith("#"):
            tasks.append((line_num, line))

    rules: list[Rule] = []
    errors: list[str] = []

    # Decide on worker count
    max_workers = (workers or 1) if (workers or 1) > 0 else 1

    if max_workers == 1:
        # Sequential path
        for line_num, line in tasks:
            try:
                rule = parse_rule(line, dialect=dialect, track_locations=track_locations)

                # Build update dict for lightweight mode support
                update_dict: dict[str, Any] = {
                    "origin": SourceOrigin(file_path=str(file_path), line_number=line_num)
                }
                # Only include raw_text if requested (memory optimization)
                if not include_raw_text:
                    update_dict["raw_text"] = None

                rule = rule.model_copy(update=update_dict)
                rules.append(rule)
            except ParseError as e:
                # Sanitized error: use filename only in user-facing errors
                errors.append(f"Line {line_num} in {_sanitize_path_for_error(file_path)}: {e}")
    else:
        # Parallel path using processes for CPU-bound parsing
        # Use batch processing for improved throughput (~40% faster)
        pool_size = min(max_workers, max(1, os.cpu_count() or 1))

        # Validate and normalize batch_size
        batch_size = max(1, min(batch_size, 1000))  # Clamp to reasonable range

        # Split tasks into batches
        batches: list[list[tuple[int, str]]] = []
        for i in range(0, len(tasks), batch_size):
            batches.append(tasks[i : i + batch_size])

        with ProcessPoolExecutor(max_workers=pool_size) as ex:
            # Submit batches to workers
            futures = [
                ex.submit(
                    _parse_batch_worker,
                    (batch, dialect, track_locations, str(file_path), include_raw_text),
                )
                for batch in batches
            ]

            # Collect results from batches
            for fut in as_completed(futures):
                batch_results = fut.result()
                for ln, parsed_rule, err in batch_results:
                    if parsed_rule is not None:
                        rules.append(parsed_rule)
                    if err:
                        # Sanitized error: use filename only in user-facing errors
                        errors.append(f"Line {ln} in {_sanitize_path_for_error(file_path)}: {err}")

    if errors and not rules:
        # All rules failed to parse
        raise ParseError("Failed to parse any rules:\n" + "\n".join(errors[:10]))

    return rules


def parse_file_streaming(
    path: Path | str,
    dialect: Dialect = Dialect.SURICATA,
    track_locations: bool = True,
    include_raw_text: bool = False,
    batch_size: int | None = None,
    skip_errors: bool = False,
    encoding: str = "utf-8",
) -> Any:
    """
    Stream parse rules from a file for memory-efficient processing.

    This function returns an iterator that yields rules on-demand, maintaining
    constant memory usage regardless of file size. Ideal for processing very
    large rulesets (100k+ rules).

    Args:
        path: Path to file containing rules
        dialect: Rule dialect
        track_locations: Enable position tracking (disable for ~10% speedup)
        include_raw_text: Store original rule text (disable for ~50% memory reduction)
        batch_size: If specified, yield StreamBatch objects; otherwise yield individual rules
        skip_errors: Skip malformed rules instead of including error diagnostics
        encoding: File encoding (default: utf-8)

    Returns:
        Iterator[Rule] if batch_size is None, Iterator[StreamBatch] otherwise

    Examples:
        >>> # Stream individual rules
        >>> for rule in parse_file_streaming("large.rules"):
        ...     process(rule)

        >>> # Stream batches of rules
        >>> for batch in parse_file_streaming("large.rules", batch_size=1000):
        ...     process_batch(batch.rules)
        ...     print(f"Batch {batch.batch_number}: {batch.success_count} rules")

        >>> # Memory-efficient mode (minimal overhead)
        >>> for rule in parse_file_streaming(
        ...     "huge.rules",
        ...     include_raw_text=False,
        ...     track_locations=False,
        ...     skip_errors=True
        ... ):
        ...     process(rule)

    Performance:
        - Constant memory usage (~10-50MB for any file size)
        - Throughput: 10k+ rules/second
        - Memory: <100MB for 100k+ rule files
        - Ideal for files >10k rules

    See Also:
        - parse_file(): Load entire file into memory (faster for small files)
        - surinort_ast.streaming: Advanced streaming APIs with processors
    """
    from ..streaming import stream_parse_file

    return stream_parse_file(
        path,
        dialect=dialect,
        batch_size=batch_size,
        track_locations=track_locations,
        include_raw_text=include_raw_text,
        skip_errors=skip_errors,
        encoding=encoding,
    )


__all__ = [
    "parse_file",
    "parse_file_streaming",
    "parse_rule",
    "parse_rules",
]
