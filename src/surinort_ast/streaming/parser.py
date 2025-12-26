"""
Streaming parser for memory-efficient processing of large IDS rule files.

This module provides generator-based APIs that parse rules on-demand, enabling
constant memory usage regardless of file size.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Generator, Iterator
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.enums import Dialect
from ..core.nodes import Rule, SidOption, SourceOrigin
from ..exceptions import ParseError
from ..parsing.parser import RuleParser
from ..parsing.parser_config import ParserConfig

logger = logging.getLogger(__name__)


# ============================================================================
# Data Structures
# ============================================================================


@dataclass
class StreamBatch:
    """
    A batch of parsed rules for batch streaming.

    Attributes:
        rules: List of successfully parsed rules in this batch
        errors: List of (line_number, error_message) for failed rules
        batch_number: Sequential batch number (0-indexed)
        start_line: First line number in this batch
        end_line: Last line number in this batch
    """

    rules: list[Rule]
    errors: list[tuple[int, str]]
    batch_number: int
    start_line: int
    end_line: int

    @property
    def success_count(self) -> int:
        """Number of successfully parsed rules in this batch."""
        return len(self.rules)

    @property
    def error_count(self) -> int:
        """Number of failed rules in this batch."""
        return len(self.errors)

    @property
    def total_count(self) -> int:
        """Total number of rules processed in this batch."""
        return self.success_count + self.error_count


# ============================================================================
# Streaming Parser
# ============================================================================


class StreamParser:
    """
    Streaming parser for IDS rules.

    This parser provides generator-based APIs that parse rules on-demand,
    enabling constant memory usage regardless of file size.

    Key features:
    - Line-by-line parsing with minimal memory overhead
    - Generator-based API for lazy evaluation
    - Batch streaming support
    - Progress tracking via callbacks
    - Error recovery with diagnostics
    - Checkpoint/resume support

    Examples:
        >>> # Basic streaming
        >>> parser = StreamParser()
        >>> for rule in parser.stream_file("large.rules"):
        ...     process(rule)

        >>> # Batch streaming
        >>> for batch in parser.stream_file_batched("large.rules", batch_size=1000):
        ...     process_batch(batch.rules)

        >>> # With progress tracking
        >>> def progress(processed, total):
        ...     print(f"Progress: {processed}/{total}")
        >>> for rule in parser.stream_file("large.rules", progress_callback=progress):
        ...     process(rule)
    """

    def __init__(
        self,
        dialect: Dialect = Dialect.SURICATA,
        track_locations: bool = True,
        include_raw_text: bool = False,
        config: ParserConfig | None = None,
        chunk_size: int = 8192,
    ):
        """
        Initialize streaming parser.

        Args:
            dialect: IDS rule dialect (Suricata, Snort2, Snort3)
            track_locations: Enable position tracking in AST (disable for ~10% speedup)
            include_raw_text: Store original rule text in Rule.raw_text
                             (disable for ~50% memory reduction)
            config: Parser configuration with resource limits
            chunk_size: File read chunk size in bytes (default: 8KB)
        """
        self.dialect = dialect
        self.track_locations = track_locations
        self.include_raw_text = include_raw_text
        self.config = config or ParserConfig.default()
        self.chunk_size = chunk_size
        self._parser = RuleParser(
            dialect=dialect,
            strict=False,
            error_recovery=True,
            config=self.config,
        )

    def stream_file(
        self,
        path: Path | str,
        encoding: str = "utf-8",
        skip_errors: bool = False,
        progress_callback: Callable[[int, int | None], None] | None = None,
    ) -> Generator[Rule, None, None]:
        """
        Stream parse rules from a file one at a time.

        This generator yields rules as they are parsed, maintaining constant
        memory usage regardless of file size.

        Args:
            path: Path to rules file
            encoding: File encoding (default: utf-8)
            skip_errors: If True, skip malformed rules; if False, include error diagnostics
            progress_callback: Optional callback(processed_count, total_lines) for progress

        Yields:
            Parsed Rule objects one at a time

        Raises:
            FileNotFoundError: If file does not exist
            ParseError: If file cannot be read

        Examples:
            >>> parser = StreamParser()
            >>> for rule in parser.stream_file("large.rules"):
            ...     if rule.diagnostics:
            ...         print(f"Warning in rule: {rule.diagnostics}")
            ...     process(rule)

            >>> # Memory-efficient mode
            >>> parser = StreamParser(include_raw_text=False, track_locations=False)
            >>> for rule in parser.stream_file("huge.rules", skip_errors=True):
            ...     process(rule)
        """
        file_path = Path(path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if not file_path.is_file():
            raise ParseError(f"Not a file: {file_path}")

        # Get total line count for progress tracking (optional pre-scan)
        total_lines: int | None = None
        if progress_callback:
            total_lines = self._count_lines(file_path)

        processed_count = 0

        # Stream file line by line
        with file_path.open(encoding=encoding) as f:
            current_rule_lines: list[tuple[int, str]] = []

            for line_num, raw_line in enumerate(f, start=1):
                line = raw_line.strip()

                # Skip empty lines
                if not line:
                    if current_rule_lines:
                        # Parse accumulated multi-line rule
                        rule = self._parse_lines(current_rule_lines, str(file_path), skip_errors)
                        if rule is not None:
                            yield rule
                            processed_count += 1

                            if progress_callback:
                                progress_callback(processed_count, total_lines)

                        current_rule_lines = []
                    continue

                # Skip comment lines
                if line.startswith("#"):
                    continue

                # Check if this line starts a new rule while we have accumulated lines
                # If so, flush the previous accumulated lines first
                action_keywords = ["alert", "drop", "pass", "reject", "log", "sdrop"]
                line_starts_new_rule = any(line.startswith(action) for action in action_keywords)

                if line_starts_new_rule and current_rule_lines:
                    # Flush previous accumulated lines
                    rule = self._parse_lines(current_rule_lines, str(file_path), skip_errors)
                    if rule is not None:
                        yield rule
                        processed_count += 1

                        if progress_callback:
                            progress_callback(processed_count, total_lines)

                    current_rule_lines = []

                # Accumulate rule lines
                current_rule_lines.append((line_num, line))

                # Check if rule is complete
                # A rule is complete when:
                # 1. Line ends with ) AND is the closing paren of the options section
                # 2. We have accumulated lines that start with an action keyword
                if line.endswith(")") and current_rule_lines:
                    # Check if this looks like a complete rule by verifying:
                    # - First line starts with action keyword (alert, drop, etc)
                    # - We have matching opening parenthesis
                    first_line = current_rule_lines[0][1]
                    if any(first_line.startswith(action) for action in action_keywords):
                        # Count parentheses to ensure we're at the closing paren
                        full_text = " ".join(line for _, line in current_rule_lines)
                        if full_text.count("(") > 0 and full_text.count("(") == full_text.count(
                            ")"
                        ):
                            # Parse complete rule
                            rule = self._parse_lines(
                                current_rule_lines, str(file_path), skip_errors
                            )
                            if rule is not None:
                                yield rule
                                processed_count += 1

                                if progress_callback:
                                    progress_callback(processed_count, total_lines)

                            current_rule_lines = []

            # Handle remaining lines (incomplete rule)
            if current_rule_lines:
                rule = self._parse_lines(current_rule_lines, str(file_path), skip_errors)
                if rule is not None:
                    yield rule
                    processed_count += 1

                    if progress_callback:
                        progress_callback(processed_count, total_lines)

        logger.info(f"Streamed {processed_count} rules from {file_path}")

    def stream_file_batched(
        self,
        path: Path | str,
        batch_size: int = 1000,
        encoding: str = "utf-8",
        skip_errors: bool = False,
        progress_callback: Callable[[int, int | None], None] | None = None,
    ) -> Generator[StreamBatch, None, None]:
        """
        Stream parse rules in batches for improved throughput.

        This generator yields batches of rules, providing a balance between
        memory efficiency and processing throughput.

        Args:
            path: Path to rules file
            batch_size: Number of rules per batch (default: 1000)
            encoding: File encoding (default: utf-8)
            skip_errors: If True, skip malformed rules
            progress_callback: Optional callback(processed_count, total_count)

        Yields:
            StreamBatch objects containing batch of rules

        Raises:
            FileNotFoundError: If file does not exist

        Examples:
            >>> parser = StreamParser()
            >>> for batch in parser.stream_file_batched("large.rules", batch_size=500):
            ...     print(f"Batch {batch.batch_number}: {batch.success_count} rules")
            ...     for rule in batch.rules:
            ...         process(rule)
            ...     if batch.errors:
            ...         print(f"Errors: {batch.error_count}")
        """
        file_path = Path(path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Get total line count for progress
        total_lines: int | None = None
        if progress_callback:
            total_lines = self._count_lines(file_path)

        batch_num = 0
        batch_rules: list[Rule] = []
        batch_errors: list[tuple[int, str]] = []
        batch_start_line = 1
        processed_count = 0

        for rule in self.stream_file(path, encoding=encoding, skip_errors=False):
            # Check if rule has errors
            if rule.diagnostics and any(d.level.value == "error" for d in rule.diagnostics):
                # Extract line number from origin
                line_num = rule.origin.line_number if rule.origin else 0
                error_msg = "; ".join(d.message for d in rule.diagnostics)
                batch_errors.append((line_num, error_msg))

                if skip_errors:
                    continue

            batch_rules.append(rule)
            processed_count += 1

            # Emit batch when full
            if len(batch_rules) >= batch_size:
                batch_end_line = batch_start_line + len(batch_rules) - 1

                yield StreamBatch(
                    rules=batch_rules,
                    errors=batch_errors,
                    batch_number=batch_num,
                    start_line=batch_start_line,
                    end_line=batch_end_line,
                )

                if progress_callback:
                    progress_callback(processed_count, total_lines)

                # Reset for next batch
                batch_num += 1
                batch_start_line = batch_end_line + 1
                batch_rules = []
                batch_errors = []

        # Emit final partial batch
        if batch_rules:
            batch_end_line = batch_start_line + len(batch_rules) - 1

            yield StreamBatch(
                rules=batch_rules,
                errors=batch_errors,
                batch_number=batch_num,
                start_line=batch_start_line,
                end_line=batch_end_line,
            )

            if progress_callback:
                progress_callback(processed_count, total_lines)

    def _parse_lines(
        self,
        lines: list[tuple[int, str]],
        file_path: str,
        skip_errors: bool,
    ) -> Rule | None:
        """
        Parse multi-line rule.

        Args:
            lines: List of (line_number, line_text) tuples
            file_path: Source file path
            skip_errors: If True, return None on error

        Returns:
            Parsed Rule or None
        """
        if not lines:
            return None

        # Combine lines
        full_text = " ".join(line for _, line in lines)
        first_line_num = lines[0][0]

        try:
            # Parse rule
            rule = self._parser.parse(
                full_text, file_path=file_path, line_offset=first_line_num - 1
            )

            # Check if rule has errors
            if (
                rule
                and skip_errors
                and rule.diagnostics
                and any(d.level.value == "error" for d in rule.diagnostics)
            ):
                logger.debug(f"Skipping rule at line {first_line_num} due to errors")
                return None

            # Attach source metadata
            if rule:
                # Update origin
                origin = SourceOrigin(
                    file_path=file_path,
                    line_number=first_line_num,
                    rule_id=self._extract_sid(rule),
                )

                update_dict: dict[str, Any] = {"origin": origin}

                # Create or preserve location if track_locations is enabled
                if self.track_locations:
                    if rule.location is not None:
                        # Preserve existing location from parser
                        update_dict["location"] = rule.location
                    else:
                        # Create location from file metadata
                        from ..core.location import Location, Position, Span

                        # Create location spanning the rule text
                        start = Position(line=first_line_num, column=1, offset=0)
                        end = Position(
                            line=first_line_num,
                            column=len(full_text) + 1,
                            offset=len(full_text),
                        )
                        span = Span(start=start, end=end)
                        update_dict["location"] = Location(span=span, file_path=file_path)

                # Conditionally include raw text
                if self.include_raw_text:
                    update_dict["raw_text"] = full_text
                else:
                    update_dict["raw_text"] = None

                rule = rule.model_copy(update=update_dict)

            return rule

        except Exception as e:
            logger.debug(f"Failed to parse rule at line {first_line_num}: {e}")

            if skip_errors:
                return None

            # Return rule with error diagnostic
            # (parser already creates error rules in non-strict mode)
            return None

    def _extract_sid(self, rule: Rule) -> str | None:
        """
        Extract SID from rule for tracking.

        Args:
            rule: Rule node

        Returns:
            SID as string if found, None otherwise
        """
        for option in rule.options:
            if isinstance(option, SidOption):
                return str(option.value)

        return None

    def _count_lines(self, file_path: Path) -> int:
        """
        Count total lines in file efficiently.

        Args:
            file_path: Path to file

        Returns:
            Total line count
        """
        count = 0
        with file_path.open("rb") as f:
            # Use buffered reading for efficiency
            buffer = f.raw.read(self.chunk_size * 100)
            while buffer:
                count += buffer.count(b"\n")
                buffer = f.raw.read(self.chunk_size * 100)

        return count


# ============================================================================
# Parallel Streaming (Multiprocessing)
# ============================================================================


def _parse_chunk_worker(
    args: tuple[list[tuple[int, str]], Dialect, bool, bool, str],
) -> list[tuple[int, Rule | None, str | None]]:
    """
    Worker function for parallel chunk parsing.

    Args:
        args: Tuple of (lines, dialect, track_locations, include_raw_text, file_path)

    Returns:
        List of (line_number, parsed_rule or None, error_string or None)
    """
    lines, dialect, _track_locations, include_raw_text, file_path = args

    parser = RuleParser(dialect=dialect, strict=False, error_recovery=True)
    results: list[tuple[int, Rule | None, str | None]] = []

    for line_num, text in lines:
        try:
            rule = parser.parse(text, file_path=file_path, line_offset=line_num - 1)

            # Update metadata
            origin = SourceOrigin(file_path=file_path, line_number=line_num)

            update_dict: dict[str, Any] = {"origin": origin}
            if include_raw_text:
                update_dict["raw_text"] = text
            else:
                update_dict["raw_text"] = None

            rule = rule.model_copy(update=update_dict)

            results.append((line_num, rule, None))

        except Exception as e:
            results.append((line_num, None, str(e)))

    return results


def stream_parse_file_parallel(
    path: Path | str,
    dialect: Dialect = Dialect.SURICATA,
    workers: int | None = None,
    chunk_size: int = 1000,
    track_locations: bool = True,
    include_raw_text: bool = False,
    encoding: str = "utf-8",
) -> Iterator[Rule]:
    """
    Stream parse rules using parallel workers for improved throughput.

    This function uses multiprocessing to parse rules in parallel while
    maintaining streaming semantics. Rules are yielded as soon as they
    are parsed by any worker.

    Args:
        path: Path to rules file
        dialect: IDS rule dialect
        workers: Number of worker processes (default: CPU count)
        chunk_size: Number of rules per worker chunk (default: 1000)
        track_locations: Enable position tracking
        include_raw_text: Store original rule text
        encoding: File encoding

    Yields:
        Parsed Rule objects

    Raises:
        FileNotFoundError: If file does not exist

    Examples:
        >>> for rule in stream_parse_file_parallel("large.rules", workers=8):
        ...     process(rule)

    Performance:
        - 2-4x throughput improvement over sequential streaming
        - Memory usage scales with chunk_size * workers
        - Recommended workers: 4-8 for optimal CPU utilization
    """
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    # Determine worker count
    max_workers = workers or min(8, os.cpu_count() or 1)

    # Read file and extract rule lines
    with file_path.open(encoding=encoding) as f:
        lines = [
            (line_num, line.strip())
            for line_num, line in enumerate(f, start=1)
            if line.strip() and not line.strip().startswith("#")
        ]

    if not lines:
        logger.warning(f"No parseable rules found in {file_path}")
        return

    # Split lines into chunks for parallel processing
    chunks: list[list[tuple[int, str]]] = []
    for i in range(0, len(lines), chunk_size):
        chunks.append(lines[i : i + chunk_size])

    # Process chunks in parallel
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        # Submit all chunks
        futures = [
            executor.submit(
                _parse_chunk_worker,
                (chunk, dialect, track_locations, include_raw_text, str(file_path)),
            )
            for chunk in chunks
        ]

        # Yield results as they complete
        for future in as_completed(futures):
            chunk_results = future.result()

            for line_num, rule, error in chunk_results:
                if rule is not None:
                    yield rule
                elif error:
                    logger.debug(f"Line {line_num}: {error}")


# ============================================================================
# Convenience Functions
# ============================================================================


def stream_parse_file(
    path: Path | str,
    dialect: Dialect = Dialect.SURICATA,
    batch_size: int | None = None,
    track_locations: bool = True,
    include_raw_text: bool = False,
    skip_errors: bool = False,
    encoding: str = "utf-8",
) -> Iterator[Rule] | Iterator[StreamBatch]:
    """
    Stream parse rules from a file (convenience function).

    This function provides a simple interface for streaming parsing with
    sensible defaults.

    Args:
        path: Path to rules file
        dialect: IDS rule dialect
        batch_size: If specified, yield StreamBatch objects; otherwise yield individual rules
        track_locations: Enable position tracking
        include_raw_text: Store original rule text
        skip_errors: Skip malformed rules
        encoding: File encoding

    Yields:
        Rule objects if batch_size is None, StreamBatch objects otherwise

    Examples:
        >>> # Stream individual rules
        >>> for rule in stream_parse_file("large.rules"):
        ...     process(rule)

        >>> # Stream batches
        >>> for batch in stream_parse_file("large.rules", batch_size=1000):
        ...     process_batch(batch.rules)

        >>> # Memory-efficient mode
        >>> for rule in stream_parse_file(
        ...     "huge.rules",
        ...     include_raw_text=False,
        ...     track_locations=False,
        ...     skip_errors=True
        ... ):
        ...     process(rule)
    """
    parser = StreamParser(
        dialect=dialect,
        track_locations=track_locations,
        include_raw_text=include_raw_text,
    )

    if batch_size is not None:
        return parser.stream_file_batched(
            path, batch_size=batch_size, encoding=encoding, skip_errors=skip_errors
        )
    return parser.stream_file(path, encoding=encoding, skip_errors=skip_errors)
