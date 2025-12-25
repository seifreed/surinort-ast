"""
Streaming writers for incremental serialization of rules.

This module provides context manager-based writers that serialize rules
incrementally, enabling memory-efficient output for large rulesets.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Generator, Iterable
from contextlib import contextmanager
from pathlib import Path
from typing import Any, TextIO

from ..core.nodes import Rule
from ..exceptions import SerializationError
from ..printer.formatter import FormatterOptions
from ..printer.text_printer import TextPrinter

logger = logging.getLogger(__name__)


# ============================================================================
# Base Stream Writer
# ============================================================================


class StreamWriter(ABC):
    """
    Abstract base class for streaming rule writers.

    Stream writers serialize rules incrementally to avoid loading
    entire rulesets into memory.

    Examples:
        >>> with StreamWriter.text("output.rules") as writer:
        ...     for rule in input_stream:
        ...         writer.write(rule)

        >>> with StreamWriter.json("output.json") as writer:
        ...     for rule in input_stream:
        ...         writer.write(rule)
    """

    def __init__(self, path: Path | str, encoding: str = "utf-8"):
        """
        Initialize stream writer.

        Args:
            path: Output file path
            encoding: File encoding (default: utf-8)
        """
        self.path = Path(path)
        self.encoding = encoding
        self._file: TextIO | None = None
        self._count = 0

    @abstractmethod
    def _write_header(self) -> None:
        """Write file header (called on open)."""

    @abstractmethod
    def _write_rule(self, rule: Rule) -> None:
        """Write a single rule."""

    @abstractmethod
    def _write_footer(self) -> None:
        """Write file footer (called on close)."""

    def __enter__(self) -> StreamWriter:
        """Open writer for writing."""
        self._file = self.path.open("w", encoding=self.encoding)
        self._count = 0
        self._write_header()
        logger.debug(f"Opened stream writer: {self.path}")
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Close writer and finalize output."""
        if self._file:
            self._write_footer()
            self._file.close()
            logger.info(f"Closed stream writer: {self.path} ({self._count} rules)")

    def write(self, rule: Rule) -> None:
        """
        Write a single rule.

        Args:
            rule: Rule to write

        Raises:
            SerializationError: If write fails
            RuntimeError: If writer not opened
        """
        if not self._file:
            raise RuntimeError("Writer not opened. Use 'with' context manager.")

        try:
            self._write_rule(rule)
            self._count += 1
        except Exception as e:
            raise SerializationError(f"Failed to write rule: {e}") from e

    def write_many(self, rules: Iterable[Rule]) -> int:
        """
        Write multiple rules.

        Args:
            rules: Iterable of rules to write

        Returns:
            Number of rules written
        """
        count = 0
        for rule in rules:
            self.write(rule)
            count += 1
        return count

    @property
    def count(self) -> int:
        """Number of rules written so far."""
        return self._count

    @staticmethod
    def text(
        path: Path | str,
        encoding: str = "utf-8",
        stable: bool = False,
    ) -> StreamWriterText:
        """
        Create a text stream writer.

        Args:
            path: Output file path
            encoding: File encoding
            stable: Use stable/canonical formatting

        Returns:
            StreamWriterText instance

        Examples:
            >>> with StreamWriter.text("output.rules") as writer:
            ...     for rule in input_stream:
            ...         writer.write(rule)
        """
        return StreamWriterText(path, encoding=encoding, stable=stable)

    @staticmethod
    def json(
        path: Path | str,
        encoding: str = "utf-8",
        indent: int | None = 2,
    ) -> StreamWriterJSON:
        """
        Create a JSON stream writer.

        Args:
            path: Output file path
            encoding: File encoding
            indent: JSON indentation (None for compact)

        Returns:
            StreamWriterJSON instance

        Examples:
            >>> with StreamWriter.json("output.json") as writer:
            ...     for rule in input_stream:
            ...         writer.write(rule)
        """
        return StreamWriterJSON(path, encoding=encoding, indent=indent)


# ============================================================================
# Text Stream Writer
# ============================================================================


class StreamWriterText(StreamWriter):
    """
    Streaming writer for text format rules.

    Serializes rules to text format incrementally, one rule per line.

    Examples:
        >>> # Basic usage
        >>> with StreamWriterText("output.rules") as writer:
        ...     for rule in input_stream:
        ...         writer.write(rule)

        >>> # Stable formatting
        >>> with StreamWriterText("output.rules", stable=True) as writer:
        ...     for rule in input_stream:
        ...         writer.write(rule)

        >>> # Custom header
        >>> with StreamWriterText("output.rules", header_comment="Generated rules") as writer:
        ...     for rule in input_stream:
        ...         writer.write(rule)
    """

    def __init__(
        self,
        path: Path | str,
        encoding: str = "utf-8",
        stable: bool = False,
        header_comment: str | None = None,
        footer_comment: str | None = None,
    ):
        """
        Initialize text stream writer.

        Args:
            path: Output file path
            encoding: File encoding
            stable: Use stable/canonical formatting
            header_comment: Optional header comment to write at start
            footer_comment: Optional footer comment to write at end
        """
        super().__init__(path, encoding)
        self.stable = stable
        self.header_comment = header_comment
        self.footer_comment = footer_comment
        self._printer = TextPrinter(
            options=FormatterOptions.stable() if stable else FormatterOptions.standard()
        )

    def _write_header(self) -> None:
        """Write optional header comment."""
        if self.header_comment and self._file:
            self._file.write(f"# {self.header_comment}\n")
            self._file.write("#\n")

    def _write_rule(self, rule: Rule) -> None:
        """
        Write rule as text.

        Args:
            rule: Rule to write
        """
        if not self._file:
            return

        # Print rule to text
        rule_text = self._printer.print_rule(rule)

        # Write to file
        self._file.write(rule_text)
        self._file.write("\n")

        # Flush periodically for real-time output
        if self._count % 1000 == 0:
            self._file.flush()

    def _write_footer(self) -> None:
        """Write optional footer comment."""
        if self.footer_comment and self._file:
            self._file.write("#\n")
            self._file.write(f"# {self.footer_comment}\n")


# ============================================================================
# JSON Stream Writer
# ============================================================================


class StreamWriterJSON(StreamWriter):
    """
    Streaming writer for JSON format rules.

    Serializes rules to JSON array incrementally, writing one rule at a time
    while maintaining valid JSON syntax.

    Examples:
        >>> # Basic usage
        >>> with StreamWriterJSON("output.json") as writer:
        ...     for rule in input_stream:
        ...         writer.write(rule)

        >>> # Compact JSON
        >>> with StreamWriterJSON("output.json", indent=None) as writer:
        ...     for rule in input_stream:
        ...         writer.write(rule)

        >>> # Pretty JSON
        >>> with StreamWriterJSON("output.json", indent=4) as writer:
        ...     for rule in input_stream:
        ...         writer.write(rule)
    """

    def __init__(
        self,
        path: Path | str,
        encoding: str = "utf-8",
        indent: int | None = 2,
    ):
        """
        Initialize JSON stream writer.

        Args:
            path: Output file path
            encoding: File encoding
            indent: JSON indentation (None for compact)
        """
        super().__init__(path, encoding)
        self.indent = indent
        self._first_rule = True

    def _write_header(self) -> None:
        """Write JSON array opening."""
        if self._file:
            self._file.write("[\n" if self.indent else "[")
            self._first_rule = True

    def _write_rule(self, rule: Rule) -> None:
        """
        Write rule as JSON object.

        Args:
            rule: Rule to write
        """
        if not self._file:
            return

        # Add comma separator (except for first rule)
        if not self._first_rule:
            self._file.write(",\n" if self.indent else ",")
        else:
            self._first_rule = False

        # Serialize rule to JSON
        rule_json = rule.model_dump_json(indent=self.indent, exclude_none=True)

        # Write to file
        if self.indent:
            # Indent each line
            indent_str = " " * self.indent
            indented = "\n".join(indent_str + line for line in rule_json.splitlines())
            self._file.write(indented)
        else:
            self._file.write(rule_json)

        # Flush periodically
        if self._count % 100 == 0:
            self._file.flush()

    def _write_footer(self) -> None:
        """Write JSON array closing."""
        if self._file:
            self._file.write("\n]\n" if self.indent else "]")


# ============================================================================
# Convenience Functions
# ============================================================================


@contextmanager
def stream_write_text(
    path: Path | str,
    encoding: str = "utf-8",
    stable: bool = False,
) -> Generator[StreamWriterText, None, None]:
    """
    Context manager for text stream writing (convenience function).

    Args:
        path: Output file path
        encoding: File encoding
        stable: Use stable formatting

    Yields:
        StreamWriterText instance

    Examples:
        >>> with stream_write_text("output.rules") as writer:
        ...     for rule in input_stream:
        ...         writer.write(rule)
    """
    with StreamWriterText(path, encoding=encoding, stable=stable) as writer:
        yield writer


@contextmanager
def stream_write_json(
    path: Path | str,
    encoding: str = "utf-8",
    indent: int | None = 2,
) -> Generator[StreamWriterJSON, None, None]:
    """
    Context manager for JSON stream writing (convenience function).

    Args:
        path: Output file path
        encoding: File encoding
        indent: JSON indentation

    Yields:
        StreamWriterJSON instance

    Examples:
        >>> with stream_write_json("output.json") as writer:
        ...     for rule in input_stream:
        ...         writer.write(rule)
    """
    with StreamWriterJSON(path, encoding=encoding, indent=indent) as writer:
        yield writer
