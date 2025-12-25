"""
Parser interfaces for dependency inversion.

This module defines protocol-based interfaces for parser implementations,
following the Dependency Inversion Principle (SOLID). This allows:
- Decoupling from specific parser libraries (Lark, etc.)
- Easy parser library swapping
- Better testability through mock implementations
- Dependency injection patterns
- Multiple parser implementations

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from ..core.nodes import Rule


@runtime_checkable
class IParser(Protocol):
    """
    Parser interface for IDS rule parsing.

    This protocol defines the contract that all parser implementations must satisfy.
    Using Protocol instead of ABC avoids runtime dependencies and allows structural
    subtyping (duck typing with type safety).

    Implementations:
        - LarkRuleParser: Lark-based parser (default)
        - Custom implementations can be provided via dependency injection

    Example:
        >>> parser: IParser = LarkRuleParser()
        >>> rule = parser.parse('alert tcp any any -> any 80 (sid:1;)')
        >>> print(rule.action)
        Action.ALERT

        >>> # Custom parser implementation
        >>> class CustomParser:
        ...     def parse(self, text: str, dialect: Dialect = Dialect.SURICATA) -> Rule:
        ...         # Custom implementation
        ...         ...
        ...
        ...     def parse_file(self, path: Path, dialect: Dialect = Dialect.SURICATA) -> list[Rule]:
        ...         # Custom implementation
        ...         ...
        ...
        >>> custom_parser: IParser = CustomParser()  # Type-checked via Protocol
    """

    def parse(
        self,
        text: str,
        file_path: str | None = None,
        line_offset: int = 0,
    ) -> Rule:
        """
        Parse a single IDS rule from text.

        Args:
            text: Rule text to parse
            file_path: Optional source file path for location tracking
            line_offset: Line number offset for multi-line files

        Returns:
            Parsed Rule AST node

        Raises:
            ParseError: If parsing fails in strict mode
            ValueError: If input validation fails

        Example:
            >>> rule = parser.parse('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
            >>> print(rule.header.protocol)
            Protocol.TCP
        """
        ...

    def parse_file(
        self,
        path: str | Path,
        encoding: str = "utf-8",
        skip_errors: bool = True,
    ) -> list[Rule]:
        """
        Parse IDS rules from a file.

        This method handles multi-line rules, comments, and blank lines.

        Args:
            path: Path to rules file
            encoding: File encoding (default: utf-8)
            skip_errors: If True, skip lines that fail to parse; if False, include ErrorNode

        Returns:
            List of parsed Rule nodes

        Raises:
            FileNotFoundError: If file does not exist
            ParseError: If strict mode enabled and parsing fails
            ValueError: If input validation fails

        Example:
            >>> rules = parser.parse_file("rules/emerging-threats.rules")
            >>> valid_rules = [r for r in rules if not isinstance(r, ErrorNode)]
            >>> print(f"Parsed {len(valid_rules)} valid rules")
        """
        ...
