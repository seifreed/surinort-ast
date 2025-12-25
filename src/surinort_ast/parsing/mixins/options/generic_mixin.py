"""
Generic and core options transformer mixin.

Handles transformation of generic/unknown options and core list processing:
- generic_option: Fallback for unknown or future options
- options: Options list processing
- option_value: Value extraction helper
- Terminals: Comment and newline handling

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from lark import Token

from ....core.nodes import GenericOption
from ._helpers import parse_quoted_string_cached


class GenericOptionsMixin:
    """
    Mixin for transforming generic and unknown options.

    This mixin handles:
    - generic_option: Fallback for unknown, future, or vendor-specific options
    - options: Filter and process options list
    - option_value: Extract and clean option values
    - Terminals: Comment and newline handling (filtered out)

    Purpose:
        Provides extensibility for:
        - Future IDS options not yet implemented
        - Vendor-specific extensions (Snort/Suricata specific)
        - Experimental or deprecated options
        - Unknown options in legacy rules

    Philosophy:
        Parse leniently, preserve unknown syntax for round-trip parsing.
    """

    # ========================================================================
    # Options List Processing
    # ========================================================================

    def options(self, items: Sequence[Any]) -> list[Any]:
        """
        Transform options list, filtering out None values.

        Args:
            items: Sequence of option nodes (may contain None)

        Returns:
            List of option nodes with None values filtered out

        Performance:
            Optimized to skip None values efficiently using list comprehension.

        Note:
            None values can appear from comments, newlines, or ignored grammar rules.
        """
        return [item for item in items if item is not None]

    # ========================================================================
    # Generic Option Fallback
    # ========================================================================

    def generic_option(self, items: Sequence[Any]) -> GenericOption:
        """
        Transform unknown/generic option.

        Args:
            items: List containing keyword and optional value

        Returns:
            GenericOption node with keyword, value, and raw string

        Usage:
            Fallback for:
            - Future options not yet implemented
            - Vendor-specific options
            - Experimental options
            - Deprecated options

        Format:
            keyword; or keyword:value;

        Note:
            GenericOption preserves the raw syntax for round-trip parsing
            and allows the AST to represent rules with unknown options.
        """
        keyword = ""
        value = None

        if items:
            keyword = str(items[0].value if isinstance(items[0], Token) else items[0])

        if len(items) > 1:
            value_item = items[1]
            if isinstance(value_item, Token):
                value_str = str(value_item.value)
                # Clean quoted strings (use cached version for performance)
                if value_str.startswith('"') and value_str.endswith('"'):
                    value = parse_quoted_string_cached(value_str)
                else:
                    value = value_str
            else:
                value = str(value_item)

        raw = f"{keyword}:{value}" if value else keyword

        return GenericOption(keyword=keyword, value=value, raw=raw)

    def option_value(self, items: Sequence[Token]) -> str:
        """
        Extract option value from tokens.

        Args:
            items: Sequence containing value token

        Returns:
            Value string with quotes removed if present

        Note:
            Used by generic_option and other option transformers.
        """
        if items:
            value_str = str(items[0].value)
            # Clean quoted strings (use cached version for performance)
            if value_str.startswith('"') and value_str.endswith('"'):
                return parse_quoted_string_cached(value_str)
            return value_str
        return ""

    # ========================================================================
    # Terminals and Ignored Elements
    # ========================================================================

    def comment(self, items: Any) -> None:
        """
        Ignore comments.

        Args:
            items: Comment tokens

        Returns:
            None (filtered out by options())

        Comment Formats:
            - Single line: # comment
            - Multi-line: /* comment */
        """
        return

    def NEWLINE(self, token: Token) -> None:  # noqa: N802 - Lark grammar rule name
        """
        Ignore newlines.

        Args:
            token: Newline token

        Returns:
            None (filtered out by options())

        Note:
            Method name must match Lark terminal name (NEWLINE).
        """
        return
