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
from ...helpers import token_to_str
from ._helpers import unquote_if_quoted


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
            None values can appear from comments, newlines, or ignored grammar
            rules. A handler may also return a list of options (e.g. uricontent
            expands to a content match plus an http_uri buffer select), which is
            flattened into the surrounding option sequence.
        """
        result: list[Any] = []
        for item in items:
            if item is None:
                continue
            if isinstance(item, list):
                result.extend(item)
            else:
                result.append(item)
        return result

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
            keyword = token_to_str(items[0])

        if len(items) > 1:
            value_item = items[1]
            if isinstance(value_item, Token):
                value = unquote_if_quoted(str(value_item.value))
            else:
                value = str(value_item)

        raw = f"{keyword}:{value}" if value is not None else keyword

        return GenericOption(keyword=keyword, value=value, raw=raw)

    def pcrexform_option(self, items: Sequence[Any]) -> GenericOption:
        value = unquote_if_quoted(token_to_str(items[0])) if items else ""
        return GenericOption(keyword="pcrexform", value=value, raw=f"pcrexform:{value}")

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
            return unquote_if_quoted(str(items[0].value))
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
