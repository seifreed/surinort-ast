"""
Pattern matching options transformer mixin.

Handles transformation of pattern matching options including:
- pcre: Perl Compatible Regular Expressions with flags

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections.abc import Sequence

from lark import Token

from ....core.nodes import PcreOption
from ...helpers import token_to_location
from ._helpers import parse_pcre_pattern_cached, parse_quoted_string_cached


class PatternMatchingOptionsMixin:
    """
    Mixin for transforming pattern matching options.

    This mixin handles PCRE (Perl Compatible Regular Expressions) options:
    - pcre: Regular expression pattern matching with optional negation

    PCRE Flags:
        - i: Case insensitive
        - m: Multiline (^ and $ match line boundaries)
        - s: Dot matches newline
        - x: Extended (ignore whitespace)
        - A: Anchor at start
        - E: Set dollar to match newline at end
        - G: Set dollar to match newline anywhere
        - R: Relative to previous match
        - U: Ungreedy (invert greedy quantifiers)
        - B: Match in HTTP response body

    Dependencies:
        This mixin expects the following attributes/methods on the parent class:
        - file_path: str | None - Source file path for location tracking
    """

    # Declare expected attributes for type checking
    file_path: str | None

    def pcre_option(self, items: Sequence[Token]) -> PcreOption:
        """
        Transform pcre option with optional negation.

        Args:
            items: [pattern] or [!, pattern] tokens

        Returns:
            PcreOption node with pattern and flags

        Usage:
            pcre:"/pattern/imsxAEGRUB";
            pcre:!"/pattern/i";

        PCRE Flags:
            - i: Case insensitive
            - m: Multiline (^ and $ match line boundaries)
            - s: Dot matches newline
            - x: Extended (ignore whitespace)
            - A: Anchor at start
            - E: Set dollar to match newline at end
            - G: Set dollar to match newline anywhere
            - R: Relative to previous match
            - U: Ungreedy (invert greedy quantifiers)
            - B: Match in HTTP response body

        Note:
            Negation (!) inverts the match - alert if pattern does NOT match.
        """
        if not items:
            return PcreOption(pattern="", flags="")
        pattern_token = items[-1]
        pattern_str = str(pattern_token.value)
        # Remove quotes if present (use cached version for performance)
        pattern_str = parse_quoted_string_cached(pattern_str)
        pattern, flags = parse_pcre_pattern_cached(pattern_str)
        return PcreOption(
            pattern=pattern,
            flags=flags,
            location=token_to_location(pattern_token, self.file_path),
        )
