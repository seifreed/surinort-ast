"""
Helper functions for AST transformation.

This module contains utility functions used by transformer mixins for
common operations like location tracking and string parsing.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import re
from typing import Any

from lark import Token, Tree

from ..core.location import Location, Position, Span

# Match a content value whose only closing delimiter is an escaped quote right
# before ';' (a real-world quirk). The lookahead requires a genuine option
# boundary after the ``\";`` — the next option keyword, a closing ``)`` or end
# of input — so a ``\";`` appearing mid-payload of a properly closed content
# value (e.g. content:"GET \"; HTTP") is left untouched.
_MISSING_CONTENT_CLOSER_RE = re.compile(
    r'(?P<prefix>\b(?:uri)?content:")(?P<body>(?:[^"\\]|\\.)*?)'
    r'\\"(?=;\s*(?:[A-Za-z_][\w.]*\s*[:;)]|\)|$))'
)


def is_marker(item: Any, name: str) -> bool:
    """True if ``item`` is a Lark ``Tree`` for the given anonymous marker rule.

    Grammar promotes anonymous ``!``/``-`` literals to named marker rules
    (``neg_bang``/``neg_sign``) so they survive transformation; this checks for
    one of them.
    """
    return isinstance(item, Tree) and item.data == name


def token_to_location(token: Token, file_path: str | None = None) -> Location:
    """
    Convert Lark Token to Location.

    Args:
        token: Lark token with position information
        file_path: Optional source file path

    Returns:
        Location object with span information
    """
    # Lark tokens have: line (1-indexed), column (0-indexed), end_line, end_column
    start = Position(
        line=token.line,
        column=(token.column or 0) + 1,  # Convert to 1-indexed
        offset=token.start_pos,
    )

    # Calculate end position
    end_line = getattr(token, "end_line", token.line)
    default_end_col = (token.column or 0) + len(token.value)
    end_column_raw = getattr(token, "end_column", default_end_col)
    end_column = (end_column_raw if end_column_raw is not None else 0) + 1  # Convert to 1-indexed

    # Calculate end offset, handling None values
    if hasattr(token, "end_pos") and token.end_pos is not None:
        end_offset = token.end_pos
    else:
        start_pos = token.start_pos if token.start_pos is not None else 0
        end_offset = start_pos + len(token.value)

    end = Position(
        line=end_line,
        column=end_column,
        offset=end_offset,
    )

    span = Span(start=start, end=end)
    return Location(span=span, file_path=file_path)


def normalize_rule_text(text: str) -> str:
    """
    Normalize a narrow set of real-world rule quirks before lexing.

    Some open-source rules terminate a content string as `...\\\";` without an
    extra closing quote. Engines accept that form in practice, but the grammar
    expects an explicit closing delimiter. Normalize only that specific pattern.
    """

    return _MISSING_CONTENT_CLOSER_RE.sub(
        lambda match: match.group("prefix") + match.group("body") + '\\""',
        text,
    )


def token_to_int(value: Token | int | str) -> int:
    """
    Convert Token, int, or string to int.

    Args:
        value: Token, int, or string to convert

    Returns:
        Integer value

    Examples:
        >>> token_to_int(Token("INT", "42"))
        42
        >>> token_to_int(42)
        42
        >>> token_to_int("42")
        42
    """
    if isinstance(value, Token):
        return int(value.value)
    return int(value)


def token_to_str(value: object) -> str:
    """
    Convert a Lark Token (or any value) to its string text.

    A Token yields its ``.value``; anything else is stringified directly, which
    matches the ``str(x.value if isinstance(x, Token) else x)`` idiom used
    throughout the transformer mixins.

    Args:
        value: Token or any other value to convert

    Returns:
        String value

    Examples:
        >>> token_to_str(Token("WORD", "example"))
        'example'
        >>> token_to_str("example")
        'example'
    """
    if isinstance(value, Token):
        return str(value.value)
    return str(value)
