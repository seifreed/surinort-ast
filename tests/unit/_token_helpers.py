"""Shared test helpers for constructing positioned Lark tokens.

Several mixin coverage tests call transformer methods directly with hand-built
tokens. Lark tokens need position attributes (line, column, start_pos, etc.)
for the location tracking the transformers perform, so this helper sets them.
"""

from __future__ import annotations

from lark import Token


def create_token(token_type: str, value: str) -> Token:
    """Create a Lark ``Token`` with the position attributes the transformer expects."""
    token = Token(token_type, value)
    token.line = 1
    token.column = 1
    token.start_pos = 0
    token.end_line = 1
    token.end_column = len(value)
    token.end_pos = len(value)
    return token
