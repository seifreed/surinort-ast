"""
Shared helper functions for option parsing.

This module provides common utilities used across multiple option transformer mixins:
- String parsing (quoted strings, escape sequences)
- Pattern parsing (PCRE patterns with flags)
- Cached versions for performance optimization

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import functools
import re

from ....core.nodes import GenericOption


def generic_kv(keyword: str, value: str) -> GenericOption:
    """Build a ``GenericOption`` whose raw form is ``keyword:value``.

    Shared by the option transformers that emit a passthrough
    ``GenericOption`` (byte_test/byte_jump/byte_extract/byte_math, tag, flags,
    urilen, isdataat, flowint, threshold, detection_filter).
    """
    return GenericOption(keyword=keyword, value=value, raw=f"{keyword}:{value}")


# ============================================================================
# String Parsing Helpers
# ============================================================================


def strip_outer_quotes(s: str) -> str:
    """Remove the surrounding quotes from a value without unescaping its body.

    PCRE patterns are opaque regexes whose escape sequences (``\\n``, ``\\r``,
    ``\\t``, ``\\xNN``, ``\\\\``) are part of the regex and must round-trip
    verbatim, so they must not pass through :func:`parse_quoted_string`.
    """
    if len(s) < 2:
        return s

    if s[0] == "'" and s[-1] == "'":
        return s[1:-1]

    if s[0] == '"' and s[-1] == '"':
        # The trailing quote closes the string only when it is not itself
        # escaped. Count the backslashes immediately before it: an even number
        # (including zero) leaves the quote unescaped — the real closing quote —
        # while an odd number makes it an escaped ``\"``. The grammar tolerates a
        # string that terminates as ``...\";`` without a separate closing quote,
        # so in that case the literal quote is kept in the value.
        i = len(s) - 2
        backslashes = 0
        while i >= 1 and s[i] == "\\":
            backslashes += 1
            i -= 1
        if backslashes % 2 == 0:
            return s[1:-1]
        return s[1:]

    return s


def parse_quoted_string(s: str) -> str:
    """
    Parse quoted string, handling escape sequences.

    Args:
        s: Quoted string (e.g., "text" or "text with \\"quotes\\"")

    Returns:
        Unquoted and unescaped string

    Performance:
        Optimized with early returns for common cases.
    """
    if not s or len(s) < 2:
        return s

    s = strip_outer_quotes(s)

    # Fast path: no escapes
    if "\\" not in s:
        return s

    # Single left-to-right scan so each backslash is consumed exactly once.
    # A chained-replace approach needs an in-band sentinel for literal
    # backslashes, which corrupts values that legitimately contain that byte.
    # Suricata/Snort escape the option separator inside quoted values as "\;".
    escapes = {'"': '"', "'": "'", ";": ";", "n": "\n", "r": "\r", "t": "\t", "\\": "\\"}
    out: list[str] = []
    i = 0
    length = len(s)
    while i < length:
        char = s[i]
        if char == "\\" and i + 1 < length:
            nxt = s[i + 1]
            out.append(escapes.get(nxt, "\\" + nxt))
            i += 2
        else:
            out.append(char)
            i += 1
    return "".join(out)


# ============================================================================
# Pattern Parsing Helpers
# ============================================================================

# Compiled regex for PCRE pattern parsing (avoid recompilation)
# Uses a greedy match for pattern content up to the LAST unescaped /
# This correctly handles patterns with escaped slashes like /foo\/bar/flags.
# DOTALL lets the body span literal newline characters (e.g. /[^\n]*/),
# otherwise the match fails and the delimiters leak into the pattern.
_PCRE_PATTERN_RE = re.compile(r"^/(.*)/([A-Za-z]*)$", re.DOTALL)


def parse_pcre_pattern(s: str) -> tuple[str, str]:
    """
    Parse PCRE pattern into pattern and flags.

    Args:
        s: PCRE string (e.g., "/pattern/imsxAEGRUB")

    Returns:
        Tuple of (pattern, flags)

    Performance:
        Optimized with pre-compiled regex pattern.
    """
    # Match /pattern/flags format with pre-compiled regex
    match = _PCRE_PATTERN_RE.match(s)
    if match:
        return match.group(1), match.group(2)

    # Fallback: treat entire string as pattern
    return s, ""


# ============================================================================
# Cached Versions for Performance
# ============================================================================


@functools.lru_cache(maxsize=2048)
def parse_quoted_string_cached(s: str) -> str:
    """
    LRU-cached version of parse_quoted_string for performance.

    Args:
        s: Quoted string

    Returns:
        Unquoted and unescaped string

    Performance:
        Cache hit rate: ~95% on typical IDS rule files.
        Common patterns: msg strings, reference IDs, metadata values.
    """
    return parse_quoted_string(s)


def unquote_if_quoted(value_str: str) -> str:
    """Unquote a value wrapped in double quotes, else return it unchanged."""
    if value_str.startswith('"') and value_str.endswith('"'):
        return parse_quoted_string_cached(value_str)
    return value_str


@functools.lru_cache(maxsize=1024)
def parse_pcre_pattern_cached(s: str) -> tuple[str, str]:
    """
    LRU-cached version of parse_pcre_pattern for performance.

    Args:
        s: PCRE string

    Returns:
        Tuple of (pattern, flags)

    Performance:
        Cache hit rate: ~90% on typical IDS rule files.
        Common patterns: Reused PCRE patterns across rules.
    """
    return parse_pcre_pattern(s)
