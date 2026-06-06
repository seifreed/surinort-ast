"""
Content transformation mixin for IDS rule parser.

This mixin handles transformation of content-related AST nodes including:
- Content pattern matching (content, uricontent)
- Content modifiers (nocase, rawbytes, depth, offset, distance, within)
- Inline content modifiers (Snort3 syntax)
- Byte operations (byte_test, byte_jump, byte_extract, byte_math)
- Pattern positioning (startswith, endswith, fast_pattern)

The mixin is designed to be composed with other transformer mixins in RuleTransformer.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from lark import Token, Tree
from lark.visitors import v_args

if TYPE_CHECKING:
    from . import DiagnosticReporter

from ...core.diagnostics import DiagnosticLevel
from ...core.enums import ContentModifierType
from ...core.nodes import (
    ContentModifier,
    ContentOption,
    DepthOption,
    DistanceOption,
    EndswithOption,
    FastPatternOption,
    GenericOption,
    NocaseOption,
    OffsetOption,
    RawbytesOption,
    StartswithOption,
    WithinOption,
)

logger = logging.getLogger(__name__)

# ============================================================================
# Helper Functions for Content Parsing
# ============================================================================


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

    # Remove quotes - use slice for performance
    if (s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'"):
        s = s[1:-1]

    # Fast path: no escapes
    if "\\" not in s:
        return s

    # Handle escape sequences - chained replace is fastest for small strings
    # Process in order: backslash first to avoid double-processing
    s = s.replace("\\\\", "\x00")  # Temporary marker for literal backslash
    s = s.replace('\\"', '"')
    s = s.replace("\\'", "'")
    s = s.replace("\\n", "\n")
    s = s.replace("\\r", "\r")
    s = s.replace("\\t", "\t")
    return s.replace("\x00", "\\")  # Restore literal backslash


# Whitespace translation table for hex strings
_HEX_WHITESPACE_TRANS = str.maketrans("", "", " \n\r\t")
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


def parse_hex_string(s: str) -> bytes:
    """
    Parse hex string to bytes.

    Args:
        s: Hex string (e.g., "|48 65 6c 6c 6f|")

    Returns:
        Raw bytes

    Raises:
        ValueError: If hex string contains invalid characters

    Performance:
        Optimized with translation table for whitespace removal.
    """
    # Remove pipes and whitespace using translate (faster than chained replace)
    hex_content = s.strip("|").translate(_HEX_WHITESPACE_TRANS)

    try:
        return bytes.fromhex(hex_content)
    except ValueError as e:
        logger.warning(f"Invalid hex string '{s}': {e}")
        raise ValueError(f"Invalid hex content in '{s}': {e}") from e


def _is_pure_hex_piped(s: str) -> bool:
    """
    Check whether a pipe-delimited content string contains only hex bytes.

    Args:
        s: Pipe-delimited content string

    Returns:
        True if the string is pipe-delimited and inner content is hex-only.
    """
    if len(s) < 2 or s[0] != "|" or not s.endswith("|"):
        return False

    inner = s[1:-1]
    if not inner:
        return False

    return all(ch in _HEX_CHARS or ch.isspace() for ch in inner)


def _token_to_int_or_str(value: Any) -> int | str:
    """Convert a token-like value to int when possible, otherwise to str."""
    raw = str(value.value) if isinstance(value, Token) else str(value)
    try:
        return int(raw)
    except ValueError:
        return raw


def _parse_mixed_content(s: str) -> bytes:
    """
    Parse content string that mixes ASCII and hex notation.

    Args:
        s: Content string with mixed ASCII and hex (e.g., "User-Agent|3a 20|Mozilla")

    Returns:
        Raw bytes with hex portions converted

    Format:
        ASCII portions are used as-is, hex portions are delimited by | characters.
        Example: "User-Agent|3a 20|Mozilla" -> b"User-Agent: Mozilla"
    """
    result = bytearray()
    i = 0

    while i < len(s):
        if s[i] == "|":
            # Find the closing pipe
            j = s.find("|", i + 1)
            if j == -1:
                # No closing pipe, treat rest as ASCII
                result.extend(s[i:].encode("utf-8", errors="replace"))
                break

            # Extract hex content between pipes
            hex_str = s[i + 1 : j]
            # Remove whitespace and convert
            hex_content = hex_str.translate(_HEX_WHITESPACE_TRANS)
            try:
                result.extend(bytes.fromhex(hex_content))
            except ValueError as e:
                logger.warning(f"Invalid hex content '{hex_str}': {e}")

            i = j + 1
        else:
            # ASCII character
            result.append(ord(s[i]))
            i += 1

    return bytes(result)


class ContentTransformerMixin:
    """
    Mixin for transforming content-related AST nodes.

    This mixin provides methods for transforming Lark parse tree nodes into
    content pattern matching and byte operation AST nodes. It handles:
    - Content patterns (quoted strings and hex strings)
    - Standalone content modifiers (nocase, rawbytes, depth, offset, etc.)
    - Inline content modifiers (Snort3 syntax for content:(...))
    - Byte inspection operations (byte_test, byte_jump, byte_extract, byte_math)
    - Fast pattern configuration for performance optimization

    Content Matching:
        Content options specify byte patterns to search for in network traffic.
        Patterns can be:
        - Quoted strings: content:"GET /" (with escape sequences)
        - Hex strings: content:|47 45 54 20 2F| (raw bytes)
        - Mixed: content:"GET |20 2F|" (some parsers support this)

    Content Modifiers:
        Modifiers control how patterns are matched:
        - Position: depth, offset, distance, within, startswith, endswith
        - Case: nocase (case-insensitive matching)
        - Encoding: rawbytes (ignore HTTP decoding)
        - Performance: fast_pattern (use this pattern for fast matching)

    Byte Operations:
        Advanced byte inspection for protocol analysis:
        - byte_test: Test byte values at specific offsets
        - byte_jump: Jump to dynamic offsets in payload
        - byte_extract: Extract byte values to variables
        - byte_math: Perform arithmetic on extracted bytes

    Dependencies:
        This mixin expects the following attributes/methods on the parent class:
        - file_path: str | None - Source file path for location tracking
        - add_diagnostic(level, message, location) - Diagnostic reporting method
    """

    # Declare expected attributes for type checking
    file_path: str | None
    add_diagnostic: DiagnosticReporter

    # ========================================================================
    # Content Options
    # ========================================================================

    @v_args(inline=True)
    def content_option(self, content_value: bytes, *modifiers: ContentModifier) -> ContentOption:
        """
        Transform content option with inline modifiers (Snort3 syntax).

        Args:
            content_value: Parsed content bytes (from content_value)
            *modifiers: Optional inline content modifiers

        Returns:
            ContentOption node with pattern and inline modifiers

        Snort3 Syntax:
            content:("pattern", depth 10, nocase)
        """
        return ContentOption(pattern=content_value, modifiers=list(modifiers) if modifiers else [])

    @v_args(inline=True)
    def uricontent_option(self, content_value: bytes, *modifiers: ContentModifier) -> ContentOption:
        """
        Transform uricontent option (legacy Snort2).

        Args:
            content_value: Parsed content bytes
            *modifiers: Optional inline content modifiers

        Returns:
            ContentOption node (same as content)

        Deprecation:
            uricontent is deprecated in favor of: content + http_uri buffer
            A diagnostic warning is added when uricontent is used.
        """
        self.add_diagnostic(
            DiagnosticLevel.WARNING,
            "uricontent is deprecated, use content with http_uri buffer",
        )
        return ContentOption(pattern=content_value, modifiers=list(modifiers) if modifiers else [])

    @v_args(inline=True)
    def content_value(self, value_token: Token) -> bytes:
        """
        Parse content value (quoted string or hex).

        Args:
            value_token: Token containing quoted string or hex string

        Returns:
            Content as raw bytes

        Performance:
            Optimized with fast path checks for common cases.

        Format Detection:
            - Hex strings: Start with | and end with | (e.g., |48 65|)
            - Quoted hex: Quoted string containing hex (e.g., "|48 65|")
            - Quoted strings: Everything else (e.g., "Hello")
            - Mixed ASCII/hex: Quoted string with | delimiters (e.g., "User-Agent|3a 20|Mozilla")
        """
        value_str = str(value_token.value)

        # Fast path: check first character for type determination
        first_char = value_str[0] if value_str else ""

        try:
            return self._parse_content_value(value_str)
        except ValueError as e:
            self.add_diagnostic(
                DiagnosticLevel.WARNING,
                f"Invalid hex content, treating as raw bytes: {e}",
            )
            return value_str.encode("utf-8", errors="replace")

    def _parse_content_value(self, value_str: str) -> bytes:
        """Parse content value string to bytes, dispatching by format."""
        first_char = value_str[0] if value_str else ""

        # Check if pure hex string (starts/ends with | and hex-only inside).
        # Strings like "|08|com|00|" are mixed and must not use parse_hex_string().
        if first_char == "|" and value_str.endswith("|") and _is_pure_hex_piped(value_str):
            return parse_hex_string(value_str)
        if first_char == "|" and value_str.endswith("|"):
            return _parse_mixed_content(value_str)

        # Check if quoted hex string (quoted string containing only hex pattern)
        if first_char in ('"', "'"):
            # Remove quotes first
            unquoted = parse_quoted_string(value_str)
            # Check if the unquoted content is a pure hex string
            if (
                unquoted
                and unquoted[0] == "|"
                and unquoted.endswith("|")
                and _is_pure_hex_piped(unquoted)
            ):
                return parse_hex_string(unquoted)
            # Check for mixed ASCII and hex (contains | but doesn't start/end with it)
            if "|" in unquoted:
                return _parse_mixed_content(unquoted)
            # Regular quoted string
            return unquoted.encode("utf-8", errors="replace")

        # Unquoted string — encode as-is
        return value_str.encode("utf-8", errors="replace")

    # ========================================================================
    # Inline Content Modifiers (Snort3 Syntax)
    # ========================================================================

    def cm_depth(self, args: list[Any]) -> ContentModifier:
        """
        Transform inline depth modifier.

        Args:
            args: [DEPTH_KW, INT] from grammar

        Returns:
            ContentModifier for DEPTH
        """
        value = _token_to_int_or_str(args[1])
        return ContentModifier(name=ContentModifierType.DEPTH, value=value)

    def cm_offset(self, args: list[Any]) -> ContentModifier:
        """
        Transform inline offset modifier.

        Args:
            args: [OFFSET_KW, INT] from grammar

        Returns:
            ContentModifier for OFFSET
        """
        value = _token_to_int_or_str(args[1])
        return ContentModifier(name=ContentModifierType.OFFSET, value=value)

    def cm_distance(self, args: list[Any]) -> ContentModifier:
        """
        Transform inline distance modifier.

        Args:
            args: [DISTANCE_KW, INT] or [DISTANCE_KW, "-", INT] from grammar

        Returns:
            ContentModifier for DISTANCE

        Note:
            Distance can be negative for backward relative matching.
        """
        if len(args) == 2:
            value = _token_to_int_or_str(args[1])
        else:
            token_value = _token_to_int_or_str(args[2])
            value = -token_value if isinstance(token_value, int) else f"-{token_value}"
        return ContentModifier(name=ContentModifierType.DISTANCE, value=value)

    def cm_within(self, args: list[Any]) -> ContentModifier:
        """
        Transform inline within modifier.

        Args:
            args: [WITHIN_KW, INT] from grammar

        Returns:
            ContentModifier for WITHIN
        """
        value = _token_to_int_or_str(args[1])
        return ContentModifier(name=ContentModifierType.WITHIN, value=value)

    def cm_nocase(self, args: list[Any]) -> ContentModifier:
        """
        Transform inline nocase modifier.

        Args:
            args: [NOCASE_KW] from grammar

        Returns:
            ContentModifier for NOCASE (no value)
        """
        return ContentModifier(name=ContentModifierType.NOCASE, value=None)

    def cm_rawbytes(self, args: list[Any]) -> ContentModifier:
        """
        Transform inline rawbytes modifier.

        Args:
            args: [RAWBYTES_KW] from grammar

        Returns:
            ContentModifier for RAWBYTES (no value)
        """
        return ContentModifier(name=ContentModifierType.RAWBYTES, value=None)

    def cm_startswith(self, args: list[Any]) -> ContentModifier:
        """
        Transform inline startswith modifier.

        Args:
            args: [STARTSWITH_KW] from grammar

        Returns:
            ContentModifier for STARTSWITH (no value)
        """
        return ContentModifier(name=ContentModifierType.STARTSWITH, value=None)

    def cm_endswith(self, args: list[Any]) -> ContentModifier:
        """
        Transform inline endswith modifier.

        Args:
            args: [ENDSWITH_KW] from grammar

        Returns:
            ContentModifier for ENDSWITH (no value)
        """
        return ContentModifier(name=ContentModifierType.ENDSWITH, value=None)

    def cm_fast_pattern(self, args: list[Any]) -> ContentModifier:
        """
        Transform inline fast_pattern modifier.

        Args:
            args: [FAST_PATTERN_KW] from grammar

        Returns:
            ContentModifier for FAST_PATTERN (no value)
        """
        return ContentModifier(name=ContentModifierType.FAST_PATTERN, value=None)

    def cm_fast_pattern_offset(self, args: list[Any]) -> ContentModifier:
        """Transform inline fast_pattern_offset modifier."""
        value = _token_to_int_or_str(args[1])
        return ContentModifier(name=ContentModifierType.FAST_PATTERN, value=f"offset {value}")

    def cm_fast_pattern_length(self, args: list[Any]) -> ContentModifier:
        """Transform inline fast_pattern_length modifier."""
        value = _token_to_int_or_str(args[1])
        return ContentModifier(name=ContentModifierType.FAST_PATTERN, value=f"length {value}")

    def cm_generic(self, args: list[Any]) -> ContentModifier:
        """
        Handle generic/unknown inline content modifiers.

        Args:
            args: Variable length list from grammar

        Returns:
            ContentModifier with the actual modifier name mapped to ContentModifierType

        Note:
            This is a fallback for unrecognized inline modifiers.
            Maps known names to their enum, falls back to NOCASE for truly unknown modifiers.
        """
        # Extract the modifier name
        modifier_name = ""
        if args:
            modifier_name = str(args[0].value) if isinstance(args[0], Token) else str(args[0])

        # Try to map the modifier name to a ContentModifierType
        modifier_type = ContentModifierType.NOCASE  # Default fallback
        name_lower = modifier_name.lower()
        for member in ContentModifierType:
            if member.value == name_lower:
                modifier_type = member
                break

        if len(args) == 1:
            return ContentModifier(name=modifier_type, value=None)
        if len(args) == 2:
            value = _token_to_int_or_str(args[1])
            return ContentModifier(name=modifier_type, value=value)
        return ContentModifier(name=modifier_type, value=None)

    # ========================================================================
    # Standalone Content Modifiers
    # ========================================================================

    def nocase_option(self, _: Any) -> NocaseOption:
        """
        Transform nocase modifier (standalone option).

        Returns:
            NocaseOption node for case-insensitive matching
        """
        return NocaseOption()

    def rawbytes_option(self, _: Any) -> RawbytesOption:
        """
        Transform rawbytes modifier (standalone option).

        Returns:
            RawbytesOption node to ignore HTTP decoding
        """
        return RawbytesOption()

    @v_args(inline=True)
    def depth_option(self, depth_token: Token) -> DepthOption:
        """
        Transform depth modifier (standalone option).

        Args:
            depth_token: Token containing depth value (int or variable name)

        Returns:
            DepthOption node with int value or string variable name

        Usage:
            depth:N - Search only first N bytes of payload
        """
        value: int | str
        try:
            value = int(depth_token.value)
        except ValueError:
            value = str(depth_token.value)
        return DepthOption(value=value)

    @v_args(inline=True)
    def offset_option(self, offset_token: Token) -> OffsetOption:
        """
        Transform offset modifier (standalone option).

        Args:
            offset_token: Token containing offset value (int or variable name)

        Returns:
            OffsetOption node with int value or string variable name

        Usage:
            offset:N - Skip first N bytes before searching
        """
        value: int | str
        try:
            value = int(offset_token.value)
        except ValueError:
            value = str(offset_token.value)
        return OffsetOption(value=value)

    def distance_option(self, items: list[Any]) -> DistanceOption:
        """
        Transform distance modifier (standalone option).

        Args:
            items: ``[value]`` or ``[neg_sign, value]`` when negative.

        Returns:
            DistanceOption node with int value or string variable name

        Usage:
            distance:N - Relative offset from previous match (can be negative)
        """
        negative = len(items) == 2
        token = items[-1]
        value: int | str
        try:
            value = int(token.value)
            if negative:
                value = -value
        except ValueError:
            text = str(token.value)
            value = f"-{text}" if negative else text
        return DistanceOption(value=value)

    @v_args(inline=True)
    def within_option(self, within_token: Token) -> WithinOption:
        """
        Transform within modifier (standalone option).

        Args:
            within_token: Token containing within value (int or variable name)

        Returns:
            WithinOption node with int value or string variable name

        Usage:
            within:N - Limit search to N bytes after previous match
        """
        value: int | str
        try:
            value = int(within_token.value)
        except ValueError:
            value = str(within_token.value)
        return WithinOption(value=value)

    def startswith_option(self, _: Any) -> StartswithOption:
        """
        Transform startswith modifier (standalone option).

        Returns:
            StartswithOption node (pattern must be at start of buffer)
        """
        return StartswithOption()

    def endswith_option(self, _: Any) -> EndswithOption:
        """
        Transform endswith modifier (standalone option).

        Returns:
            EndswithOption node (pattern must be at end of buffer)
        """
        return EndswithOption()

    def fast_pattern_offset(self, items: list[Any]) -> tuple[str, int, int]:
        """Transform ``fast_pattern:<offset>,<length>`` parameters."""
        return ("offset", int(items[0].value), int(items[1].value))

    def fast_pattern_only(self, items: list[Any]) -> tuple[str]:
        """Transform ``fast_pattern:only``."""
        return ("only",)

    def fast_pattern_option(self, items: Sequence[Any]) -> FastPatternOption:
        """
        Transform fast_pattern option (standalone with optional parameters).

        Args:
            items: Empty, or a single parameter spec produced by
                :meth:`fast_pattern_offset` / :meth:`fast_pattern_only`.

        Returns:
            FastPatternOption node with optional offset and length

        Usage:
            fast_pattern; - Use entire pattern for fast matching
            fast_pattern:10,20; - Use 20 bytes starting at offset 10
            fast_pattern:only; - Use only this content for fast matching
        """
        offset = None
        length = None

        if items:
            spec = items[0]
            if isinstance(spec, tuple) and spec[0] == "offset":
                offset = spec[1]
                length = spec[2]

        return FastPatternOption(offset=offset, length=length)

    # ========================================================================
    # Byte Operations
    # ========================================================================

    def byte_test_option(self, items: Sequence[Any]) -> GenericOption:
        """
        Transform byte_test option.

        Args:
            items: List containing byte_test parameters

        Returns:
            GenericOption with keyword="byte_test" and formatted value string

        Usage:
            byte_test:bytes,operator,value,offset[,flags]
            byte_test:4,>,1000,0,relative

        Complex Parsing:
            byte_test has complex syntax with:
            - Required: bytes, operator, value, offset
            - Optional: endianness, string conversion, relative/absolute
            - Special: bitmask with hex value (e.g., bitmask 0x8000)
        """
        params = items[0] if items else []

        # Process each param to extract proper values
        processed_params = []
        for p in params:
            if isinstance(p, Token):
                processed_params.append(str(p.value))
            elif isinstance(p, str):
                # Already transformed (e.g., operator from byte_test_operator)
                processed_params.append(p)
            elif isinstance(p, Tree):
                # Handle byte_test_flag tree nodes (e.g., "bitmask 0x8000")
                if p.data == "byte_test_flag" and p.children:
                    # Extract flag name and optional value
                    flag_parts = []
                    for child in p.children:
                        if isinstance(child, Token):
                            flag_parts.append(str(child.value))
                        else:
                            flag_parts.append(str(child))
                    processed_params.append(" ".join(flag_parts))
                else:
                    processed_params.append(str(p))
            else:
                processed_params.append(str(p))

        value_str = ",".join(processed_params)
        return GenericOption(keyword="byte_test", value=value_str, raw=f"byte_test:{value_str}")

    def byte_test_params(self, items: Sequence[Token]) -> Sequence[Token]:
        """Pass through byte_test params."""
        return items

    def byte_test_value(self, items: Sequence[Token]) -> Token:
        """Pass through byte_test value (number or variable name)."""
        return items[0] if items else Token("INT", "0")

    def byte_test_offset(self, items: Sequence[Token]) -> str:
        """
        Handle byte_test offset with optional negative sign.

        Args:
            items: ["-", number] or [number]

        Returns:
            Offset string with sign
        """
        if len(items) == 2:
            # Negative offset: "-" followed by number
            value = items[1].value if isinstance(items[1], Token) else items[1]
            return f"-{value}"
        if len(items) == 1:
            # Positive offset
            return str(items[0].value if isinstance(items[0], Token) else items[0])
        return "0"

    def byte_test_flag(self, items: Sequence[Token]) -> str:
        """
        Handle byte_test flags including 'bitmask VALUE' syntax.

        Args:
            items: ["bitmask", value] or [regular_flag]

        Returns:
            Flag string (may contain space for "bitmask 0x8000")
        """
        if len(items) >= 2:
            # bitmask with value: join with space
            return " ".join(str(item.value if isinstance(item, Token) else item) for item in items)
        if len(items) == 1:
            # Regular flag
            return str(items[0].value if isinstance(items[0], Token) else items[0])
        return ""

    @v_args(inline=True)
    def byte_test_operator(self, operator_token: Token) -> str:
        """
        Transform byte_test operator to string.

        Args:
            operator_token: Token containing operator (>, <, =, etc.)

        Returns:
            Operator string
        """
        return str(operator_token.value)

    def byte_jump_option(self, items: Sequence[Any]) -> GenericOption:
        """
        Transform byte_jump option.

        Args:
            items: List containing byte_jump parameters

        Returns:
            GenericOption with keyword="byte_jump" and formatted value string

        Usage:
            byte_jump:bytes,offset[,flags]
            byte_jump:4,0,relative,little

        Complex Parsing:
            byte_jump has complex syntax with:
            - Required: bytes, offset
            - Optional: endianness, relative/absolute, alignment
            - Special: post_offset with value (e.g., post_offset 10)
        """
        params = items[0] if items else []

        # Process each param to extract proper values from Tree/Token/list objects
        processed_params = []
        for p in params:
            if isinstance(p, Tree):
                # For Tree objects (like byte_jump_flag), extract the actual value
                if p.children:
                    flag = p.children[0]
                    flag_value = str(flag.value if isinstance(flag, Token) else flag)
                    # If there's a second child (INT for flags like "post_offset 10")
                    if len(p.children) > 1:
                        flag_arg = p.children[1]
                        flag_arg_value = str(
                            flag_arg.value if isinstance(flag_arg, Token) else flag_arg
                        )
                        processed_params.append(f"{flag_value} {flag_arg_value}")
                    else:
                        processed_params.append(flag_value)
                else:
                    processed_params.append(str(p))
            elif isinstance(p, (list, tuple)):
                # For list/tuple (from byte_jump_flag returning items)
                if len(p) == 1:
                    processed_params.append(str(p[0].value if isinstance(p[0], Token) else p[0]))
                elif len(p) == 2:
                    flag_name = str(p[0].value if isinstance(p[0], Token) else p[0])
                    flag_arg = str(p[1].value if isinstance(p[1], Token) else p[1])
                    processed_params.append(f"{flag_name} {flag_arg}")
                else:
                    processed_params.append(
                        " ".join(str(item.value if isinstance(item, Token) else item) for item in p)
                    )
            elif isinstance(p, Token):
                processed_params.append(str(p.value))
            else:
                processed_params.append(str(p))

        value_str = ",".join(processed_params)
        return GenericOption(keyword="byte_jump", value=value_str, raw=f"byte_jump:{value_str}")

    def byte_jump_params(self, items: Sequence[Any]) -> Sequence[Any]:
        """Pass through byte_jump params."""
        return items

    def byte_jump_offset(self, items: Sequence[Any]) -> str:
        """
        Handle byte_jump offset with optional negative sign or variable name.

        Args:
            items: ["-", value] or [value]

        Returns:
            Offset string preserving sign
        """
        if len(items) == 2:
            value = items[1].value if isinstance(items[1], Token) else items[1]
            return f"-{value}"
        if len(items) == 1:
            return str(items[0].value if isinstance(items[0], Token) else items[0])
        return "0"

    def byte_jump_flag(self, items: Sequence[Any]) -> Sequence[Any]:
        """Resolve a byte_jump flag and its optional (possibly negative) argument.

        Handles ``relative`` (no arg), ``post_offset 10`` and ``post_offset -10``;
        the leading minus arrives as a ``neg_sign`` marker rule.
        """
        if not items:
            return []
        name = items[0]
        if len(items) == 1:
            return [name]
        negative = any(isinstance(item, Tree) and item.data == "neg_sign" for item in items[1:])
        int_token = items[-1]
        int_value = int_token.value if isinstance(int_token, Token) else int_token
        return [name, f"-{int_value}" if negative else str(int_value)]

    def byte_extract_option(self, items: Sequence[Any]) -> GenericOption:
        """
        Transform byte_extract option.

        Args:
            items: List containing byte_extract parameters

        Returns:
            GenericOption with keyword="byte_extract" and formatted value string

        Usage:
            byte_extract:bytes,offset,name[,flags]
            byte_extract:4,0,extracted_value,relative
        """
        params = items[0] if items else []
        value_str = ",".join(str(p.value if isinstance(p, Token) else p) for p in params)
        return GenericOption(
            keyword="byte_extract", value=value_str, raw=f"byte_extract:{value_str}"
        )

    def byte_extract_params(self, items: Sequence[Any]) -> Sequence[Any]:
        """Pass through byte_extract params."""
        return items

    def byte_extract_offset(self, items: Sequence[Token]) -> str:
        """
        Handle byte_extract offset with optional negative sign.

        Args:
            items: ["-", INT] or [INT]

        Returns:
            Offset string preserving sign.
        """
        if len(items) == 2:
            return f"-{items[1].value}"
        if len(items) == 1:
            return str(items[0].value)
        return "0"

    def byte_math_option(self, items: Sequence[Any]) -> GenericOption:
        """
        Transform byte_math option.

        Args:
            items: List containing byte_math parameters

        Returns:
            GenericOption with keyword="byte_math" and formatted value string

        Usage:
            byte_math:bytes,offset,operator,rvalue,result[,flags]
            byte_math:4,0,+,10,calculated_value
        """
        params = items[0] if items else []
        value_str = ",".join(str(p.value if isinstance(p, Token) else p) for p in params)
        return GenericOption(keyword="byte_math", value=value_str, raw=f"byte_math:{value_str}")

    def byte_math_params(self, items: Sequence[Token]) -> Sequence[Token]:
        """Pass through byte_math params."""
        return items
