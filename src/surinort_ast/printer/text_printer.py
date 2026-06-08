"""
Pretty-printer for converting AST nodes to text format.

This module provides text rendering for Suricata/Snort rule AST nodes,
with support for multiple formatting styles and stable canonical output.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections.abc import Sequence
from functools import singledispatch
from typing import Protocol

from surinort_ast.core.enums import ContentModifierType
from surinort_ast.core.nodes import (
    AddressExpr,
    AddressList,
    AddressNegation,
    AddressVariable,
    AnyAddress,
    AnyPort,
    BufferSelectOption,
    ByteExtractOption,
    ByteJumpOption,
    ByteTestOption,
    ClasstypeOption,
    ContentModifier,
    ContentOption,
    DepthOption,
    DetectionFilterOption,
    DistanceOption,
    EndswithOption,
    FastPatternOption,
    FilestoreOption,
    FlowbitsOption,
    FlowOption,
    GenericOption,
    GidOption,
    Header,
    IPAddress,
    IPCIDRRange,
    IPRange,
    LuajitOption,
    LuaOption,
    MetadataOption,
    MsgOption,
    NocaseOption,
    OffsetOption,
    Option,
    PcreOption,
    Port,
    PortExpr,
    PortList,
    PortNegation,
    PortRange,
    PortVariable,
    PriorityOption,
    RawbytesOption,
    ReferenceOption,
    RevOption,
    Rule,
    SidOption,
    StartswithOption,
    TagOption,
    ThresholdOption,
    WithinOption,
)

from .formatter import FormatterOptions


class _TextPrinter(Protocol):
    """Minimal interface expected by option dispatch implementations."""

    def _print_content(self, option: ContentOption) -> str:
        """Format a content option for output."""


# ============================================================================
# Option Printing Dispatch (Singledispatch for O(1) type-based dispatch)
# ============================================================================


@singledispatch
def _print_option_dispatch(
    option: Option, fmt_opts: FormatterOptions, printer: _TextPrinter
) -> str:
    """
    Print option using singledispatch pattern.

    This function uses functools.singledispatch to provide O(1) type-based
    dispatch instead of O(n) isinstance chains, reducing cyclomatic complexity.

    Args:
        option: The option to print
        fmt_opts: Formatting options
        printer: The TextPrinter instance (for accessing helper methods)

    Returns:
        Formatted option text
    """
    # Fallback for unknown option types — try to preserve data
    keyword = option.node_type.lower()
    # Try common field names to avoid silent data loss
    value = getattr(option, "value", None)
    if value is not None:
        return f"{keyword}:{value};"
    raw = getattr(option, "raw", None)
    if raw is not None:
        return f"{raw};" if not raw.endswith(";") else raw
    return f"{keyword};"


_CONTENT_HEX_BYTES = frozenset({ord("|"), ord("\\"), ord('"'), ord(";")})


def _escape_quoted(text: str) -> str:
    """Escape backslashes and double quotes so quoted text re-parses exactly.

    Mirrors the unescaping done when parsing a quoted string (``\\"`` -> ``"``,
    ``\\\\`` -> ``\\``); backslashes must be escaped first.
    """
    return text.replace("\\", "\\\\").replace('"', '\\"')


@_print_option_dispatch.register
def _(option: MsgOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    quote = fmt_opts.get_quote_char()
    return f"msg:{quote}{_escape_quoted(option.text)}{quote};"


@_print_option_dispatch.register
def _(option: SidOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return f"sid:{option.value};"


@_print_option_dispatch.register
def _(option: RevOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return f"rev:{option.value};"


@_print_option_dispatch.register
def _(option: GidOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return f"gid:{option.value};"


@_print_option_dispatch.register
def _(option: ClasstypeOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return f"classtype:{option.value};"


@_print_option_dispatch.register
def _(option: PriorityOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return f"priority:{option.value};"


@_print_option_dispatch.register
def _(option: ReferenceOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return f"reference:{option.ref_type},{option.ref_id};"


@_print_option_dispatch.register
def _(option: MetadataOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    sep = fmt_opts.format_list_separator()
    entries = sep.join(f"{k} {v}" for k, v in option.entries)
    return f"metadata:{entries};"


@_print_option_dispatch.register
def _(option: ContentOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return printer._print_content(option)


@_print_option_dispatch.register
def _(option: PcreOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    quote = fmt_opts.get_quote_char()
    flags = option.flags if option.flags else ""
    negation = "!" if option.negated else ""
    return f"pcre:{negation}{quote}/{option.pattern}/{flags}{quote};"


@_print_option_dispatch.register
def _(option: FlowOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    sep = fmt_opts.format_list_separator()
    parts: list[str] = []
    parts.extend(d.value for d in option.directions)
    parts.extend(s.value for s in option.states)
    flow_str = sep.join(parts)
    return f"flow:{flow_str};"


@_print_option_dispatch.register
def _(option: FlowbitsOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    # Actions like noalert have no bit name; emitting a trailing comma
    # (flowbits:noalert,;) produces unparseable output.
    if option.name:
        return f"flowbits:{option.action},{option.name};"
    return f"flowbits:{option.action};"


@_print_option_dispatch.register
def _(option: ThresholdOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    sep = fmt_opts.format_list_separator()
    parts = [
        f"type {option.threshold_type}",
        f"track {option.track}",
        f"count {option.count}",
        f"seconds {option.seconds}",
    ]
    return f"threshold:{sep.join(parts)};"


@_print_option_dispatch.register
def _(option: DetectionFilterOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    sep = fmt_opts.format_list_separator()
    parts = [
        f"track {option.track}",
        f"count {option.count}",
        f"seconds {option.seconds}",
    ]
    return f"detection_filter:{sep.join(parts)};"


@_print_option_dispatch.register
def _(option: BufferSelectOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return f"{option.buffer_name};"


@_print_option_dispatch.register
def _(option: ByteTestOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    sep = fmt_opts.format_list_separator()
    parts = [
        str(option.bytes_to_extract),
        option.operator,
        str(option.value),
        str(option.offset),
    ]
    if option.flags:
        parts.extend(option.flags)
    return f"byte_test:{sep.join(parts)};"


@_print_option_dispatch.register
def _(option: ByteJumpOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    sep = fmt_opts.format_list_separator()
    parts = [str(option.bytes_to_extract), str(option.offset)]
    if option.flags:
        parts.extend(option.flags)
    return f"byte_jump:{sep.join(parts)};"


@_print_option_dispatch.register
def _(option: ByteExtractOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    sep = fmt_opts.format_list_separator()
    parts = [
        str(option.bytes_to_extract),
        str(option.offset),
        option.var_name,
    ]
    if option.flags:
        parts.extend(option.flags)
    return f"byte_extract:{sep.join(parts)};"


@_print_option_dispatch.register
def _(option: FastPatternOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    if option.offset is not None and option.length is not None:
        return f"fast_pattern:{option.offset},{option.length};"
    return "fast_pattern;"


@_print_option_dispatch.register
def _(option: TagOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return f"tag:{option.tag_type},{option.count},{option.metric};"


@_print_option_dispatch.register
def _(option: FilestoreOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    if option.direction and option.scope:
        return f"filestore:{option.direction},{option.scope};"
    if option.direction:
        return f"filestore:{option.direction};"
    return "filestore;"


@_print_option_dispatch.register
def _(option: LuaOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    negation = "!" if option.negated else ""
    return f"lua:{negation}{option.script_name};"


@_print_option_dispatch.register
def _(option: LuajitOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    negation = "!" if option.negated else ""
    return f"luajit:{negation}{option.script_name};"


@_print_option_dispatch.register
def _(option: NocaseOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return "nocase;"


@_print_option_dispatch.register
def _(option: RawbytesOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return "rawbytes;"


@_print_option_dispatch.register
def _(option: DepthOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return f"depth:{option.value};"


@_print_option_dispatch.register
def _(option: OffsetOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return f"offset:{option.value};"


@_print_option_dispatch.register
def _(option: DistanceOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return f"distance:{option.value};"


@_print_option_dispatch.register
def _(option: WithinOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return f"within:{option.value};"


@_print_option_dispatch.register
def _(option: StartswithOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return "startswith;"


@_print_option_dispatch.register
def _(option: EndswithOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    return "endswith;"


@_print_option_dispatch.register
def _(option: GenericOption, fmt_opts: FormatterOptions, printer: _TextPrinter) -> str:
    # Use raw representation (returned as-is to preserve original formatting)
    # Add semicolon only if not already present
    if option.raw.endswith(";"):
        return option.raw
    return f"{option.raw};"


class TextPrinter:
    """
    Pretty-printer for AST nodes to text format.

    Converts AST nodes back to their textual representation with
    configurable formatting options.

    Attributes:
        options: Formatting options
    """

    def __init__(self, options: FormatterOptions | None = None) -> None:
        """
        Initialize the text printer.

        Args:
            options: Formatting options (defaults to standard style)
        """
        self.options = options or FormatterOptions.standard()

    def print_rule(self, rule: Rule) -> str:
        """
        Print a single rule to text format.

        Args:
            rule: The rule to print

        Returns:
            Formatted rule text

        Example:
            >>> printer = TextPrinter()
            >>> text = printer.print_rule(rule)
            >>> print(text)
            alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001; rev:1;)
        """
        parts = []

        # Add comments if present
        if self.options.preserve_comments and rule.comments:
            for comment in rule.comments:
                # Split multi-line comments so every physical line is
                # prefixed with '#'; otherwise an embedded newline would
                # leave a bare continuation that could be mistaken for a
                # new rule by downstream consumers.
                for line in comment.split("\n"):
                    parts.append(f"# {line}")

        # Build rule line: action header (options)
        rule_line = f"{rule.action.value} {self._print_header(rule.header)}"

        if rule.options:
            options_text = self._print_options(rule.options)
            rule_line += f" ({options_text})"

        parts.append(rule_line)

        return "\n".join(parts)

    def print_rules(self, rules: Sequence[Rule]) -> str:
        """
        Print multiple rules to text format.

        Args:
            rules: Sequence of rules to print

        Returns:
            Formatted rules text with one rule per line

        Example:
            >>> printer = TextPrinter()
            >>> text = printer.print_rules(rules)
        """
        return "\n".join(self.print_rule(rule) for rule in rules)

    def _print_header(self, header: Header) -> str:
        """
        Print rule header.

        Args:
            header: The header to print

        Returns:
            Formatted header text
        """
        src_addr = self._print_address(header.src_addr)
        src_port = self._print_port(header.src_port)
        dst_addr = self._print_address(header.dst_addr)
        dst_port = self._print_port(header.dst_port)

        parts = [
            header.protocol.value,
            src_addr,
            src_port,
            header.direction.value,
            dst_addr,
            dst_port,
        ]

        return " ".join(parts)

    def _print_address(self, addr: AddressExpr) -> str:
        """
        Print address expression.

        Args:
            addr: Address expression to print

        Returns:
            Formatted address text
        """
        if isinstance(addr, AnyAddress):
            return "any"
        if isinstance(addr, IPAddress):
            return addr.value
        if isinstance(addr, IPCIDRRange):
            return f"{addr.network}/{addr.prefix_len}"
        if isinstance(addr, IPRange):
            return f"[{addr.start}-{addr.end}]"
        if isinstance(addr, AddressVariable):
            return f"${addr.name}"
        if isinstance(addr, AddressNegation):
            inner = self._print_address(addr.expr)
            return f"!{inner}"
        if isinstance(addr, AddressList):
            sep = self.options.format_list_separator()
            elements = sep.join(self._print_address(e) for e in addr.elements)
            return f"[{elements}]"
        return "any"

    def _print_port(self, port: PortExpr) -> str:
        """
        Print port expression.

        Args:
            port: Port expression to print

        Returns:
            Formatted port text
        """
        if isinstance(port, AnyPort):
            return "any"
        if isinstance(port, Port):
            return str(port.value)
        if isinstance(port, PortRange):
            return f"{port.start}:{port.end}"
        if isinstance(port, PortVariable):
            return f"${port.name}"
        if isinstance(port, PortNegation):
            inner = self._print_port(port.expr)
            return f"!{inner}"
        if isinstance(port, PortList):
            sep = self.options.format_list_separator()
            elements = sep.join(self._print_port(e) for e in port.elements)
            return f"[{elements}]"
        return "any"

    def _print_options(self, options: Sequence[Option]) -> str:
        """
        Print rule options.

        Args:
            options: Sequence of options to print

        Returns:
            Formatted options text
        """
        option_strs = [self._print_option(opt) for opt in options]
        separator = self.options.option_separator
        return separator.join(option_strs)

    def _print_option(self, option: Option) -> str:
        """
        Print a single option using singledispatch.

        Args:
            option: The option to print

        Returns:
            Formatted option text
        """
        return _print_option_dispatch(option, self.options, self)

    def _print_content(self, content: ContentOption) -> str:
        """
        Print content option with modifiers.

        Args:
            content: Content option to print

        Returns:
            Formatted content text
        """
        quote = self.options.get_quote_char()

        # Format the pattern
        pattern_str = self._format_content_pattern(content.pattern)

        # Build content string
        negation = "!" if content.negated else ""
        result = f"content:{negation}{quote}{pattern_str}{quote};"

        # Add modifiers
        if content.modifiers:
            sep = self.options.option_separator
            modifier_strs = [self._print_content_modifier(m) for m in content.modifiers]
            result += sep + sep.join(modifier_strs)

        return result

    def _format_content_pattern(self, pattern: bytes) -> str:
        """
        Format content pattern as human-readable string.

        Converts bytes to appropriate representation (printable ASCII or hex).

        Args:
            pattern: The pattern bytes

        Returns:
            Formatted pattern string
        """
        parts = []
        i = 0

        def is_literal(byte: int) -> bool:
            # Printable ASCII, excluding bytes that are special inside a quoted
            # content string and must be hex-encoded: | (hex delimiter),
            # backslash, double quote (string terminator) and ; (option
            # terminator). Emitting these literally yields unparseable output.
            return 32 <= byte <= 126 and byte not in _CONTENT_HEX_BYTES

        while i < len(pattern):
            byte = pattern[i]

            if is_literal(byte):
                # Accumulate printable characters
                start = i
                while i < len(pattern) and is_literal(pattern[i]):
                    i += 1
                parts.append(pattern[start:i].decode("ascii"))
            else:
                # Format as hex
                hex_str = f"{byte:02X}" if self.options.hex_uppercase else f"{byte:02x}"
                parts.append(f"|{hex_str}|")
                i += 1

        return "".join(parts)

    def _print_content_modifier(self, modifier: ContentModifier) -> str:
        """
        Print content modifier.

        Args:
            modifier: Content modifier to print

        Returns:
            Formatted modifier text
        """
        name = (
            modifier.name.value if isinstance(modifier.name, ContentModifierType) else modifier.name
        )
        if modifier.value is None:
            return f"{name};"
        return f"{name}:{modifier.value};"


def print_rule(rule: Rule, options: FormatterOptions | None = None) -> str:
    """
    Convenience function to print a rule.

    Args:
        rule: The rule to print
        options: Formatting options (optional)

    Returns:
        Formatted rule text
    """
    printer = TextPrinter(options)
    return printer.print_rule(rule)


def print_rules(rules: Sequence[Rule], options: FormatterOptions | None = None) -> str:
    """
    Convenience function to print multiple rules.

    Args:
        rules: Sequence of rules to print
        options: Formatting options (optional)

    Returns:
        Formatted rules text
    """
    printer = TextPrinter(options)
    return printer.print_rules(rules)
