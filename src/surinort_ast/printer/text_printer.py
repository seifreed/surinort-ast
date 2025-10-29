"""
Pretty-printer for converting AST nodes to text format.

This module provides text rendering for Suricata/Snort rule AST nodes,
with support for multiple formatting styles and stable canonical output.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections.abc import Sequence

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
    DetectionFilterOption,
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
    MetadataOption,
    MsgOption,
    Option,
    PcreOption,
    Port,
    PortExpr,
    PortList,
    PortNegation,
    PortRange,
    PortVariable,
    PriorityOption,
    ReferenceOption,
    RevOption,
    Rule,
    SidOption,
    TagOption,
    ThresholdOption,
)

from .formatter import FormatterOptions


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
                parts.append(f"# {comment}")

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
        Print a single option.

        Args:
            option: The option to print

        Returns:
            Formatted option text
        """
        if isinstance(option, MsgOption):
            quote = self.options.get_quote_char()
            return f"msg:{quote}{option.text}{quote};"

        if isinstance(option, SidOption):
            return f"sid:{option.value};"

        if isinstance(option, RevOption):
            return f"rev:{option.value};"

        if isinstance(option, GidOption):
            return f"gid:{option.value};"

        if isinstance(option, ClasstypeOption):
            return f"classtype:{option.value};"

        if isinstance(option, PriorityOption):
            return f"priority:{option.value};"

        if isinstance(option, ReferenceOption):
            return f"reference:{option.ref_type},{option.ref_id};"

        if isinstance(option, MetadataOption):
            sep = self.options.format_list_separator()
            entries = sep.join(f"{k} {v}" for k, v in option.entries)
            return f"metadata:{entries};"

        if isinstance(option, ContentOption):
            return self._print_content(option)

        if isinstance(option, PcreOption):
            quote = self.options.get_quote_char()
            flags = option.flags if option.flags else ""
            return f"pcre:{quote}/{option.pattern}/{flags}{quote};"

        if isinstance(option, FlowOption):
            sep = self.options.format_list_separator()
            parts = []
            parts.extend(d.value for d in option.directions)
            parts.extend(s.value for s in option.states)
            flow_str = sep.join(parts)
            return f"flow:{flow_str};"

        if isinstance(option, FlowbitsOption):
            return f"flowbits:{option.action},{option.name};"

        if isinstance(option, ThresholdOption):
            sep = self.options.format_list_separator()
            parts = [
                f"type {option.threshold_type}",
                f"track {option.track}",
                f"count {option.count}",
                f"seconds {option.seconds}",
            ]
            return f"threshold:{sep.join(parts)};"

        if isinstance(option, DetectionFilterOption):
            sep = self.options.format_list_separator()
            parts = [
                f"track {option.track}",
                f"count {option.count}",
                f"seconds {option.seconds}",
            ]
            return f"detection_filter:{sep.join(parts)};"

        if isinstance(option, BufferSelectOption):
            return f"{option.buffer_name};"

        if isinstance(option, ByteTestOption):
            sep = self.options.format_list_separator()
            parts = [
                str(option.bytes_to_extract),
                option.operator,
                str(option.value),
                str(option.offset),
            ]
            if option.flags:
                parts.extend(option.flags)
            return f"byte_test:{sep.join(parts)};"

        if isinstance(option, ByteJumpOption):
            sep = self.options.format_list_separator()
            parts = [str(option.bytes_to_extract), str(option.offset)]
            if option.flags:
                parts.extend(option.flags)
            return f"byte_jump:{sep.join(parts)};"

        if isinstance(option, ByteExtractOption):
            sep = self.options.format_list_separator()
            parts = [
                str(option.bytes_to_extract),
                str(option.offset),
                option.var_name,
            ]
            if option.flags:
                parts.extend(option.flags)
            return f"byte_extract:{sep.join(parts)};"

        if isinstance(option, FastPatternOption):
            if option.offset is not None and option.length is not None:
                return f"fast_pattern:{option.offset},{option.length};"
            return "fast_pattern;"

        if isinstance(option, TagOption):
            return f"tag:{option.tag_type},{option.count},{option.metric};"

        if isinstance(option, FilestoreOption):
            if option.direction and option.scope:
                return f"filestore:{option.direction},{option.scope};"
            if option.direction:
                return f"filestore:{option.direction};"
            return "filestore;"

        if isinstance(option, GenericOption):
            # Use raw representation if available
            return option.raw

        # Fallback for unknown options
        return f"{option.node_type.lower()};"

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
        result = f"content:{quote}{pattern_str}{quote};"

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

        while i < len(pattern):
            byte = pattern[i]

            # Check if printable ASCII
            if 32 <= byte <= 126 and byte not in (ord("|"), ord("\\")):
                # Accumulate printable characters
                start = i
                while i < len(pattern) and 32 <= pattern[i] <= 126 and pattern[i] not in (
                    ord("|"),
                    ord("\\"),
                ):
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
        if modifier.value is None:
            return f"{modifier.name.value};"
        return f"{modifier.name.value}:{modifier.value};"


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
