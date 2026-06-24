"""
Fluent builder for constructing IDS rules programmatically.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import Enum
from typing import TypeVar

from ..core.enums import Action, Dialect, Direction, Protocol
from ..core.nodes import (
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
    WithinOption,
)
from .option_builders import ContentBuilder, FlowBuilder, ThresholdBuilder

_PCRE_FLAG_CHARS = frozenset("ismxAEGRUBPHKDSWYCO")

_EnumT = TypeVar("_EnumT", bound=Enum)


def _coerce_enum(value: _EnumT | str, enum_cls: type[_EnumT]) -> _EnumT:
    """Coerce a string into ``enum_cls``; leave an existing enum member as-is."""
    return enum_cls(value) if isinstance(value, str) else value


def _normalize_pcre(pattern: str) -> tuple[str, str]:
    """Split a ``/body/flags`` PCRE literal into ``(body, flags)``.

    The AST stores the bare regex body separately from the flags (the printer
    re-adds the ``/.../`` delimiters), so a delimited literal must be unwrapped
    to round-trip correctly. A bare pattern is returned unchanged with empty
    flags. Only a leading ``/`` whose closing ``/`` is followed exclusively by
    valid PCRE flag characters is treated as delimited, so a pattern that merely
    starts with ``/`` is preserved verbatim.
    """
    if len(pattern) >= 2 and pattern.startswith("/"):
        close = pattern.rfind("/")
        if close > 0:
            candidate_flags = pattern[close + 1 :]
            if all(char in _PCRE_FLAG_CHARS for char in candidate_flags):
                return pattern[1:close], candidate_flags
    return pattern, ""


class BuilderError(Exception):
    """Exception raised when builder configuration is invalid."""


class RuleBuilder:
    """
    Fluent builder for constructing IDS Rule AST nodes.

    This class provides a chainable API for building rules programmatically
    without parsing text. All configuration is validated at build() time.

    Example:
        >>> rule = (
        ...     RuleBuilder()
        ...     .alert()
        ...     .protocol("tcp")
        ...     .source_ip("any").source_port("any")
        ...     .dest_ip("$HOME_NET").dest_port(80)
        ...     .msg("Example rule")
        ...     .sid(1000001)
        ...     .rev(1)
        ...     .build()
        ... )

    Attributes:
        _action: Rule action (alert, drop, etc.)
        _protocol: Network protocol
        _src_addr: Source address expression
        _src_port: Source port expression
        _direction: Traffic direction
        _dst_addr: Destination address expression
        _dst_port: Destination port expression
        _options: List of rule options
        _dialect: Rule dialect (Suricata, Snort2, Snort3)
    """

    def __init__(self) -> None:
        """Initialize empty rule builder."""
        self._action: Action | None = None
        self._protocol: Protocol | None = None
        self._src_addr: AddressExpr | None = None
        self._src_port: PortExpr | None = None
        self._direction: Direction = Direction.TO
        self._dst_addr: AddressExpr | None = None
        self._dst_port: PortExpr | None = None
        self._options: list[Option] = []
        self._dialect: Dialect = Dialect.SURICATA

    # ========================================================================
    # Action Methods
    # ========================================================================

    def action(self, action: Action | str) -> RuleBuilder:
        """
        Set the rule action.

        Args:
            action: Action enum or string ("alert", "drop", etc.)

        Returns:
            Self for chaining
        """
        self._action = _coerce_enum(action, Action)
        return self

    def alert(self) -> RuleBuilder:
        """Set action to ALERT."""
        return self.action(Action.ALERT)

    def drop(self) -> RuleBuilder:
        """Set action to DROP."""
        return self.action(Action.DROP)

    def reject(self) -> RuleBuilder:
        """Set action to REJECT."""
        return self.action(Action.REJECT)

    def pass_(self) -> RuleBuilder:
        """Set action to PASS."""
        return self.action(Action.PASS)

    def log(self) -> RuleBuilder:
        """Set action to LOG."""
        return self.action(Action.LOG)

    def sdrop(self) -> RuleBuilder:
        """Set action to SDROP (Suricata)."""
        return self.action(Action.SDROP)

    # ========================================================================
    # Header Configuration
    # ========================================================================

    def protocol(self, proto: Protocol | str) -> RuleBuilder:
        """
        Set the protocol.

        Args:
            proto: Protocol enum or string ("tcp", "udp", "http", etc.)

        Returns:
            Self for chaining
        """
        self._protocol = _coerce_enum(proto, Protocol)
        return self

    def tcp(self) -> RuleBuilder:
        """Set protocol to TCP."""
        return self.protocol(Protocol.TCP)

    def udp(self) -> RuleBuilder:
        """Set protocol to UDP."""
        return self.protocol(Protocol.UDP)

    def icmp(self) -> RuleBuilder:
        """Set protocol to ICMP."""
        return self.protocol(Protocol.ICMP)

    def http(self) -> RuleBuilder:
        """Set protocol to HTTP."""
        return self.protocol(Protocol.HTTP)

    def dns(self) -> RuleBuilder:
        """Set protocol to DNS."""
        return self.protocol(Protocol.DNS)

    def tls(self) -> RuleBuilder:
        """Set protocol to TLS."""
        return self.protocol(Protocol.TLS)

    def source_ip(self, addr: str | AddressExpr) -> RuleBuilder:
        """
        Set source IP address.

        Args:
            addr: Address string or AddressExpr node
                 Examples: "any", "192.168.1.1", "10.0.0.0/8", "$HOME_NET"

        Returns:
            Self for chaining
        """
        self._src_addr = self._parse_address(addr)
        return self

    def source_port(self, port: int | str | PortExpr) -> RuleBuilder:
        """
        Set source port.

        Args:
            port: Port number, "any", or PortExpr node
                 Examples: 80, "any", "1024:65535", "$HTTP_PORTS"

        Returns:
            Self for chaining
        """
        self._src_port = self._parse_port(port)
        return self

    def dest_ip(self, addr: str | AddressExpr) -> RuleBuilder:
        """
        Set destination IP address.

        Args:
            addr: Address string or AddressExpr node

        Returns:
            Self for chaining
        """
        self._dst_addr = self._parse_address(addr)
        return self

    def dest_port(self, port: int | str | PortExpr) -> RuleBuilder:
        """
        Set destination port.

        Args:
            port: Port number, "any", or PortExpr node

        Returns:
            Self for chaining
        """
        self._dst_port = self._parse_port(port)
        return self

    def direction(self, direction: Direction | str) -> RuleBuilder:
        """
        Set traffic direction.

        Args:
            direction: Direction enum or string ("->", "<-", "<>")

        Returns:
            Self for chaining
        """
        self._direction = _coerce_enum(direction, Direction)
        return self

    def to(self) -> RuleBuilder:
        """Set direction to TO (->)."""
        self._direction = Direction.TO
        return self

    def from_(self) -> RuleBuilder:
        """Set direction to FROM (<-)."""
        self._direction = Direction.FROM
        return self

    def bidirectional(self) -> RuleBuilder:
        """Set direction to BIDIRECTIONAL (<>)."""
        self._direction = Direction.BIDIRECTIONAL
        return self

    def dialect(self, dialect: Dialect | str) -> RuleBuilder:
        """
        Set rule dialect.

        Args:
            dialect: Dialect enum or string ("suricata", "snort2", "snort3")

        Returns:
            Self for chaining
        """
        self._dialect = _coerce_enum(dialect, Dialect)
        return self

    # ========================================================================
    # Common Options
    # ========================================================================

    def _add_option(self, option: Option) -> RuleBuilder:
        """Append a rule option and return self for chaining."""
        self._options.append(option)
        return self

    def msg(self, text: str) -> RuleBuilder:
        """
        Add msg option.

        Args:
            text: Alert message text

        Returns:
            Self for chaining
        """
        return self._add_option(MsgOption(text=text))

    def sid(self, value: int) -> RuleBuilder:
        """
        Add sid option.

        Args:
            value: Signature ID (must be >= 1)

        Returns:
            Self for chaining
        """
        return self._add_option(SidOption(value=value))

    def rev(self, value: int) -> RuleBuilder:
        """
        Add rev option.

        Args:
            value: Revision number (must be >= 1)

        Returns:
            Self for chaining
        """
        return self._add_option(RevOption(value=value))

    def gid(self, value: int) -> RuleBuilder:
        """
        Add gid option.

        Args:
            value: Generator ID (must be >= 1)

        Returns:
            Self for chaining
        """
        return self._add_option(GidOption(value=value))

    def classtype(self, value: str) -> RuleBuilder:
        """
        Add classtype option.

        Args:
            value: Classification type (e.g., "trojan-activity")

        Returns:
            Self for chaining
        """
        return self._add_option(ClasstypeOption(value=value))

    def priority(self, value: int) -> RuleBuilder:
        """
        Add priority option.

        Args:
            value: Priority level (1-4)

        Returns:
            Self for chaining
        """
        return self._add_option(PriorityOption(value=value))

    def reference(self, ref_type: str, ref_id: str) -> RuleBuilder:
        """
        Add reference option.

        Args:
            ref_type: Reference system (e.g., "cve", "url", "bugtraq")
            ref_id: Reference identifier

        Returns:
            Self for chaining
        """
        return self._add_option(ReferenceOption(ref_type=ref_type, ref_id=ref_id))

    def metadata(self, *entries: tuple[str, str]) -> RuleBuilder:
        """
        Add metadata option.

        Args:
            *entries: Variable number of (key, value) tuples

        Returns:
            Self for chaining

        Example:
            >>> builder.metadata(("policy", "balanced"), ("created_at", "2025-01-01"))
        """
        return self._add_option(MetadataOption(entries=list(entries)))

    # ========================================================================
    # Content and Pattern Matching
    # ========================================================================

    def content(
        self,
        pattern: bytes,
        nocase: bool = False,
        offset: int | str | None = None,
        depth: int | str | None = None,
        distance: int | str | None = None,
        within: int | str | None = None,
        rawbytes: bool = False,
        fast_pattern: bool = False,
        startswith: bool = False,
        endswith: bool = False,
        **sticky_buffers: bool,
    ) -> RuleBuilder:
        """
        Add content option with modifiers.

        Args:
            pattern: Byte pattern to match
            nocase: Case-insensitive matching
            offset: Offset from start of buffer
            depth: Maximum search depth
            distance: Distance from previous match
            within: Within bytes of previous match
            rawbytes: Match on raw packet data
            fast_pattern: Use as fast pattern
            startswith: Match at start of buffer
            endswith: Match at end of buffer
            **sticky_buffers: Sticky buffer selections (http_uri=True, etc.)

        Returns:
            Self for chaining

        Example:
            >>> builder.content(b"GET", nocase=True, http_uri=True)
            >>> builder.content(b"admin", offset=0, depth=100)
        """
        # Add sticky buffer selections BEFORE content (IDS rule ordering)
        for buffer_name, enabled in sticky_buffers.items():
            if enabled:
                self._options.append(BufferSelectOption(buffer_name=buffer_name))

        # Add content option
        self._options.append(ContentOption(pattern=pattern, modifiers=[]))

        # Add modifier options AFTER content (IDS rule ordering)
        if nocase:
            self._options.append(NocaseOption())
        if rawbytes:
            self._options.append(RawbytesOption())
        if offset is not None:
            self._options.append(OffsetOption(value=offset))
        if depth is not None:
            self._options.append(DepthOption(value=depth))
        if distance is not None:
            self._options.append(DistanceOption(value=distance))
        if within is not None:
            self._options.append(WithinOption(value=within))
        if startswith:
            self._options.append(StartswithOption())
        if endswith:
            self._options.append(EndswithOption())
        if fast_pattern:
            self._options.append(FastPatternOption())

        return self

    def content_builder(self) -> ContentBuilder:
        """
        Get a ContentBuilder for advanced content configuration.

        Returns:
            ContentBuilder instance linked to this RuleBuilder
        """
        return ContentBuilder(self)

    def pcre(self, pattern: str, flags: str = "") -> RuleBuilder:
        """
        Add pcre option.

        Args:
            pattern: Regular expression pattern
            flags: PCRE flags (i, s, m, x, etc.)

        Returns:
            Self for chaining

        The pattern may be given either as the bare regex body or as a full
        ``/body/flags`` literal; in both cases the stored option holds the bare
        body so it re-serializes correctly. An explicit ``flags`` argument takes
        precedence over flags embedded in a delimited pattern.

        Example:
            >>> builder.pcre("admin", flags="i")
            >>> builder.pcre(r"/admin/i")
        """
        body, embedded_flags = _normalize_pcre(pattern)
        return self._add_option(PcreOption(pattern=body, flags=flags or embedded_flags))

    # ========================================================================
    # Flow and State
    # ========================================================================

    def flow_builder(self) -> FlowBuilder:
        """
        Get a FlowBuilder for advanced flow configuration.

        Returns:
            FlowBuilder instance linked to this RuleBuilder
        """
        return FlowBuilder(self)

    def flowbits(self, action: str, name: str) -> RuleBuilder:
        """
        Add flowbits option.

        Args:
            action: Flowbits action (set, isset, toggle, unset, etc.)
            name: Flowbit name

        Returns:
            Self for chaining
        """
        return self._add_option(FlowbitsOption(action=action, name=name))

    # ========================================================================
    # Thresholding
    # ========================================================================

    def threshold_builder(self) -> ThresholdBuilder:
        """
        Get a ThresholdBuilder for advanced threshold configuration.

        Returns:
            ThresholdBuilder instance linked to this RuleBuilder
        """
        return ThresholdBuilder(self)

    def detection_filter(self, track: str, count: int, seconds: int) -> RuleBuilder:
        """
        Add detection_filter option.

        Args:
            track: Track by (by_src, by_dst)
            count: Event count threshold
            seconds: Time window in seconds

        Returns:
            Self for chaining
        """
        return self._add_option(DetectionFilterOption(track=track, count=count, seconds=seconds))

    # ========================================================================
    # Advanced Options
    # ========================================================================

    def byte_test(
        self,
        bytes_to_extract: int,
        operator: str,
        value: int,
        offset: int,
        flags: Sequence[str] | None = None,
    ) -> RuleBuilder:
        """
        Add byte_test option.

        Args:
            bytes_to_extract: Number of bytes to extract
            operator: Comparison operator (>, <, =, etc.)
            value: Value to compare against
            offset: Offset from cursor
            flags: Optional flags list

        Returns:
            Self for chaining
        """
        self._options.append(
            ByteTestOption(
                bytes_to_extract=bytes_to_extract,
                operator=operator,
                value=value,
                offset=offset,
                flags=list(flags) if flags else [],
            )
        )
        return self

    def byte_jump(
        self,
        bytes_to_extract: int,
        offset: int,
        flags: Sequence[str] | None = None,
    ) -> RuleBuilder:
        """
        Add byte_jump option.

        Args:
            bytes_to_extract: Number of bytes to extract
            offset: Offset adjustment
            flags: Optional flags list

        Returns:
            Self for chaining
        """
        self._options.append(
            ByteJumpOption(
                bytes_to_extract=bytes_to_extract,
                offset=offset,
                flags=list(flags) if flags else [],
            )
        )
        return self

    def byte_extract(
        self,
        bytes_to_extract: int,
        offset: int,
        var_name: str,
        flags: Sequence[str] | None = None,
    ) -> RuleBuilder:
        """
        Add byte_extract option.

        Args:
            bytes_to_extract: Number of bytes to extract
            offset: Offset from cursor
            var_name: Variable name
            flags: Optional flags list

        Returns:
            Self for chaining
        """
        self._options.append(
            ByteExtractOption(
                bytes_to_extract=bytes_to_extract,
                offset=offset,
                var_name=var_name,
                flags=list(flags) if flags else [],
            )
        )
        return self

    def tag(self, tag_type: str, count: int, metric: str) -> RuleBuilder:
        """
        Add tag option.

        Args:
            tag_type: Tag type (session, host)
            count: Count value
            metric: Metric (packets, seconds, bytes)

        Returns:
            Self for chaining
        """
        return self._add_option(TagOption(tag_type=tag_type, count=count, metric=metric))

    def filestore(self, direction: str | None = None, scope: str | None = None) -> RuleBuilder:
        """
        Add filestore option.

        Args:
            direction: Optional direction (request, response, both)
            scope: Optional scope (file, stream)

        Returns:
            Self for chaining
        """
        return self._add_option(FilestoreOption(direction=direction, scope=scope))

    def lua(self, script_name: str, negated: bool = False) -> RuleBuilder:
        """
        Add lua option.

        Args:
            script_name: Lua script filename
            negated: Whether to negate the match

        Returns:
            Self for chaining
        """
        return self._add_option(LuaOption(script_name=script_name, negated=negated))

    def luajit(self, script_name: str, negated: bool = False) -> RuleBuilder:
        """
        Add luajit option.

        Args:
            script_name: Lua script filename
            negated: Whether to negate the match

        Returns:
            Self for chaining
        """
        return self._add_option(LuajitOption(script_name=script_name, negated=negated))

    def buffer_select(self, buffer_name: str) -> RuleBuilder:
        """
        Add sticky buffer selection.

        Args:
            buffer_name: Buffer name (http_uri, http_header, file_data, etc.)

        Returns:
            Self for chaining
        """
        return self._add_option(BufferSelectOption(buffer_name=buffer_name))

    def fast_pattern(self, offset: int | None = None, length: int | None = None) -> RuleBuilder:
        """
        Add fast_pattern option.

        Args:
            offset: Optional offset
            length: Optional length

        Returns:
            Self for chaining
        """
        return self._add_option(FastPatternOption(offset=offset, length=length))

    # ========================================================================
    # Raw Option Addition
    # ========================================================================

    def option(self, opt: Option) -> RuleBuilder:
        """
        Add a raw Option node.

        Args:
            opt: Option instance

        Returns:
            Self for chaining
        """
        return self._add_option(opt)

    # ========================================================================
    # Build Method
    # ========================================================================

    def build(self) -> Rule:
        """
        Build and validate the Rule AST.

        Returns:
            Validated Rule instance

        Raises:
            BuilderError: If configuration is invalid or incomplete
        """
        # Validate required fields
        if self._action is None:
            raise BuilderError("Action is required (use .alert(), .drop(), etc.)")

        if self._protocol is None:
            raise BuilderError("Protocol is required (use .protocol() or .tcp(), .udp(), etc.)")

        if self._src_addr is None:
            raise BuilderError("Source IP is required (use .source_ip())")

        if self._src_port is None:
            raise BuilderError("Source port is required (use .source_port())")

        if self._dst_addr is None:
            raise BuilderError("Destination IP is required (use .dest_ip())")

        if self._dst_port is None:
            raise BuilderError("Destination port is required (use .dest_port())")

        # Build header
        header = Header(
            protocol=self._protocol,
            src_addr=self._src_addr,
            src_port=self._src_port,
            direction=self._direction,
            dst_addr=self._dst_addr,
            dst_port=self._dst_port,
        )

        # Build rule
        return Rule(
            action=self._action,
            header=header,
            options=self._options,
            dialect=self._dialect,
        )

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def _parse_address(self, addr: str | AddressExpr) -> AddressExpr:
        """
        Parse address string into AddressExpr node.

        Args:
            addr: Address string or node

        Returns:
            AddressExpr node

        Raises:
            BuilderError: If address format is invalid
        """
        if isinstance(addr, AddressExpr):
            return addr

        addr_str = addr.strip()

        # Handle "any"
        if addr_str.lower() == "any":
            return AnyAddress()

        # Handle variables ($HOME_NET, etc.) — store without $ prefix
        if addr_str.startswith("$"):
            return AddressVariable(name=addr_str[1:])

        # Handle negation (!192.168.1.1)
        if addr_str.startswith("!"):
            inner = self._parse_address(addr_str[1:])
            return AddressNegation(expr=inner)

        # Handle bracketed range or list ([10.0.0.1-10.0.0.255] / [a,b,c])
        if addr_str.startswith("[") and addr_str.endswith("]"):
            return self._parse_bracketed_address(addr_str)

        # Handle CIDR (10.0.0.0/8)
        if "/" in addr_str:
            parts = addr_str.split("/")
            if len(parts) != 2:
                raise BuilderError(f"Invalid CIDR format: {addr_str}")
            try:
                prefix_len = int(parts[1])
            except ValueError as e:
                raise BuilderError(f"Invalid CIDR prefix length: {parts[1]}") from e
            # The IPCIDRRange model is version-less and bounds the prefix at 128
            # (the IPv6 max), so an IPv4 network with a prefix in 33-128 would be
            # stored as a structurally invalid node. Reject it at the boundary;
            # IPv6 is detected by a colon in the network.
            max_prefix = 128 if ":" in parts[0] else 32
            if not 0 <= prefix_len <= max_prefix:
                version = 6 if ":" in parts[0] else 4
                raise BuilderError(
                    f"CIDR prefix /{prefix_len} out of range for IPv{version} "
                    f"(0-{max_prefix}): {addr_str}"
                )
            return IPCIDRRange(network=parts[0], prefix_len=prefix_len)

        # Handle a bare range (10.0.0.1-10.0.0.255). Lists are always bracketed
        # and a single IP never contains a dash, so an unbracketed dash denotes a
        # start-end range — without this it would fall through to IPAddress and
        # store a structurally invalid value.
        if "-" in addr_str:
            return self._parse_ip_range(addr_str)

        # Handle single IP (assume IPv4/IPv6)
        if ":" in addr_str:
            # IPv6
            return IPAddress(value=addr_str, version=6)
        # IPv4
        return IPAddress(value=addr_str, version=4)

    @staticmethod
    def _parse_ip_range(range_str: str) -> IPRange:
        """Parse a ``start-end`` IP range string into an IPRange node."""
        parts = range_str.split("-")
        if len(parts) != 2:
            raise BuilderError(f"Invalid IP range format: {range_str}")
        return IPRange(start=parts[0].strip(), end=parts[1].strip())

    def _parse_bracketed_address(self, addr_str: str) -> AddressExpr:
        """Parse a bracketed address: a range ``[a-b]`` or a list ``[a,b,c]``."""
        inner = addr_str[1:-1]
        if "-" in inner and "," not in inner:
            return self._parse_ip_range(inner)
        elements = [self._parse_address(e.strip()) for e in inner.split(",")]
        return AddressList(elements=elements)

    def _parse_port(self, port: int | str | PortExpr) -> PortExpr:
        """
        Parse port into PortExpr node.

        Args:
            port: Port number, string, or node

        Returns:
            PortExpr node

        Raises:
            BuilderError: If port format is invalid
        """
        if isinstance(port, PortExpr):
            return port

        # Handle integer
        if isinstance(port, int):
            return Port(value=port)

        port_str = str(port).strip()

        # Handle "any"
        if port_str.lower() == "any":
            return AnyPort()

        # Handle variables ($HTTP_PORTS, etc.) — store without $ prefix
        if port_str.startswith("$"):
            return PortVariable(name=port_str[1:])

        # Handle negation (!80)
        if port_str.startswith("!"):
            inner = self._parse_port(port_str[1:])
            return PortNegation(expr=inner)

        # Handle lists [80,443,8080:8090]
        if port_str.startswith("[") and port_str.endswith("]"):
            elements_str = port_str[1:-1].split(",")
            elements = [self._parse_port(e.strip()) for e in elements_str]
            return PortList(elements=elements)

        # Handle ranges (1024:65535, 1024:, :1024)
        if ":" in port_str:
            return self._parse_port_range(port_str)

        # Handle single port
        try:
            return Port(value=int(port_str))
        except ValueError as e:
            raise BuilderError(f"Invalid port format: {port_str}") from e

    def _parse_port_range(self, port_str: str) -> PortRange:
        """
        Build a ``PortRange`` from a string like ``"1024:65535"``,
        ``"1024:"`` (open-ended, end defaults to 65535), or ``":1024"``
        (upper-bounded, start is 0). Reversed ranges (e.g. ``"5000:1000"``)
        are auto-swapped, matching the parser's behavior.

        Args:
            port_str: Range expression with exactly one or two colons.

        Returns:
            A ``PortRange`` node.

        Raises:
            BuilderError: If the range syntax is invalid.
        """
        head, _, tail = port_str.partition(":")
        if ":" in tail:
            raise BuilderError(f"Invalid port range format: {port_str}")
        try:
            if head == "":
                return PortRange(start=0, end=int(tail))
            if tail == "":
                return PortRange(start=int(head), end=65535)
            start, end = int(head), int(tail)
        except ValueError as e:
            raise BuilderError(f"Invalid port range values: {port_str}") from e
        if start > end:
            start, end = end, start
        return PortRange(start=start, end=end)
