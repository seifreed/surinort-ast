"""
Fluent builder for constructing IDS rules programmatically.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections.abc import Sequence

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
        self._action = Action(action) if isinstance(action, str) else action
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
        self._protocol = Protocol(proto) if isinstance(proto, str) else proto
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
        self._direction = Direction(direction) if isinstance(direction, str) else direction
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
        self._dialect = Dialect(dialect) if isinstance(dialect, str) else dialect
        return self

    # ========================================================================
    # Common Options
    # ========================================================================

    def msg(self, text: str) -> RuleBuilder:
        """
        Add msg option.

        Args:
            text: Alert message text

        Returns:
            Self for chaining
        """
        self._options.append(MsgOption(text=text))
        return self

    def sid(self, value: int) -> RuleBuilder:
        """
        Add sid option.

        Args:
            value: Signature ID (must be >= 1)

        Returns:
            Self for chaining
        """
        self._options.append(SidOption(value=value))
        return self

    def rev(self, value: int) -> RuleBuilder:
        """
        Add rev option.

        Args:
            value: Revision number (must be >= 1)

        Returns:
            Self for chaining
        """
        self._options.append(RevOption(value=value))
        return self

    def gid(self, value: int) -> RuleBuilder:
        """
        Add gid option.

        Args:
            value: Generator ID (must be >= 1)

        Returns:
            Self for chaining
        """
        self._options.append(GidOption(value=value))
        return self

    def classtype(self, value: str) -> RuleBuilder:
        """
        Add classtype option.

        Args:
            value: Classification type (e.g., "trojan-activity")

        Returns:
            Self for chaining
        """
        self._options.append(ClasstypeOption(value=value))
        return self

    def priority(self, value: int) -> RuleBuilder:
        """
        Add priority option.

        Args:
            value: Priority level (1-4)

        Returns:
            Self for chaining
        """
        self._options.append(PriorityOption(value=value))
        return self

    def reference(self, ref_type: str, ref_id: str) -> RuleBuilder:
        """
        Add reference option.

        Args:
            ref_type: Reference system (e.g., "cve", "url", "bugtraq")
            ref_id: Reference identifier

        Returns:
            Self for chaining
        """
        self._options.append(ReferenceOption(ref_type=ref_type, ref_id=ref_id))
        return self

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
        self._options.append(MetadataOption(entries=list(entries)))
        return self

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
        modifiers: list[ContentModifier] = []

        # Build modifiers list
        if offset is not None:
            self._options.append(OffsetOption(value=offset))
        if depth is not None:
            self._options.append(DepthOption(value=depth))
        if distance is not None:
            self._options.append(DistanceOption(value=distance))
        if within is not None:
            self._options.append(WithinOption(value=within))

        # Add content option
        self._options.append(ContentOption(pattern=pattern, modifiers=modifiers))

        # Add boolean modifier options
        if nocase:
            self._options.append(NocaseOption())
        if rawbytes:
            self._options.append(RawbytesOption())
        if startswith:
            self._options.append(StartswithOption())
        if endswith:
            self._options.append(EndswithOption())
        if fast_pattern:
            self._options.append(FastPatternOption())

        # Add sticky buffer selections
        for buffer_name, enabled in sticky_buffers.items():
            if enabled:
                self._options.append(BufferSelectOption(buffer_name=buffer_name))

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

        Example:
            >>> builder.pcre(r"/admin/i", flags="i")
        """
        self._options.append(PcreOption(pattern=pattern, flags=flags))
        return self

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
        self._options.append(FlowbitsOption(action=action, name=name))
        return self

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
        self._options.append(DetectionFilterOption(track=track, count=count, seconds=seconds))
        return self

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
        self._options.append(TagOption(tag_type=tag_type, count=count, metric=metric))
        return self

    def filestore(self, direction: str | None = None, scope: str | None = None) -> RuleBuilder:
        """
        Add filestore option.

        Args:
            direction: Optional direction (request, response, both)
            scope: Optional scope (file, stream)

        Returns:
            Self for chaining
        """
        self._options.append(FilestoreOption(direction=direction, scope=scope))
        return self

    def lua(self, script_name: str, negated: bool = False) -> RuleBuilder:
        """
        Add lua option.

        Args:
            script_name: Lua script filename
            negated: Whether to negate the match

        Returns:
            Self for chaining
        """
        self._options.append(LuaOption(script_name=script_name, negated=negated))
        return self

    def luajit(self, script_name: str, negated: bool = False) -> RuleBuilder:
        """
        Add luajit option.

        Args:
            script_name: Lua script filename
            negated: Whether to negate the match

        Returns:
            Self for chaining
        """
        self._options.append(LuajitOption(script_name=script_name, negated=negated))
        return self

    def buffer_select(self, buffer_name: str) -> RuleBuilder:
        """
        Add sticky buffer selection.

        Args:
            buffer_name: Buffer name (http_uri, http_header, file_data, etc.)

        Returns:
            Self for chaining
        """
        self._options.append(BufferSelectOption(buffer_name=buffer_name))
        return self

    def fast_pattern(self, offset: int | None = None, length: int | None = None) -> RuleBuilder:
        """
        Add fast_pattern option.

        Args:
            offset: Optional offset
            length: Optional length

        Returns:
            Self for chaining
        """
        self._options.append(FastPatternOption(offset=offset, length=length))
        return self

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
        self._options.append(opt)
        return self

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

        # Handle variables ($HOME_NET, etc.)
        if addr_str.startswith("$"):
            return AddressVariable(name=addr_str)

        # Handle negation (!192.168.1.1)
        if addr_str.startswith("!"):
            inner = self._parse_address(addr_str[1:])
            return AddressNegation(expr=inner)

        # Handle ranges [10.0.0.1-10.0.0.255] - check before lists
        if addr_str.startswith("[") and addr_str.endswith("]"):
            inner = addr_str[1:-1]
            # Check if it's a range (contains dash but not comma)
            if "-" in inner and "," not in inner:
                parts = inner.split("-")
                if len(parts) != 2:
                    raise BuilderError(f"Invalid IP range format: {addr_str}")
                return IPRange(start=parts[0].strip(), end=parts[1].strip())
            # Otherwise it's a list
            elements_str = inner.split(",")
            elements = [self._parse_address(e.strip()) for e in elements_str]
            return AddressList(elements=elements)

        # Handle CIDR (10.0.0.0/8)
        if "/" in addr_str:
            parts = addr_str.split("/")
            if len(parts) != 2:
                raise BuilderError(f"Invalid CIDR format: {addr_str}")
            try:
                prefix_len = int(parts[1])
                return IPCIDRRange(network=parts[0], prefix_len=prefix_len)
            except ValueError as e:
                raise BuilderError(f"Invalid CIDR prefix length: {parts[1]}") from e

        # Handle single IP (assume IPv4/IPv6)
        if ":" in addr_str:
            # IPv6
            return IPAddress(value=addr_str, version=6)
        # IPv4
        return IPAddress(value=addr_str, version=4)

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

        # Handle variables ($HTTP_PORTS, etc.)
        if port_str.startswith("$"):
            return PortVariable(name=port_str)

        # Handle negation (!80)
        if port_str.startswith("!"):
            inner = self._parse_port(port_str[1:])
            return PortNegation(expr=inner)

        # Handle lists [80,443,8080:8090]
        if port_str.startswith("[") and port_str.endswith("]"):
            elements_str = port_str[1:-1].split(",")
            elements = [self._parse_port(e.strip()) for e in elements_str]
            return PortList(elements=elements)

        # Handle ranges (1024:65535)
        if ":" in port_str:
            parts = port_str.split(":")
            if len(parts) != 2:
                raise BuilderError(f"Invalid port range format: {port_str}")
            try:
                start = int(parts[0])
                end = int(parts[1])
                return PortRange(start=start, end=end)
            except ValueError as e:
                raise BuilderError(f"Invalid port range values: {port_str}") from e

        # Handle single port
        try:
            return Port(value=int(port_str))
        except ValueError as e:
            raise BuilderError(f"Invalid port format: {port_str}") from e
