"""
Lark Transformer for converting parse trees to AST nodes.

This module transforms Lark parse trees into our typed AST nodes defined
in surinort_ast.core.nodes. It handles location tracking, error recovery,
and semantic validation during transformation.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from typing import Any

from lark import Token, Tree
from lark.visitors import Transformer, v_args

from ..core.diagnostics import Diagnostic, DiagnosticLevel
from ..core.enums import (
    Action,
    ContentModifierType,
    Dialect,
    Direction,
    FlowDirection,
    FlowState,
    Protocol,
)
from ..core.location import Location, Position, Span
from ..core.nodes import (
    AddressList,
    AddressNegation,
    AddressVariable,
    AnyAddress,
    AnyPort,
    BufferSelectOption,
    ClasstypeOption,
    ContentModifier,
    ContentOption,
    DepthOption,
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
    MetadataOption,
    MsgOption,
    NocaseOption,
    OffsetOption,
    PcreOption,
    Port,
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
    WithinOption,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Helper Functions
# ============================================================================


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
        column=token.column + 1,  # Convert to 1-indexed
        offset=token.start_pos,
    )

    # Calculate end position
    end_line = getattr(token, "end_line", token.line)
    end_column = getattr(token, "end_column", token.column + len(token.value))

    end = Position(
        line=end_line,
        column=end_column + 1,  # Convert to 1-indexed
        offset=token.end_pos if hasattr(token, "end_pos") else token.start_pos + len(token.value),
    )

    span = Span(start=start, end=end)
    return Location(span=span, file_path=file_path)


def tree_to_location(tree: Tree[Token], file_path: str | None = None) -> Location | None:
    """
    Extract location from Lark Tree metadata.

    Args:
        tree: Lark parse tree
        file_path: Optional source file path

    Returns:
        Location if metadata available, None otherwise
    """
    if not hasattr(tree, "meta"):
        return None

    meta = tree.meta

    if not hasattr(meta, "line"):
        return None

    start = Position(
        line=meta.line,
        column=meta.column + 1,  # Convert to 1-indexed
        offset=meta.start_pos if hasattr(meta, "start_pos") else 0,
    )

    end_line = getattr(meta, "end_line", meta.line)
    end_column = getattr(meta, "end_column", meta.column)

    end = Position(
        line=end_line,
        column=end_column + 1,  # Convert to 1-indexed
        offset=meta.end_pos if hasattr(meta, "end_pos") else start.offset,
    )

    span = Span(start=start, end=end)
    return Location(span=span, file_path=file_path)


def parse_quoted_string(s: str) -> str:
    """
    Parse quoted string, handling escape sequences.

    Args:
        s: Quoted string (e.g., "text" or "text with \\"quotes\\"")

    Returns:
        Unquoted and unescaped string
    """
    if not s or len(s) < 2:
        return s

    # Remove quotes
    if (s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'"):
        s = s[1:-1]

    # Handle common escape sequences
    s = s.replace('\\"', '"')
    s = s.replace("\\'", "'")
    s = s.replace("\\\\", "\\")
    s = s.replace("\\n", "\n")
    s = s.replace("\\r", "\r")
    s = s.replace("\\t", "\t")

    return s


def parse_hex_string(s: str) -> bytes:
    """
    Parse hex string to bytes.

    Args:
        s: Hex string (e.g., "|48 65 6c 6c 6f|")

    Returns:
        Raw bytes
    """
    # Remove pipes and whitespace
    hex_content = (
        s.strip("|").replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")
    )

    try:
        return bytes.fromhex(hex_content)
    except ValueError as e:
        logger.warning(f"Invalid hex string '{s}': {e}")
        return b""


def parse_pcre_pattern(s: str) -> tuple[str, str]:
    """
    Parse PCRE pattern into pattern and flags.

    Args:
        s: PCRE string (e.g., "/pattern/imsxAEGRUB")

    Returns:
        Tuple of (pattern, flags)
    """
    # Match /pattern/flags format
    match = re.match(r"^/(.*)/([\w]*)$", s)
    if match:
        return match.group(1), match.group(2)

    # Fallback: treat entire string as pattern
    return s, ""


# ============================================================================
# AST Transformer
# ============================================================================


class RuleTransformer(Transformer[Token, Any]):
    """
    Transform Lark parse tree to AST nodes.

    This transformer converts the Lark parse tree into our strongly-typed
    AST node hierarchy. It handles:
    - Type conversions (tokens to enums, integers, etc.)
    - Location tracking for all nodes
    - Error recovery and diagnostic generation
    - Semantic validation during transformation
    """

    def __init__(self, file_path: str | None = None, dialect: Dialect = Dialect.SURICATA):
        """
        Initialize transformer.

        Args:
            file_path: Source file path for location tracking
            dialect: Target IDS dialect (Suricata, Snort2, Snort3)
        """
        super().__init__()
        self.file_path = file_path
        self.dialect = dialect
        self.diagnostics: list[Diagnostic] = []

    def add_diagnostic(
        self,
        level: DiagnosticLevel,
        message: str,
        location: Location | None = None,
        code: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Add a diagnostic message."""
        diag = Diagnostic(level=level, message=message, location=location, code=code, hint=hint)
        self.diagnostics.append(diag)
        logger.debug(f"Diagnostic: {diag}")

    # ========================================================================
    # Top-Level Rule
    # ========================================================================

    @v_args(inline=True)
    def rule(self, action: Action, header: Header, options: list[Any]) -> Rule:
        """Transform rule: action header (options)"""
        location = header.location  # Use header location as rule location

        rule_obj = Rule(
            action=action,
            header=header,
            options=options,
            dialect=self.dialect,
            location=location,
            diagnostics=self.diagnostics.copy(),
        )

        # Clear diagnostics for next rule
        self.diagnostics = []

        return rule_obj

    @v_args(inline=True)
    def rule_file(self, *rules: Rule | None) -> list[Rule]:
        """Transform rule_file: multiple rules"""
        # Filter out None values (from comments/newlines)
        return [r for r in rules if r is not None]

    # ========================================================================
    # Actions
    # ========================================================================

    def alert(self, _: Any) -> Action:
        """Transform 'alert' action"""
        return Action.ALERT

    def log(self, _: Any) -> Action:
        """Transform 'log' action"""
        return Action.LOG

    def pass_(self, _: Any) -> Action:
        """Transform 'pass' action"""
        return Action.PASS

    def drop(self, _: Any) -> Action:
        """Transform 'drop' action"""
        return Action.DROP

    def reject(self, _: Any) -> Action:
        """Transform 'reject' action"""
        return Action.REJECT

    def sdrop(self, _: Any) -> Action:
        """Transform 'sdrop' action"""
        return Action.SDROP

    # ========================================================================
    # Protocols
    # ========================================================================

    def tcp(self, _: Any) -> Protocol:
        return Protocol.TCP

    def udp(self, _: Any) -> Protocol:
        return Protocol.UDP

    def icmp(self, _: Any) -> Protocol:
        return Protocol.ICMP

    def ip(self, _: Any) -> Protocol:
        return Protocol.IP

    def http(self, _: Any) -> Protocol:
        return Protocol.HTTP

    def http2(self, _: Any) -> Protocol:
        return Protocol.HTTP2

    def dns(self, _: Any) -> Protocol:
        return Protocol.DNS

    def tls(self, _: Any) -> Protocol:
        return Protocol.TLS

    def ssh(self, _: Any) -> Protocol:
        return Protocol.SSH

    def ftp(self, _: Any) -> Protocol:
        return Protocol.FTP

    def ftp_data(self, _: Any) -> Protocol:
        return Protocol.FTP_DATA

    def smb(self, _: Any) -> Protocol:
        return Protocol.SMB

    def smtp(self, _: Any) -> Protocol:
        return Protocol.SMTP

    def imap(self, _: Any) -> Protocol:
        return Protocol.IMAP

    def dcerpc(self, _: Any) -> Protocol:
        return Protocol.DCERPC

    def dhcp(self, _: Any) -> Protocol:
        return Protocol.DHCP

    def nfs(self, _: Any) -> Protocol:
        return Protocol.NFS

    def sip(self, _: Any) -> Protocol:
        return Protocol.SIP

    def rdp(self, _: Any) -> Protocol:
        return Protocol.RDP

    def mqtt(self, _: Any) -> Protocol:
        return Protocol.MQTT

    def modbus(self, _: Any) -> Protocol:
        return Protocol.MODBUS

    def dnp3(self, _: Any) -> Protocol:
        return Protocol.DNP3

    def enip(self, _: Any) -> Protocol:
        return Protocol.ENIP

    def ike(self, _: Any) -> Protocol:
        return Protocol.IKE

    def krb5(self, _: Any) -> Protocol:
        return Protocol.KRB5

    def ntp(self, _: Any) -> Protocol:
        return Protocol.NTP

    def snmp(self, _: Any) -> Protocol:
        return Protocol.SNMP

    def tftp(self, _: Any) -> Protocol:
        return Protocol.TFTP

    # ========================================================================
    # Direction
    # ========================================================================

    def to(self, _: Any) -> Direction:
        """Transform '->' direction"""
        return Direction.TO

    def from_dir(self, _: Any) -> Direction:
        """Transform '<-' direction"""
        return Direction.FROM

    def bidirectional(self, _: Any) -> Direction:
        """Transform '<>' direction"""
        return Direction.BIDIRECTIONAL

    # ========================================================================
    # Header
    # ========================================================================

    @v_args(inline=True)
    def header(
        self,
        protocol: Protocol,
        src_addr: Any,
        src_port: Any,
        direction: Direction,
        dst_addr: Any,
        dst_port: Any,
    ) -> Header:
        """Transform header: protocol address port direction address port"""
        return Header(
            protocol=protocol,
            src_addr=src_addr,
            src_port=src_port,
            direction=direction,
            dst_addr=dst_addr,
            dst_port=dst_port,
        )

    # ========================================================================
    # Address Expressions
    # ========================================================================

    def address_any(self, _: Any) -> AnyAddress:
        """Transform 'any' address"""
        return AnyAddress()

    @v_args(inline=True)
    def address_var(self, var_token: Token) -> AddressVariable:
        """Transform $VARIABLE address"""
        name = str(var_token.value)
        # Remove leading $
        if name.startswith("$"):
            name = name[1:]
        return AddressVariable(name=name, location=token_to_location(var_token, self.file_path))

    @v_args(inline=True)
    def address_negation(self, addr: Any) -> AddressNegation:
        """Transform !address"""
        return AddressNegation(expr=addr)

    def address_list(self, items: Sequence[Any]) -> AddressList:
        """Transform [addr1,addr2,...]"""
        return AddressList(elements=list(items))

    @v_args(inline=True)
    def ipv4_cidr(self, ip_token: Token, prefix_token: Token) -> IPCIDRRange:
        """Transform IPv4 CIDR: 192.168.1.0/24"""
        network = str(ip_token.value)
        prefix_len = int(prefix_token.value)

        if prefix_len < 0 or prefix_len > 32:
            self.add_diagnostic(
                DiagnosticLevel.WARNING,
                f"IPv4 CIDR prefix length {prefix_len} out of range (0-32)",
                token_to_location(prefix_token, self.file_path),
            )

        return IPCIDRRange(
            network=network,
            prefix_len=prefix_len,
            location=token_to_location(ip_token, self.file_path),
        )

    @v_args(inline=True)
    def ipv6_cidr(self, ip_token: Token, prefix_token: Token) -> IPCIDRRange:
        """Transform IPv6 CIDR: 2001:db8::/32"""
        network = str(ip_token.value)
        prefix_len = int(prefix_token.value)

        if prefix_len < 0 or prefix_len > 128:
            self.add_diagnostic(
                DiagnosticLevel.WARNING,
                f"IPv6 CIDR prefix length {prefix_len} out of range (0-128)",
                token_to_location(prefix_token, self.file_path),
            )

        return IPCIDRRange(
            network=network,
            prefix_len=prefix_len,
            location=token_to_location(ip_token, self.file_path),
        )

    @v_args(inline=True)
    def address_range(self, start: Any, end: Any) -> IPRange:
        """Transform [ip1-ip2] range"""
        # Extract IP address strings
        start_ip = start.value if isinstance(start, IPAddress) else str(start)
        end_ip = end.value if isinstance(end, IPAddress) else str(end)

        return IPRange(start=start_ip, end=end_ip)

    @v_args(inline=True)
    def address_ip(self, ip_token: Token) -> IPAddress:
        """Transform single IP address"""
        ip_str = str(ip_token.value)

        # Detect IP version
        version: int = 6 if ":" in ip_str else 4

        return IPAddress(
            value=ip_str,
            version=version,  # type: ignore
            location=token_to_location(ip_token, self.file_path),
        )

    # ========================================================================
    # Port Expressions
    # ========================================================================

    def port_any(self, _: Any) -> AnyPort:
        """Transform 'any' port"""
        return AnyPort()

    @v_args(inline=True)
    def port_var(self, var_token: Token) -> PortVariable:
        """Transform $VARIABLE port"""
        name = str(var_token.value)
        if name.startswith("$"):
            name = name[1:]
        return PortVariable(name=name, location=token_to_location(var_token, self.file_path))

    @v_args(inline=True)
    def port_negation(self, port: Any) -> PortNegation:
        """Transform !port"""
        return PortNegation(expr=port)

    def port_list(self, items: Sequence[Any]) -> PortList:
        """Transform [port1,port2,...]"""
        return PortList(elements=list(items))

    def port_range(self, args: list) -> PortRange:
        """Transform port range: 1024:65535 or open-ended 1024:"""
        start_token = args[0]
        start = int(start_token.value)

        # Check if end port is provided (may be open-ended like "1024:")
        if len(args) > 1 and args[1] is not None:
            end_token = args[1]
            end = int(end_token.value)
        else:
            # Open-ended range, default to max port
            end = 65535
            end_token = None

        if start < 0 or start > 65535:
            self.add_diagnostic(
                DiagnosticLevel.ERROR,
                f"Port range start {start} out of range (0-65535)",
                token_to_location(start_token, self.file_path),
            )

        if end < 0 or end > 65535:
            if end_token:
                self.add_diagnostic(
                    DiagnosticLevel.ERROR,
                    f"Port range end {end} out of range (0-65535)",
                    token_to_location(end_token, self.file_path),
                )

        if start > end:
            self.add_diagnostic(
                DiagnosticLevel.ERROR,
                f"Port range start {start} > end {end}",
                token_to_location(start_token, self.file_path),
            )

        return PortRange(start=start, end=end)

    @v_args(inline=True)
    def port_single(self, port_token: Token) -> Port:
        """Transform single port number"""
        port_num = int(port_token.value)

        if port_num < 0 or port_num > 65535:
            self.add_diagnostic(
                DiagnosticLevel.ERROR,
                f"Port {port_num} out of range (0-65535)",
                token_to_location(port_token, self.file_path),
            )

        return Port(value=port_num, location=token_to_location(port_token, self.file_path))

    def port_elem(self, items: Sequence[Any]) -> Any:
        """Transform port list element (range or single)"""
        return items[0] if items else None

    # ========================================================================
    # Options
    # ========================================================================

    def options(self, items: Sequence[Any]) -> list[Any]:
        """Transform options list"""
        return [item for item in items if item is not None]

    @v_args(inline=True)
    def msg_option(self, text_token: Token) -> MsgOption:
        """Transform msg:"text" option"""
        text = parse_quoted_string(str(text_token.value))
        return MsgOption(text=text, location=token_to_location(text_token, self.file_path))

    @v_args(inline=True)
    def sid_option(self, sid_token: Token) -> SidOption:
        """Transform sid:12345 option"""
        sid = int(sid_token.value)
        if sid < 1:
            self.add_diagnostic(
                DiagnosticLevel.ERROR,
                f"SID must be >= 1, got {sid}",
                token_to_location(sid_token, self.file_path),
            )
        return SidOption(value=sid, location=token_to_location(sid_token, self.file_path))

    @v_args(inline=True)
    def rev_option(self, rev_token: Token) -> RevOption:
        """Transform rev:1 option"""
        rev = int(rev_token.value)
        if rev < 1:
            self.add_diagnostic(
                DiagnosticLevel.ERROR,
                f"Rev must be >= 1, got {rev}",
                token_to_location(rev_token, self.file_path),
            )
        return RevOption(value=rev, location=token_to_location(rev_token, self.file_path))

    @v_args(inline=True)
    def gid_option(self, gid_token: Token) -> GidOption:
        """Transform gid:1 option"""
        gid = int(gid_token.value)
        return GidOption(value=gid, location=token_to_location(gid_token, self.file_path))

    @v_args(inline=True)
    def classtype_option(self, classtype_token: Token) -> ClasstypeOption:
        """Transform classtype:trojan-activity option"""
        classtype = str(classtype_token.value)
        return ClasstypeOption(
            value=classtype, location=token_to_location(classtype_token, self.file_path)
        )

    @v_args(inline=True)
    def priority_option(self, priority_token: Token) -> PriorityOption:
        """Transform priority:1 option"""
        priority = int(priority_token.value)
        if priority < 1 or priority > 4:
            self.add_diagnostic(
                DiagnosticLevel.WARNING,
                f"Priority should be 1-4, got {priority}",
                token_to_location(priority_token, self.file_path),
            )
        return PriorityOption(
            value=priority, location=token_to_location(priority_token, self.file_path)
        )

    @v_args(inline=True)
    def reference_option(self, ref_type_token: Token, ref_id: Any) -> ReferenceOption:
        """Transform reference:cve,2021-12345 option"""
        ref_type = str(ref_type_token.value)
        # ref_id can be Token or already processed string
        ref_id_str = str(ref_id.value if isinstance(ref_id, Token) else ref_id)
        return ReferenceOption(
            ref_type=ref_type,
            ref_id=ref_id_str,
            location=token_to_location(ref_type_token, self.file_path),
        )

    def reference_id(self, items: Sequence[Token]) -> str:
        """Extract reference ID (can be WORD, INT, or pattern)"""
        if items:
            return str(items[0].value)
        return ""

    def metadata_option(self, items: Sequence[Any]) -> MetadataOption:
        """Transform metadata:key1 value1, key2 value2 option"""
        entries: list[tuple[str, str]] = []

        for item in items:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                entries.append((str(item[0]), str(item[1])))

        return MetadataOption(entries=entries)

    def metadata_entry(self, items: Sequence[Any]) -> tuple[str, str]:
        """Transform metadata entry: key value1 value2... (multiple values possible)"""
        if not items:
            return ("", "")

        # Extract values from tokens or trees
        values = []
        for item in items:
            if isinstance(item, Token):
                values.append(str(item.value))
            elif isinstance(item, Tree):
                # Tree from metadata_word - extract first child token
                if item.children:
                    child = item.children[0]
                    if isinstance(child, Token):
                        values.append(str(child.value))
            elif isinstance(item, str):
                values.append(item)

        if not values:
            return ("", "")

        # First value is the key, rest are concatenated as the value
        key = values[0]
        value = " ".join(values[1:]) if len(values) > 1 else ""
        return (key, value)

    @v_args(inline=True)
    def content_option(self, content_value: bytes, *modifiers: ContentModifier) -> ContentOption:
        """Transform content:"text" or content:|hex| option with optional Snort3 modifiers"""
        return ContentOption(pattern=content_value, modifiers=list(modifiers) if modifiers else [])

    @v_args(inline=True)
    def uricontent_option(self, content_value: bytes, *modifiers: ContentModifier) -> ContentOption:
        """Transform uricontent (legacy Snort2) - treat as content"""
        self.add_diagnostic(
            DiagnosticLevel.WARNING,
            "uricontent is deprecated, use content with http_uri buffer",
        )
        return ContentOption(pattern=content_value, modifiers=list(modifiers) if modifiers else [])

    @v_args(inline=True)
    def content_value(self, value_token: Token) -> bytes:
        """Parse content value (quoted string or hex)"""
        value_str = str(value_token.value)

        # Check if hex string
        if value_str.startswith("|") and value_str.endswith("|"):
            return parse_hex_string(value_str)
        # Quoted string - parse and encode
        text = parse_quoted_string(value_str)
        return text.encode("utf-8", errors="replace")

    # Content modifier transformers for Snort3 inline syntax
    def cm_depth(self, args: list) -> ContentModifier:
        # args = [DEPTH_KW, INT]
        value = int(args[1].value) if isinstance(args[1], Token) else int(args[1])
        return ContentModifier(name=ContentModifierType.DEPTH, value=value)

    def cm_offset(self, args: list) -> ContentModifier:
        value = int(args[1].value) if isinstance(args[1], Token) else int(args[1])
        return ContentModifier(name=ContentModifierType.OFFSET, value=value)

    def cm_distance(self, args: list) -> ContentModifier:
        # May have negative sign: [DISTANCE_KW, INT] or [DISTANCE_KW, "-", INT]
        if len(args) == 2:
            value = int(args[1].value) if isinstance(args[1], Token) else int(args[1])
        else:
            value = -int(args[2].value) if isinstance(args[2], Token) else -int(args[2])
        return ContentModifier(name=ContentModifierType.DISTANCE, value=value)

    def cm_within(self, args: list) -> ContentModifier:
        value = int(args[1].value) if isinstance(args[1], Token) else int(args[1])
        return ContentModifier(name=ContentModifierType.WITHIN, value=value)

    def cm_nocase(self, args: list) -> ContentModifier:
        return ContentModifier(name=ContentModifierType.NOCASE, value=None)

    def cm_rawbytes(self, args: list) -> ContentModifier:
        return ContentModifier(name=ContentModifierType.RAWBYTES, value=None)

    def cm_startswith(self, args: list) -> ContentModifier:
        return ContentModifier(name=ContentModifierType.STARTSWITH, value=None)

    def cm_endswith(self, args: list) -> ContentModifier:
        return ContentModifier(name=ContentModifierType.ENDSWITH, value=None)

    def cm_fast_pattern(self, args: list) -> ContentModifier:
        return ContentModifier(name=ContentModifierType.FAST_PATTERN, value=None)

    def cm_generic(self, args: list) -> ContentModifier:
        """Handle generic/unknown content modifiers"""
        if len(args) == 1:
            # Modifier name only
            name = str(args[0].value) if isinstance(args[0], Token) else str(args[0])
            return ContentModifier(name=ContentModifierType.NOCASE, value=None)  # Default
        elif len(args) == 2:
            # Modifier name and value
            name = str(args[0].value) if isinstance(args[0], Token) else str(args[0])
            value = int(args[1].value) if isinstance(args[1], Token) else int(args[1])
            return ContentModifier(name=ContentModifierType.NOCASE, value=value)
        return ContentModifier(name=ContentModifierType.NOCASE, value=None)

    @v_args(inline=True)
    def pcre_option(self, pattern_token: Token) -> PcreOption:
        """Transform pcre:"/pattern/flags" option"""
        pattern_str = str(pattern_token.value)
        # Remove quotes if present (QUOTED_STRING token includes quotes)
        pattern_str = parse_quoted_string(pattern_str)
        pattern, flags = parse_pcre_pattern(pattern_str)

        return PcreOption(
            pattern=pattern,
            flags=flags,
            location=token_to_location(pattern_token, self.file_path),
        )

    def flow_option(self, items: Sequence[Token]) -> FlowOption:
        """Transform flow:established,to_server option"""
        directions: list[FlowDirection] = []
        states: list[FlowState] = []

        for item in items:
            value = str(item.value)

            # Check if it's a direction
            try:
                directions.append(FlowDirection(value))
                continue
            except ValueError:
                pass

            # Check if it's a state
            try:
                states.append(FlowState(value))
                continue
            except ValueError:
                pass

            # Unknown flow value
            self.add_diagnostic(
                DiagnosticLevel.WARNING,
                f"Unknown flow value: {value}",
                token_to_location(item, self.file_path),
            )

        return FlowOption(directions=directions, states=states)

    def flow_value(self, items: Sequence[Token]) -> Token:
        """Extract flow value token"""
        return items[0] if items else Token("WORD", "")

    def flowbits_option(self, items: Sequence[Any]) -> FlowbitsOption:
        """Transform flowbits:set,name or flowbits:isset,name option"""
        action = ""
        name = ""

        if len(items) >= 1:
            action = str(items[0].value if isinstance(items[0], Token) else items[0])
        if len(items) >= 2:
            name = str(items[1].value if isinstance(items[1], Token) else items[1])

        return FlowbitsOption(action=action, name=name)

    def flowbits_action(self, items: Sequence[Token]) -> Sequence[Token]:
        """Pass through flowbits action tokens"""
        return items

    def threshold_option(self, items: Sequence[Any]) -> GenericOption:
        """Transform threshold option (simplified as generic)"""
        # items[0] should be threshold_params which is a list of tuples
        params = items[0] if items else []

        # Build params string
        param_strs = []
        for item in params:
            if isinstance(item, tuple) and len(item) == 2:
                param_strs.append(f"{item[0]} {item[1]}")
            elif isinstance(item, Token):
                param_strs.append(str(item.value))
            else:
                param_strs.append(str(item))

        params_str = ", ".join(param_strs)
        return GenericOption(keyword="threshold", value=params_str, raw=f"threshold:{params_str}")

    def threshold_params(self, items: Sequence[Any]) -> Sequence[Any]:
        """Pass through threshold params"""
        return items

    def threshold_param(self, items: Sequence[Token]) -> tuple[str, str]:
        """Parse threshold param: word (word|int)"""
        if len(items) >= 2:
            key = str(items[0].value)
            value = str(items[1].value)
            return (key, value)
        if len(items) == 1:
            return (str(items[0].value), "")
        return ("", "")

    def detection_filter_option(self, items: Sequence[Any]) -> GenericOption:
        """Transform detection_filter option"""
        params_str = ", ".join(
            f"{item[0].value} {item[1].value}" if isinstance(item, (list, tuple)) else str(item)
            for item in items
        )
        return GenericOption(
            keyword="detection_filter",
            value=params_str,
            raw=f"detection_filter:{params_str}",
        )

    def detection_params(self, items: Sequence[Any]) -> Sequence[Any]:
        """Pass through detection params"""
        return items

    def detection_param(self, items: Sequence[Token]) -> tuple[str, str]:
        """Parse detection param: word int"""
        if len(items) >= 2:
            return (str(items[0].value), str(items[1].value))
        return ("", "")

    # Content modifiers

    def fast_pattern_option(self, items: Sequence[Token]) -> FastPatternOption:
        """Transform fast_pattern or fast_pattern:10,20 option"""
        offset = None
        length = None

        if len(items) >= 2:
            offset = int(items[0].value)
            length = int(items[1].value)

        return FastPatternOption(offset=offset, length=length)

    def nocase_option(self, _: Any) -> NocaseOption:
        """Transform nocase modifier"""
        return NocaseOption()

    def rawbytes_option(self, _: Any) -> RawbytesOption:
        """Transform rawbytes modifier"""
        return RawbytesOption()

    @v_args(inline=True)
    def depth_option(self, depth_token: Token) -> DepthOption:
        """Transform depth:N modifier"""
        return DepthOption(value=int(depth_token.value))

    @v_args(inline=True)
    def offset_option(self, offset_token: Token) -> OffsetOption:
        """Transform offset:N modifier"""
        return OffsetOption(value=int(offset_token.value))

    @v_args(inline=True)
    def distance_option(self, distance_token: Token) -> DistanceOption:
        """Transform distance:N modifier"""
        return DistanceOption(value=int(distance_token.value))

    @v_args(inline=True)
    def within_option(self, within_token: Token) -> WithinOption:
        """Transform within:N modifier"""
        return WithinOption(value=int(within_token.value))

    def startswith_option(self, _: Any) -> StartswithOption:
        """Transform startswith modifier"""
        return StartswithOption()

    def endswith_option(self, _: Any) -> EndswithOption:
        """Transform endswith modifier"""
        return EndswithOption()

    # Byte operations

    def isdataat_option(self, items: Sequence[Token]) -> GenericOption:
        """Transform isdataat:N,relative option"""
        value_str = ",".join(str(item.value) for item in items)
        return GenericOption(keyword="isdataat", value=value_str, raw=f"isdataat:{value_str}")

    def byte_test_option(self, items: Sequence[Any]) -> GenericOption:
        """Transform byte_test option (simplified as generic)"""
        params = items[0] if items else []
        value_str = ",".join(str(p.value if isinstance(p, Token) else p) for p in params)
        return GenericOption(keyword="byte_test", value=value_str, raw=f"byte_test:{value_str}")

    def byte_test_params(self, items: Sequence[Token]) -> Sequence[Token]:
        """Pass through byte_test params"""
        return items

    def byte_jump_option(self, items: Sequence[Any]) -> GenericOption:
        """Transform byte_jump option"""
        params = items[0] if items else []
        value_str = ",".join(str(p.value if isinstance(p, Token) else p) for p in params)
        return GenericOption(keyword="byte_jump", value=value_str, raw=f"byte_jump:{value_str}")

    def byte_jump_params(self, items: Sequence[Token]) -> Sequence[Token]:
        """Pass through byte_jump params"""
        return items

    def byte_extract_option(self, items: Sequence[Any]) -> GenericOption:
        """Transform byte_extract option"""
        params = items[0] if items else []
        value_str = ",".join(str(p.value if isinstance(p, Token) else p) for p in params)
        return GenericOption(
            keyword="byte_extract", value=value_str, raw=f"byte_extract:{value_str}"
        )

    def byte_extract_params(self, items: Sequence[Token]) -> Sequence[Token]:
        """Pass through byte_extract params"""
        return items

    def byte_math_option(self, items: Sequence[Any]) -> GenericOption:
        """Transform byte_math option"""
        params = items[0] if items else []
        value_str = ",".join(str(p.value if isinstance(p, Token) else p) for p in params)
        return GenericOption(keyword="byte_math", value=value_str, raw=f"byte_math:{value_str}")

    def byte_math_params(self, items: Sequence[Token]) -> Sequence[Token]:
        """Pass through byte_math params"""
        return items

    # Sticky buffers

    @v_args(inline=True)
    def buffer_select_option(self, buffer_token: Token) -> BufferSelectOption:
        """Transform sticky buffer selection (http.uri, dns_query, etc.)"""
        # BUFFER_NAME is now a terminal, so we get the token directly
        return BufferSelectOption(buffer_name=str(buffer_token.value))

    # Tag and filestore

    def tag_option(self, items: Sequence[Any]) -> GenericOption:
        """Transform tag option"""
        params = items[0] if items else []
        value_str = ",".join(str(p.value if isinstance(p, Token) else p) for p in params)
        return GenericOption(keyword="tag", value=value_str, raw=f"tag:{value_str}")

    def tag_params(self, items: Sequence[Token]) -> Sequence[Token]:
        """Pass through tag params"""
        return items

    def filestore_option(self, items: Sequence[Any]) -> FilestoreOption:
        """Transform filestore option"""
        direction = None
        scope = None

        if items and len(items) > 0:
            params = items[0] if isinstance(items[0], (list, tuple)) else items
            if len(params) >= 1:
                direction = str(params[0].value if isinstance(params[0], Token) else params[0])
            if len(params) >= 2:
                scope = str(params[1].value if isinstance(params[1], Token) else params[1])

        return FilestoreOption(direction=direction, scope=scope)

    def filestore_params(self, items: Sequence[Token]) -> Sequence[Token]:
        """Pass through filestore params"""
        return items

    # Flowint option

    def flowint_option(self, items: Sequence[Token]) -> GenericOption:
        """Transform flowint option"""
        value_str = ",".join(str(item.value) for item in items)
        return GenericOption(keyword="flowint", value=value_str, raw=f"flowint:{value_str}")

    # Generic fallback

    def generic_option(self, items: Sequence[Any]) -> GenericOption:
        """Transform unknown/generic option"""
        keyword = ""
        value = None

        if items:
            keyword = str(items[0].value if isinstance(items[0], Token) else items[0])

        if len(items) > 1:
            value_item = items[1]
            if isinstance(value_item, Token):
                value_str = str(value_item.value)
                # Clean quoted strings
                if value_str.startswith('"') and value_str.endswith('"'):
                    value = parse_quoted_string(value_str)
                else:
                    value = value_str
            else:
                value = str(value_item)

        raw = f"{keyword}:{value}" if value else keyword

        return GenericOption(keyword=keyword, value=value, raw=raw)

    def option_value(self, items: Sequence[Token]) -> str:
        """Extract option value"""
        if items:
            value_str = str(items[0].value)
            # Clean quoted strings
            if value_str.startswith('"') and value_str.endswith('"'):
                return parse_quoted_string(value_str)
            return value_str
        return ""

    # ========================================================================
    # Terminals and Ignored Elements
    # ========================================================================

    def comment(self, items: Any) -> None:
        """Ignore comments"""
        return

    def NEWLINE(self, token: Token) -> None:  # noqa: N802 - Lark grammar rule name
        """Ignore newlines"""
        return
