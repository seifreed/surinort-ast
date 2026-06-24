"""
AST Node Definitions for Surinort-AST v1.0

This module defines the complete Abstract Syntax Tree for Suricata and Snort IDS rules.
All nodes are immutable Pydantic v2 models with full type safety.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import base64
from collections.abc import Iterator
from typing import TYPE_CHECKING, Annotated, Any, Literal, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    WithJsonSchema,
    field_serializer,
    field_validator,
)

if TYPE_CHECKING:
    pass

from .diagnostics import Diagnostic
from .enums import (
    Action,
    ContentModifierType,
    Dialect,
    Direction,
    FlowDirection,
    FlowState,
    Protocol,
)
from .location import Location

# ============================================================================
# Base Node
# ============================================================================


class ASTNode(BaseModel):
    """
    Base class for all AST nodes.

    All nodes are immutable, validated Pydantic models with:
    - Structural typing with full type hints
    - Automatic validation
    - JSON serialization support
    - Optional location tracking
    """

    model_config = ConfigDict(
        frozen=True,  # Immutable
        extra="forbid",  # Strict schema
        use_enum_values=False,
        validate_assignment=True,
        use_attribute_docstrings=True,  # Use docstrings as field descriptions
    )

    location: Location | None = None
    comments: tuple[str, ...] = Field(default_factory=tuple)

    @property
    def node_type(self) -> str:
        """Get the node type name."""
        return self.__class__.__name__


# ============================================================================
# Rule Structure
# ============================================================================


class SourceOrigin(BaseModel):
    """
    Metadata about rule origin.

    Attributes:
        file_path: Source file path
        line_number: Line number in file
        rule_id: SID if available
    """

    file_path: str | None = None
    line_number: int | None = Field(None, ge=1)
    rule_id: str | None = None


class Header(ASTNode):
    """
    Rule header: protocol src_addr src_port direction dst_addr dst_port

    Example:
        tcp any any -> any 80
    """

    protocol: Protocol
    # Discriminated unions (resolved after the subclasses are defined) so the
    # concrete address/port subtype survives JSON serialization and round-trips.
    src_addr: DiscriminatedAddress
    src_port: DiscriminatedPort
    direction: Direction
    dst_addr: DiscriminatedAddress
    dst_port: DiscriminatedPort

    @classmethod
    def wildcard(cls, protocol: Protocol = Protocol.IP) -> Header:
        """Build a header matching any address and port in the ``TO`` direction.

        Used where only the protocol is known: short-form rules
        (``action protocol (...)``) and error-recovery placeholders.
        """
        return cls(
            protocol=protocol,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )


class Rule(ASTNode):
    """
    Top-level rule node.

    Example:
        alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001; rev:1;)
    """

    action: Action
    header: Header
    # Note: options type will be updated after all Option subclasses are defined
    # See DiscriminatedOption type alias at the end of this file
    options: tuple[DiscriminatedOption, ...]  # Forward reference
    dialect: Dialect = Dialect.SURICATA

    # Metadata
    origin: SourceOrigin | None = None
    diagnostics: tuple[Diagnostic, ...] = Field(default_factory=tuple)
    raw_text: str | None = None  # Original rule text


# ============================================================================
# Address Expressions
# ============================================================================


class AddressExpr(ASTNode):
    """Base for address expressions."""


class IPAddress(AddressExpr):
    """Single IP: 192.168.1.1 or 2001:db8::1"""

    type: Literal["IPAddress"] = "IPAddress"
    value: str
    version: Literal[4, 6]


class IPCIDRRange(AddressExpr):
    """CIDR range: 10.0.0.0/8"""

    type: Literal["IPCIDRRange"] = "IPCIDRRange"
    network: str
    prefix_len: int = Field(ge=0, le=128)

    @field_validator("prefix_len")
    @classmethod
    def validate_prefix_len(cls, v: int, info: Any) -> int:
        """Reject a prefix length out of range for the network's IP version.

        The field bound (0-128) covers IPv6; an IPv4 network (no colon) is
        limited to /32, so a larger prefix would be a structurally invalid node.
        """
        network = info.data.get("network", "")
        max_prefix = 128 if ":" in network else 32
        if v > max_prefix:
            version = 6 if ":" in network else 4
            raise ValueError(f"CIDR prefix /{v} out of range for IPv{version} (0-{max_prefix})")
        return v


class IPRange(AddressExpr):
    """Explicit range: [10.0.0.1-10.0.0.255]"""

    type: Literal["IPRange"] = "IPRange"
    start: str
    end: str


class AddressVariable(AddressExpr):
    """Variable reference: $HOME_NET"""

    type: Literal["AddressVariable"] = "AddressVariable"
    name: str


class AddressNegation(AddressExpr):
    """Negation: !192.168.1.1"""

    type: Literal["AddressNegation"] = "AddressNegation"
    expr: DiscriminatedAddress


class AddressList(AddressExpr):
    """List: [192.168.1.0/24,10.0.0.0/8]"""

    type: Literal["AddressList"] = "AddressList"
    elements: tuple[DiscriminatedAddress, ...]


class AnyAddress(AddressExpr):
    """Wildcard: any"""

    type: Literal["AnyAddress"] = "AnyAddress"


# ============================================================================
# Port Expressions
# ============================================================================


class PortExpr(ASTNode):
    """Base for port expressions."""


class Port(PortExpr):
    """Single port: 80"""

    type: Literal["Port"] = "Port"
    value: int = Field(ge=0, le=65535)


class PortRange(PortExpr):
    """Port range: 1024:65535"""

    type: Literal["PortRange"] = "PortRange"
    start: int = Field(ge=0, le=65535)
    end: int = Field(ge=0, le=65535)

    @field_validator("end")
    @classmethod
    def validate_range(cls, v: int, info: Any) -> int:
        """Ensure end >= start."""
        if "start" in info.data and v < info.data["start"]:
            raise ValueError(f"Port range end ({v}) must be >= start ({info.data['start']})")
        return v


class PortVariable(PortExpr):
    """Variable: $HTTP_PORTS"""

    type: Literal["PortVariable"] = "PortVariable"
    name: str


class PortNegation(PortExpr):
    """Negation: !80"""

    type: Literal["PortNegation"] = "PortNegation"
    expr: DiscriminatedPort


class PortList(PortExpr):
    """List: [80,443,8080:8090]"""

    type: Literal["PortList"] = "PortList"
    elements: tuple[DiscriminatedPort, ...]


class AnyPort(PortExpr):
    """Wildcard: any"""

    type: Literal["AnyPort"] = "AnyPort"


# ============================================================================
# Content Modifiers
# ============================================================================


class ContentModifier(BaseModel):
    """
    Modifier for content matching.

    Examples:
        - nocase (no value)
        - offset:10 (int value)
        - fast_pattern:10,20 (string value)
    """

    model_config = ConfigDict(frozen=True)

    # A known modifier maps to the enum; an unrecognized inline modifier keeps
    # its literal name as a string rather than being coerced to a wrong member.
    name: ContentModifierType | str
    value: int | str | None = None

    @property
    def name_str(self) -> str:
        """The modifier name as a string, whether it is a known enum or a literal."""
        return self.name.value if isinstance(self.name, ContentModifierType) else self.name


# ============================================================================
# Options (Rule Options)
# ============================================================================


class Option(ASTNode):
    """Base class for rule options."""


class MsgOption(Option):
    """msg:"alert text";"""

    type: Literal["MsgOption"] = "MsgOption"
    text: str


# sid/rev/gid are 32-bit unsigned integers in Suricata/Snort; bounding the model
# to that range keeps JSON, protobuf (uint32) and the model in agreement and
# rejects out-of-range values consistently instead of crashing the protobuf
# serializer.
_UINT32_MAX = 4294967295


class SidOption(Option):
    """sid:1000001;"""

    type: Literal["SidOption"] = "SidOption"
    value: int = Field(ge=1, le=_UINT32_MAX)


class RevOption(Option):
    """rev:1;"""

    type: Literal["RevOption"] = "RevOption"
    value: int = Field(ge=1, le=_UINT32_MAX)


class GidOption(Option):
    """gid:1;"""

    type: Literal["GidOption"] = "GidOption"
    value: int = Field(ge=1, le=_UINT32_MAX)


class ClasstypeOption(Option):
    """classtype:trojan-activity;"""

    type: Literal["ClasstypeOption"] = "ClasstypeOption"
    value: str


class PriorityOption(Option):
    """priority:1;"""

    type: Literal["PriorityOption"] = "PriorityOption"
    # Snort documents priority 1-255; Suricata imposes no documented upper
    # bound. Only the lower bound (>= 1) is enforced so valid rules parse.
    value: int = Field(ge=1)


class ReferenceOption(Option):
    """
    reference:cve,2021-12345;

    Attributes:
        ref_type: Reference system (cve, bugtraq, url, etc.)
        ref_id: Reference identifier
    """

    type: Literal["ReferenceOption"] = "ReferenceOption"
    ref_type: str
    ref_id: str


class MetadataOption(Option):
    """
    metadata:key1 value1, key2 value2;

    Attributes:
        entries: List of (key, value) tuples
    """

    type: Literal["MetadataOption"] = "MetadataOption"
    entries: tuple[tuple[str, str], ...]


# JSON key used to tag base64-encoded binary content patterns that are not
# valid UTF-8, so they survive a JSON round-trip without data loss.
_BYTES_B64_KEY = "__bytes_b64__"

# A content pattern is raw bytes serialized to JSON either as a UTF-8 string or,
# for non-UTF-8 bytes, as a {"__bytes_b64__": "<base64>"} object. The default
# bytes schema only advertises the string form, so JSON emitted for binary
# patterns failed validation against the generated schema; advertise both forms.
_PatternBytes = Annotated[
    bytes,
    WithJsonSchema(
        {
            "title": "Pattern",
            "oneOf": [
                {"type": "string"},
                {
                    "type": "object",
                    "properties": {_BYTES_B64_KEY: {"type": "string"}},
                    "required": [_BYTES_B64_KEY],
                    "additionalProperties": False,
                },
            ],
        }
    ),
]


class ContentOption(Option):
    """
    content:"GET"; nocase; offset:0; depth:10;

    Attributes:
        pattern: Raw bytes pattern
        modifiers: List of content modifiers
        negated: Whether the match is negated (content:!"...")

    JSON round-tripping:
        ``pattern`` is raw bytes and IDS content is frequently binary, so it
        cannot always be decoded as UTF-8. For JSON it is emitted as a plain
        string when the bytes are valid UTF-8 (keeping printable patterns
        readable) and otherwise as ``{"__bytes_b64__": "<base64>"}``. Both forms
        decode back to the exact original bytes.
    """

    type: Literal["ContentOption"] = "ContentOption"
    pattern: _PatternBytes
    modifiers: tuple[ContentModifier, ...] = Field(default_factory=tuple)
    negated: bool = False

    @field_validator("pattern", mode="before")
    @classmethod
    def _coerce_pattern(cls, value: Any) -> Any:
        """Accept raw bytes, a UTF-8 string, or the base64-tagged binary form."""
        if isinstance(value, str):
            return value.encode("utf-8")
        if isinstance(value, dict) and _BYTES_B64_KEY in value:
            return base64.b64decode(value[_BYTES_B64_KEY])
        return value

    @field_serializer("pattern", when_used="json")
    def _serialize_pattern(self, value: bytes) -> str | dict[str, str]:
        """Emit UTF-8 patterns as readable strings, binary as a base64 tag."""
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return {_BYTES_B64_KEY: base64.b64encode(value).decode("ascii")}


class PcreOption(Option):
    """
    pcre:"/pattern/flags"; or pcre:!"/pattern/flags";

    Attributes:
        pattern: Regular expression pattern
        flags: PCRE flags (i, s, m, x, etc.)
        negated: Whether the match is negated (!)
    """

    type: Literal["PcreOption"] = "PcreOption"
    pattern: str
    flags: str = ""
    negated: bool = False


class FlowOption(Option):
    """
    flow:established,to_server;

    Attributes:
        directions: Flow directions (to_client, to_server, etc.)
        states: Flow states (established, stateless, etc.)
    """

    type: Literal["FlowOption"] = "FlowOption"
    directions: tuple[FlowDirection, ...] = Field(default_factory=tuple)
    states: tuple[FlowState, ...] = Field(default_factory=tuple)


class FlowbitsOption(Option):
    """
    flowbits:set,name; flowbits:isset,name;

    Attributes:
        action: set, isset, toggle, unset, isnotset, noalert
        name: Flowbit name
    """

    type: Literal["FlowbitsOption"] = "FlowbitsOption"
    action: str
    name: str


class ThresholdOption(Option):
    """
    threshold:type limit,track by_src,count 10,seconds 60;

    Attributes:
        threshold_type: limit, threshold, both
        track: by_src, by_dst
        count: Event count
        seconds: Time window
    """

    type: Literal["ThresholdOption"] = "ThresholdOption"
    threshold_type: str
    track: str
    count: int = Field(ge=1)
    seconds: int = Field(ge=1)


class DetectionFilterOption(Option):
    """
    detection_filter:track by_src,count 10,seconds 60;

    Similar to threshold but applies before rule action.
    """

    type: Literal["DetectionFilterOption"] = "DetectionFilterOption"
    track: str
    count: int = Field(ge=1)
    seconds: int = Field(ge=1)


class BufferSelectOption(Option):
    """
    Sticky buffer selection options.

    Examples:
        - http_uri
        - http_header
        - file_data
        - dns_query
        - tls.sni
    """

    type: Literal["BufferSelectOption"] = "BufferSelectOption"
    buffer_name: str


class ByteTestOption(Option):
    """
    byte_test:4,>,1000,0;

    Attributes:
        bytes_to_extract: Number of bytes
        operator: Comparison operator (>, <, =, etc.)
        value: Value to compare against
        offset: Offset from cursor
        flags: Additional flags
    """

    type: Literal["ByteTestOption"] = "ByteTestOption"
    bytes_to_extract: int = Field(ge=1, le=10)
    operator: str
    value: int
    offset: int
    flags: tuple[str, ...] = Field(default_factory=tuple)


class ByteJumpOption(Option):
    """
    byte_jump:4,0,relative;

    Attributes:
        bytes_to_extract: Number of bytes
        offset: Offset adjustment
        flags: Additional flags
    """

    type: Literal["ByteJumpOption"] = "ByteJumpOption"
    bytes_to_extract: int = Field(ge=1, le=10)
    offset: int
    flags: tuple[str, ...] = Field(default_factory=tuple)


class ByteExtractOption(Option):
    """
    byte_extract:4,0,var_name;

    Attributes:
        bytes_to_extract: Number of bytes
        offset: Offset from cursor
        var_name: Variable name
        flags: Additional flags
    """

    type: Literal["ByteExtractOption"] = "ByteExtractOption"
    bytes_to_extract: int = Field(ge=1, le=10)
    offset: int
    var_name: str
    flags: tuple[str, ...] = Field(default_factory=tuple)


class FastPatternOption(Option):
    """
    fast_pattern; fast_pattern:10,20; fast_pattern:only;

    Attributes:
        offset: Optional offset
        length: Optional length
        only: True for ``fast_pattern:only`` (content used only for fast-pattern
            matching, not re-evaluated). Mutually exclusive with offset/length.
    """

    type: Literal["FastPatternOption"] = "FastPatternOption"
    offset: int | None = None
    length: int | None = None
    only: bool = False


class TagOption(Option):
    """
    tag:session,10,packets;

    Attributes:
        tag_type: session, host
        count: Count value
        metric: packets, seconds, bytes
    """

    type: Literal["TagOption"] = "TagOption"
    tag_type: str
    # A tag count is a non-negative quantity stored as int32 in protobuf.
    count: int = Field(ge=0, le=2147483647)
    metric: str


class FilestoreOption(Option):
    """
    filestore;

    Attributes:
        direction: Optional direction (request, response, both)
        scope: Optional scope (file, stream)
    """

    type: Literal["FilestoreOption"] = "FilestoreOption"
    direction: str | None = None
    scope: str | None = None


class LuaOption(Option):
    """
    lua:script.lua; or lua:!script.lua;

    Lua scripting option for Suricata IDS.
    Allows running Lua scripts as part of detection logic.

    Attributes:
        script_name: Name of the Lua script file
        negated: Whether the match is negated (!)
    """

    type: Literal["LuaOption"] = "LuaOption"
    script_name: str
    negated: bool = False


class LuajitOption(Option):
    """
    luajit:script.lua; or luajit:!script.lua;

    LuaJIT scripting option for Suricata IDS (alternative keyword).
    Functionally equivalent to lua: but explicitly indicates LuaJIT usage.

    Attributes:
        script_name: Name of the Lua script file
        negated: Whether the match is negated (!)
    """

    type: Literal["LuajitOption"] = "LuajitOption"
    script_name: str
    negated: bool = False


class DepthOption(Option):
    """
    depth:N; - Limits pattern match to N bytes from start of buffer.

    Attributes:
        value: Number of bytes to search (int) or variable name from byte_extract (str)
    """

    type: Literal["DepthOption"] = "DepthOption"
    value: int | str


class OffsetOption(Option):
    """
    offset:N; - Skip N bytes before starting pattern match.

    Attributes:
        value: Number of bytes to skip (int) or variable name from byte_extract (str)
    """

    type: Literal["OffsetOption"] = "OffsetOption"
    value: int | str


class DistanceOption(Option):
    """
    distance:N; - Match must occur N bytes after previous match.

    Attributes:
        value: Distance in bytes (int, can be negative) or variable name from byte_extract (str)
    """

    type: Literal["DistanceOption"] = "DistanceOption"
    value: int | str


class WithinOption(Option):
    """
    within:N; - Match must occur within N bytes of previous match.

    Attributes:
        value: Maximum distance in bytes (int) or variable name from byte_extract (str)
    """

    type: Literal["WithinOption"] = "WithinOption"
    value: int | str


class NocaseOption(Option):
    """
    nocase; - Case-insensitive pattern matching.
    """

    type: Literal["NocaseOption"] = "NocaseOption"


class RawbytesOption(Option):
    """
    rawbytes; - Match on raw packet data (Snort 2.x).
    """

    type: Literal["RawbytesOption"] = "RawbytesOption"


class StartswithOption(Option):
    """
    startswith; - Pattern must match at start of buffer (Suricata).
    """

    type: Literal["StartswithOption"] = "StartswithOption"


class EndswithOption(Option):
    """
    endswith; - Pattern must match at end of buffer (Suricata).
    """

    type: Literal["EndswithOption"] = "EndswithOption"


class GenericOption(Option):
    """
    Fallback for unknown/custom options.

    Preserves original text for options not explicitly supported.
    """

    type: Literal["GenericOption"] = "GenericOption"
    keyword: str
    value: str | None = None
    raw: str  # Original text


# ============================================================================
# Error Nodes (for error recovery)
# ============================================================================


class ErrorNode(ASTNode):
    """
    Represents a parse error within the AST.

    Used for error recovery to maintain partial AST structure.
    """

    error_type: str
    message: str
    recovered_text: str | None = None
    expected: tuple[str, ...] | None = None
    actual: str | None = None


# ============================================================================
# Type Aliases
# ============================================================================

# All possible address expression types
AddressExpression = Union[
    IPAddress,
    IPCIDRRange,
    IPRange,
    AddressVariable,
    AddressNegation,
    AddressList,
    AnyAddress,
]

# All possible port expression types
PortExpression = Union[
    Port,
    PortRange,
    PortVariable,
    PortNegation,
    PortList,
    AnyPort,
]

# All possible option types
RuleOption = Union[
    MsgOption,
    SidOption,
    RevOption,
    GidOption,
    ClasstypeOption,
    PriorityOption,
    ReferenceOption,
    MetadataOption,
    ContentOption,
    PcreOption,
    FlowOption,
    FlowbitsOption,
    ThresholdOption,
    DetectionFilterOption,
    BufferSelectOption,
    ByteTestOption,
    ByteJumpOption,
    ByteExtractOption,
    FastPatternOption,
    TagOption,
    FilestoreOption,
    LuaOption,
    LuajitOption,
    DepthOption,
    OffsetOption,
    DistanceOption,
    WithinOption,
    NocaseOption,
    RawbytesOption,
    StartswithOption,
    EndswithOption,
    GenericOption,
]

# Discriminated unions for proper JSON serialization/deserialization.
# Used via forward references in Header, the recursive address/port nodes,
# and Rule.options.
DiscriminatedAddress = Annotated[AddressExpression, Field(discriminator="type")]
DiscriminatedPort = Annotated[PortExpression, Field(discriminator="type")]
DiscriminatedOption = Annotated[RuleOption, Field(discriminator="type")]

# Now that the discriminated unions are defined, rebuild the models that
# reference them through forward references.
AddressNegation.model_rebuild()
AddressList.model_rebuild()
PortNegation.model_rebuild()
PortList.model_rebuild()
Header.model_rebuild()
Rule.model_rebuild()


def extract_sid(rule: Rule) -> int | None:
    """Return the rule's SID value, or None when it has no sid option."""
    for option in rule.options:
        if isinstance(option, SidOption):
            return option.value
    return None


def extract_sid_str(rule: Rule) -> str | None:
    """Return the rule's SID as a string, or None when it has no sid option."""
    sid = extract_sid(rule)
    return None if sid is None else str(sid)


def iter_child_nodes(node: ASTNode) -> Iterator[ASTNode]:
    """Yield the direct AST-node children of ``node`` in field-declaration order.

    Descends into list/tuple fields, yielding their AST-node members; non-node
    fields (scalars, enums, locations) are skipped. Shared by the visitor and
    query traversals so the definition of "a node's children" lives in one place.
    """
    for field_name in type(node).model_fields:
        value = getattr(node, field_name)
        if isinstance(value, ASTNode):
            yield value
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, ASTNode):
                    yield item
