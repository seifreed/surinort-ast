"""
Core AST module for surinort-ast.

This module provides the complete AST definition for Suricata and Snort IDS rules.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

# Enums
# Diagnostics
from .diagnostics import (
    Diagnostic,
    DiagnosticList,
)
from .enums import (
    Action,
    ContentModifierType,
    DiagnosticLevel,
    Dialect,
    Direction,
    FlowDirection,
    FlowState,
    Protocol,
)

# Location tracking
from .location import (
    Location,
    Position,
    Span,
)

# AST Nodes
from .nodes import (
    # Addresses
    AddressExpr,
    # Type aliases
    AddressExpression,
    AddressList,
    AddressNegation,
    AddressVariable,
    AnyAddress,
    AnyPort,
    # Base
    ASTNode,
    BufferSelectOption,
    ByteExtractOption,
    ByteJumpOption,
    ByteTestOption,
    ClasstypeOption,
    ContentModifier,
    ContentOption,
    DetectionFilterOption,
    # Error nodes
    ErrorNode,
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
    # Options
    Option,
    PcreOption,
    Port,
    # Ports
    PortExpr,
    PortExpression,
    PortList,
    PortNegation,
    PortRange,
    PortVariable,
    PriorityOption,
    ReferenceOption,
    RevOption,
    # Rule structure
    Rule,
    RuleOption,
    SidOption,
    SourceOrigin,
    TagOption,
    ThresholdOption,
)

# Visitor pattern
from .visitor import (
    ASTTransformer,
    ASTVisitor,
    ASTWalker,
)

__all__ = [
    # Base
    "ASTNode",
    # Visitor
    "ASTTransformer",
    "ASTVisitor",
    "ASTWalker",
    # Enums
    "Action",
    # Addresses
    "AddressExpr",
    # Type aliases
    "AddressExpression",
    "AddressList",
    "AddressNegation",
    "AddressVariable",
    "AnyAddress",
    # Ports
    "AnyPort",
    # Options
    "BufferSelectOption",
    "ByteExtractOption",
    "ByteJumpOption",
    "ByteTestOption",
    "ClasstypeOption",
    "ContentModifier",
    "ContentModifierType",
    "ContentOption",
    "DetectionFilterOption",
    # Diagnostics
    "Diagnostic",
    "DiagnosticLevel",
    "DiagnosticList",
    "Dialect",
    "Direction",
    # Error nodes
    "ErrorNode",
    "FastPatternOption",
    "FilestoreOption",
    "FlowDirection",
    "FlowOption",
    "FlowState",
    "FlowbitsOption",
    "GenericOption",
    "GidOption",
    # Rule structure
    "Header",
    "IPAddress",
    "IPCIDRRange",
    "IPRange",
    # Location
    "Location",
    "MetadataOption",
    "MsgOption",
    "Option",
    "PcreOption",
    "Port",
    "PortExpr",
    "PortExpression",
    "PortList",
    "PortNegation",
    "PortRange",
    "PortVariable",
    "Position",
    "PriorityOption",
    "Protocol",
    "ReferenceOption",
    "RevOption",
    "Rule",
    "RuleOption",
    "SidOption",
    "SourceOrigin",
    "Span",
    "TagOption",
    "ThresholdOption",
]
