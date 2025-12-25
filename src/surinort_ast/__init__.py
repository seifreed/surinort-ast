"""
Surinort-AST: Parser and AST for Suricata/Snort IDS Rules.

A high-performance, type-safe parser for IDS/IPS rule languages with
complete AST representation, validation, and formatting capabilities.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

# Version info
# Core API - most users should import from here
# Note: Importing from api package (api/__init__.py) maintains backward compatibility
from .api import (
    from_json,
    parse_file,
    parse_file_streaming,
    parse_rule,
    parse_rules,
    print_rule,
    to_json,
    to_json_schema,
    validate_rule,
)

# Core types and enums
from .core import (
    Action,
    Diagnostic,
    DiagnosticLevel,
    Dialect,
    Direction,
    Protocol,
    Rule,
)

# Exceptions
from .exceptions import (
    ParseError,
    SerializationError,
    SurinortASTError,
    UnsupportedDialectError,
    ValidationError,
)
from .version import (
    __ast_version__,
    __author__,
    __email__,
    __license__,
    __version__,
)

__all__ = [
    # Enums
    "Action",
    # Core types
    "Diagnostic",
    "DiagnosticLevel",
    "Dialect",
    "Direction",
    # Exceptions
    "ParseError",
    "Protocol",
    "Rule",
    "SerializationError",
    "SurinortASTError",
    "UnsupportedDialectError",
    "ValidationError",
    # Version info
    "__ast_version__",
    "__author__",
    "__email__",
    "__license__",
    "__version__",
    # Core API functions
    "from_json",
    "parse_file",
    "parse_file_streaming",
    "parse_rule",
    "parse_rules",
    "print_rule",
    "to_json",
    "to_json_schema",
    "validate_rule",
]
