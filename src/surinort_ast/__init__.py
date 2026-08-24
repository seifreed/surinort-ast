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
    coverage_report_to_sarif,
    diagnostics_to_sarif,
    from_json,
    migrate_ast,
    optimization_results_to_sarif,
    parse_file,
    parse_file_streaming,
    parse_rule,
    parse_rules,
    parse_source_file,
    print_rule,
    to_json,
    to_json_schema,
    to_sarif,
    validate_rule,
    validate_rules,
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
    RuleForm,
    SourceFile,
)

# Exceptions
from .exceptions import (
    ParseError,
    SerializationError,
    SurinortASTError,
    UnsupportedDialectError,
    ValidationError,
)
from .printer import CanonicalPrinter, SourcePrinter
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
    "CanonicalPrinter",
    # Core types
    "Diagnostic",
    "DiagnosticLevel",
    "Dialect",
    "Direction",
    # Exceptions
    "ParseError",
    "Protocol",
    "Rule",
    "RuleForm",
    "SerializationError",
    "SourceFile",
    "SourcePrinter",
    "SurinortASTError",
    "UnsupportedDialectError",
    "ValidationError",
    # Version info
    "__ast_version__",
    "__author__",
    "__email__",
    "__license__",
    "__version__",
    "coverage_report_to_sarif",
    "diagnostics_to_sarif",
    # Core API functions
    "from_json",
    "migrate_ast",
    "optimization_results_to_sarif",
    "parse_file",
    "parse_file_streaming",
    "parse_rule",
    "parse_rules",
    "parse_source_file",
    "print_rule",
    "to_json",
    "to_json_schema",
    "to_sarif",
    "validate_rule",
    "validate_rules",
]
