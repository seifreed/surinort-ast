"""
Public API for surinort-ast.

This module provides the main public interface for parsing, printing,
and serializing Suricata/Snort IDS rules.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

# Import all public API functions from submodules
from .parsing import parse_file, parse_file_streaming, parse_rule, parse_rules, parse_source_file
from .printing import print_rule
from .serialization import (
    coverage_report_to_sarif,
    diagnostics_to_sarif,
    from_json,
    migrate_ast,
    optimization_results_to_sarif,
    to_json,
    to_json_schema,
    to_sarif,
)
from .validation import apply_safe_fixes, validate_rule, validate_rules

__all__ = [
    "apply_safe_fixes",
    "coverage_report_to_sarif",
    "diagnostics_to_sarif",
    "from_json",
    "migrate_ast",
    "optimization_results_to_sarif",
    "parse_file",
    "parse_file_streaming",
    # Parsing
    "parse_rule",
    "parse_rules",
    "parse_source_file",
    # Printing
    "print_rule",
    "to_json",
    "to_json_schema",
    # JSON serialization
    "to_sarif",
    # Validation
    "validate_rule",
    "validate_rules",
]
