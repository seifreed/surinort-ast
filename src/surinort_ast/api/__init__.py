"""
Public API for surinort-ast.

This module provides the main public interface for parsing, printing,
and serializing Suricata/Snort IDS rules.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

# Import all public API functions from submodules
from .parsing import parse_file, parse_file_streaming, parse_rule, parse_rules
from .printing import print_rule
from .serialization import from_json, to_json, to_json_schema
from .validation import validate_rule

__all__ = [
    "from_json",
    "parse_file",
    "parse_file_streaming",
    # Parsing
    "parse_rule",
    "parse_rules",
    # Printing
    "print_rule",
    # JSON serialization
    "to_json",
    "to_json_schema",
    # Validation
    "validate_rule",
]
