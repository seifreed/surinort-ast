"""
Parsing module for Suricata and Snort IDS rules.

This module provides the complete parsing pipeline for IDS rules:
- RuleParser: Main parser class with error recovery
- parse_rule: Convenience function for parsing single rules
- parse_rules_file: Convenience function for parsing rule files
- RuleTransformer: Lark transformer for AST construction (internal)

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from .parser import RuleParser, parse_rule, parse_rules_file
from .transformer import RuleTransformer

__all__ = [
    # Main parser interface
    "RuleParser",
    # Transformer (for advanced usage)
    "RuleTransformer",
    # Convenience functions
    "parse_rule",
    "parse_rules_file",
]
