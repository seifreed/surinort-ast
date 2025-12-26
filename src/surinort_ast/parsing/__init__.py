"""
Parsing module for Suricata and Snort IDS rules.

This module provides the complete parsing pipeline for IDS rules:
- IParser: Protocol interface for parser implementations (dependency inversion)
- LarkRuleParser: Lark-based parser implementation
- ParserFactory: Factory for creating parser instances
- RuleParser: Backward compatibility wrapper around LarkRuleParser
- parse_rule: Convenience function for parsing single rules
- parse_rules_file: Convenience function for parsing rule files
- RuleTransformer: Lark transformer for AST construction (internal)

Recommended Usage:
    For new code, prefer using LarkRuleParser directly or ParserFactory:
    >>> from surinort_ast.parsing import LarkRuleParser, ParserFactory
    >>> parser = LarkRuleParser()  # Direct instantiation
    >>> parser = ParserFactory.create()  # Factory pattern

    For dependency injection:
    >>> from surinort_ast.parsing import IParser, ParserFactory
    >>> def process_rules(parser: IParser):
    ...     rule = parser.parse('alert tcp any any -> any 80 (sid:1;)')
    ...
    >>> process_rules(ParserFactory.create())

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from .factory import ParserFactory
from .interfaces import IParser
from .lark_parser import LarkRuleParser
from .parser import RuleParser, parse_rule, parse_rules_file
from .parser_config import ParserConfig
from .transformer import RuleTransformer

__all__ = [
    # Parser interface (for dependency inversion)
    "IParser",
    # Parser implementations
    "LarkRuleParser",
    # Parser configuration
    "ParserConfig",
    # Parser factory (recommended for DI)
    "ParserFactory",
    # Main parser interface (backward compatibility)
    "RuleParser",
    # Transformer (for advanced usage)
    "RuleTransformer",
    # Convenience functions
    "parse_rule",
    "parse_rules_file",
]
