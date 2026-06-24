"""
Printing functions for surinort-ast.

This module provides functions for converting Rule ASTs back to text format.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from ..core.nodes import Rule
from ..printer.formatter import FormatterOptions
from ..printer.text_printer import TextPrinter


def print_rule(rule: Rule) -> str:
    """
    Convert a Rule AST back to text format.

    The output is built directly from the AST and is therefore deterministic.

    Args:
        rule: Rule AST to print

    Returns:
        Formatted rule text

    Example:
        >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
        >>> text = print_rule(rule)
        >>> print(text)
        alert tcp any any -> any 80 (msg:"Test"; sid:1;)
    """
    printer = TextPrinter(options=FormatterOptions.standard())
    return printer.print_rule(rule)


__all__ = [
    "print_rule",
]
