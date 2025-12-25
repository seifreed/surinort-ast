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


def print_rule(rule: Rule, stable: bool = False) -> str:
    """
    Convert a Rule AST back to text format.

    Args:
        rule: Rule AST to print
        stable: Use stable/canonical formatting

    Returns:
        Formatted rule text

    Example:
        >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
        >>> text = print_rule(rule)
        >>> print(text)
        alert tcp any any -> any 80 (msg:"Test"; sid:1;)
    """
    options = FormatterOptions.stable() if stable else FormatterOptions.standard()

    printer = TextPrinter(options=options)
    return printer.print_rule(rule)


__all__ = [
    "print_rule",
]
