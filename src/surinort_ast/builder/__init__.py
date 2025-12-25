"""
Builder pattern for constructing IDS rules programmatically.

This module provides a fluent API for creating Suricata/Snort IDS rules
without parsing text. Useful for rule generation, templating, and testing.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com

Example:
    >>> from surinort_ast.builder import RuleBuilder
    >>>
    >>> rule = (
    ...     RuleBuilder()
    ...     .alert()
    ...     .protocol("tcp")
    ...     .source_ip("any").source_port("any")
    ...     .dest_ip("192.168.1.0/24").dest_port("80")
    ...     .msg("HTTP traffic to internal network")
    ...     .sid(1000001)
    ...     .rev(1)
    ...     .content(b"GET", http_uri=True)
    ...     .pcre(r"/admin/", flags="i")
    ...     .build()
    ... )
"""

from .option_builders import ContentBuilder, FlowBuilder, ThresholdBuilder
from .rule_builder import RuleBuilder

__all__ = [
    "ContentBuilder",
    "FlowBuilder",
    "RuleBuilder",
    "ThresholdBuilder",
]
