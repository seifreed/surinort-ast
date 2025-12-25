#!/usr/bin/env python3
"""
AST Inspection Examples for surinort-ast

This example demonstrates how to traverse and inspect the AST structure
of parsed IDS/IPS rules using visitor patterns and direct traversal.

Author: Marc Rivero | @seifreed
License: GPL v3.0
"""

from surinort_ast import parse_rule
from surinort_ast.core.visitor import ASTVisitor, ASTWalker


def example_1_manual_inspection():
    """Manually inspect AST structure without visitor pattern."""
    print("=" * 70)
    print("Example 1: Manual AST Inspection")
    print("=" * 70)

    rule_text = 'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"HTTP Request"; content:"GET"; http_method; sid:1000001; rev:1;)'

    print(f"\nParsing rule:\n{rule_text}\n")

    rule = parse_rule(rule_text)

    # Inspect header
    print("Rule Header:")
    print(f"  Action: {rule.action.value}")
    print(f"  Protocol: {rule.header.protocol.value}")
    print(f"  Direction: {rule.header.direction.value}")

    # Inspect addresses
    print("\nSource Address:")
    print(f"  Type: {rule.header.src_addr.node_type}")
    if hasattr(rule.header.src_addr, "name"):
        print(f"  Variable Name: {rule.header.src_addr.name}")

    print("\nDestination Address:")
    print(f"  Type: {rule.header.dst_addr.node_type}")
    if hasattr(rule.header.dst_addr, "name"):
        print(f"  Variable Name: {rule.header.dst_addr.name}")

    # Inspect ports
    print("\nDestination Port:")
    print(f"  Type: {rule.header.dst_port.node_type}")
    if hasattr(rule.header.dst_port, "value"):
        print(f"  Value: {rule.header.dst_port.value}")

    # Inspect options
    print(f"\nRule Options ({len(rule.options)} total):")
    for opt in rule.options:
        print(f"  - {opt.node_type}")


def example_2_simple_visitor():
    """Use a simple visitor to collect statistics."""
    print("\n" + "=" * 70)
    print("Example 2: Simple Visitor - Collect SIDs")
    print("=" * 70)

    class SIDCollector(ASTVisitor):
        """Visitor that collects all SID values."""

        def __init__(self):
            self.sids = []

        def visit_SidOption(self, node):
            """Visit SID option and collect value."""
            self.sids.append(node.value)

        def default_return(self):
            return None

    # Parse multiple rules
    rules = [
        'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1000001;)',
        'alert tcp any any -> any 443 (msg:"Rule 2"; sid:1000002;)',
        'alert udp any any -> any 53 (msg:"Rule 3"; sid:1000003;)',
    ]

    collector = SIDCollector()

    print("\nCollecting SIDs from rules:")
    for rule_text in rules:
        rule = parse_rule(rule_text)
        collector.visit(rule)
        print(f"  Parsed: sid:{rule.options[-1].value}")

    print(f"\nCollected SIDs: {collector.sids}")


def example_3_content_analyzer():
    """Analyze content patterns in rules."""
    print("\n" + "=" * 70)
    print("Example 3: Content Pattern Analyzer")
    print("=" * 70)

    class ContentAnalyzer(ASTVisitor):
        """Visitor that analyzes content patterns."""

        def __init__(self):
            self.content_patterns = []
            self.has_pcre = False
            self.http_keywords = []

        def visit_ContentOption(self, node):
            """Collect content patterns."""
            pattern = node.pattern
            # Convert bytes to string for display
            if isinstance(pattern, bytes):
                pattern_str = pattern.decode("utf-8", errors="ignore")
            else:
                pattern_str = str(pattern)
            self.content_patterns.append(pattern_str)

        def visit_PcreOption(self, node):
            """Check for PCRE patterns."""
            self.has_pcre = True

        def visit_HttpMethodOption(self, node):
            """Track HTTP-specific keywords."""
            self.http_keywords.append("http_method")

        def visit_HttpUriOption(self, node):
            """Track HTTP URI keywords."""
            self.http_keywords.append("http_uri")

        def default_return(self):
            return None

    rule_text = 'alert http any any -> any any (msg:"HTTP Attack"; content:"GET"; http_method; content:"/admin"; http_uri; sid:1;)'

    print(f"\nAnalyzing rule:\n{rule_text}\n")

    rule = parse_rule(rule_text)
    analyzer = ContentAnalyzer()
    analyzer.visit(rule)

    print("Analysis Results:")
    print(f"  Content patterns: {analyzer.content_patterns}")
    print(f"  Has PCRE: {analyzer.has_pcre}")
    print(f"  HTTP keywords: {analyzer.http_keywords}")


def example_4_walker_pattern():
    """Use ASTWalker for side-effect operations."""
    print("\n" + "=" * 70)
    print("Example 4: AST Walker Pattern")
    print("=" * 70)

    class RuleStatsPrinter(ASTWalker):
        """Walker that prints statistics as it traverses."""

        def __init__(self):
            self.option_count = 0
            self.content_count = 0

        def visit_Rule(self, node):
            """Visit rule and print basic info."""
            print(f"\nRule: {node.action.value} {node.header.protocol.value}")
            super().visit_Rule(node)

        def visit_ContentOption(self, node):
            """Count content options."""
            self.content_count += 1
            print(f"  Found content pattern #{self.content_count}")

        def generic_visit(self, node):
            """Count all options."""
            if node.node_type.endswith("Option"):
                self.option_count += 1
            super().generic_visit(node)

    rule_text = 'alert tcp any any -> any 80 (msg:"Multiple Contents"; content:"admin"; content:"password"; sid:1;)'

    print(f"\nWalking rule:\n{rule_text}")

    rule = parse_rule(rule_text)
    walker = RuleStatsPrinter()
    walker.walk(rule)

    print(f"\nTotal options visited: {walker.option_count}")
    print(f"Content patterns found: {walker.content_count}")


def example_5_option_statistics():
    """Collect comprehensive option statistics."""
    print("\n" + "=" * 70)
    print("Example 5: Comprehensive Option Statistics")
    print("=" * 70)

    class OptionStatsCollector(ASTVisitor):
        """Collect statistics about option types."""

        def __init__(self):
            self.option_types = {}

        def generic_visit(self, node):
            """Count option types."""
            if node.node_type.endswith("Option"):
                self.option_types[node.node_type] = self.option_types.get(node.node_type, 0) + 1
            super().generic_visit(node)

        def default_return(self):
            return None

    rules = [
        'alert tcp any any -> any 80 (msg:"Test1"; content:"test"; nocase; sid:1;)',
        'alert tcp any any -> any 443 (msg:"Test2"; flow:established; sid:2;)',
        'alert tcp any any -> any 22 (msg:"Test3"; content:"SSH"; offset:0; depth:10; sid:3;)',
    ]

    print("\nAnalyzing multiple rules...")

    collector = OptionStatsCollector()
    for rule_text in rules:
        rule = parse_rule(rule_text)
        collector.visit(rule)

    print("\nOption type statistics:")
    for option_type, count in sorted(collector.option_types.items()):
        print(f"  {option_type:25s}: {count}")


def example_6_nested_structure_inspection():
    """Inspect nested AST structures like lists."""
    print("\n" + "=" * 70)
    print("Example 6: Nested Structure Inspection")
    print("=" * 70)

    rule_text = 'alert tcp [192.168.1.1,192.168.1.2,10.0.0.0/8] [80,443] -> any any (msg:"Multiple addresses"; sid:1;)'

    print(f"\nRule with lists:\n{rule_text}\n")

    rule = parse_rule(rule_text)

    # Inspect source address list
    src_addr = rule.header.src_addr
    print(f"Source Address Type: {src_addr.node_type}")

    if src_addr.node_type == "AddressList":
        print(f"  Number of addresses: {len(src_addr.elements)}")
        for i, addr in enumerate(src_addr.elements, 1):
            print(f"    {i}. {addr.node_type}", end="")
            if hasattr(addr, "value"):
                print(f" - {addr.value}")
            elif hasattr(addr, "network"):
                print(f" - {addr.network}/{addr.prefix_len}")
            else:
                print()

    # Inspect source port list
    src_port = rule.header.src_port
    print(f"\nSource Port Type: {src_port.node_type}")

    if src_port.node_type == "PortList":
        print(f"  Number of ports: {len(src_port.elements)}")
        for i, port in enumerate(src_port.elements, 1):
            if hasattr(port, "value"):
                print(f"    {i}. Port {port.value}")


def main():
    """Run all examples."""
    print("\n" + "=" * 70)
    print("SURINORT-AST: AST Inspection Examples")
    print("=" * 70)
    print("\nDemonstrating various techniques for inspecting parsed AST structures.\n")

    try:
        example_1_manual_inspection()
        example_2_simple_visitor()
        example_3_content_analyzer()
        example_4_walker_pattern()
        example_5_option_statistics()
        example_6_nested_structure_inspection()

        print("\n" + "=" * 70)
        print("All examples completed successfully!")
        print("=" * 70)

    except Exception as e:
        print(f"\nError: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
