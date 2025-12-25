#!/usr/bin/env python3
"""
Custom Visitor Examples for surinort-ast

This example demonstrates how to create custom AST visitors for advanced
rule analysis, pattern detection, and intelligence extraction.

Author: Marc Rivero | @seifreed
License: GPL v3.0
"""

from collections import Counter, defaultdict

from surinort_ast import parse_rule, parse_rules
from surinort_ast.core.visitor import ASTTransformer, ASTVisitor


def example_1_signature_id_collector():
    """Collect all signature IDs and metadata."""
    print("=" * 70)
    print("Example 1: Signature ID Collector")
    print("=" * 70)

    class SignatureCollector(ASTVisitor):
        """Collect SID, GID, and revision information."""

        def __init__(self):
            self.signatures = []

        def visit_Rule(self, node):
            """Extract signature metadata from rule."""
            sig_info = {
                "sid": None,
                "gid": None,
                "rev": None,
                "msg": None,
                "action": node.action.value,
                "protocol": node.header.protocol.value,
            }

            for opt in node.options:
                if opt.node_type == "SidOption":
                    sig_info["sid"] = opt.value
                elif opt.node_type == "GidOption":
                    sig_info["gid"] = opt.value
                elif opt.node_type == "RevOption":
                    sig_info["rev"] = opt.value
                elif opt.node_type == "MsgOption":
                    sig_info["msg"] = opt.text

            self.signatures.append(sig_info)

        def default_return(self):
            return None

    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP Attack"; sid:1000001; rev:1; gid:1;)',
        'alert tcp any any -> any 443 (msg:"HTTPS Attack"; sid:1000002; rev:2;)',
        'drop tcp any any -> any 22 (msg:"SSH Block"; sid:1000003; rev:1;)',
    ]

    print(f"\nCollecting signatures from {len(rules_text)} rules...\n")

    collector = SignatureCollector()
    rules, _ = parse_rules(rules_text)

    for rule in rules:
        collector.visit(rule)

    print("Collected signatures:")
    for sig in collector.signatures:
        print(f"  SID {sig['sid']:7d} (rev {sig['rev']}): {sig['msg']}")


def example_2_content_pattern_extractor():
    """Extract all content patterns and analyze them."""
    print("\n" + "=" * 70)
    print("Example 2: Content Pattern Extractor")
    print("=" * 70)

    class ContentExtractor(ASTVisitor):
        """Extract and analyze content patterns."""

        def __init__(self):
            self.patterns = []
            self.current_rule_sid = None

        def visit_Rule(self, node):
            """Track which rule we're in."""
            # Find SID first
            for opt in node.options:
                if opt.node_type == "SidOption":
                    self.current_rule_sid = opt.value
                    break

            # Visit all options
            super().visit_Rule(node)
            self.current_rule_sid = None

        def visit_ContentOption(self, node):
            """Extract content pattern."""
            pattern = node.pattern
            if isinstance(pattern, bytes):
                pattern_str = pattern.decode("utf-8", errors="ignore")
            else:
                pattern_str = str(pattern)

            pattern_info = {
                "sid": self.current_rule_sid,
                "pattern": pattern_str,
                "nocase": False,
                "offset": None,
                "depth": None,
            }

            self.patterns.append(pattern_info)

        def visit_NocaseOption(self, node):
            """Mark last pattern as case-insensitive."""
            if self.patterns:
                self.patterns[-1]["nocase"] = True

        def visit_OffsetOption(self, node):
            """Record offset for last pattern."""
            if self.patterns:
                self.patterns[-1]["offset"] = node.value

        def visit_DepthOption(self, node):
            """Record depth for last pattern."""
            if self.patterns:
                self.patterns[-1]["depth"] = node.value

        def default_return(self):
            return None

    rule_text = 'alert tcp any any -> any 80 (msg:"Admin Access"; content:"admin"; nocase; offset:0; depth:100; content:"password"; sid:1;)'

    print(f"\nExtracting content patterns:\n{rule_text}\n")

    rule = parse_rule(rule_text)
    extractor = ContentExtractor()
    extractor.visit(rule)

    print(f"Found {len(extractor.patterns)} content pattern(s):")
    for i, pat in enumerate(extractor.patterns, 1):
        print(f"\n  Pattern {i}:")
        print(f"    Content: {pat['pattern']}")
        print(f"    Case-insensitive: {pat['nocase']}")
        if pat["offset"] is not None:
            print(f"    Offset: {pat['offset']}")
        if pat["depth"] is not None:
            print(f"    Depth: {pat['depth']}")


def example_3_protocol_analyzer():
    """Analyze protocol-specific features in rules."""
    print("\n" + "=" * 70)
    print("Example 3: Protocol-Specific Feature Analyzer")
    print("=" * 70)

    class ProtocolAnalyzer(ASTVisitor):
        """Analyze protocol-specific keywords."""

        def __init__(self):
            self.http_keywords = Counter()
            self.tls_keywords = Counter()
            self.dns_keywords = Counter()
            self.current_protocol = None

        def visit_Rule(self, node):
            """Track protocol."""
            self.current_protocol = node.header.protocol.value
            super().visit_Rule(node)

        def generic_visit(self, node):
            """Count protocol-specific keywords."""
            option_type = node.node_type

            # HTTP keywords
            if option_type.startswith("Http"):
                self.http_keywords[option_type] += 1

            # TLS keywords (example)
            elif "tls" in option_type.lower():
                self.tls_keywords[option_type] += 1

            # DNS keywords (example)
            elif "dns" in option_type.lower():
                self.dns_keywords[option_type] += 1

            super().generic_visit(node)

        def default_return(self):
            return None

    rules_text = [
        'alert http any any -> any any (msg:"HTTP"; http_method; http_uri; sid:1;)',
        'alert http any any -> any any (msg:"HTTP2"; http_header; http_cookie; sid:2;)',
        'alert tcp any any -> any any (msg:"TLS"; content:"tls"; sid:3;)',
    ]

    print(f"\nAnalyzing {len(rules_text)} rules...\n")

    analyzer = ProtocolAnalyzer()
    rules, _ = parse_rules(rules_text)

    for rule in rules:
        analyzer.visit(rule)

    print("Protocol-specific keyword usage:")
    if analyzer.http_keywords:
        print("\n  HTTP keywords:")
        for keyword, count in analyzer.http_keywords.most_common():
            print(f"    {keyword:25s}: {count}")


def example_4_complexity_scorer():
    """Score rule complexity based on various factors."""
    print("\n" + "=" * 70)
    print("Example 4: Rule Complexity Scorer")
    print("=" * 70)

    class ComplexityScorer(ASTVisitor):
        """Calculate complexity score for rules."""

        def __init__(self):
            self.score = 0
            self.details = defaultdict(int)

        def visit_ContentOption(self, node):
            """Content patterns add complexity."""
            self.score += 10
            self.details["content_patterns"] += 1

        def visit_PcreOption(self, node):
            """PCRE patterns are more complex."""
            self.score += 20
            self.details["pcre_patterns"] += 1

        def visit_ByteTestOption(self, node):
            """Byte tests add significant complexity."""
            self.score += 15
            self.details["byte_operations"] += 1

        def visit_FlowOption(self, node):
            """Flow tracking adds complexity."""
            self.score += 5
            self.details["flow_tracking"] += 1

        def default_return(self):
            return None

    rules_text = [
        'alert tcp any any -> any 80 (msg:"Simple"; sid:1;)',
        'alert tcp any any -> any 80 (msg:"Medium"; content:"test"; flow:established; sid:2;)',
        'alert tcp any any -> any 80 (msg:"Complex"; content:"admin"; pcre:"/admin.*/i"; byte_test:4,>,1000,0; sid:3;)',
    ]

    print(f"\nScoring {len(rules_text)} rules...\n")

    rules, _ = parse_rules(rules_text)

    for i, rule in enumerate(rules, 1):
        scorer = ComplexityScorer()
        scorer.visit(rule)

        # Get message
        msg = "Unknown"
        for opt in rule.options:
            if opt.node_type == "MsgOption":
                msg = opt.text
                break

        print(f"Rule {i}: {msg}")
        print(f"  Complexity Score: {scorer.score}")
        if scorer.details:
            print("  Details:")
            for feature, count in scorer.details.items():
                print(f"    {feature}: {count}")
        print()


def example_5_rule_relationship_finder():
    """Find relationships between rules."""
    print("\n" + "=" * 70)
    print("Example 5: Rule Relationship Finder")
    print("=" * 70)

    class RuleMetadataExtractor(ASTVisitor):
        """Extract metadata for relationship analysis."""

        def __init__(self):
            self.sid = None
            self.references = []
            self.classtype = None

        def visit_SidOption(self, node):
            self.sid = node.value

        def visit_ReferenceOption(self, node):
            self.references.append(f"{node.ref_type}:{node.ref_id}")

        def visit_ClasstypeOption(self, node):
            self.classtype = node.value

        def default_return(self):
            return None

    rules_text = [
        'alert tcp any any -> any 80 (msg:"CVE-2021-1234"; reference:cve,2021-1234; classtype:web-application-attack; sid:1;)',
        'alert tcp any any -> any 80 (msg:"Related attack"; reference:cve,2021-1234; classtype:web-application-attack; sid:2;)',
        'alert tcp any any -> any 443 (msg:"Different attack"; reference:cve,2021-5678; classtype:trojan-activity; sid:3;)',
    ]

    print(f"\nAnalyzing {len(rules_text)} rules for relationships...\n")

    rules, _ = parse_rules(rules_text)

    # Extract metadata
    rule_metadata = []
    for rule in rules:
        extractor = RuleMetadataExtractor()
        extractor.visit(rule)
        rule_metadata.append(
            {
                "sid": extractor.sid,
                "references": extractor.references,
                "classtype": extractor.classtype,
            }
        )

    # Find relationships
    print("Rule relationships:")

    # Group by classtype
    by_classtype = defaultdict(list)
    for meta in rule_metadata:
        if meta["classtype"]:
            by_classtype[meta["classtype"]].append(meta["sid"])

    print("\n  By Classtype:")
    for classtype, sids in by_classtype.items():
        print(f"    {classtype}: SIDs {sids}")

    # Group by reference
    by_reference = defaultdict(list)
    for meta in rule_metadata:
        for ref in meta["references"]:
            by_reference[ref].append(meta["sid"])

    print("\n  By Reference:")
    for ref, sids in by_reference.items():
        if len(sids) > 1:  # Only show shared references
            print(f"    {ref}: SIDs {sids}")


def example_6_ast_transformer_chain():
    """Chain multiple transformers together."""
    print("\n" + "=" * 70)
    print("Example 6: Chained AST Transformers")
    print("=" * 70)

    class SIDOffsetTransformer(ASTTransformer):
        """Add offset to SIDs."""

        def __init__(self, offset):
            self.offset = offset

        def visit_SidOption(self, node):
            return node.model_copy(update={"value": node.value + self.offset})

    class RevBumper(ASTTransformer):
        """Increment revision numbers."""

        def visit_RevOption(self, node):
            return node.model_copy(update={"value": node.value + 1})

    from surinort_ast import print_rule

    rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:100; rev:1;)'

    print(f"\nOriginal rule:\n{rule_text}\n")

    rule = parse_rule(rule_text)

    # Apply transformers in sequence
    transformer1 = SIDOffsetTransformer(offset=1000000)
    transformer2 = RevBumper()

    print("Applying transformations:")
    print("  1. Add 1000000 to SID")
    print("  2. Increment revision")

    transformed = transformer1.visit(rule)
    transformed = transformer2.visit(transformed)

    result = print_rule(transformed)
    print(f"\nTransformed rule:\n{result}")


def main():
    """Run all examples."""
    print("\n" + "=" * 70)
    print("SURINORT-AST: Custom Visitor Examples")
    print("=" * 70)
    print("\nDemonstrating advanced AST visitor patterns.\n")

    try:
        example_1_signature_id_collector()
        example_2_content_pattern_extractor()
        example_3_protocol_analyzer()
        example_4_complexity_scorer()
        example_5_rule_relationship_finder()
        example_6_ast_transformer_chain()

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
