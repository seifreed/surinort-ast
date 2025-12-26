"""
Advanced Query API Examples for surinort-ast.

This module demonstrates advanced patterns and real-world use cases for the
Query API, including complex filtering, rule corpus analysis, and integration
with other APIs.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

from collections import Counter
from typing import Any

from surinort_ast import parse_rule
from surinort_ast.query import query, query_exists, query_first

# ============================================================================
# Example 1: Complex Rule Filtering
# ============================================================================


def example_complex_filtering():
    """Demonstrate complex rule filtering patterns."""
    print("=" * 80)
    print("Example 1: Complex Rule Filtering")
    print("=" * 80)

    rules = [
        parse_rule(
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"HTTP"; content:"admin"; sid:1;)'
        ),
        parse_rule('drop tcp any any -> any 443 (msg:"HTTPS Block"; pcre:"/admin/i"; sid:2;)'),
        parse_rule('alert udp any any -> any 53 (msg:"DNS Query"; sid:3;)'),
        parse_rule('alert tcp any any -> any 80 (msg:"Malware"; content:"evil"; sid:4;)'),
    ]

    # Filter 1: Find all TCP rules
    tcp_rules = []
    for rule in rules:
        if query_exists(rule, "Header[protocol=tcp]"):
            tcp_rules.append(rule)

    print(f"\n1. TCP Rules: {len(tcp_rules)}/{len(rules)}")
    for rule_node in tcp_rules:
        msg = query_first(rule_node, "MsgOption")
        sid = query_first(rule_node, "SidOption")
        print(f"   - SID {sid.value}: {msg.text}")

    # Filter 2: Find rules with content patterns
    content_rules = []
    for rule in rules:
        if query_exists(rule, "ContentOption"):
            content_rules.append(rule)

    print(f"\n2. Rules with Content Patterns: {len(content_rules)}/{len(rules)}")
    for rule_node in content_rules:
        sid = query_first(rule_node, "SidOption")
        contents = query(rule_node, "ContentOption")
        print(f"   - SID {sid.value}: {len(contents)} content pattern(s)")

    # Filter 3: Find rules with PCRE
    pcre_rules = []
    for rule in rules:
        if query_exists(rule, "PcreOption"):
            pcre_rules.append(rule)

    print(f"\n3. Rules with PCRE: {len(pcre_rules)}/{len(rules)}")


# ============================================================================
# Example 2: Rule Corpus Statistics
# ============================================================================


def example_corpus_statistics():
    """Demonstrate statistical analysis of rule corpus."""
    print("\n" + "=" * 80)
    print("Example 2: Rule Corpus Statistics")
    print("=" * 80)

    # Create diverse rule set
    rules = [
        parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)'),
        parse_rule('alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)'),
        parse_rule('drop tcp any any -> any 22 (msg:"SSH Block"; sid:3;)'),
        parse_rule('alert udp any any -> any 53 (msg:"DNS"; sid:4;)'),
        parse_rule('alert tcp any any -> any 80 (msg:"Malware"; content:"evil"; sid:5;)'),
        parse_rule('alert tcp any any -> any 80 (msg:"XSS"; pcre:"/script/i"; sid:6;)'),
    ]

    print(f"\nCorpus size: {len(rules)} rules\n")

    # Action distribution
    action_counts = Counter()
    for rule in rules:
        rule_node = query_first(rule, "Rule")
        action_counts[rule_node.action] += 1

    print("1. Action Distribution:")
    for action, count in action_counts.most_common():
        print(f"   - {action}: {count} ({100 * count / len(rules):.1f}%)")

    # Protocol distribution
    protocol_counts = Counter()
    for rule in rules:
        header = query_first(rule, "Header")
        protocol_counts[header.protocol] += 1

    print("\n2. Protocol Distribution:")
    for protocol, count in protocol_counts.most_common():
        print(f"   - {protocol}: {count} ({100 * count / len(rules):.1f}%)")

    # Content pattern usage
    content_count = sum(1 for r in rules if query_exists(r, "ContentOption"))
    pcre_count = sum(1 for r in rules if query_exists(r, "PcreOption"))

    print("\n3. Pattern Detection Methods:")
    print(f"   - Content patterns: {content_count} ({100 * content_count / len(rules):.1f}%)")
    print(f"   - PCRE patterns: {pcre_count} ({100 * pcre_count / len(rules):.1f}%)")


# ============================================================================
# Example 3: Content Pattern Analysis
# ============================================================================


def example_content_analysis():
    """Demonstrate content pattern extraction and analysis."""
    print("\n" + "=" * 80)
    print("Example 3: Content Pattern Analysis")
    print("=" * 80)

    rule = parse_rule(
        "alert tcp any any -> any 80 "
        '(content:"GET"; http_method; '
        'content:"/admin"; http_uri; '
        'content:"password"; nocase; '
        "sid:1;)"
    )

    # Extract all content patterns
    contents = query(rule, "ContentOption")
    print(f"\n1. Found {len(contents)} content pattern(s):")
    for i, content in enumerate(contents, 1):
        print(f"   {i}. Pattern: {content.pattern}")

        # Check for modifiers
        # Note: In Phase 1, we can't do "content > modifier" queries
        # So we just check if modifiers exist in the rule
        has_nocase = query_exists(rule, "NocaseOption")
        if has_nocase:
            print("      - Has nocase modifier somewhere in rule")

    # Analyze pattern characteristics
    total_bytes = sum(len(c.pattern) for c in contents)
    print("\n2. Pattern Statistics:")
    print(f"   - Total patterns: {len(contents)}")
    print(f"   - Total bytes: {total_bytes}")
    print(f"   - Average bytes per pattern: {total_bytes / len(contents):.1f}")


# ============================================================================
# Example 4: Metadata Extraction
# ============================================================================


def example_metadata_extraction():
    """Demonstrate extracting rule metadata."""
    print("\n" + "=" * 80)
    print("Example 4: Metadata Extraction")
    print("=" * 80)

    rule = parse_rule(
        "alert tcp any any -> any 80 "
        '(msg:"MALWARE-CNC Backdoor callback"; '
        "reference:url,example.com/malware; "
        "classtype:trojan-activity; "
        "priority:1; "
        "sid:2000001; "
        "rev:5;)"
    )

    metadata: dict[str, Any] = {}

    # Extract message
    msg = query_first(rule, "MsgOption")
    if msg:
        metadata["message"] = msg.text

    # Extract SID
    sid = query_first(rule, "SidOption")
    if sid:
        metadata["sid"] = sid.value

    # Extract revision
    rev = query_first(rule, "RevOption")
    if rev:
        metadata["revision"] = rev.value

    # Extract priority
    priority = query_first(rule, "PriorityOption")
    if priority:
        metadata["priority"] = priority.value

    # Extract classification
    classtype = query_first(rule, "ClasstypeOption")
    if classtype:
        metadata["classtype"] = classtype.value

    # Extract references
    references = query(rule, "ReferenceOption")
    if references:
        metadata["reference_count"] = len(references)

    print("\nExtracted Metadata:")
    for key, value in metadata.items():
        print(f"   - {key}: {value}")


# ============================================================================
# Example 5: Rule Quality Checks
# ============================================================================


def example_quality_checks():
    """Demonstrate rule quality validation checks."""
    print("\n" + "=" * 80)
    print("Example 5: Rule Quality Checks")
    print("=" * 80)

    rules = [
        parse_rule('alert tcp any any -> any 80 (msg:"Good Rule"; sid:1; rev:1;)'),
        parse_rule("alert tcp any any -> any 80 (sid:2;)"),  # Missing msg
        parse_rule('alert tcp any any -> any 80 (msg:"No SID";)'),  # Missing sid
    ]

    print(f"\nChecking {len(rules)} rules for quality issues:\n")

    for i, rule in enumerate(rules, 1):
        sid = query_first(rule, "SidOption")
        sid_value = sid.value if sid else "MISSING"

        issues = []

        # Check for required message
        if not query_exists(rule, "MsgOption"):
            issues.append("Missing 'msg' option")

        # Check for required SID
        if not query_exists(rule, "SidOption"):
            issues.append("Missing 'sid' option")

        # Check for revision
        if not query_exists(rule, "RevOption"):
            issues.append("Missing 'rev' option (optional)")

        print(f"Rule {i} (SID: {sid_value}):")
        if issues:
            print(f"   Issues found: {len(issues)}")
            for issue in issues:
                print(f"   - {issue}")
        else:
            print("   ✓ No issues found")


# ============================================================================
# Example 6: Port Analysis
# ============================================================================


def example_port_analysis():
    """Demonstrate port-based rule analysis."""
    print("\n" + "=" * 80)
    print("Example 6: Port Analysis")
    print("=" * 80)

    rules = [
        parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)'),
        parse_rule('alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)'),
        parse_rule('alert tcp any any -> any 22 (msg:"SSH"; sid:3;)'),
        parse_rule('alert tcp any any -> any 80 (msg:"HTTP 2"; sid:4;)'),
        parse_rule('alert udp any any -> any 53 (msg:"DNS"; sid:5;)'),
    ]

    # Count rules by checking if they have Port nodes
    rules_with_ports = []
    for rule in rules:
        if query_exists(rule, "Port"):
            rules_with_ports.append(rule)

    print(f"\n1. Rules with specific ports: {len(rules_with_ports)}/{len(rules)}")

    # Note: Phase 1 doesn't support attribute comparison, so we can't do Port[port=80]
    # But we can demonstrate the concept
    print("\n2. Port distribution (manual analysis):")
    print("   - Port 80 (HTTP): 2 rules")
    print("   - Port 443 (HTTPS): 1 rule")
    print("   - Port 22 (SSH): 1 rule")
    print("   - Port 53 (DNS): 1 rule")


# ============================================================================
# Example 7: Flow-Based Analysis
# ============================================================================


def example_flow_analysis():
    """Demonstrate flow-based rule analysis."""
    print("\n" + "=" * 80)
    print("Example 7: Flow-Based Analysis")
    print("=" * 80)

    rules = [
        parse_rule("alert tcp any any -> any 80 (flow:established,to_server; sid:1;)"),
        parse_rule("alert tcp any any -> any 80 (flow:established,to_client; sid:2;)"),
        parse_rule("alert tcp any any -> any 80 (sid:3;)"),  # No flow
    ]

    # Find rules with flow analysis
    flow_rules = []
    no_flow_rules = []

    for rule in rules:
        if query_exists(rule, "FlowOption"):
            flow_rules.append(rule)
        else:
            no_flow_rules.append(rule)

    print(f"\n1. Rules with flow analysis: {len(flow_rules)}/{len(rules)}")
    for rule_node in flow_rules:
        sid = query_first(rule_node, "SidOption")
        print(f"   - SID {sid.value}: Has flow analysis")

    print(f"\n2. Rules without flow analysis: {len(no_flow_rules)}/{len(rules)}")
    for rule_node in no_flow_rules:
        sid = query_first(rule_node, "SidOption")
        print(f"   - SID {sid.value}: No flow analysis")


# ============================================================================
# Example 8: Variable Usage Analysis
# ============================================================================


def example_variable_analysis():
    """Demonstrate variable usage analysis."""
    print("\n" + "=" * 80)
    print("Example 8: Variable Usage Analysis")
    print("=" * 80)

    rules = [
        parse_rule("alert tcp $HOME_NET any -> $EXTERNAL_NET any (sid:1;)"),
        parse_rule("alert tcp any any -> $HTTP_SERVERS 80 (sid:2;)"),
        parse_rule("alert tcp any any -> any any (sid:3;)"),  # No variables
    ]

    print(f"\nAnalyzing {len(rules)} rules for variable usage:\n")

    for i, rule in enumerate(rules, 1):
        sid = query_first(rule, "SidOption")
        variables = query(rule, "AddressVariable")

        print(f"Rule {i} (SID {sid.value}):")
        if variables:
            print(f"   Uses {len(variables)} variable(s):")
            for var in variables:
                print(f"   - ${var.name}")
        else:
            print("   No variables used")


# ============================================================================
# Example 9: Integration with Printer API
# ============================================================================


def example_printer_integration():
    """Demonstrate integration with Printer API."""
    print("\n" + "=" * 80)
    print("Example 9: Integration with Printer API")
    print("=" * 80)

    from surinort_ast.printer import print_rule

    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; content:"admin"; sid:1;)')

    # Find and display specific node
    content = query_first(rule, "ContentOption")
    if content:
        print("\n1. Found ContentOption node:")
        print(f"   Pattern: {content.pattern}")
        print(f"   Node type: {content.node_type}")

    # Format the entire rule
    formatted = print_rule(rule)
    print("\n2. Formatted complete rule:")
    print(f"   {formatted}")

    # Display specific option
    sid = query_first(rule, "SidOption")
    if sid:
        print("\n3. SID option details:")
        print(f"   Value: {sid.value}")
        print(f"   Type: {type(sid).__name__}")


# ============================================================================
# Example 10: Advanced Pattern Matching
# ============================================================================


def example_advanced_patterns():
    """Demonstrate advanced querying patterns."""
    print("\n" + "=" * 80)
    print("Example 10: Advanced Pattern Matching")
    print("=" * 80)

    rule = parse_rule(
        "alert tcp $HOME_NET any -> $EXTERNAL_NET 80 "
        '(msg:"Complex Rule"; '
        'content:"GET"; http_method; '
        'content:"/admin"; http_uri; depth:20; '
        'content:"password"; nocase; offset:10; '
        'pcre:"/admin.*password/i"; '
        "classtype:web-application-attack; "
        "sid:1000001; rev:3;)"
    )

    print("\n1. Pattern Detection Methods:")

    # Check for different pattern types
    has_content = query_exists(rule, "ContentOption")
    has_pcre = query_exists(rule, "PcreOption")

    print(f"   - Has content patterns: {has_content}")
    print(f"   - Has PCRE patterns: {has_pcre}")

    if has_content:
        contents = query(rule, "ContentOption")
        print(f"   - Number of content patterns: {len(contents)}")

    print("\n2. Content Modifiers:")
    modifiers = {
        "nocase": query_exists(rule, "NocaseOption"),
        "depth": query_exists(rule, "DepthOption"),
        "offset": query_exists(rule, "OffsetOption"),
        "distance": query_exists(rule, "DistanceOption"),
        "within": query_exists(rule, "WithinOption"),
    }

    for modifier, exists in modifiers.items():
        status = "✓" if exists else "✗"
        print(f"   {status} {modifier}")

    print("\n3. Rule Complexity:")
    all_options = query(rule, "*")
    print(f"   - Total AST nodes: {len(all_options)}")

    # Count different option types
    option_types = set()
    for node in all_options:
        if "Option" in node.node_type:
            option_types.add(node.node_type)

    print(f"   - Unique option types: {len(option_types)}")


# ============================================================================
# Main Entry Point
# ============================================================================


def main():
    """Run all advanced examples."""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 18 + "QUERY API ADVANCED EXAMPLES" + " " * 33 + "║")
    print("║" + " " * 78 + "║")
    print("║" + " " * 12 + "Real-World Use Cases & Integration Patterns" + " " * 23 + "║")
    print("╚" + "=" * 78 + "╝")

    examples = [
        example_complex_filtering,
        example_corpus_statistics,
        example_content_analysis,
        example_metadata_extraction,
        example_quality_checks,
        example_port_analysis,
        example_flow_analysis,
        example_variable_analysis,
        example_printer_integration,
        example_advanced_patterns,
    ]

    for example_func in examples:
        try:
            example_func()
        except Exception as e:
            print(f"\n[ERROR] {example_func.__name__}: {e}")
            import traceback

            traceback.print_exc()

    print("\n" + "=" * 80)
    print("All advanced examples completed!")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
