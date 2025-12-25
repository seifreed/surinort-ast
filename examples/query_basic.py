"""
Basic Query API Examples for surinort-ast.

This module demonstrates the fundamental features of the Query API Phase 1,
showing how to search and filter AST nodes using CSS-style selectors.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

from surinort_ast import parse_rule
from surinort_ast.query import query, query_all, query_exists, query_first

# ============================================================================
# Example 1: Basic Type Selectors
# ============================================================================


def example_type_selectors():
    """Demonstrate basic type selector queries."""
    print("=" * 80)
    print("Example 1: Basic Type Selectors")
    print("=" * 80)

    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; content:"admin"; sid:1;)')

    # Find all ContentOption nodes
    contents = query(rule, "ContentOption")
    print(f"\n1. Found {len(contents)} ContentOption node(s)")
    for content in contents:
        print(f"   - Pattern: {content.pattern}")

    # Find SID option
    sids = query(rule, "SidOption")
    print(f"\n2. Found {len(sids)} SidOption node(s)")
    for sid in sids:
        print(f"   - SID value: {sid.value}")

    # Find message option
    msgs = query(rule, "MsgOption")
    print(f"\n3. Found {len(msgs)} MsgOption node(s)")
    for msg in msgs:
        print(f"   - Message: {msg.text}")


# ============================================================================
# Example 2: Universal Selector
# ============================================================================


def example_universal_selector():
    """Demonstrate universal selector (*) to match all nodes."""
    print("\n" + "=" * 80)
    print("Example 2: Universal Selector")
    print("=" * 80)

    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

    # Find all nodes
    all_nodes = query(rule, "*")
    print(f"\nFound {len(all_nodes)} total AST nodes")

    # Group by node type
    node_types = {}
    for node in all_nodes:
        node_type = node.node_type
        node_types[node_type] = node_types.get(node_type, 0) + 1

    print("\nNode type distribution:")
    for node_type, count in sorted(node_types.items()):
        print(f"   - {node_type}: {count}")


# ============================================================================
# Example 3: Attribute Equality Selectors
# ============================================================================


def example_attribute_selectors():
    """Demonstrate attribute equality matching."""
    print("\n" + "=" * 80)
    print("Example 3: Attribute Equality Selectors")
    print("=" * 80)

    rule = parse_rule("alert tcp any any -> any 80 (sid:1000001;)")

    # Find SID with specific value
    results = query(rule, "SidOption[value=1000001]")
    print("\n1. Query: SidOption[value=1000001]")
    print(f"   Found: {len(results)} match(es)")
    if results:
        print(f"   SID value: {results[0].value}")

    # Try non-matching value
    results = query(rule, "SidOption[value=9999]")
    print("\n2. Query: SidOption[value=9999]")
    print(f"   Found: {len(results)} match(es) (should be 0)")

    # Match rule action
    results = query(rule, "Rule[action=alert]")
    print("\n3. Query: Rule[action=alert]")
    print(f"   Found: {len(results)} match(es)")
    if results:
        print(f"   Rule action: {results[0].action}")


# ============================================================================
# Example 4: Query Helper Functions
# ============================================================================


def example_query_helpers():
    """Demonstrate query_first() and query_exists() helpers."""
    print("\n" + "=" * 80)
    print("Example 4: Query Helper Functions")
    print("=" * 80)

    rule = parse_rule('alert tcp any any -> any 80 (content:"A"; content:"B"; sid:1;)')

    # query_first() - Get only the first match
    first_content = query_first(rule, "ContentOption")
    print("\n1. query_first(rule, 'ContentOption')")
    if first_content:
        print(f"   First ContentOption pattern: {first_content.pattern}")
    else:
        print("   No match found")

    # query_exists() - Check if any match exists
    has_pcre = query_exists(rule, "PcreOption")
    print("\n2. query_exists(rule, 'PcreOption')")
    print(f"   Has PCRE option: {has_pcre}")

    has_sid = query_exists(rule, "SidOption")
    print("\n3. query_exists(rule, 'SidOption')")
    print(f"   Has SID option: {has_sid}")


# ============================================================================
# Example 5: Querying Multiple Rules
# ============================================================================


def example_query_all():
    """Demonstrate querying across multiple rules."""
    print("\n" + "=" * 80)
    print("Example 5: Querying Multiple Rules")
    print("=" * 80)

    rules = [
        parse_rule('alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)'),
        parse_rule('drop tcp any any -> any 443 (msg:"HTTPS Block"; sid:2;)'),
        parse_rule('alert udp any any -> any 53 (msg:"DNS"; sid:3;)'),
    ]

    # Find all alert rules
    alert_rules = query_all(rules, "Rule[action=alert]")
    print(f"\n1. Found {len(alert_rules)} alert rule(s)")
    for rule_node in alert_rules:
        sid = query_first(rule_node, "SidOption")
        msg = query_first(rule_node, "MsgOption")
        print(f"   - SID {sid.value}: {msg.text}")

    # Find all drop rules
    drop_rules = query_all(rules, "Rule[action=drop]")
    print(f"\n2. Found {len(drop_rules)} drop rule(s)")
    for rule_node in drop_rules:
        sid = query_first(rule_node, "SidOption")
        msg = query_first(rule_node, "MsgOption")
        print(f"   - SID {sid.value}: {msg.text}")

    # Find all SID options across all rules
    all_sids = query_all(rules, "SidOption")
    print(f"\n3. Found {len(all_sids)} SID option(s) total")
    for sid in all_sids:
        print(f"   - SID: {sid.value}")


# ============================================================================
# Example 6: Protocol and Header Queries
# ============================================================================


def example_protocol_queries():
    """Demonstrate querying protocol and header information."""
    print("\n" + "=" * 80)
    print("Example 6: Protocol and Header Queries")
    print("=" * 80)

    tcp_rule = parse_rule("alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (sid:1;)")
    udp_rule = parse_rule("alert udp any any -> any 53 (sid:2;)")

    # Find TCP headers
    print("\n1. TCP Rule:")
    tcp_headers = query(tcp_rule, "Header[protocol=tcp]")
    print(f"   Has TCP header: {len(tcp_headers) > 0}")

    udp_in_tcp = query(tcp_rule, "Header[protocol=udp]")
    print(f"   Has UDP header: {len(udp_in_tcp) > 0}")

    # Find UDP headers
    print("\n2. UDP Rule:")
    udp_headers = query(udp_rule, "Header[protocol=udp]")
    print(f"   Has UDP header: {len(udp_headers) > 0}")

    tcp_in_udp = query(udp_rule, "Header[protocol=tcp]")
    print(f"   Has TCP header: {len(tcp_in_udp) > 0}")

    # Find variables in headers
    print("\n3. Address Variables:")
    variables = query(tcp_rule, "AddressVariable")
    for var in variables:
        print(f"   - Variable: ${var.name}")


# ============================================================================
# Example 7: Content Modifier Queries
# ============================================================================


def example_content_modifiers():
    """Demonstrate querying content modifiers."""
    print("\n" + "=" * 80)
    print("Example 7: Content Modifier Queries")
    print("=" * 80)

    rule = parse_rule(
        'alert tcp any any -> any 80 (content:"admin"; nocase; depth:10; offset:5; sid:1;)'
    )

    # Find content option
    content = query_first(rule, "ContentOption")
    print(f"\n1. Content pattern: {content.pattern if content else 'N/A'}")

    # Find modifiers
    has_nocase = query_exists(rule, "NocaseOption")
    print(f"\n2. Has nocase modifier: {has_nocase}")

    has_depth = query_exists(rule, "DepthOption")
    print(f"3. Has depth modifier: {has_depth}")
    if has_depth:
        depth = query_first(rule, "DepthOption")
        print(f"   Depth value: {depth.value}")

    has_offset = query_exists(rule, "OffsetOption")
    print(f"\n4. Has offset modifier: {has_offset}")
    if has_offset:
        offset = query_first(rule, "OffsetOption")
        print(f"   Offset value: {offset.value}")


# ============================================================================
# Example 8: Compound Selectors
# ============================================================================


def example_compound_selectors():
    """Demonstrate compound selectors (type + attribute)."""
    print("\n" + "=" * 80)
    print("Example 8: Compound Selectors")
    print("=" * 80)

    rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1000001; rev:5;)')

    # Type + attribute selector
    results = query(rule, "SidOption[value=1000001]")
    print("\n1. Query: SidOption[value=1000001]")
    print(f"   Found: {len(results)} match(es)")
    if results:
        print(f"   Node type: {results[0].node_type}")
        print(f"   SID value: {results[0].value}")

    # Another compound selector
    results = query(rule, "RevOption[value=5]")
    print("\n2. Query: RevOption[value=5]")
    print(f"   Found: {len(results)} match(es)")
    if results:
        print(f"   Rev value: {results[0].value}")


# ============================================================================
# Example 9: Real-World Use Case - Rule Analysis
# ============================================================================


def example_rule_analysis():
    """Demonstrate practical rule analysis use case."""
    print("\n" + "=" * 80)
    print("Example 9: Real-World Rule Analysis")
    print("=" * 80)

    rule = parse_rule(
        "alert tcp $HOME_NET any -> $EXTERNAL_NET 80 "
        '(msg:"HTTP Admin Access"; '
        "flow:established,to_server; "
        'content:"GET"; http_method; '
        'content:"/admin"; http_uri; '
        "classtype:web-application-attack; "
        "sid:1000001; rev:2;)"
    )

    print("\nRule Analysis:")

    # Basic info
    rule_node = query_first(rule, "Rule")
    print(f"\n1. Action: {rule_node.action}")

    # Protocol
    header = query_first(rule, "Header")
    print(f"2. Protocol: {header.protocol}")

    # Message
    msg = query_first(rule, "MsgOption")
    print(f"3. Message: {msg.text}")

    # Content patterns
    contents = query(rule, "ContentOption")
    print(f"\n4. Content patterns ({len(contents)} total):")
    for content in contents:
        print(f"   - {content.pattern}")

    # Classification
    classtype = query_first(rule, "ClasstypeOption")
    if classtype:
        print(f"\n5. Classification: {classtype.value}")

    # Metadata
    sid = query_first(rule, "SidOption")
    rev = query_first(rule, "RevOption")
    print("\n6. Metadata:")
    print(f"   - SID: {sid.value}")
    print(f"   - Revision: {rev.value}")

    # Flow analysis
    has_flow = query_exists(rule, "FlowOption")
    print(f"\n7. Has flow analysis: {has_flow}")


# ============================================================================
# Example 10: Performance - Querying Large Rule Sets
# ============================================================================


def example_performance():
    """Demonstrate performance with large rule sets."""
    print("\n" + "=" * 80)
    print("Example 10: Performance with Large Rule Sets")
    print("=" * 80)

    # Create 100 rules
    rules = [
        parse_rule(f'alert tcp any any -> any {80 + i} (msg:"Rule {i}"; sid:{1000 + i};)')
        for i in range(100)
    ]

    print(f"\n1. Created {len(rules)} rules")

    # Find all SID options
    all_sids = query_all(rules, "SidOption")
    print(f"2. Found {len(all_sids)} SID options across all rules")

    # Find all alert rules
    alert_rules = query_all(rules, "Rule[action=alert]")
    print(f"3. Found {len(alert_rules)} alert rules")

    # Use query_first for efficiency
    first_sid = query_first(rules[0], "SidOption")
    print(f"4. First rule SID: {first_sid.value}")


# ============================================================================
# Main Entry Point
# ============================================================================


def main():
    """Run all examples."""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "QUERY API BASIC EXAMPLES" + " " * 34 + "║")
    print("║" + " " * 78 + "║")
    print("║" + " " * 15 + "Phase 1 Implementation - surinort-ast" + " " * 26 + "║")
    print("╚" + "=" * 78 + "╝")

    examples = [
        example_type_selectors,
        example_universal_selector,
        example_attribute_selectors,
        example_query_helpers,
        example_query_all,
        example_protocol_queries,
        example_content_modifiers,
        example_compound_selectors,
        example_rule_analysis,
        example_performance,
    ]

    for example_func in examples:
        try:
            example_func()
        except Exception as e:
            print(f"\n[ERROR] {example_func.__name__}: {e}")

    print("\n" + "=" * 80)
    print("All examples completed successfully!")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
