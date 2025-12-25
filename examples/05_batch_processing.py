#!/usr/bin/env python3
"""
Batch Processing Examples for surinort-ast

This example demonstrates efficient batch processing of multiple IDS/IPS rules,
including error handling, statistics collection, and bulk transformations.

Author: Marc Rivero | @seifreed
License: GPL v3.0
"""

from collections import Counter, defaultdict

from surinort_ast import parse_rules, print_rule


def example_1_parse_multiple_rules():
    """Parse multiple rules using parse_rules function."""
    print("=" * 70)
    print("Example 1: Parse Multiple Rules")
    print("=" * 70)

    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001;)',
        'alert tcp any any -> any 443 (msg:"HTTPS Traffic"; sid:1000002;)',
        'alert udp any any -> any 53 (msg:"DNS Query"; sid:1000003;)',
        'alert tcp any any -> any 22 (msg:"SSH Connection"; sid:1000004;)',
    ]

    print(f"\nParsing {len(rules_text)} rules...\n")

    # Parse all rules, collecting errors
    successful_rules, errors = parse_rules(rules_text)

    print("Results:")
    print(f"  Successful: {len(successful_rules)}")
    print(f"  Failed: {len(errors)}")

    print("\nParsed rules:")
    for i, rule in enumerate(successful_rules, 1):
        print(
            f"  {i}. {rule.header.protocol.value:5s} port {rule.header.dst_port.value if hasattr(rule.header.dst_port, 'value') else 'any'}"
        )


def example_2_handle_parse_errors():
    """Handle parsing errors gracefully in batch processing."""
    print("\n" + "=" * 70)
    print("Example 2: Handle Parse Errors")
    print("=" * 70)

    rules_text = [
        'alert tcp any any -> any 80 (msg:"Valid rule 1"; sid:1;)',
        "invalid rule syntax here",  # This will fail
        'alert tcp any any -> any 443 (msg:"Valid rule 2"; sid:2;)',
        "alert tcp any any ->",  # Incomplete rule
        'alert tcp any any -> any 22 (msg:"Valid rule 3"; sid:3;)',
    ]

    print(f"\nProcessing {len(rules_text)} rules (some may be invalid)...\n")

    successful_rules, errors = parse_rules(rules_text)

    print("Results:")
    print(f"  Successful: {len(successful_rules)}")
    print(f"  Failed: {len(errors)}")

    if errors:
        print("\nErrors encountered:")
        for idx, error_msg in errors:
            print(f"  Rule {idx + 1}: {error_msg[:80]}...")

    print("\nSuccessfully parsed rules:")
    for rule in successful_rules:
        for opt in rule.options:
            if opt.node_type == "SidOption":
                print(f"  SID {opt.value}: {print_rule(rule)[:60]}...")


def example_3_collect_statistics():
    """Collect statistics from a batch of rules."""
    print("\n" + "=" * 70)
    print("Example 3: Collect Statistics")
    print("=" * 70)

    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)',
        'drop tcp any any -> any 22 (msg:"SSH Block"; sid:3;)',
        'alert udp any any -> any 53 (msg:"DNS"; sid:4;)',
        'alert http any any -> any any (msg:"HTTP App"; sid:5;)',
        'drop tcp any any -> any 23 (msg:"Telnet Block"; sid:6;)',
    ]

    print(f"\nAnalyzing {len(rules_text)} rules...\n")

    rules, _ = parse_rules(rules_text)

    # Collect statistics
    action_counts = Counter(rule.action.value for rule in rules)
    protocol_counts = Counter(rule.header.protocol.value for rule in rules)
    direction_counts = Counter(rule.header.direction.value for rule in rules)

    print("Statistics:")
    print("\n  Actions:")
    for action, count in action_counts.most_common():
        percentage = (count / len(rules)) * 100
        print(f"    {action:6s}: {count:3d} ({percentage:5.1f}%)")

    print("\n  Protocols:")
    for protocol, count in protocol_counts.most_common():
        percentage = (count / len(rules)) * 100
        print(f"    {protocol:6s}: {count:3d} ({percentage:5.1f}%)")

    print("\n  Directions:")
    for direction, count in direction_counts.most_common():
        percentage = (count / len(rules)) * 100
        print(f"    {direction:6s}: {count:3d} ({percentage:5.1f}%)")


def example_4_filter_rules():
    """Filter rules based on criteria."""
    print("\n" + "=" * 70)
    print("Example 4: Filter Rules by Criteria")
    print("=" * 70)

    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'drop tcp any any -> any 80 (msg:"HTTP Block"; sid:2;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:3;)',
        'drop tcp any any -> any 22 (msg:"SSH Block"; sid:4;)',
        'alert udp any any -> any 53 (msg:"DNS"; sid:5;)',
    ]

    print(f"\nFiltering {len(rules_text)} rules...\n")

    rules, _ = parse_rules(rules_text)

    # Filter 1: Only alert rules
    alert_rules = [r for r in rules if r.action.value == "alert"]
    print(f"Alert rules: {len(alert_rules)}/{len(rules)}")

    # Filter 2: Only TCP rules
    tcp_rules = [r for r in rules if r.header.protocol.value == "tcp"]
    print(f"TCP rules: {len(tcp_rules)}/{len(rules)}")

    # Filter 3: Rules targeting port 80
    port_80_rules = []
    for r in rules:
        if hasattr(r.header.dst_port, "value") and r.header.dst_port.value == 80:
            port_80_rules.append(r)
    print(f"Port 80 rules: {len(port_80_rules)}/{len(rules)}")

    # Filter 4: Drop rules
    drop_rules = [r for r in rules if r.action.value == "drop"]
    print(f"Drop rules: {len(drop_rules)}/{len(rules)}")

    print("\nDrop rules:")
    for rule in drop_rules:
        print(f"  - {print_rule(rule)}")


def example_5_bulk_transformation():
    """Apply bulk transformations to multiple rules."""
    print("\n" + "=" * 70)
    print("Example 5: Bulk Transformation")
    print("=" * 70)

    from surinort_ast.core.visitor import ASTTransformer

    class BulkSIDUpdater(ASTTransformer):
        """Add offset to all SIDs."""

        def __init__(self, offset):
            self.offset = offset

        def visit_SidOption(self, node):
            return node.model_copy(update={"value": node.value + self.offset})

    rules_text = [
        'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)',
        'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)',
        'alert udp any any -> any 53 (msg:"Rule 3"; sid:3;)',
    ]

    print(f"\nTransforming {len(rules_text)} rules (adding 1000000 to SIDs)...\n")

    rules, _ = parse_rules(rules_text)

    print("Original SIDs:")
    for rule in rules:
        for opt in rule.options:
            if opt.node_type == "SidOption":
                print(f"  {opt.value}")

    # Apply transformation
    transformer = BulkSIDUpdater(offset=1000000)
    transformed_rules = [transformer.visit(rule) for rule in rules]

    print("\nTransformed SIDs:")
    for rule in transformed_rules:
        for opt in rule.options:
            if opt.node_type == "SidOption":
                print(f"  {opt.value}")

    print("\nTransformed rules:")
    for rule in transformed_rules:
        print(f"  {print_rule(rule)}")


def example_6_option_analysis():
    """Analyze option usage across multiple rules."""
    print("\n" + "=" * 70)
    print("Example 6: Option Usage Analysis")
    print("=" * 70)

    rules_text = [
        'alert tcp any any -> any 80 (msg:"Test1"; content:"admin"; nocase; sid:1;)',
        'alert tcp any any -> any 443 (msg:"Test2"; content:"password"; sid:2;)',
        'alert tcp any any -> any 22 (msg:"Test3"; flow:established; sid:3;)',
        'alert tcp any any -> any 21 (msg:"Test4"; content:"USER"; offset:0; depth:4; sid:4;)',
    ]

    print(f"\nAnalyzing options in {len(rules_text)} rules...\n")

    rules, _ = parse_rules(rules_text)

    # Count option types
    option_counts = Counter()
    for rule in rules:
        for opt in rule.options:
            option_counts[opt.node_type] += 1

    print("Option usage:")
    for opt_type, count in option_counts.most_common():
        print(f"  {opt_type:25s}: {count}")

    # Find rules with content matching
    rules_with_content = []
    for rule in rules:
        for opt in rule.options:
            if opt.node_type == "ContentOption":
                rules_with_content.append(rule)
                break

    print(f"\nRules with content matching: {len(rules_with_content)}/{len(rules)}")


def example_7_parallel_processing_simulation():
    """Simulate efficient batch processing pattern."""
    print("\n" + "=" * 70)
    print("Example 7: Efficient Batch Processing Pattern")
    print("=" * 70)

    # Simulate a larger batch
    rules_text = []
    for i in range(1, 21):
        port = 80 + i
        rules_text.append(f'alert tcp any any -> any {port} (msg:"Rule {i}"; sid:{i};)')

    print(f"\nProcessing {len(rules_text)} rules in batches...\n")

    # Process in batches
    batch_size = 5
    all_rules = []
    all_errors = []

    for batch_num, i in enumerate(range(0, len(rules_text), batch_size), 1):
        batch = rules_text[i : i + batch_size]
        rules, errors = parse_rules(batch)

        all_rules.extend(rules)
        all_errors.extend((idx + i, err) for idx, err in errors)

        print(f"  Batch {batch_num}: {len(rules)} successful, {len(errors)} errors")

    print("\nTotal results:")
    print(f"  Successful: {len(all_rules)}")
    print(f"  Errors: {len(all_errors)}")

    # Show distribution by port ranges
    port_ranges = defaultdict(int)
    for rule in all_rules:
        if hasattr(rule.header.dst_port, "value"):
            port = rule.header.dst_port.value
            if port < 100:
                port_ranges["80-99"] += 1
            elif port < 150:
                port_ranges["100-149"] += 1
            else:
                port_ranges["150+"] += 1

    print("\nPort distribution:")
    for range_name, count in sorted(port_ranges.items()):
        print(f"  {range_name}: {count}")


def main():
    """Run all examples."""
    print("\n" + "=" * 70)
    print("SURINORT-AST: Batch Processing Examples")
    print("=" * 70)
    print("\nDemonstrating efficient processing of multiple rules.\n")

    try:
        example_1_parse_multiple_rules()
        example_2_handle_parse_errors()
        example_3_collect_statistics()
        example_4_filter_rules()
        example_5_bulk_transformation()
        example_6_option_analysis()
        example_7_parallel_processing_simulation()

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
