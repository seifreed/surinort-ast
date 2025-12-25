#!/usr/bin/env python3
"""
Rule Optimization Example for surinort-ast

Demonstrates how to optimize IDS rules for better performance while preserving
detection logic. This example shows:
- Performance cost estimation
- Rule optimization strategies
- Before/after comparison
- Batch optimization with statistics

Copyright (c) 2025 Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from surinort_ast import parse_rule, print_rule
from surinort_ast.analysis import PerformanceEstimator, RuleOptimizer


def demonstrate_single_rule_optimization():
    """
    Demonstrate optimizing a single rule with detailed analysis.
    """
    print("=" * 80)
    print("Single Rule Optimization")
    print("=" * 80)
    print()

    # Create a suboptimal rule (expensive operations first)
    original_rule = parse_rule(
        "alert tcp any any -> any 80 ("
        'pcre:"/(?i)(union.*select|select.*from|insert.*into)/"; '
        "byte_test:4,>,1000,0; "
        'content:"admin"; '
        'content:"password"; '
        'msg:"SQL injection with admin access"; sid:1000;)'
    )

    print("Original Rule:")
    print(f"  {print_rule(original_rule)}")
    print()

    # Estimate original cost
    estimator = PerformanceEstimator()
    original_cost = estimator.estimate_cost(original_rule)

    print(f"Original Cost Estimate: {original_cost:.2f} units")
    print()

    # Get cost breakdown
    breakdown = estimator.get_cost_breakdown(original_rule)
    print("Cost Breakdown by Option Type:")
    for option_type, cost in sorted(breakdown.items(), key=lambda x: x[1], reverse=True):
        percentage = (cost / original_cost) * 100 if original_cost > 0 else 0
        print(f"  {option_type:25s}: {cost:6.2f} units ({percentage:5.1f}%)")
    print()

    # Optimize the rule
    optimizer = RuleOptimizer()
    result = optimizer.optimize(original_rule)

    if result.was_modified:
        print("Optimized Rule:")
        print(f"  {print_rule(result.optimized)}")
        print()

        optimized_cost = estimator.estimate_cost(result.optimized)
        improvement = result.total_improvement

        print(f"Optimized Cost Estimate: {optimized_cost:.2f} units")
        print(f"Performance Improvement: {improvement:+.1f}%")
        print()

        print("Optimizations Applied:")
        for i, opt in enumerate(result.optimizations, 1):
            print(f"  {i}. [{opt.strategy}] {opt.description}")
            print(f"     Estimated gain: {opt.estimated_gain:+.1f}%")
        print()
    else:
        print("✓ Rule is already optimized - no changes needed")
        print()


def demonstrate_batch_optimization():
    """
    Demonstrate batch optimization with statistics.
    """
    print("=" * 80)
    print("Batch Rule Optimization")
    print("=" * 80)
    print()

    # Create a set of rules with various optimization opportunities
    rules = [
        # Rule 1: Suboptimal ordering (PCRE before content)
        parse_rule(
            "alert tcp any any -> any 80 ("
            'pcre:"/malicious/i"; '
            'content:"GET"; '
            'msg:"Malicious HTTP request"; sid:2001;)'
        ),
        # Rule 2: Multiple content without fast_pattern
        parse_rule(
            "alert tcp any any -> any 443 ("
            'content:"secret"; '
            'content:"password"; '
            'content:"admin"; '
            'msg:"Sensitive data in HTTPS"; sid:2002;)'
        ),
        # Rule 3: Complex PCRE with better content available
        parse_rule(
            "alert tcp any any -> any 80 ("
            'pcre:"/^POST.*login/"; '
            'content:"username"; '
            'content:"password"; '
            'msg:"Login attempt"; sid:2003;)'
        ),
        # Rule 4: Already optimal
        parse_rule(
            "alert tcp any any -> any 22 ("
            "flow:to_server; "
            'content:"SSH-"; '
            'msg:"SSH connection"; sid:2004;)'
        ),
        # Rule 5: Many expensive operations
        parse_rule(
            "alert tcp any any -> any 80 ("
            'pcre:"/pattern1/"; '
            'pcre:"/pattern2/"; '
            "byte_test:4,>,100,0; "
            'content:"test"; '
            'msg:"Multiple expensive ops"; sid:2005;)'
        ),
    ]

    print(f"Optimizing {len(rules)} rules...")
    print()

    # Perform batch optimization
    optimizer = RuleOptimizer()
    results = optimizer.optimize_ruleset(rules, verbose=True)
    print()

    # Display results
    print("Optimization Results:")
    print("-" * 80)

    for i, result in enumerate(results, 1):
        if result.was_modified:
            print(f"\nRule #{i} (SID {i + 2000}): OPTIMIZED")
            print(f"  Original: {print_rule(result.original)}")
            print(f"  Optimized: {print_rule(result.optimized)}")
            print(f"  Improvement: {result.total_improvement:+.1f}%")
            print(f"  Strategies: {', '.join(result.strategy_names)}")
        else:
            print(f"\nRule #{i} (SID {i + 2000}): No changes needed")

    print()

    # Get and display statistics
    stats = optimizer.get_statistics(results)

    print("=" * 80)
    print("Optimization Statistics")
    print("=" * 80)
    print()

    print(f"Total Rules: {stats['total_rules']}")
    print(f"Rules Modified: {stats['modified_count']}")
    print(f"Modification Rate: {stats['modification_rate']:.1f}%")
    print()

    if stats["modified_count"] > 0:
        print(f"Average Improvement: {stats['avg_improvement']:.1f}%")
        print(f"Maximum Improvement: {stats['max_improvement']:.1f}%")
        print(f"Total Optimizations Applied: {stats['total_optimizations']}")
        print()

        print("Strategies Applied:")
        for strategy, count in sorted(
            stats["strategy_counts"].items(), key=lambda x: x[1], reverse=True
        ):
            print(f"  {strategy:25s}: {count} times")
        print()


def demonstrate_performance_estimation():
    """
    Demonstrate performance estimation for different rule patterns.
    """
    print("=" * 80)
    print("Performance Cost Comparison")
    print("=" * 80)
    print()

    test_rules = [
        ("Minimal metadata-only", 'alert ip any any -> any any (msg:"Minimal"; sid:1;)'),
        (
            "Simple content match",
            'alert tcp any any -> any 80 (content:"test"; msg:"Content"; sid:2;)',
        ),
        (
            "Multiple content",
            'alert tcp any any -> any 80 (content:"a"; content:"b"; content:"c"; msg:"Multi"; sid:3;)',
        ),
        (
            "Content with modifiers",
            'alert tcp any any -> any 80 (content:"test"; nocase; depth:100; msg:"Modified"; sid:4;)',
        ),
        ("Simple PCRE", 'alert tcp any any -> any 80 (pcre:"/test/"; msg:"PCRE"; sid:5;)'),
        (
            "Complex PCRE",
            'alert tcp any any -> any 80 (pcre:"/(?i)complex.*pattern.*with.*groups|alternative/"; msg:"Complex"; sid:6;)',
        ),
        (
            "Byte operations",
            'alert tcp any any -> any 80 (byte_test:4,>,100,0; byte_jump:4,0; msg:"Bytes"; sid:7;)',
        ),
        (
            "Mixed expensive",
            'alert tcp any any -> any 80 (pcre:"/test/"; byte_test:4,>,100,0; content:"a"; msg:"Mixed"; sid:8;)',
        ),
    ]

    estimator = PerformanceEstimator()

    print(f"{'Rule Type':<25s} {'Cost':>10s} {'Relative':>10s}")
    print("-" * 80)

    base_cost = None

    for rule_name, rule_text in test_rules:
        rule = parse_rule(rule_text)
        cost = estimator.estimate_cost(rule)

        if base_cost is None:
            base_cost = cost
            relative = "1.0x"
        else:
            relative_val = cost / base_cost if base_cost > 0 else 0
            relative = f"{relative_val:.1f}x"

        print(f"{rule_name:<25s} {cost:>10.2f} {relative:>10s}")

    print()


def main():
    """
    Run all optimization demonstrations.
    """
    print("\n" + "=" * 80)
    print("IDS Rule Optimization Examples")
    print("=" * 80)
    print()

    # Run demonstrations
    demonstrate_performance_estimation()
    print()

    demonstrate_single_rule_optimization()
    print()

    demonstrate_batch_optimization()
    print()

    print("=" * 80)
    print("Optimization Complete")
    print("=" * 80)
    print()
    print("Key Takeaways:")
    print("  1. Option ordering matters - put fast checks first")
    print("  2. Use fast_pattern on distinctive content for better filtering")
    print("  3. PCRE is expensive - minimize usage when possible")
    print("  4. Batch optimization provides aggregate statistics")
    print("  5. Performance gains compound across large rule sets")
    print()


if __name__ == "__main__":
    main()
