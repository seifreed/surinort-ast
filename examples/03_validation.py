#!/usr/bin/env python3
"""
Example 03: Rule Validation

This example demonstrates:
- Parsing and validating rules
- Filtering diagnostics by severity level
- Handling validation errors and warnings

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0
"""

from surinort_ast import parse_rules, validate_rule
from surinort_ast.core.diagnostics import DiagnosticLevel


def main():
    """Demonstrate rule validation."""
    # Sample rules with different validation states
    rule_texts = [
        'alert tcp any any -> any 80 (msg:"Valid Rule"; sid:1;)',
        'alert tcp any any -> any 443 (msg:"Another Valid"; sid:2;)',
        'alert tcp any any -> any 8080 (msg:"Valid with custom port"; sid:3;)',
    ]

    print("Parsing and Validating Rules:")
    print("=" * 60)

    # Parse rules
    rules, parse_errors = parse_rules(rule_texts)

    print(f"Parsed {len(rules)} rules successfully")
    if parse_errors:
        print(f"Failed to parse {len(parse_errors)} rules")

    # Validate each rule
    for idx, rule in enumerate(rules, 1):
        print(f"\nRule {idx}:")
        diagnostics = validate_rule(rule)

        # Filter by level
        errors = [d for d in diagnostics if d.level == DiagnosticLevel.ERROR]
        warnings = [d for d in diagnostics if d.level == DiagnosticLevel.WARNING]
        infos = [d for d in diagnostics if d.level == DiagnosticLevel.INFO]

        print(f"  Errors: {len(errors)}")
        print(f"  Warnings: {len(warnings)}")
        print(f"  Info: {len(infos)}")

        # Show diagnostic messages
        for diag in diagnostics:
            print(f"    [{diag.level.value.upper()}] {diag.message}")


if __name__ == "__main__":
    main()
