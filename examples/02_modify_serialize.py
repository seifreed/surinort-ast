#!/usr/bin/env python3
"""
Example 02: Modify and Serialize Rules

This example demonstrates:
- Parsing a rule
- Modifying AST components (immutable pattern)
- Serializing back to rule text
- Different formatting options

Copyright (C) 2025 Marc Rivero López
Licensed under the GNU General Public License v3.0
"""

from surinort_ast import parse_rule
from surinort_ast.core.nodes import Action
from surinort_ast.printer import print_rule


def main():
    """Demonstrate rule modification and serialization."""
    # Parse existing rule
    original_rule = 'alert tcp any any -> any 80 (msg:"Test Rule"; sid:1;)'
    rule = parse_rule(original_rule)

    print("Original Rule:")
    print(f"  {print_rule(rule)}")

    # Modify action (Pydantic immutable pattern - create new instance)
    modified_rule = rule.model_copy(update={"action": Action.DROP})

    print("\nModified Rule (action changed to DROP):")
    print(f"  {print_rule(modified_rule)}")

    # Serialize with stable formatting
    stable_output = print_rule(modified_rule, stable=True)
    print("\nStable/Canonical Format:")
    print(f"  {stable_output}")


if __name__ == "__main__":
    main()
