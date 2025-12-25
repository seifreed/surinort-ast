#!/usr/bin/env python3
"""
Rule Modification Examples for surinort-ast

This example demonstrates how to modify IDS/IPS rules by creating new AST nodes.
All nodes are immutable (Pydantic frozen models), so modifications create new instances.

Author: Marc Rivero | @seifreed
License: GPL v3.0
"""

from surinort_ast import Action, parse_rule, print_rule
from surinort_ast.core.visitor import ASTTransformer


def example_1_change_action():
    """Change rule action from alert to drop."""
    print("=" * 70)
    print("Example 1: Change Rule Action")
    print("=" * 70)

    original = 'alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001;)'

    print(f"\nOriginal rule:\n{original}\n")

    rule = parse_rule(original)
    print(f"Original action: {rule.action.value}")

    # Modify action - create new rule with updated action
    modified_rule = rule.model_copy(update={"action": Action.DROP})

    print(f"Modified action: {modified_rule.action.value}")

    # Serialize back to text
    modified_text = print_rule(modified_rule)
    print(f"\nModified rule:\n{modified_text}")


def example_2_update_sid():
    """Update the SID of a rule."""
    print("\n" + "=" * 70)
    print("Example 2: Update Rule SID")
    print("=" * 70)

    original = 'alert tcp any any -> any 443 (msg:"TLS Traffic"; sid:1; rev:1;)'

    print(f"\nOriginal rule:\n{original}\n")

    rule = parse_rule(original)

    # Find and update SID option
    new_options = []
    for opt in rule.options:
        if opt.node_type == "SidOption":
            # Create new SID option with updated value
            new_opt = opt.model_copy(update={"value": 1000001})
            new_options.append(new_opt)
            print(f"Changed SID: {opt.value} -> {new_opt.value}")
        else:
            new_options.append(opt)

    # Create new rule with updated options
    modified_rule = rule.model_copy(update={"options": new_options})

    modified_text = print_rule(modified_rule)
    print(f"\nModified rule:\n{modified_text}")


def example_3_add_option():
    """Add a new option to a rule."""
    print("\n" + "=" * 70)
    print("Example 3: Add New Option")
    print("=" * 70)

    from surinort_ast.core.nodes import RevOption

    original = 'alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001;)'

    print(f"\nOriginal rule:\n{original}\n")

    rule = parse_rule(original)
    print(f"Original options: {len(rule.options)}")

    # Add a revision option
    rev_option = RevOption(value=2)
    new_options = list(rule.options) + [rev_option]

    # Create new rule with additional option
    modified_rule = rule.model_copy(update={"options": new_options})

    print(f"Modified options: {len(modified_rule.options)}")

    modified_text = print_rule(modified_rule)
    print(f"\nModified rule:\n{modified_text}")


def example_4_modify_message():
    """Modify the message text of a rule."""
    print("\n" + "=" * 70)
    print("Example 4: Modify Message Text")
    print("=" * 70)

    original = 'alert tcp any any -> any 22 (msg:"SSH Connection"; sid:1000001;)'

    print(f"\nOriginal rule:\n{original}\n")

    rule = parse_rule(original)

    # Update message option
    new_options = []
    for opt in rule.options:
        if opt.node_type == "MsgOption":
            # Create new message with updated text
            new_opt = opt.model_copy(update={"text": "Potential SSH Brute Force"})
            new_options.append(new_opt)
            print("Changed message:")
            print(f"  Old: {opt.text}")
            print(f"  New: {new_opt.text}")
        else:
            new_options.append(opt)

    modified_rule = rule.model_copy(update={"options": new_options})

    modified_text = print_rule(modified_rule)
    print(f"\nModified rule:\n{modified_text}")


def example_5_bulk_sid_update():
    """Update SIDs across multiple rules using a transformer."""
    print("\n" + "=" * 70)
    print("Example 5: Bulk SID Update with Transformer")
    print("=" * 70)

    class SIDRewriter(ASTTransformer):
        """Transformer that adds offset to all SIDs."""

        def __init__(self, offset):
            self.offset = offset

        def visit_SidOption(self, node):
            """Add offset to SID value."""
            return node.model_copy(update={"value": node.value + self.offset})

    rules = [
        'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)',
        'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)',
        'alert udp any any -> any 53 (msg:"Rule 3"; sid:3;)',
    ]

    print("\nOriginal rules:")
    for i, rule_text in enumerate(rules, 1):
        print(f"  {i}. {rule_text}")

    # Apply transformer to add 1000000 to all SIDs
    transformer = SIDRewriter(offset=1000000)

    print("\nTransformed rules (SID + 1000000):")
    for i, rule_text in enumerate(rules, 1):
        rule = parse_rule(rule_text)
        transformed = transformer.visit(rule)
        result = print_rule(transformed)
        print(f"  {i}. {result}")


def example_6_change_port():
    """Modify the destination port of a rule."""
    print("\n" + "=" * 70)
    print("Example 6: Change Destination Port")
    print("=" * 70)

    from surinort_ast.core.nodes import Port

    original = 'alert tcp any any -> any 80 (msg:"HTTP on standard port"; sid:1;)'

    print(f"\nOriginal rule:\n{original}\n")

    rule = parse_rule(original)

    # Create new port
    new_port = Port(value=8080)

    # Create new header with updated port
    new_header = rule.header.model_copy(update={"dst_port": new_port})

    # Create new rule with updated header
    modified_rule = rule.model_copy(update={"header": new_header})

    # Also update message to reflect the change
    new_options = []
    for opt in modified_rule.options:
        if opt.node_type == "MsgOption":
            new_opt = opt.model_copy(update={"text": "HTTP on alternate port"})
            new_options.append(new_opt)
        else:
            new_options.append(opt)

    modified_rule = modified_rule.model_copy(update={"options": new_options})

    modified_text = print_rule(modified_rule)
    print(f"Modified rule:\n{modified_text}")


def example_7_remove_option():
    """Remove an option from a rule."""
    print("\n" + "=" * 70)
    print("Example 7: Remove Option")
    print("=" * 70)

    original = 'alert tcp any any -> any 80 (msg:"Test"; content:"admin"; nocase; sid:1; rev:1;)'

    print(f"\nOriginal rule:\n{original}\n")
    print(f"Original has {len(parse_rule(original).options)} options")

    rule = parse_rule(original)

    # Remove the 'rev' option
    new_options = [opt for opt in rule.options if opt.node_type != "RevOption"]

    print(f"After removing RevOption: {len(new_options)} options")

    modified_rule = rule.model_copy(update={"options": new_options})

    modified_text = print_rule(modified_rule)
    print(f"\nModified rule:\n{modified_text}")


def example_8_change_direction():
    """Change the direction of a rule."""
    print("\n" + "=" * 70)
    print("Example 8: Change Rule Direction")
    print("=" * 70)

    from surinort_ast import Direction

    original = 'alert tcp any any -> any 80 (msg:"Outbound HTTP"; sid:1;)'

    print(f"\nOriginal rule:\n{original}\n")

    rule = parse_rule(original)
    print(f"Original direction: {rule.header.direction.value}")

    # Change to bidirectional
    new_header = rule.header.model_copy(update={"direction": Direction.BIDIRECTIONAL})
    modified_rule = rule.model_copy(update={"header": new_header})

    # Update message
    new_options = []
    for opt in modified_rule.options:
        if opt.node_type == "MsgOption":
            new_opt = opt.model_copy(update={"text": "Bidirectional HTTP"})
            new_options.append(new_opt)
        else:
            new_options.append(opt)

    modified_rule = modified_rule.model_copy(update={"options": new_options})

    print(f"Modified direction: {modified_rule.header.direction.value}")

    modified_text = print_rule(modified_rule)
    print(f"\nModified rule:\n{modified_text}")


def main():
    """Run all examples."""
    print("\n" + "=" * 70)
    print("SURINORT-AST: Rule Modification Examples")
    print("=" * 70)
    print("\nDemonstrating how to modify IDS/IPS rules using immutable AST nodes.\n")

    try:
        example_1_change_action()
        example_2_update_sid()
        example_3_add_option()
        example_4_modify_message()
        example_5_bulk_sid_update()
        example_6_change_port()
        example_7_remove_option()
        example_8_change_direction()

        print("\n" + "=" * 70)
        print("All examples completed successfully!")
        print("=" * 70)
        print("\nKey takeaway: All modifications create new immutable instances.")

    except Exception as e:
        print(f"\nError: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
