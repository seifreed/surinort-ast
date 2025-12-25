#!/usr/bin/env python3
"""
Advanced AST Transformation Examples for surinort-ast

This example demonstrates advanced AST transformation patterns including:
- Complex rule transformations
- Multi-pass transformations
- Conditional transformations
- Rule optimization

Author: Marc Rivero | @seifreed
License: GPL v3.0
"""

from surinort_ast import Action, parse_rule, print_rule
from surinort_ast.core.nodes import ClasstypeOption, RevOption
from surinort_ast.core.visitor import ASTTransformer


def example_1_action_converter():
    """Convert all alert rules to drop rules."""
    print("=" * 70)
    print("Example 1: Action Converter")
    print("=" * 70)

    class AlertToDropConverter(ASTTransformer):
        """Convert alert actions to drop."""

        def visit_Rule(self, node):
            """Convert alert to drop."""
            if node.action == Action.ALERT:
                # Create new rule with drop action
                new_rule = node.model_copy(update={"action": Action.DROP})

                # Update message to reflect change
                new_options = []
                for opt in new_rule.options:
                    if opt.node_type == "MsgOption":
                        new_msg = f"[BLOCKED] {opt.text}"
                        new_opt = opt.model_copy(update={"text": new_msg})
                        new_options.append(new_opt)
                    else:
                        new_options.append(opt)

                return new_rule.model_copy(update={"options": new_options})

            return node

    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP Attack"; sid:1;)',
        'alert tcp any any -> any 443 (msg:"HTTPS Attack"; sid:2;)',
        'pass tcp any any -> any 22 (msg:"SSH Allow"; sid:3;)',
    ]

    print("\nConverting alert rules to drop:\n")

    transformer = AlertToDropConverter()

    for rule_text in rules_text:
        rule = parse_rule(rule_text)
        print(f"Original: {rule.action.value:6s} - {rule_text[:50]}...")

        transformed = transformer.visit(rule)
        result = print_rule(transformed)
        print(f"Result:   {transformed.action.value:6s} - {result[:50]}...")
        print()


def example_2_sid_namespace_migrator():
    """Migrate SIDs to a different namespace."""
    print("\n" + "=" * 70)
    print("Example 2: SID Namespace Migration")
    print("=" * 70)

    class SIDNamespaceMigrator(ASTTransformer):
        """Migrate SIDs to new namespace."""

        def __init__(self, old_start, new_start):
            self.old_start = old_start
            self.new_start = new_start
            self.migration_map = {}

        def visit_SidOption(self, node):
            """Migrate SID if in old namespace."""
            old_sid = node.value

            # Check if in old namespace
            if old_sid >= self.old_start and old_sid < self.old_start + 1000:
                # Calculate new SID
                offset = old_sid - self.old_start
                new_sid = self.new_start + offset

                # Track migration
                self.migration_map[old_sid] = new_sid

                return node.model_copy(update={"value": new_sid})

            return node

    rules_text = [
        'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1000;)',
        'alert tcp any any -> any 443 (msg:"Rule 2"; sid:1001;)',
        'alert tcp any any -> any 22 (msg:"Rule 3"; sid:2000;)',  # Outside range
    ]

    print("\nMigrating SIDs from 1000-1999 to 9000000-9000999:\n")

    migrator = SIDNamespaceMigrator(old_start=1000, new_start=9000000)

    for rule_text in rules_text:
        rule = parse_rule(rule_text)
        transformed = migrator.visit(rule)
        result = print_rule(transformed)
        print(f"  {result}")

    print("\nMigration map:")
    for old_sid, new_sid in migrator.migration_map.items():
        print(f"  {old_sid} -> {new_sid}")


def example_3_revision_bumper():
    """Automatically bump revision numbers."""
    print("\n" + "=" * 70)
    print("Example 3: Automatic Revision Bumper")
    print("=" * 70)

    class RevisionBumper(ASTTransformer):
        """Increment revision numbers or add if missing."""

        def visit_Rule(self, node):
            """Ensure rule has revision and bump it."""
            has_rev = False
            new_options = []

            for opt in node.options:
                if opt.node_type == "RevOption":
                    has_rev = True
                    # Increment revision
                    new_opt = opt.model_copy(update={"value": opt.value + 1})
                    new_options.append(new_opt)
                else:
                    new_options.append(opt)

            # Add rev:1 if missing
            if not has_rev:
                new_options.append(RevOption(value=1))

            return node.model_copy(update={"options": new_options})

    rules_text = [
        'alert tcp any any -> any 80 (msg:"With revision"; sid:1; rev:1;)',
        'alert tcp any any -> any 443 (msg:"Without revision"; sid:2;)',
    ]

    print("\nBumping revisions:\n")

    bumper = RevisionBumper()

    for rule_text in rules_text:
        rule = parse_rule(rule_text)
        print(f"Original: {rule_text}")

        transformed = bumper.visit(rule)
        result = print_rule(transformed)
        print(f"Result:   {result}")
        print()


def example_4_metadata_enricher():
    """Add metadata to rules that are missing it."""
    print("\n" + "=" * 70)
    print("Example 4: Metadata Enricher")
    print("=" * 70)

    class MetadataEnricher(ASTTransformer):
        """Add missing metadata to rules."""

        def __init__(self, default_classtype="unknown"):
            self.default_classtype = default_classtype

        def visit_Rule(self, node):
            """Add missing classtype."""
            has_classtype = any(opt.node_type == "ClasstypeOption" for opt in node.options)

            if not has_classtype:
                # Add default classtype
                new_opt = ClasstypeOption(value=self.default_classtype)
                new_options = list(node.options) + [new_opt]
                return node.model_copy(update={"options": new_options})

            return node

    rules_text = [
        'alert tcp any any -> any 80 (msg:"Has classtype"; classtype:web-application-attack; sid:1;)',
        'alert tcp any any -> any 443 (msg:"Missing classtype"; sid:2;)',
    ]

    print("\nAdding default classtype to incomplete rules:\n")

    enricher = MetadataEnricher(default_classtype="not-suspicious")

    for rule_text in rules_text:
        rule = parse_rule(rule_text)
        transformed = enricher.visit(rule)
        result = print_rule(transformed)

        # Check if classtype was added
        has_classtype = any(opt.node_type == "ClasstypeOption" for opt in transformed.options)
        status = (
            "✓ Already had classtype"
            if any(opt.node_type == "ClasstypeOption" for opt in rule.options)
            else "✓ Added classtype"
        )

        print(f"  {result}")
        print(f"    {status}")
        print()


def example_5_port_normalizer():
    """Normalize port specifications."""
    print("\n" + "=" * 70)
    print("Example 5: Port Normalizer")
    print("=" * 70)

    from surinort_ast.core.nodes import Port

    class PortNormalizer(ASTTransformer):
        """Normalize common port aliases to explicit ports."""

        def __init__(self):
            self.port_map = {
                # Common service ports
                "http": 80,
                "https": 443,
                "ssh": 22,
                "ftp": 21,
                "dns": 53,
            }

        def visit_PortVariable(self, node):
            """Replace common port variables with explicit ports."""
            # Check if variable name matches known service
            var_name = node.name.lower().replace("$", "").replace("_port", "")

            if var_name in self.port_map:
                return Port(value=self.port_map[var_name])

            return node

    # Note: This example shows the concept, but actual port variables
    # would need to be in the rule text
    print("\nConcept: Port normalization")
    print("  Would replace: $HTTP_PORT -> 80")
    print("  Would replace: $HTTPS_PORT -> 443")
    print("  Would replace: $SSH_PORT -> 22")


def example_6_multi_pass_transformation():
    """Apply multiple transformations in sequence."""
    print("\n" + "=" * 70)
    print("Example 6: Multi-Pass Transformation")
    print("=" * 70)

    class Pass1_SIDMigrator(ASTTransformer):
        """First pass: Migrate SIDs."""

        def visit_SidOption(self, node):
            if node.value < 1000000:
                return node.model_copy(update={"value": node.value + 1000000})
            return node

    class Pass2_RevBumper(ASTTransformer):
        """Second pass: Bump revisions."""

        def visit_RevOption(self, node):
            return node.model_copy(update={"value": node.value + 1})

    class Pass3_MetadataAdder(ASTTransformer):
        """Third pass: Add metadata."""

        def visit_Rule(self, node):
            has_classtype = any(opt.node_type == "ClasstypeOption" for opt in node.options)
            if not has_classtype:
                new_opt = ClasstypeOption(value="updated-rule")
                new_options = list(node.options) + [new_opt]
                return node.model_copy(update={"options": new_options})
            return node

    rule_text = 'alert tcp any any -> any 80 (msg:"Multi-pass test"; sid:100; rev:1;)'

    print(f"\nOriginal rule:\n{rule_text}\n")

    rule = parse_rule(rule_text)

    # Apply transformations in sequence
    pass1 = Pass1_SIDMigrator()
    pass2 = Pass2_RevBumper()
    pass3 = Pass3_MetadataAdder()

    print("Applying transformations:")
    print("  Pass 1: SID migration")
    rule = pass1.visit(rule)
    print(f"    Result: {print_rule(rule)[:70]}...")

    print("  Pass 2: Revision bump")
    rule = pass2.visit(rule)
    print(f"    Result: {print_rule(rule)[:70]}...")

    print("  Pass 3: Metadata addition")
    rule = pass3.visit(rule)
    print(f"    Result: {print_rule(rule)[:70]}...")

    print(f"\nFinal result:\n{print_rule(rule)}")


def example_7_conditional_transformer():
    """Transform rules based on conditions."""
    print("\n" + "=" * 70)
    print("Example 7: Conditional Transformation")
    print("=" * 70)

    class ConditionalTransformer(ASTTransformer):
        """Transform only rules matching certain conditions."""

        def visit_Rule(self, node):
            """Transform only TCP rules on port 80."""
            is_tcp = node.header.protocol.value == "tcp"

            is_port_80 = False
            if hasattr(node.header.dst_port, "value"):
                is_port_80 = node.header.dst_port.value == 80

            if is_tcp and is_port_80 and node.action == Action.ALERT:
                # Convert to drop
                new_rule = node.model_copy(update={"action": Action.DROP})

                # Add note to message
                new_options = []
                for opt in new_rule.options:
                    if opt.node_type == "MsgOption":
                        new_msg = f"[AUTO-BLOCKED] {opt.text}"
                        new_options.append(opt.model_copy(update={"text": new_msg}))
                    else:
                        new_options.append(opt)

                return new_rule.model_copy(update={"options": new_options})

            return node

    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',  # Will transform
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)',  # Won't transform (port)
        'alert udp any any -> any 80 (msg:"UDP"; sid:3;)',  # Won't transform (protocol)
        'drop tcp any any -> any 80 (msg:"Already drop"; sid:4;)',  # Won't transform (action)
    ]

    print("\nConditionally transforming rules (TCP + port 80 + alert):\n")

    transformer = ConditionalTransformer()

    for rule_text in rules_text:
        rule = parse_rule(rule_text)
        transformed = transformer.visit(rule)

        changed = rule.action != transformed.action
        status = "TRANSFORMED" if changed else "unchanged"

        print(f"  [{status}] {print_rule(transformed)[:70]}...")


def main():
    """Run all examples."""
    print("\n" + "=" * 70)
    print("SURINORT-AST: Advanced AST Transformation Examples")
    print("=" * 70)
    print("\nDemonstrating advanced transformation patterns.\n")

    try:
        example_1_action_converter()
        example_2_sid_namespace_migrator()
        example_3_revision_bumper()
        example_4_metadata_enricher()
        example_5_port_normalizer()
        example_6_multi_pass_transformation()
        example_7_conditional_transformer()

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
