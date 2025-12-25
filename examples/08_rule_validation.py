#!/usr/bin/env python3
"""
Rule Validation Examples for surinort-ast

This example demonstrates comprehensive rule validation including:
- Required option checking
- Semantic validation
- Best practices checking
- Custom validation rules

Author: Marc Rivero | @seifreed
License: GPL v3.0
"""

from surinort_ast import DiagnosticLevel, parse_rule, parse_rules, validate_rule
from surinort_ast.core.visitor import ASTVisitor


def example_1_basic_validation():
    """Validate rules for required options."""
    print("=" * 70)
    print("Example 1: Basic Rule Validation")
    print("=" * 70)

    rules_text = [
        'alert tcp any any -> any 80 (msg:"Complete rule"; sid:1; rev:1;)',  # Complete
        'alert tcp any any -> any 443 (msg:"Missing revision"; sid:2;)',  # No rev
        "alert tcp any any -> any 22 (sid:3;)",  # Missing msg
        'alert tcp any any -> any 21 (msg:"Missing SID";)',  # No SID
    ]

    print(f"\nValidating {len(rules_text)} rules:\n")

    for i, rule_text in enumerate(rules_text, 1):
        print(f"Rule {i}: {rule_text[:50]}...")

        try:
            rule = parse_rule(rule_text)
            diagnostics = validate_rule(rule)

            if diagnostics:
                for diag in diagnostics:
                    print(f"  {diag.level.value}: {diag.message}")
            else:
                print("  ✓ No issues")

        except Exception as e:
            print(f"  ERROR: {e}")

        print()


def example_2_diagnostic_levels():
    """Understand different diagnostic levels."""
    print("\n" + "=" * 70)
    print("Example 2: Diagnostic Levels")
    print("=" * 70)

    rule_text = 'alert tcp any any -> any 80 (msg:"Test";)'  # Missing SID

    print(f"\nValidating rule:\n{rule_text}\n")

    rule = parse_rule(rule_text)
    diagnostics = validate_rule(rule)

    print("Diagnostics by level:")

    warnings = [d for d in diagnostics if d.level == DiagnosticLevel.WARNING]
    errors = [d for d in diagnostics if d.level == DiagnosticLevel.ERROR]
    info = [d for d in diagnostics if d.level == DiagnosticLevel.INFO]

    print(f"\n  Errors: {len(errors)}")
    for diag in errors:
        print(f"    - {diag.message}")

    print(f"\n  Warnings: {len(warnings)}")
    for diag in warnings:
        print(f"    - {diag.message}")

    print(f"\n  Info: {len(info)}")
    for diag in info:
        print(f"    - {diag.message}")


def example_3_custom_validator():
    """Create custom validation logic."""
    print("\n" + "=" * 70)
    print("Example 3: Custom Validation Logic")
    print("=" * 70)

    from surinort_ast.core.visitor import ASTVisitor

    class CustomValidator(ASTVisitor):
        """Custom validator for specific requirements."""

        def __init__(self):
            self.issues = []

        def visit_Rule(self, node):
            """Validate rule-level requirements."""
            # Check for required metadata
            has_msg = any(opt.node_type == "MsgOption" for opt in node.options)
            has_sid = any(opt.node_type == "SidOption" for opt in node.options)
            has_rev = any(opt.node_type == "RevOption" for opt in node.options)

            if not has_msg:
                self.issues.append("Missing required option: msg")
            if not has_sid:
                self.issues.append("Missing required option: sid")
            if not has_rev:
                self.issues.append("Best practice: Include rev option")

            # Check for classtype
            has_classtype = any(opt.node_type == "ClasstypeOption" for opt in node.options)
            if not has_classtype:
                self.issues.append("Best practice: Include classtype option")

            # Check action
            if node.action.value == "drop" or node.action.value == "reject":
                # Blocking rules should have justification
                has_reference = any(opt.node_type == "ReferenceOption" for opt in node.options)
                if not has_reference:
                    self.issues.append("Blocking rule should include reference")

            super().visit_Rule(node)

        def default_return(self):
            return None

    rules_text = [
        'alert tcp any any -> any 80 (msg:"Good rule"; sid:1; rev:1; classtype:web-application-attack;)',
        'drop tcp any any -> any 22 (msg:"SSH block"; sid:2;)',  # Missing reference
        "alert tcp any any -> any 443 (sid:3;)",  # Missing msg
    ]

    print(f"\nCustom validation of {len(rules_text)} rules:\n")

    for i, rule_text in enumerate(rules_text, 1):
        print(f"Rule {i}:")
        print(f"  {rule_text[:70]}...")

        rule = parse_rule(rule_text)
        validator = CustomValidator()
        validator.visit(rule)

        if validator.issues:
            for issue in validator.issues:
                print(f"    - {issue}")
        else:
            print("    ✓ Passes custom validation")
        print()


def example_4_port_range_validation():
    """Validate port ranges and values."""
    print("\n" + "=" * 70)
    print("Example 4: Port Range Validation")
    print("=" * 70)

    class PortValidator(ASTVisitor):
        """Validate port specifications."""

        def __init__(self):
            self.issues = []

        def visit_Port(self, node):
            """Validate single port value."""
            if node.value < 0 or node.value > 65535:
                self.issues.append(f"Invalid port: {node.value} (must be 0-65535)")
            elif node.value == 0:
                self.issues.append("Warning: Port 0 is unusual")

        def visit_PortRange(self, node):
            """Validate port range."""
            if node.start > node.end:
                self.issues.append(f"Invalid range: {node.start}:{node.end} (start > end)")
            if node.end - node.start > 60000:
                self.issues.append(
                    f"Warning: Very large port range ({node.end - node.start} ports)"
                )

        def default_return(self):
            return None

    rules_text = [
        'alert tcp any any -> any 80 (msg:"Normal port"; sid:1;)',
        'alert tcp any any -> any 1024:65535 (msg:"High ports"; sid:2;)',
        'alert tcp any any -> any 0 (msg:"Port 0"; sid:3;)',  # Unusual
    ]

    print("\nValidating port specifications:\n")

    for rule_text in rules_text:
        print(f"{rule_text[:60]}...")
        rule = parse_rule(rule_text)
        validator = PortValidator()
        validator.visit(rule)

        if validator.issues:
            for issue in validator.issues:
                print(f"  {issue}")
        else:
            print("  ✓ Port specification valid")
        print()


def example_5_content_validation():
    """Validate content patterns."""
    print("\n" + "=" * 70)
    print("Example 5: Content Pattern Validation")
    print("=" * 70)

    class ContentValidator(ASTVisitor):
        """Validate content pattern usage."""

        def __init__(self):
            self.issues = []
            self.content_count = 0
            self.has_depth_or_offset = False

        def visit_ContentOption(self, node):
            """Track content patterns."""
            self.content_count += 1

            # Check for empty patterns
            pattern = node.pattern
            if (isinstance(pattern, bytes) and len(pattern) == 0) or (
                isinstance(pattern, str) and len(pattern.strip()) == 0
            ):
                self.issues.append("Empty content pattern detected")

        def visit_OffsetOption(self, node):
            """Track offset usage."""
            self.has_depth_or_offset = True
            if node.value < 0:
                self.issues.append(f"Invalid offset: {node.value} (must be >= 0)")

        def visit_DepthOption(self, node):
            """Track depth usage."""
            self.has_depth_or_offset = True
            if node.value <= 0:
                self.issues.append(f"Invalid depth: {node.value} (must be > 0)")

        def visit_Rule(self, node):
            """Validate at rule level."""
            super().visit_Rule(node)

            # Performance tip: Using depth/offset with content improves performance
            if self.content_count > 0 and not self.has_depth_or_offset:
                self.issues.append("Performance tip: Consider using offset/depth with content")

        def default_return(self):
            return None

    rules_text = [
        'alert tcp any any -> any 80 (msg:"Good"; content:"admin"; offset:0; depth:50; sid:1;)',
        'alert tcp any any -> any 80 (msg:"No offset/depth"; content:"test"; sid:2;)',
        'alert tcp any any -> any 80 (msg:"Multiple content"; content:"user"; content:"pass"; sid:3;)',
    ]

    print("\nValidating content patterns:\n")

    for rule_text in rules_text:
        print(f"{rule_text[:70]}...")
        rule = parse_rule(rule_text)
        validator = ContentValidator()
        validator.visit(rule)

        if validator.issues:
            for issue in validator.issues:
                print(f"  {issue}")
        else:
            print("  ✓ Content patterns valid")
        print()


def example_6_batch_validation():
    """Validate multiple rules and generate report."""
    print("\n" + "=" * 70)
    print("Example 6: Batch Validation Report")
    print("=" * 70)

    rules_text = [
        'alert tcp any any -> any 80 (msg:"Complete"; sid:1000001; rev:1;)',
        'alert tcp any any -> any 443 (msg:"No rev"; sid:1000002;)',
        "alert tcp any any -> any 22 (sid:1000003;)",
        'drop tcp any any -> any 23 (msg:"Telnet"; sid:1000004; rev:1;)',
        'alert tcp any any -> any 21 (msg:"FTP"; sid:1000005; rev:1;)',
    ]

    print(f"\nValidating {len(rules_text)} rules...\n")

    rules, parse_errors = parse_rules(rules_text)

    # Collect validation results
    validation_results = []
    for rule in rules:
        diagnostics = validate_rule(rule)

        # Get SID for reference
        sid = None
        for opt in rule.options:
            if opt.node_type == "SidOption":
                sid = opt.value
                break

        validation_results.append(
            {
                "sid": sid,
                "diagnostics": diagnostics,
                "rule": rule,
            }
        )

    # Generate report
    print("Validation Report:")
    print("=" * 70)

    total_issues = sum(len(r["diagnostics"]) for r in validation_results)

    print("\nSummary:")
    print(f"  Total rules: {len(rules)}")
    print(f"  Parse errors: {len(parse_errors)}")
    print(f"  Validation issues: {total_issues}")

    # Count by level
    all_diagnostics = [d for r in validation_results for d in r["diagnostics"]]
    warnings = sum(1 for d in all_diagnostics if d.level == DiagnosticLevel.WARNING)
    errors = sum(1 for d in all_diagnostics if d.level == DiagnosticLevel.ERROR)

    print(f"\n  Errors: {errors}")
    print(f"  Warnings: {warnings}")

    # Show problematic rules
    if total_issues > 0:
        print("\nProblematic rules:")
        for result in validation_results:
            if result["diagnostics"]:
                print(f"\n  SID {result['sid']}:")
                for diag in result["diagnostics"]:
                    print(f"    {diag.level.value}: {diag.message}")


def main():
    """Run all examples."""
    print("\n" + "=" * 70)
    print("SURINORT-AST: Rule Validation Examples")
    print("=" * 70)
    print("\nDemonstrating comprehensive rule validation techniques.\n")

    try:
        example_1_basic_validation()
        example_2_diagnostic_levels()
        example_3_custom_validator()
        example_4_port_range_validation()
        example_5_content_validation()
        example_6_batch_validation()

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
