#!/usr/bin/env python3
"""
Error Handling Examples for surinort-ast

This example demonstrates robust error handling patterns for parsing IDS/IPS rules,
including syntax errors, validation errors, and recovery strategies.

Author: Marc Rivero | @seifreed
License: GPL v3.0
"""

from surinort_ast import (
    ParseError,
    SerializationError,
    from_json,
    parse_rule,
    parse_rules,
    to_json,
)


def example_1_basic_error_handling():
    """Handle basic parsing errors."""
    print("=" * 70)
    print("Example 1: Basic Error Handling")
    print("=" * 70)

    invalid_rules = [
        "invalid rule",
        "alert tcp",  # Incomplete
        "alert tcp any any",  # Still incomplete
        "alert tcp any any -> any",  # Missing port
    ]

    print("\nTrying to parse invalid rules:\n")

    for rule_text in invalid_rules:
        try:
            rule = parse_rule(rule_text)
            print(f"  SUCCESS: {rule_text}")
        except ParseError as e:
            print(f"  FAILED: {rule_text[:40]:40s}")
            print(f"          Error: {str(e)[:60]}...")


def example_2_try_except_pattern():
    """Demonstrate try/except pattern for safe parsing."""
    print("\n" + "=" * 70)
    print("Example 2: Try/Except Pattern")
    print("=" * 70)

    def safe_parse(rule_text):
        """Safely parse a rule, returning None on error."""
        try:
            return parse_rule(rule_text)
        except ParseError as e:
            print(f"Parse error: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error: {e}")
            return None

    rules_text = [
        'alert tcp any any -> any 80 (msg:"Valid"; sid:1;)',
        "invalid syntax here",
        'alert tcp any any -> any 443 (msg:"Also valid"; sid:2;)',
    ]

    print("\nParsing with safe_parse function:\n")

    successful = 0
    failed = 0

    for rule_text in rules_text:
        print(f"Parsing: {rule_text[:50]}...")
        rule = safe_parse(rule_text)

        if rule is not None:
            print("  ✓ Success")
            successful += 1
        else:
            print("  ✗ Failed")
            failed += 1

    print(f"\nResults: {successful} successful, {failed} failed")


def example_3_collect_errors():
    """Collect and report all errors."""
    print("\n" + "=" * 70)
    print("Example 3: Collect All Errors")
    print("=" * 70)

    rules_text = [
        'alert tcp any any -> any 80 (msg:"Good rule 1"; sid:1;)',
        "bad syntax",
        'alert tcp any any -> any 443 (msg:"Good rule 2"; sid:2;)',
        "alert tcp incomplete",
        'alert tcp any any -> any 22 (msg:"Good rule 3"; sid:3;)',
        "another bad one",
    ]

    print(f"\nParsing {len(rules_text)} rules...\n")

    # Using parse_rules which collects errors
    successful_rules, errors = parse_rules(rules_text)

    print("Results:")
    print(f"  Successful: {len(successful_rules)}")
    print(f"  Failed: {len(errors)}")

    if errors:
        print("\nDetailed error report:")
        for idx, error_msg in errors:
            print(f"\n  Rule #{idx + 1}:")
            print(f"    Input: {rules_text[idx][:60]}...")
            print(f"    Error: {error_msg[:80]}...")


def example_4_validation_errors():
    """Handle validation errors for parsed rules."""
    print("\n" + "=" * 70)
    print("Example 4: Validation Errors")
    print("=" * 70)

    from surinort_ast import validate_rule

    # Rules with validation issues (but parseable)
    rules_text = [
        'alert tcp any any -> any 80 (msg:"Missing SID";)',  # Missing SID
        "alert tcp any any -> any 443 (sid:1;)",  # Missing MSG
        'alert tcp any any -> any 22 (msg:"Complete rule"; sid:2; rev:1;)',  # Valid
    ]

    print("\nValidating rules:\n")

    for i, rule_text in enumerate(rules_text, 1):
        try:
            rule = parse_rule(rule_text)
            diagnostics = validate_rule(rule)

            print(f"Rule {i}:")
            if diagnostics:
                for diag in diagnostics:
                    print(f"  {diag.level.value}: {diag.message}")
            else:
                print("  ✓ No issues")

        except ParseError as e:
            print(f"Rule {i}:")
            print(f"  PARSE ERROR: {e}")


def example_5_serialization_errors():
    """Handle JSON serialization errors."""
    print("\n" + "=" * 70)
    print("Example 5: Serialization Error Handling")
    print("=" * 70)

    rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
    rule = parse_rule(rule_text)

    # Test JSON serialization
    try:
        json_str = to_json(rule, indent=2)
        print("✓ JSON serialization successful")
        print(f"  Size: {len(json_str)} bytes")
    except SerializationError as e:
        print(f"✗ Serialization error: {e}")

    # Test JSON deserialization with invalid data
    invalid_json_inputs = [
        "not valid json",
        '{"invalid": "structure"}',
        "[]",  # Wrong type
    ]

    print("\nTesting deserialization with invalid inputs:\n")

    for json_input in invalid_json_inputs:
        try:
            rule = from_json(json_input)
            print(f"  Unexpected success: {json_input[:30]}...")
        except SerializationError as e:
            print(f"  Expected error: {str(e)[:60]}...")


def example_6_graceful_degradation():
    """Demonstrate graceful degradation pattern."""
    print("\n" + "=" * 70)
    print("Example 6: Graceful Degradation")
    print("=" * 70)

    def process_rule_with_fallback(rule_text, fallback_action=None):
        """
        Process a rule with fallback behavior.

        Returns (rule, error_message) tuple.
        """
        try:
            rule = parse_rule(rule_text)
            return rule, None

        except ParseError as e:
            error_msg = f"Parse failed: {str(e)[:50]}"

            if fallback_action:
                print(f"  Applying fallback: {fallback_action}")

            return None, error_msg

    rules_text = [
        'alert tcp any any -> any 80 (msg:"Valid"; sid:1;)',
        "invalid rule here",
        'alert tcp any any -> any 443 (msg:"Also valid"; sid:2;)',
    ]

    print("\nProcessing rules with fallback:\n")

    processed = []
    for i, rule_text in enumerate(rules_text, 1):
        print(f"Rule {i}: {rule_text[:40]}...")

        rule, error = process_rule_with_fallback(rule_text, fallback_action="Skip and continue")

        if rule:
            processed.append(rule)
            print("  ✓ Processed successfully")
        else:
            print(f"  ✗ {error}")

    print(f"\nSuccessfully processed {len(processed)}/{len(rules_text)} rules")


def example_7_custom_error_handling():
    """Implement custom error handling strategy."""
    print("\n" + "=" * 70)
    print("Example 7: Custom Error Handling Strategy")
    print("=" * 70)

    class RuleProcessor:
        """Process rules with comprehensive error handling."""

        def __init__(self):
            self.successful = []
            self.failed = []
            self.warnings = []

        def process(self, rule_text, line_number=None):
            """Process a single rule."""
            location = f"line {line_number}" if line_number else "unknown location"

            try:
                rule = parse_rule(rule_text)

                # Validate
                from surinort_ast import validate_rule

                diagnostics = validate_rule(rule)

                if diagnostics:
                    self.warnings.append(
                        {"location": location, "rule": rule_text, "diagnostics": diagnostics}
                    )

                self.successful.append(rule)
                return True

            except ParseError as e:
                self.failed.append({"location": location, "rule": rule_text, "error": str(e)})
                return False

            except Exception as e:
                self.failed.append(
                    {"location": location, "rule": rule_text, "error": f"Unexpected error: {e}"}
                )
                return False

        def report(self):
            """Generate error report."""
            print("\nProcessing Report:")
            print(f"  Successful: {len(self.successful)}")
            print(f"  Failed: {len(self.failed)}")
            print(f"  Warnings: {len(self.warnings)}")

            if self.failed:
                print("\n  Failed rules:")
                for item in self.failed[:5]:  # Show first 5
                    print(f"    {item['location']}: {item['error'][:60]}...")

            if self.warnings:
                print("\n  Warnings:")
                for item in self.warnings[:5]:  # Show first 5
                    print(f"    {item['location']}: {len(item['diagnostics'])} issue(s)")

    # Test the processor
    rules = [
        'alert tcp any any -> any 80 (msg:"Good"; sid:1;)',
        "bad rule",
        'alert tcp any any -> any 443 (msg:"Missing SID";)',  # Valid but incomplete
        'alert tcp any any -> any 22 (msg:"Complete"; sid:2; rev:1;)',
    ]

    print("\nProcessing rules with custom handler:\n")

    processor = RuleProcessor()

    for i, rule_text in enumerate(rules, 1):
        print(f"Processing rule {i}...", end=" ")
        success = processor.process(rule_text, line_number=i)
        print("✓" if success else "✗")

    processor.report()


def main():
    """Run all examples."""
    print("\n" + "=" * 70)
    print("SURINORT-AST: Error Handling Examples")
    print("=" * 70)
    print("\nDemonstrating robust error handling patterns.\n")

    try:
        example_1_basic_error_handling()
        example_2_try_except_pattern()
        example_3_collect_errors()
        example_4_validation_errors()
        example_5_serialization_errors()
        example_6_graceful_degradation()
        example_7_custom_error_handling()

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
