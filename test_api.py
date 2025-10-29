#!/usr/bin/env python3
"""
Test script for surinort-ast API.

This script demonstrates the usage of the public API.
"""

from pathlib import Path

from surinort_ast import (
    Dialect,
    from_json,
    parse_file,
    parse_rule,
    print_rule,
    to_json,
    validate_rule,
)


def test_parse_rule():
    """Test basic rule parsing."""
    print("=" * 60)
    print("TEST: parse_rule()")
    print("=" * 60)

    rule_text = 'alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001; rev:1;)'
    rule = parse_rule(rule_text)

    print(f"Action: {rule.action}")
    print(f"Protocol: {rule.header.protocol}")
    print(f"Direction: {rule.header.direction}")
    print(f"Options count: {len(rule.options)}")
    print()


def test_parse_file():
    """Test file parsing."""
    print("=" * 60)
    print("TEST: parse_file()")
    print("=" * 60)

    file_path = Path("test_rules.txt")
    rules = parse_file(file_path)

    print(f"Parsed {len(rules)} rules from {file_path}")
    for idx, rule in enumerate(rules, 1):
        print(f"  Rule {idx}: {rule.action.value} {rule.header.protocol.value}")
    print()


def test_print_rule():
    """Test rule printing."""
    print("=" * 60)
    print("TEST: print_rule()")
    print("=" * 60)

    rule_text = 'alert tcp any any -> any 443 (msg:"HTTPS Traffic"; sid:2000001; rev:1;)'
    rule = parse_rule(rule_text)

    # Standard format
    formatted = print_rule(rule, stable=False)
    print("Standard format:")
    print(formatted)

    # Stable format
    stable = print_rule(rule, stable=True)
    print("\nStable format:")
    print(stable)
    print()


def test_json_serialization():
    """Test JSON serialization/deserialization."""
    print("=" * 60)
    print("TEST: to_json() / from_json()")
    print("=" * 60)

    # Parse a rule
    rule_text = (
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH Traffic"; sid:3000001; rev:1;)'
    )
    rule = parse_rule(rule_text)

    # Serialize to JSON
    json_str = to_json(rule)
    print("JSON (first 200 chars):")
    print(json_str[:200] + "...")

    # Deserialize from JSON
    rule_restored = from_json(json_str)
    print(f"\nRestored rule action: {rule_restored.action}")
    print(f"Restored rule protocol: {rule_restored.header.protocol}")
    print()


def test_validate_rule():
    """Test rule validation."""
    print("=" * 60)
    print("TEST: validate_rule()")
    print("=" * 60)

    # Valid rule
    valid_rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
    diagnostics = validate_rule(valid_rule)
    print(f"Valid rule diagnostics: {len(diagnostics)} issues")

    # Rule missing sid
    try:
        incomplete_rule = parse_rule('alert tcp any any -> any 80 (msg:"Test";)')
        diagnostics = validate_rule(incomplete_rule)
        print(f"Incomplete rule diagnostics: {len(diagnostics)} issues")
        for diag in diagnostics:
            print(f"  - {diag.level.value}: {diag.message}")
    except Exception as e:
        print(f"Error parsing incomplete rule: {e}")

    print()


def test_dialects():
    """Test different dialects."""
    print("=" * 60)
    print("TEST: Dialect support")
    print("=" * 60)

    rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

    for dialect in [Dialect.SURICATA, Dialect.SNORT2, Dialect.SNORT3]:
        try:
            rule = parse_rule(rule_text, dialect=dialect)
            print(f"{dialect.value}: Parsed successfully")
        except Exception as e:
            print(f"{dialect.value}: {e}")

    print()


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("SURINORT-AST API TEST SUITE")
    print("=" * 60 + "\n")

    test_parse_rule()
    test_parse_file()
    test_print_rule()
    test_json_serialization()
    test_validate_rule()
    test_dialects()

    print("=" * 60)
    print("ALL TESTS COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()
