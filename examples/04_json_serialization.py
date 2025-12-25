#!/usr/bin/env python3
"""
JSON Serialization Examples for surinort-ast

This example demonstrates JSON export/import capabilities, including:
- Converting rules to JSON
- Loading rules from JSON
- Roundtrip conversion
- JSON Schema generation

Author: Marc Rivero | @seifreed
License: GPL v3.0
"""

import json

from surinort_ast import from_json, parse_rule, print_rule, to_json, to_json_schema


def example_1_basic_json_export():
    """Export a rule to JSON format."""
    print("=" * 70)
    print("Example 1: Basic JSON Export")
    print("=" * 70)

    rule_text = 'alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001; rev:1;)'

    print(f"\nOriginal rule:\n{rule_text}\n")

    rule = parse_rule(rule_text)

    # Export to JSON
    json_output = to_json(rule, indent=2)

    print("JSON representation:")
    print(json_output)

    # Verify it's valid JSON
    parsed_json = json.loads(json_output)
    print(f"\nJSON is valid: {isinstance(parsed_json, dict)}")
    print(f"Top-level keys: {list(parsed_json.keys())}")


def example_2_compact_json():
    """Export rule to compact JSON (no indentation)."""
    print("\n" + "=" * 70)
    print("Example 2: Compact JSON Export")
    print("=" * 70)

    rule_text = 'alert tcp any any -> any 443 (msg:"TLS"; sid:2; rev:1;)'

    rule = parse_rule(rule_text)

    # Compact JSON (no indentation)
    compact_json = to_json(rule, indent=None)

    print("\nCompact JSON (first 200 chars):")
    print(compact_json[:200] + "...")

    # Pretty JSON for comparison
    pretty_json = to_json(rule, indent=2)

    print("\nSize comparison:")
    print(f"  Compact: {len(compact_json)} bytes")
    print(f"  Pretty:  {len(pretty_json)} bytes")
    print(f"  Ratio:   {len(pretty_json) / len(compact_json):.2f}x")


def example_3_json_import():
    """Import a rule from JSON."""
    print("\n" + "=" * 70)
    print("Example 3: Import Rule from JSON")
    print("=" * 70)

    # First export a rule to see the proper JSON structure
    sample_rule = parse_rule(
        'alert tcp any any -> any 22 (msg:"SSH Connection"; sid:3000001; rev:1;)'
    )
    json_str = to_json(sample_rule, indent=2)

    print("Proper JSON structure (exported from a rule):")
    print(json_str[:400] + "...\n")

    # Now import it back
    print("Importing from JSON string:")
    rule = from_json(json_str)

    print("\nSuccessfully imported rule!")
    print(f"  Action: {rule.action.value}")
    print(f"  Protocol: {rule.header.protocol.value}")

    # Convert to rule text
    rule_text = print_rule(rule)
    print(f"\nRule text:\n  {rule_text}")


def example_4_roundtrip_conversion():
    """Demonstrate roundtrip conversion: rule -> JSON -> rule."""
    print("\n" + "=" * 70)
    print("Example 4: Roundtrip Conversion")
    print("=" * 70)

    original_text = 'alert http any any -> any any (msg:"HTTP POST with Admin"; content:"POST"; http_method; content:"admin"; http_uri; sid:4000001; rev:2;)'

    print(f"\nOriginal rule:\n{original_text}\n")

    # Parse original
    original_rule = parse_rule(original_text)

    # Convert to JSON
    json_str = to_json(original_rule, indent=2)
    print(f"Step 1: Converted to JSON ({len(json_str)} bytes)")

    # Import from JSON
    restored_rule = from_json(json_str)
    print("Step 2: Restored from JSON")

    # Convert back to text
    restored_text = print_rule(restored_rule)
    print(f"\nRestored rule:\n{restored_text}\n")

    # Verify semantic equivalence
    print("Verification:")
    print(f"  Action matches: {original_rule.action == restored_rule.action}")
    print(f"  Protocol matches: {original_rule.header.protocol == restored_rule.header.protocol}")
    print(f"  Option count matches: {len(original_rule.options) == len(restored_rule.options)}")


def example_5_json_schema():
    """Generate and examine JSON Schema for rules."""
    print("\n" + "=" * 70)
    print("Example 5: JSON Schema Generation")
    print("=" * 70)

    schema = to_json_schema()

    print("Generated JSON Schema:")
    print(f"  Schema version: {schema.get('$schema', 'N/A')}")
    print(f"  Title: {schema.get('title', 'N/A')}")

    # Show some properties
    if "properties" in schema:
        print(f"\nTop-level properties ({len(schema['properties'])}):")
        for prop_name in list(schema["properties"].keys())[:10]:
            print(f"    - {prop_name}")

    # Show definitions/defs count
    defs_key = "$defs" if "$defs" in schema else "definitions"
    if defs_key in schema:
        print(f"\n  Defined types: {len(schema[defs_key])}")

    # Save to file for inspection
    schema_file = "/tmp/surinort_ast_schema.json"
    with open(schema_file, "w") as f:
        json.dump(schema, f, indent=2)
    print(f"\nFull schema saved to: {schema_file}")


def example_6_multiple_rules_json():
    """Export multiple rules as JSON array."""
    print("\n" + "=" * 70)
    print("Example 6: Multiple Rules as JSON Array")
    print("=" * 70)

    rules_text = [
        'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
        'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)',
        'alert udp any any -> any 53 (msg:"DNS"; sid:3;)',
    ]

    print(f"\nParsing {len(rules_text)} rules...\n")

    # Parse all rules
    rules = [parse_rule(text) for text in rules_text]

    # Create JSON array manually (to_json works on single rules)
    json_array = [json.loads(to_json(rule, indent=None)) for rule in rules]

    # Convert to JSON string
    json_output = json.dumps(json_array, indent=2)

    print("JSON array (first 400 chars):")
    print(json_output[:400] + "...")

    print(f"\nArray contains {len(json_array)} rules")

    # Import back
    imported_rules = [from_json(rule_dict) for rule_dict in json_array]

    print(f"Successfully imported {len(imported_rules)} rules")

    print("\nRestored rules:")
    for rule in imported_rules:
        print(f"  - {print_rule(rule)}")


def example_7_json_filtering():
    """Export JSON with selective fields."""
    print("\n" + "=" * 70)
    print("Example 7: Exploring JSON Structure")
    print("=" * 70)

    rule_text = 'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Example"; content:"test"; offset:5; depth:10; sid:1;)'

    print(f"\nRule:\n{rule_text}\n")

    rule = parse_rule(rule_text)

    # Get full JSON as dict
    full_json = json.loads(to_json(rule, indent=2))

    print("JSON structure overview:")
    print(f"  Action: {full_json.get('action')}")
    print(f"  Dialect: {full_json.get('dialect')}")

    # Examine header structure
    if "header" in full_json:
        header = full_json["header"]
        print("\n  Header:")
        print(f"    Protocol: {header.get('protocol')}")
        print(f"    Direction: {header.get('direction')}")
        print(f"    Src Address Type: {header.get('src_addr', {}).get('node_type')}")
        print(f"    Dst Port Type: {header.get('dst_port', {}).get('node_type')}")

    # Examine options
    if "options" in full_json:
        print(f"\n  Options ({len(full_json['options'])}):")
        for opt in full_json["options"]:
            opt_type = opt.get("node_type", "Unknown")
            print(f"    - {opt_type}")


def main():
    """Run all examples."""
    print("\n" + "=" * 70)
    print("SURINORT-AST: JSON Serialization Examples")
    print("=" * 70)
    print("\nDemonstrating JSON export/import and schema generation.\n")

    try:
        example_1_basic_json_export()
        example_2_compact_json()
        example_3_json_import()
        example_4_roundtrip_conversion()
        example_5_json_schema()
        example_6_multiple_rules_json()
        example_7_json_filtering()

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
