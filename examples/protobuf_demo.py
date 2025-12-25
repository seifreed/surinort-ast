#!/usr/bin/env python3
"""
Protocol Buffers Serialization Demo

This example demonstrates the usage and performance characteristics of
protobuf serialization for Suricata/Snort IDS rules.

Features demonstrated:
    - Basic protobuf serialization/deserialization
    - Roundtrip fidelity verification
    - Performance comparison with JSON
    - Batch rule serialization
    - Size comparison

Usage:
    python examples/protobuf_demo.py

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

import time
from pathlib import Path

# Import surinort-ast
from surinort_ast import parse_rule
from surinort_ast.serialization.protobuf import (
    ProtobufSerializer,
    from_protobuf,
    to_protobuf,
)

# Sample rules for testing
SAMPLE_RULES = [
    'alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001; rev:1;)',
    'alert tcp any any -> any 443 (msg:"HTTPS Traffic"; content:"GET"; nocase; sid:1000002; rev:1;)',
    'alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Outbound HTTP"; flow:established,to_server; content:"POST"; sid:1000003; rev:2;)',
    'alert http any any -> any any (msg:"HTTP URI Test"; http_uri; content:"/admin"; sid:1000004; rev:1;)',
    'alert tcp any any -> any any (msg:"Complex Rule"; content:"GET"; nocase; pcre:"/test/i"; flow:established,to_server; classtype:web-application-attack; reference:cve,2021-12345; metadata:policy balanced-ips; sid:1000005; rev:3;)',
]


def print_header(title: str) -> None:
    """Print a formatted section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def demo_basic_usage() -> None:
    """Demonstrate basic protobuf serialization usage."""
    print_header("1. Basic Protobuf Serialization")

    # Parse a rule
    rule_text = 'alert tcp any any -> any 80 (msg:"Test Rule"; sid:1; rev:1;)'
    print(f"\nOriginal rule: {rule_text}")

    rule = parse_rule(rule_text)
    print(f"Parsed rule action: {rule.action}")
    print(f"Parsed rule protocol: {rule.header.protocol}")

    # Serialize to protobuf
    print("\nSerializing to protobuf binary format...")
    binary_data = to_protobuf(rule)
    print(f"Binary data size: {len(binary_data)} bytes")
    print(f"Binary data (first 50 bytes): {binary_data[:50]!r}...")

    # Deserialize from protobuf
    print("\nDeserializing from protobuf binary format...")
    restored_rule = from_protobuf(binary_data)
    print(f"Restored rule action: {restored_rule.action}")
    print(f"Restored rule protocol: {restored_rule.header.protocol}")

    # Verify roundtrip fidelity
    print("\nVerifying roundtrip fidelity...")
    if rule == restored_rule:
        print("SUCCESS: Rule perfectly restored (roundtrip successful)")
    else:
        print("FAILURE: Rule differs after roundtrip")


def demo_serializer_options() -> None:
    """Demonstrate serializer configuration options."""
    print_header("2. Serializer Options")

    rule = parse_rule(SAMPLE_RULES[0])

    # With metadata
    print("\nSerializer with metadata envelope:")
    serializer = ProtobufSerializer(include_metadata=True)
    binary_with_metadata = serializer.to_protobuf(rule)
    print(f"Size with metadata: {len(binary_with_metadata)} bytes")

    # Without metadata
    print("\nSerializer without metadata envelope:")
    serializer = ProtobufSerializer(include_metadata=False)
    binary_without_metadata = serializer.to_protobuf(rule)
    print(f"Size without metadata: {len(binary_without_metadata)} bytes")

    print(f"\nMetadata overhead: {len(binary_with_metadata) - len(binary_without_metadata)} bytes")


def demo_batch_serialization() -> None:
    """Demonstrate batch rule serialization."""
    print_header("3. Batch Rule Serialization")

    # Parse all sample rules
    print(f"\nParsing {len(SAMPLE_RULES)} rules...")
    rules = [parse_rule(text) for text in SAMPLE_RULES]
    print(f"Successfully parsed {len(rules)} rules")

    # Serialize all rules together
    print("\nSerializing all rules to protobuf...")
    binary_data = to_protobuf(rules)
    print(f"Total binary size: {len(binary_data)} bytes")
    print(f"Average per rule: {len(binary_data) // len(rules)} bytes")

    # Deserialize all rules
    print("\nDeserializing all rules from protobuf...")
    restored_rules = from_protobuf(binary_data)
    print(f"Restored {len(restored_rules)} rules")

    # Verify all rules
    print("\nVerifying roundtrip fidelity for all rules...")
    all_match = all(orig == rest for orig, rest in zip(rules, restored_rules))
    if all_match:
        print(f"SUCCESS: All {len(rules)} rules perfectly restored")
    else:
        print("FAILURE: Some rules differ after roundtrip")


def demo_performance_comparison() -> None:
    """Compare protobuf vs JSON performance."""
    print_header("4. Performance Comparison: Protobuf vs JSON")

    # Use a complex rule for testing
    rule = parse_rule(SAMPLE_RULES[4])  # Complex rule with many options

    iterations = 1000
    print(f"\nRunning {iterations} iterations for each format...\n")

    # Test protobuf serialization
    print("Testing Protobuf serialization...")
    start_time = time.time()
    for _ in range(iterations):
        binary = to_protobuf(rule, include_metadata=False)
    protobuf_serialize_time = time.time() - start_time

    # Test protobuf deserialization
    print("Testing Protobuf deserialization...")
    serializer = ProtobufSerializer(include_metadata=False)
    start_time = time.time()
    for _ in range(iterations):
        serializer.from_protobuf(binary)
    protobuf_deserialize_time = time.time() - start_time

    # Test JSON serialization
    print("Testing JSON serialization...")
    start_time = time.time()
    for _ in range(iterations):
        json_str = rule.model_dump_json()
    json_serialize_time = time.time() - start_time

    # Test JSON deserialization
    print("Testing JSON deserialization...")
    import json

    start_time = time.time()
    for _ in range(iterations):
        json.loads(json_str)
    json_deserialize_time = time.time() - start_time

    # Print results
    print("\n" + "-" * 70)
    print("Performance Results:")
    print("-" * 70)
    print(f"{'Operation':<30} {'Protobuf':<15} {'JSON':<15} {'Speedup':<10}")
    print("-" * 70)

    print(
        f"{'Serialization':<30} {protobuf_serialize_time:.4f}s{'':<7} {json_serialize_time:.4f}s{'':<7} {json_serialize_time / protobuf_serialize_time:.2f}x"
    )
    print(
        f"{'Deserialization':<30} {protobuf_deserialize_time:.4f}s{'':<7} {json_deserialize_time:.4f}s{'':<7} {json_deserialize_time / protobuf_deserialize_time:.2f}x"
    )

    total_protobuf = protobuf_serialize_time + protobuf_deserialize_time
    total_json = json_serialize_time + json_deserialize_time
    print("-" * 70)
    print(
        f"{'Total (roundtrip)':<30} {total_protobuf:.4f}s{'':<7} {total_json:.4f}s{'':<7} {total_json / total_protobuf:.2f}x"
    )
    print("-" * 70)

    # Note about implementation
    print("\nNote: This implementation uses JSON internally for simplicity.")
    print("A native protobuf implementation would show greater performance gains.")


def demo_size_comparison() -> None:
    """Compare protobuf vs JSON size."""
    print_header("5. Size Comparison: Protobuf vs JSON")

    print("\nComparing sizes for different rule complexities...\n")
    print(f"{'Rule Type':<30} {'Protobuf':<12} {'JSON':<12} {'Ratio':<10}")
    print("-" * 70)

    for idx, rule_text in enumerate(SAMPLE_RULES, 1):
        rule = parse_rule(rule_text)

        # Get sizes
        protobuf_size = len(to_protobuf(rule, include_metadata=False))
        json_size = len(rule.model_dump_json())

        # Calculate ratio
        ratio = json_size / protobuf_size

        # Determine rule type
        if idx == 1:
            rule_type = "Simple"
        elif idx == 2:
            rule_type = "With Content"
        elif idx == 3:
            rule_type = "With Variables"
        elif idx == 4:
            rule_type = "With Sticky Buffer"
        else:
            rule_type = "Complex"

        print(f"{rule_type:<30} {protobuf_size:<12} {json_size:<12} {ratio:.2f}x")

    print("-" * 70)
    print("\nNote: Our implementation uses JSON internally, so sizes are similar.")
    print("A native protobuf implementation would show greater size reduction.")


def demo_file_operations() -> None:
    """Demonstrate saving and loading from files."""
    print_header("6. File Operations")

    rule = parse_rule(SAMPLE_RULES[0])

    # Save to file
    output_file = Path("/tmp/rule.pb")
    print(f"\nSaving rule to {output_file}...")
    binary_data = to_protobuf(rule)
    output_file.write_bytes(binary_data)
    print(f"Saved {len(binary_data)} bytes")

    # Load from file
    print(f"\nLoading rule from {output_file}...")
    loaded_data = output_file.read_bytes()
    loaded_rule = from_protobuf(loaded_data)
    print(f"Loaded {len(loaded_data)} bytes")

    # Verify
    if rule == loaded_rule:
        print("SUCCESS: Rule correctly saved and loaded")
    else:
        print("FAILURE: Rule differs after file roundtrip")

    # Cleanup
    output_file.unlink()
    print(f"\nCleaned up {output_file}")


def main() -> None:
    """Run all demonstrations."""
    print("\n" + "=" * 70)
    print("  Surinort-AST: Protocol Buffers Serialization Demo")
    print("=" * 70)
    print("\nThis demo showcases protobuf serialization features and performance.")

    try:
        # Run demonstrations
        demo_basic_usage()
        demo_serializer_options()
        demo_batch_serialization()
        demo_performance_comparison()
        demo_size_comparison()
        demo_file_operations()

        # Summary
        print_header("Summary")
        print("\nKey Features:")
        print("  - Binary format for efficient storage")
        print("  - Perfect roundtrip fidelity")
        print("  - Batch serialization support")
        print("  - Metadata envelope option")
        print("  - Compatible with all AST node types")

        print("\nBest Use Cases:")
        print("  - Large-scale rule storage and transmission")
        print("  - High-performance rule processing pipelines")
        print("  - Cross-language rule interchange")
        print("  - Efficient caching of parsed rules")

        print("\n" + "=" * 70)
        print("  Demo completed successfully!")
        print("=" * 70 + "\n")

    except Exception as e:
        print(f"\nError running demo: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
