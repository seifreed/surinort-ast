"""
Advanced memory profiling using memory_profiler.

This module provides line-by-line memory profiling for detailed analysis
of memory usage patterns. It complements the tracemalloc-based profiling
in profile_hotspots.py.

Install memory_profiler with: pip install memory-profiler

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from surinort_ast.api import from_json, parse_file, parse_rule, parse_rules, print_rule, to_json

# ============================================================================
# Test Data
# ============================================================================

SIMPLE_RULE = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

COMPLEX_RULE = """alert tcp $HOME_NET any -> $EXTERNAL_NET [80,443,8080:8090] (
    msg:"Complex HTTP attack detected";
    flow:established,to_server;
    content:"GET"; http_method; nocase;
    content:"/admin"; http_uri; depth:10;
    content:"User-Agent"; http_header;
    pcre:"/(?:select|union|insert|drop)\\s+/i";
    content:"|0d 0a|"; rawbytes;
    byte_test:4,>,1000,0,relative;
    byte_jump:2,0,relative,post_offset 4;
    metadata:policy balanced-ips drop, ruleset community;
    reference:cve,2021-12345;
    classtype:web-application-attack;
    sid:1000001;
    rev:3;
)"""


def generate_test_rules(count: int) -> list[str]:
    """Generate test rules."""
    rules = []
    for i in range(count):
        rule = SIMPLE_RULE.replace("sid:1", f"sid:{i}")
        rules.append(rule)
    return rules


# ============================================================================
# Memory-Profiled Functions
# ============================================================================
# These functions can be profiled with memory_profiler using:
#   python -m memory_profiler memory_profiler.py
#
# Or programmatically with:
#   from memory_profiler import profile
#   @profile decorator
# ============================================================================


def memory_benchmark_parsing() -> None:
    """
    Memory benchmark for parsing.

    Run with: python -m memory_profiler -o parsing_memory.txt memory_profiler.py
    """
    rules = []
    for i in range(10000):
        rule = parse_rule(SIMPLE_RULE.replace("sid:1", f"sid:{i}"))
        rules.append(rule)

    print(f"Parsed {len(rules)} rules")


def memory_benchmark_parsing_no_raw() -> None:
    """
    Memory benchmark for parsing without raw text.

    Should show ~50% memory reduction.
    """
    rules = []
    for i in range(10000):
        rule = parse_rule(SIMPLE_RULE.replace("sid:1", f"sid:{i}"), include_raw_text=False)
        rules.append(rule)

    print(f"Parsed {len(rules)} rules (no raw text)")


def memory_benchmark_serialization() -> None:
    """Memory benchmark for serialization."""
    rule = parse_rule(COMPLEX_RULE)

    json_results = []
    for _ in range(1000):
        json_data = to_json(rule)
        json_results.append(json_data)

    print(f"Serialized to JSON {len(json_results)} times")


def memory_benchmark_deserialization() -> None:
    """Memory benchmark for deserialization."""
    rule = parse_rule(COMPLEX_RULE)
    json_data = to_json(rule)

    rules = []
    for _ in range(1000):
        deserialized = from_json(json_data)
        rules.append(deserialized)

    print(f"Deserialized {len(rules)} rules")


def memory_benchmark_printing() -> None:
    """Memory benchmark for text printing."""
    rule = parse_rule(COMPLEX_RULE)

    printed = []
    for _ in range(10000):
        text = print_rule(rule)
        printed.append(text)

    print(f"Printed {len(printed)} times")


def memory_benchmark_batch_parsing() -> None:
    """Memory benchmark for batch parsing."""
    rules_text = generate_test_rules(5000)

    parsed = parse_rules(rules_text)

    print(f"Batch parsed {len(parsed)} rules")


def memory_benchmark_file_parsing() -> None:
    """Memory benchmark for file parsing."""
    rules_text = generate_test_rules(5000)

    # Create temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        temp_path = Path(f.name)
        f.write("\n".join(rules_text))

    try:
        parsed = parse_file(temp_path, parallel=False)
        print(f"File parsed {len(parsed)} rules")
    finally:
        temp_path.unlink()


# ============================================================================
# Main Runner
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("MEMORY PROFILING BENCHMARKS")
    print("=" * 80)
    print("")
    print("To run with memory_profiler:")
    print("  pip install memory-profiler")
    print("  python -m memory_profiler benchmarks/memory_profiler.py")
    print("")
    print("To profile specific function:")
    print("  1. Add @profile decorator to the function")
    print("  2. Run: python -m memory_profiler benchmarks/memory_profiler.py")
    print("")
    print("=" * 80)

    # Check if memory_profiler is available
    try:
        import memory_profiler

        print("\n✓ memory_profiler is installed")
        print("\nRunning memory benchmarks...")
        print("-" * 80)

        # Run benchmarks
        print("\n[1/7] Parsing benchmark...")
        memory_benchmark_parsing()

        print("\n[2/7] Parsing without raw text...")
        memory_benchmark_parsing_no_raw()

        print("\n[3/7] Serialization benchmark...")
        memory_benchmark_serialization()

        print("\n[4/7] Deserialization benchmark...")
        memory_benchmark_deserialization()

        print("\n[5/7] Printing benchmark...")
        memory_benchmark_printing()

        print("\n[6/7] Batch parsing benchmark...")
        memory_benchmark_batch_parsing()

        print("\n[7/7] File parsing benchmark...")
        memory_benchmark_file_parsing()

        print("\n" + "=" * 80)
        print("✓ All memory benchmarks completed")
        print("=" * 80)

    except ImportError:
        print("\n⚠ memory_profiler not installed")
        print("Install with: pip install memory-profiler")
        print("")
        print("Running basic memory benchmarks without profiler...")
        print("-" * 80)

        # Run without profiling
        memory_benchmark_parsing()
        memory_benchmark_parsing_no_raw()
        memory_benchmark_serialization()
        memory_benchmark_deserialization()
        memory_benchmark_printing()
        memory_benchmark_batch_parsing()
        memory_benchmark_file_parsing()

        print("\n" + "=" * 80)
        print("✓ Basic memory benchmarks completed")
        print("=" * 80)
