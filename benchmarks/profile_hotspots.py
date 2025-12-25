"""
Profiling tools for hotspot analysis.

This module provides CPU and memory profiling utilities to identify
performance bottlenecks in parsing, serialization, and other operations.

Uses:
- cProfile for CPU profiling
- pstats for statistical analysis
- tracemalloc for memory profiling (if line_profiler not available)

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from __future__ import annotations

import argparse
import cProfile
import pstats
import sys
import tempfile
import tracemalloc
from io import StringIO
from pathlib import Path
from pstats import SortKey

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
    reference:url,example.com/advisory;
    classtype:web-application-attack;
    priority:1;
    sid:1000001;
    rev:3;
)"""


def generate_test_rules(count: int) -> list[str]:
    """Generate test rules for profiling."""
    rules = []
    for i in range(count):
        if i % 2 == 0:
            rule = COMPLEX_RULE.replace("sid:1000001", f"sid:{1000000 + i}")
        else:
            rule = SIMPLE_RULE.replace("sid:1", f"sid:{1000000 + i}")
        rules.append(rule)
    return rules


# ============================================================================
# CPU Profiling
# ============================================================================


def profile_parsing(iterations: int = 1000, top_n: int = 20) -> str:
    """
    Profile parsing operations.

    Args:
        iterations: Number of parsing iterations
        top_n: Number of top functions to display

    Returns:
        Profiling report as string
    """
    profiler = cProfile.Profile()

    # Profile parsing workload
    profiler.enable()
    for _ in range(iterations):
        parse_rule(SIMPLE_RULE)
        parse_rule(COMPLEX_RULE)
    profiler.disable()

    # Generate report
    output = StringIO()
    stats = pstats.Stats(profiler, stream=output)
    stats.strip_dirs()
    stats.sort_stats(SortKey.CUMULATIVE)

    output.write("=" * 80 + "\n")
    output.write(f"PARSING PROFILING REPORT ({iterations} iterations)\n")
    output.write("=" * 80 + "\n\n")
    output.write(f"Top {top_n} functions by cumulative time:\n\n")

    stats.print_stats(top_n)

    output.write("\n" + "=" * 80 + "\n")
    output.write("Top callers:\n")
    output.write("=" * 80 + "\n\n")

    stats.sort_stats(SortKey.CUMULATIVE)
    stats.print_callers(10)

    return output.getvalue()


def profile_serialization(iterations: int = 1000, top_n: int = 20) -> str:
    """
    Profile serialization operations.

    Args:
        iterations: Number of serialization iterations
        top_n: Number of top functions to display

    Returns:
        Profiling report as string
    """
    # Prepare test data
    rule = parse_rule(COMPLEX_RULE)

    profiler = cProfile.Profile()

    # Profile serialization workload
    profiler.enable()
    for _ in range(iterations):
        json_data = to_json(rule)
        from_json(json_data)
    profiler.disable()

    # Generate report
    output = StringIO()
    stats = pstats.Stats(profiler, stream=output)
    stats.strip_dirs()
    stats.sort_stats(SortKey.CUMULATIVE)

    output.write("=" * 80 + "\n")
    output.write(f"SERIALIZATION PROFILING REPORT ({iterations} iterations)\n")
    output.write("=" * 80 + "\n\n")
    output.write(f"Top {top_n} functions by cumulative time:\n\n")

    stats.print_stats(top_n)

    output.write("\n" + "=" * 80 + "\n")
    output.write("Top callers:\n")
    output.write("=" * 80 + "\n\n")

    stats.sort_stats(SortKey.CUMULATIVE)
    stats.print_callers(10)

    return output.getvalue()


def profile_printing(iterations: int = 1000, top_n: int = 20) -> str:
    """
    Profile text printing operations.

    This is particularly important for verifying singledispatch
    performance after refactoring.

    Args:
        iterations: Number of printing iterations
        top_n: Number of top functions to display

    Returns:
        Profiling report as string
    """
    # Prepare test data
    rule = parse_rule(COMPLEX_RULE)

    profiler = cProfile.Profile()

    # Profile printing workload
    profiler.enable()
    for _ in range(iterations):
        print_rule(rule)
    profiler.disable()

    # Generate report
    output = StringIO()
    stats = pstats.Stats(profiler, stream=output)
    stats.strip_dirs()
    stats.sort_stats(SortKey.CUMULATIVE)

    output.write("=" * 80 + "\n")
    output.write(f"PRINTING PROFILING REPORT ({iterations} iterations)\n")
    output.write("=" * 80 + "\n\n")
    output.write(
        "This report shows singledispatch performance after refactoring.\n"
        "Look for _print_option_dispatch in the call stack.\n\n"
    )
    output.write(f"Top {top_n} functions by cumulative time:\n\n")

    stats.print_stats(top_n)

    output.write("\n" + "=" * 80 + "\n")
    output.write("Singledispatch dispatch overhead:\n")
    output.write("=" * 80 + "\n\n")

    # Filter for dispatch-related functions
    stats.sort_stats(SortKey.CUMULATIVE)
    stats.print_stats("dispatch")

    return output.getvalue()


def profile_batch_parsing(rule_count: int = 1000, top_n: int = 20) -> str:
    """
    Profile batch parsing operations.

    Args:
        rule_count: Number of rules to parse
        top_n: Number of top functions to display

    Returns:
        Profiling report as string
    """
    rules_text = generate_test_rules(rule_count)

    profiler = cProfile.Profile()

    # Profile batch parsing
    profiler.enable()
    parse_rules(rules_text)
    profiler.disable()

    # Generate report
    output = StringIO()
    stats = pstats.Stats(profiler, stream=output)
    stats.strip_dirs()
    stats.sort_stats(SortKey.CUMULATIVE)

    output.write("=" * 80 + "\n")
    output.write(f"BATCH PARSING PROFILING REPORT ({rule_count} rules)\n")
    output.write("=" * 80 + "\n\n")
    output.write(f"Top {top_n} functions by cumulative time:\n\n")

    stats.print_stats(top_n)

    return output.getvalue()


def profile_file_parsing(rule_count: int = 1000, parallel: bool = False, top_n: int = 20) -> str:
    """
    Profile file parsing operations.

    Args:
        rule_count: Number of rules in test file
        parallel: Whether to use parallel parsing
        top_n: Number of top functions to display

    Returns:
        Profiling report as string
    """
    rules_text = generate_test_rules(rule_count)

    # Create temporary file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        temp_path = Path(f.name)
        f.write("\n".join(rules_text))

    try:
        profiler = cProfile.Profile()

        # Profile file parsing
        profiler.enable()
        parse_file(temp_path, parallel=parallel)
        profiler.disable()

        # Generate report
        output = StringIO()
        stats = pstats.Stats(profiler, stream=output)
        stats.strip_dirs()
        stats.sort_stats(SortKey.CUMULATIVE)

        mode = "PARALLEL" if parallel else "SEQUENTIAL"
        output.write("=" * 80 + "\n")
        output.write(f"FILE PARSING PROFILING REPORT - {mode} ({rule_count} rules)\n")
        output.write("=" * 80 + "\n\n")
        output.write(f"Top {top_n} functions by cumulative time:\n\n")

        stats.print_stats(top_n)

        return output.getvalue()

    finally:
        temp_path.unlink()


# ============================================================================
# Memory Profiling
# ============================================================================


def profile_memory_parsing(rule_count: int = 1000) -> str:
    """
    Profile memory usage during parsing.

    Uses tracemalloc to track memory allocations.

    Args:
        rule_count: Number of rules to parse

    Returns:
        Memory profiling report as string
    """
    rules_text = generate_test_rules(rule_count)

    # Start memory tracking
    tracemalloc.start()

    # Take snapshot before
    snapshot_before = tracemalloc.take_snapshot()

    # Parse rules
    parsed_rules = []
    for rule_text in rules_text:
        rule = parse_rule(rule_text)
        parsed_rules.append(rule)

    # Take snapshot after
    snapshot_after = tracemalloc.take_snapshot()

    # Calculate statistics
    top_stats = snapshot_after.compare_to(snapshot_before, "lineno")

    # Generate report
    output = StringIO()
    output.write("=" * 80 + "\n")
    output.write(f"MEMORY PROFILING REPORT - PARSING ({rule_count} rules)\n")
    output.write("=" * 80 + "\n\n")

    current, peak = tracemalloc.get_traced_memory()
    output.write(f"Current memory usage: {current / (1024 * 1024):.2f} MB\n")
    output.write(f"Peak memory usage: {peak / (1024 * 1024):.2f} MB\n\n")

    output.write("Top 10 memory allocations:\n\n")
    for stat in top_stats[:10]:
        output.write(f"{stat}\n")

    tracemalloc.stop()

    return output.getvalue()


def profile_memory_serialization(iterations: int = 100) -> str:
    """
    Profile memory usage during serialization.

    Args:
        iterations: Number of serialization iterations

    Returns:
        Memory profiling report as string
    """
    rule = parse_rule(COMPLEX_RULE)

    # Start memory tracking
    tracemalloc.start()

    # Take snapshot before
    snapshot_before = tracemalloc.take_snapshot()

    # Serialize multiple times
    for _ in range(iterations):
        json_data = to_json(rule)
        from_json(json_data)

    # Take snapshot after
    snapshot_after = tracemalloc.take_snapshot()

    # Calculate statistics
    top_stats = snapshot_after.compare_to(snapshot_before, "lineno")

    # Generate report
    output = StringIO()
    output.write("=" * 80 + "\n")
    output.write(f"MEMORY PROFILING REPORT - SERIALIZATION ({iterations} iterations)\n")
    output.write("=" * 80 + "\n\n")

    current, peak = tracemalloc.get_traced_memory()
    output.write(f"Current memory usage: {current / (1024 * 1024):.2f} MB\n")
    output.write(f"Peak memory usage: {peak / (1024 * 1024):.2f} MB\n\n")

    output.write("Top 10 memory allocations:\n\n")
    for stat in top_stats[:10]:
        output.write(f"{stat}\n")

    tracemalloc.stop()

    return output.getvalue()


# ============================================================================
# Main Runner
# ============================================================================


def main() -> int:
    """Run profiling tools."""
    parser = argparse.ArgumentParser(description="Profile surinort-ast operations")
    parser.add_argument(
        "--operation",
        choices=["parsing", "serialization", "printing", "batch", "file", "all"],
        default="all",
        help="Operation to profile",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1000,
        help="Number of iterations (default: 1000)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="Number of top functions to display (default: 20)",
    )
    parser.add_argument(
        "--memory",
        action="store_true",
        help="Include memory profiling",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file for profiling report",
    )

    args = parser.parse_args()

    reports = []

    # CPU Profiling
    if args.operation in ("parsing", "all"):
        print("Profiling parsing operations...")
        report = profile_parsing(args.iterations, args.top)
        reports.append(report)
        print("✓ Parsing profiling complete\n")

    if args.operation in ("serialization", "all"):
        print("Profiling serialization operations...")
        report = profile_serialization(args.iterations, args.top)
        reports.append(report)
        print("✓ Serialization profiling complete\n")

    if args.operation in ("printing", "all"):
        print("Profiling printing operations...")
        report = profile_printing(args.iterations, args.top)
        reports.append(report)
        print("✓ Printing profiling complete\n")

    if args.operation in ("batch", "all"):
        print("Profiling batch parsing...")
        report = profile_batch_parsing(args.iterations, args.top)
        reports.append(report)
        print("✓ Batch parsing profiling complete\n")

    if args.operation in ("file", "all"):
        print("Profiling file parsing (sequential)...")
        report = profile_file_parsing(args.iterations, parallel=False, top_n=args.top)
        reports.append(report)
        print("✓ File parsing profiling complete\n")

    # Memory Profiling
    if args.memory:
        print("Profiling memory usage (parsing)...")
        report = profile_memory_parsing(args.iterations)
        reports.append(report)
        print("✓ Memory profiling (parsing) complete\n")

        print("Profiling memory usage (serialization)...")
        report = profile_memory_serialization(min(args.iterations, 100))
        reports.append(report)
        print("✓ Memory profiling (serialization) complete\n")

    # Output results
    full_report = "\n\n".join(reports)

    if args.output:
        args.output.write_text(full_report)
        print(f"✓ Profiling report saved to {args.output}")
    else:
        print(full_report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
