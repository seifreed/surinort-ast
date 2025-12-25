"""
Comprehensive benchmark suite for surinort-ast performance testing.

This module provides benchmarks for all major operations to verify
no regression after refactoring:
- Parsing (simple, complex, file-based)
- Serialization (JSON, Protobuf if available)
- Text printing (after singledispatch refactoring)
- Query API operations
- Parallel processing

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from __future__ import annotations

import statistics
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

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

MEDIUM_RULE = """alert http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"ET MALWARE Observed Malicious SSL Cert";
    flow:established,from_server;
    content:"Subject"; nocase;
    content:"CN="; distance:0;
    classtype:trojan-activity;
    sid:2024001;
    rev:2;
)"""


def generate_test_rules(count: int) -> list[str]:
    """Generate test rules for benchmarking."""
    rules = []
    for i in range(count):
        if i % 3 == 0:
            rule = COMPLEX_RULE.replace("sid:1000001", f"sid:{1000001 + i}")
        elif i % 3 == 1:
            rule = MEDIUM_RULE.replace("sid:2024001", f"sid:{2000001 + i}")
        else:
            rule = SIMPLE_RULE.replace("sid:1", f"sid:{3000001 + i}")
        rules.append(rule)
    return rules


# ============================================================================
# Benchmark Infrastructure
# ============================================================================


class BenchmarkResult:
    """Store benchmark results with statistics."""

    def __init__(
        self,
        name: str,
        iterations: int,
        total_time: float,
        times: list[float],
        throughput: float | None = None,
        memory_mb: float | None = None,
    ):
        self.name = name
        self.iterations = iterations
        self.total_time = total_time
        self.times = times
        self.mean_time = statistics.mean(times) if times else 0
        self.median_time = statistics.median(times) if times else 0
        self.stdev_time = statistics.stdev(times) if len(times) > 1 else 0
        self.min_time = min(times) if times else 0
        self.max_time = max(times) if times else 0
        self.throughput = throughput  # operations per second
        self.memory_mb = memory_mb

    def __repr__(self) -> str:
        return (
            f"BenchmarkResult(name={self.name!r}, "
            f"mean={self.mean_time:.6f}s, "
            f"stdev={self.stdev_time:.6f}s, "
            f"throughput={self.throughput:.2f} ops/s)"
        )


def benchmark(
    func: Callable[[], Any],
    iterations: int = 100,
    warmup: int = 10,
    name: str = "benchmark",
) -> BenchmarkResult:
    """
    Run benchmark with statistical analysis.

    Args:
        func: Function to benchmark (no arguments)
        iterations: Number of iterations for timing
        warmup: Number of warmup iterations
        name: Benchmark name

    Returns:
        BenchmarkResult with statistics
    """
    # Warmup
    for _ in range(warmup):
        func()

    # Benchmark
    times = []
    start_total = time.perf_counter()

    for _ in range(iterations):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        times.append(end - start)

    end_total = time.perf_counter()
    total_time = end_total - start_total

    # Calculate throughput (ops/second)
    throughput = iterations / total_time if total_time > 0 else 0

    return BenchmarkResult(
        name=name,
        iterations=iterations,
        total_time=total_time,
        times=times,
        throughput=throughput,
    )


# ============================================================================
# A. Parsing Benchmarks
# ============================================================================


def benchmark_parse_simple_rule(iterations: int = 10000) -> BenchmarkResult:
    """
    Benchmark simple rule parsing.

    This tests the baseline parsing performance with minimal options.
    """

    def run() -> None:
        parse_rule(SIMPLE_RULE)

    return benchmark(run, iterations=iterations, name="parse_simple_rule")


def benchmark_parse_medium_rule(iterations: int = 5000) -> BenchmarkResult:
    """Benchmark medium complexity rule parsing."""

    def run() -> None:
        parse_rule(MEDIUM_RULE)

    return benchmark(run, iterations=iterations, name="parse_medium_rule")


def benchmark_parse_complex_rule(iterations: int = 1000) -> BenchmarkResult:
    """
    Benchmark complex rule parsing.

    This tests parsing of rules with many options, content modifiers,
    PCRE patterns, and metadata.
    """

    def run() -> None:
        parse_rule(COMPLEX_RULE)

    return benchmark(run, iterations=iterations, name="parse_complex_rule")


def benchmark_parse_no_location_tracking(iterations: int = 10000) -> BenchmarkResult:
    """
    Benchmark parsing without location tracking.

    Should show ~10% performance improvement.
    """

    def run() -> None:
        parse_rule(SIMPLE_RULE, track_locations=False)

    return benchmark(run, iterations=iterations, name="parse_no_location_tracking")


def benchmark_parse_no_raw_text(iterations: int = 10000) -> BenchmarkResult:
    """
    Benchmark parsing without raw text storage.

    Should show ~50% memory reduction.
    """

    def run() -> None:
        parse_rule(SIMPLE_RULE, include_raw_text=False)

    return benchmark(run, iterations=iterations, name="parse_no_raw_text")


def benchmark_parse_batch_sequential(rule_count: int = 1000) -> BenchmarkResult:
    """
    Benchmark sequential batch parsing.

    This tests parse_rules() with multiple rules.
    """
    rules_text = generate_test_rules(rule_count)

    def run() -> None:
        parse_rules(rules_text)

    result = benchmark(run, iterations=10, warmup=2, name="parse_batch_sequential")
    # Calculate rules per second
    result.throughput = (rule_count * result.iterations) / result.total_time
    return result


def benchmark_parse_file_sequential(rule_count: int = 1000) -> BenchmarkResult:
    """
    Benchmark file parsing (sequential).

    Creates temporary file with test rules.
    """
    rules_text = generate_test_rules(rule_count)

    # Create temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        temp_path = Path(f.name)
        f.write("\n".join(rules_text))

    try:

        def run() -> None:
            parse_file(temp_path, workers=1)

        result = benchmark(run, iterations=5, warmup=1, name="parse_file_sequential")
        result.throughput = (rule_count * result.iterations) / result.total_time
        return result

    finally:
        temp_path.unlink()


def benchmark_parse_file_parallel(
    rule_count: int = 1000, worker_counts: list[int] | None = None
) -> dict[str, BenchmarkResult]:
    """
    Benchmark file parsing with different worker counts.

    Tests parallel processing scalability.
    """
    if worker_counts is None:
        worker_counts = [2, 4, 8]

    rules_text = generate_test_rules(rule_count)

    # Create temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
        temp_path = Path(f.name)
        f.write("\n".join(rules_text))

    results = {}

    try:
        for workers in worker_counts:

            def run() -> None:
                parse_file(temp_path, workers=workers)

            result = benchmark(
                run,
                iterations=5,
                warmup=1,
                name=f"parse_file_parallel_{workers}w",
            )
            result.throughput = (rule_count * result.iterations) / result.total_time
            results[f"parallel_{workers}w"] = result

        return results

    finally:
        temp_path.unlink()


# ============================================================================
# B. Serialization Benchmarks
# ============================================================================


def benchmark_json_serialize(iterations: int = 1000) -> BenchmarkResult:
    """
    Benchmark JSON serialization.

    Tests the performance of to_json() with Pydantic model serialization.
    """
    rule = parse_rule(COMPLEX_RULE)

    def run() -> None:
        to_json(rule)

    return benchmark(run, iterations=iterations, name="json_serialize")


def benchmark_json_deserialize(iterations: int = 1000) -> BenchmarkResult:
    """
    Benchmark JSON deserialization.

    Tests the performance of from_json() after dictionary dispatch refactoring.
    Should show improvement due to CC reduction (33 → 4).
    """
    rule = parse_rule(COMPLEX_RULE)
    json_data = to_json(rule)

    def run() -> None:
        from_json(json_data)

    return benchmark(run, iterations=iterations, name="json_deserialize")


def benchmark_json_roundtrip(iterations: int = 500) -> BenchmarkResult:
    """Benchmark full JSON serialize + deserialize roundtrip."""
    rule = parse_rule(COMPLEX_RULE)

    def run() -> None:
        json_data = to_json(rule)
        from_json(json_data)

    return benchmark(run, iterations=iterations, name="json_roundtrip")


def benchmark_json_batch_serialize(rule_count: int = 100) -> BenchmarkResult:
    """Benchmark batch JSON serialization."""
    from surinort_ast.serialization.json_serializer import JSONSerializer

    rules = [parse_rule(rule_text) for rule_text in generate_test_rules(rule_count)]
    serializer = JSONSerializer()

    def run() -> None:
        serializer.to_json(rules)

    result = benchmark(run, iterations=10, name="json_batch_serialize")
    result.throughput = (rule_count * result.iterations) / result.total_time
    return result


# ============================================================================
# C. Text Printing Benchmarks
# ============================================================================


def benchmark_text_print_simple(iterations: int = 10000) -> BenchmarkResult:
    """
    Benchmark text printing for simple rule.

    Tests singledispatch performance after refactoring (CC 46 → 1).
    Should show improvement due to O(1) dispatch vs O(n) if/elif chain.
    """
    rule = parse_rule(SIMPLE_RULE)

    def run() -> None:
        print_rule(rule)

    return benchmark(run, iterations=iterations, name="text_print_simple")


def benchmark_text_print_complex(iterations: int = 1000) -> BenchmarkResult:
    """
    Benchmark text printing for complex rule.

    Complex rules benefit more from singledispatch optimization
    due to many option types requiring dispatch.
    """
    rule = parse_rule(COMPLEX_RULE)

    def run() -> None:
        print_rule(rule)

    return benchmark(run, iterations=iterations, name="text_print_complex")


def benchmark_text_print_batch(rule_count: int = 100) -> BenchmarkResult:
    """Benchmark batch text printing."""
    rules = [parse_rule(rule_text) for rule_text in generate_test_rules(rule_count)]

    def run() -> None:
        for rule in rules:
            print_rule(rule)

    result = benchmark(run, iterations=10, name="text_print_batch")
    result.throughput = (rule_count * result.iterations) / result.total_time
    return result


def benchmark_roundtrip_parse_print_parse(iterations: int = 100) -> BenchmarkResult:
    """
    Benchmark full roundtrip: parse → print → parse.

    Tests that printed output is valid and can be re-parsed.
    """

    def run() -> None:
        rule1 = parse_rule(MEDIUM_RULE)
        text = print_rule(rule1)
        parse_rule(text)

    return benchmark(run, iterations=iterations, name="roundtrip_parse_print_parse")


# ============================================================================
# D. Query API Benchmarks (if available)
# ============================================================================


def benchmark_query_simple(iterations: int = 1000) -> BenchmarkResult | None:
    """Benchmark simple CSS-style query execution."""
    try:
        from surinort_ast.query import query

        rule = parse_rule(COMPLEX_RULE)

        def run() -> None:
            query(rule, "option[type='content']")

        return benchmark(run, iterations=iterations, name="query_simple")

    except ImportError:
        return None


def benchmark_query_complex(iterations: int = 500) -> BenchmarkResult | None:
    """Benchmark complex hierarchical query."""
    try:
        from surinort_ast.query import query

        rule = parse_rule(COMPLEX_RULE)

        def run() -> None:
            query(rule, "rule > options > option[type='content'] modifier")

        return benchmark(run, iterations=iterations, name="query_complex")

    except ImportError:
        return None


# ============================================================================
# E. API Function Benchmarks
# ============================================================================


def benchmark_api_parse_rule(iterations: int = 1000) -> BenchmarkResult:
    """Benchmark high-level API parse_rule function."""

    def run() -> None:
        parse_rule(MEDIUM_RULE)

    return benchmark(run, iterations=iterations, name="api_parse_rule")


def benchmark_api_full_workflow(iterations: int = 100) -> BenchmarkResult:
    """
    Benchmark full API workflow: parse → serialize → print.

    This tests the complete pipeline end-to-end.
    """

    def run() -> None:
        rule = parse_rule(COMPLEX_RULE)
        json_data = to_json(rule)
        from_json(json_data)
        print_rule(rule)

    return benchmark(run, iterations=iterations, name="api_full_workflow")


# ============================================================================
# F. Memory Benchmarks
# ============================================================================


def benchmark_memory_usage() -> dict[str, float]:
    """
    Benchmark memory usage for various operations.

    Returns memory in MB.
    """
    import gc
    import sys

    results = {}

    # Measure rule parsing memory
    gc.collect()
    rules = []
    before = sys.getsizeof(rules)
    for i in range(1, 1001):
        rule = parse_rule(SIMPLE_RULE.replace("sid:1", f"sid:{i}"))
        rules.append(rule)
    after = sys.getsizeof(rules) + sum(sys.getsizeof(r) for r in rules)
    results["parse_1000_rules_mb"] = (after - before) / (1024 * 1024)

    # Measure with raw_text disabled
    gc.collect()
    rules_no_raw = []
    before = sys.getsizeof(rules_no_raw)
    for i in range(1, 1001):
        rule = parse_rule(SIMPLE_RULE.replace("sid:1", f"sid:{i}"), include_raw_text=False)
        rules_no_raw.append(rule)
    after = sys.getsizeof(rules_no_raw) + sum(sys.getsizeof(r) for r in rules_no_raw)
    results["parse_1000_rules_no_raw_mb"] = (after - before) / (1024 * 1024)

    # Calculate memory reduction
    if results["parse_1000_rules_mb"] > 0:
        reduction = (
            (results["parse_1000_rules_mb"] - results["parse_1000_rules_no_raw_mb"])
            / results["parse_1000_rules_mb"]
        ) * 100
        results["memory_reduction_percent"] = reduction

    return results


# ============================================================================
# Master Runner
# ============================================================================


def run_all_benchmarks() -> dict[str, Any]:
    """
    Run all benchmarks and return results.

    Returns:
        Dictionary with all benchmark results
    """
    results = {}

    print("=" * 80)
    print("SURINORT-AST PERFORMANCE BENCHMARK SUITE")
    print("=" * 80)

    # A. Parsing Benchmarks
    print("\n[A] PARSING BENCHMARKS")
    print("-" * 80)

    print("Running: parse_simple_rule...")
    results["parse_simple_rule"] = benchmark_parse_simple_rule()
    print(f"  ✓ {results['parse_simple_rule'].throughput:.0f} ops/sec")

    print("Running: parse_medium_rule...")
    results["parse_medium_rule"] = benchmark_parse_medium_rule()
    print(f"  ✓ {results['parse_medium_rule'].throughput:.0f} ops/sec")

    print("Running: parse_complex_rule...")
    results["parse_complex_rule"] = benchmark_parse_complex_rule()
    print(f"  ✓ {results['parse_complex_rule'].throughput:.0f} ops/sec")

    print("Running: parse_no_location_tracking...")
    results["parse_no_location"] = benchmark_parse_no_location_tracking()
    print(f"  ✓ {results['parse_no_location'].throughput:.0f} ops/sec")

    print("Running: parse_no_raw_text...")
    results["parse_no_raw"] = benchmark_parse_no_raw_text()
    print(f"  ✓ {results['parse_no_raw'].throughput:.0f} ops/sec")

    print("Running: parse_batch_sequential (1000 rules)...")
    results["parse_batch_seq"] = benchmark_parse_batch_sequential(1000)
    print(f"  ✓ {results['parse_batch_seq'].throughput:.0f} rules/sec")

    print("Running: parse_file_sequential (1000 rules)...")
    results["parse_file_seq"] = benchmark_parse_file_sequential(1000)
    print(f"  ✓ {results['parse_file_seq'].throughput:.0f} rules/sec")

    print("Running: parse_file_parallel (1000 rules)...")
    parallel_results = benchmark_parse_file_parallel(1000, [2, 4, 8])
    results.update(parallel_results)
    for key, res in parallel_results.items():
        print(f"  ✓ {key}: {res.throughput:.0f} rules/sec")

    # B. Serialization Benchmarks
    print("\n[B] SERIALIZATION BENCHMARKS")
    print("-" * 80)

    print("Running: json_serialize...")
    results["json_serialize"] = benchmark_json_serialize()
    print(f"  ✓ {results['json_serialize'].throughput:.0f} ops/sec")

    print("Running: json_deserialize...")
    results["json_deserialize"] = benchmark_json_deserialize()
    print(f"  ✓ {results['json_deserialize'].throughput:.0f} ops/sec")

    print("Running: json_roundtrip...")
    results["json_roundtrip"] = benchmark_json_roundtrip()
    print(f"  ✓ {results['json_roundtrip'].throughput:.0f} ops/sec")

    print("Running: json_batch_serialize (100 rules)...")
    results["json_batch"] = benchmark_json_batch_serialize(100)
    print(f"  ✓ {results['json_batch'].throughput:.0f} rules/sec")

    # C. Text Printing Benchmarks
    print("\n[C] TEXT PRINTING BENCHMARKS (Singledispatch)")
    print("-" * 80)

    print("Running: text_print_simple...")
    results["print_simple"] = benchmark_text_print_simple()
    print(f"  ✓ {results['print_simple'].throughput:.0f} ops/sec")

    print("Running: text_print_complex...")
    results["print_complex"] = benchmark_text_print_complex()
    print(f"  ✓ {results['print_complex'].throughput:.0f} ops/sec")

    print("Running: text_print_batch (100 rules)...")
    results["print_batch"] = benchmark_text_print_batch(100)
    print(f"  ✓ {results['print_batch'].throughput:.0f} rules/sec")

    print("Running: roundtrip_parse_print_parse...")
    results["roundtrip"] = benchmark_roundtrip_parse_print_parse()
    print(f"  ✓ {results['roundtrip'].throughput:.0f} ops/sec")

    # D. Query Benchmarks (optional)
    print("\n[D] QUERY API BENCHMARKS")
    print("-" * 80)

    query_simple = benchmark_query_simple()
    if query_simple:
        results["query_simple"] = query_simple
        print(f"  ✓ query_simple: {query_simple.throughput:.0f} ops/sec")
    else:
        print("  ⚠ Query API not available")

    query_complex = benchmark_query_complex()
    if query_complex:
        results["query_complex"] = query_complex
        print(f"  ✓ query_complex: {query_complex.throughput:.0f} ops/sec")

    # E. API Benchmarks
    print("\n[E] API FUNCTION BENCHMARKS")
    print("-" * 80)

    print("Running: api_parse_rule...")
    results["api_parse"] = benchmark_api_parse_rule()
    print(f"  ✓ {results['api_parse'].throughput:.0f} ops/sec")

    print("Running: api_full_workflow...")
    results["api_workflow"] = benchmark_api_full_workflow()
    print(f"  ✓ {results['api_workflow'].throughput:.0f} ops/sec")

    # F. Memory Benchmarks
    print("\n[F] MEMORY USAGE BENCHMARKS")
    print("-" * 80)

    print("Running: memory_usage...")
    memory_results = benchmark_memory_usage()
    results["memory"] = memory_results
    for key, value in memory_results.items():
        print(f"  ✓ {key}: {value:.2f}")

    print("\n" + "=" * 80)
    print("BENCHMARK SUITE COMPLETE")
    print("=" * 80)

    return results


if __name__ == "__main__":
    results = run_all_benchmarks()
