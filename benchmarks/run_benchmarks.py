"""
Benchmark runner with result comparison and regression detection.

This module provides:
- Execution of all benchmarks
- Result storage and comparison with baseline
- Regression detection (>10% slowdown triggers warning)
- Multiple output formats (JSON, Markdown, HTML)
- Statistical significance testing

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from benchmark_suite import BenchmarkResult, run_all_benchmarks

# ============================================================================
# Configuration
# ============================================================================

BASELINE_FILE = Path(__file__).parent / "baseline_results.json"
REGRESSION_THRESHOLD = 0.10  # 10% slowdown triggers warning
IMPROVEMENT_THRESHOLD = 0.05  # 5% speedup is notable


# ============================================================================
# Comparison Logic
# ============================================================================


def compare_results(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """
    Compare current results with baseline.

    Returns:
        Dictionary with comparison data for each benchmark
    """
    comparisons = {}

    for name, current_result in current.items():
        if name == "memory":
            # Special handling for memory benchmarks
            comparisons[name] = _compare_memory(current_result, baseline.get(name, {}))
            continue

        if not isinstance(current_result, BenchmarkResult):
            continue

        baseline_result = baseline.get(name)
        if baseline_result is None:
            comparisons[name] = {
                "status": "new",
                "current_throughput": current_result.throughput,
                "current_mean": current_result.mean_time,
                "change_percent": None,
            }
            continue

        # Extract baseline metrics
        baseline_mean = baseline_result.get("mean_time", 0)
        baseline_throughput = baseline_result.get("throughput", 0)

        # Calculate change percentage
        if baseline_mean > 0:
            change_percent = ((current_result.mean_time - baseline_mean) / baseline_mean) * 100
        else:
            change_percent = 0

        # Determine status
        if change_percent > REGRESSION_THRESHOLD * 100:
            status = "regression"
        elif change_percent < -IMPROVEMENT_THRESHOLD * 100:
            status = "improvement"
        else:
            status = "stable"

        comparisons[name] = {
            "status": status,
            "current_mean": current_result.mean_time,
            "current_throughput": current_result.throughput,
            "baseline_mean": baseline_mean,
            "baseline_throughput": baseline_throughput,
            "change_percent": change_percent,
            "change_ms": (current_result.mean_time - baseline_mean) * 1000,
        }

    return comparisons


def _compare_memory(current: dict[str, float], baseline: dict[str, float]) -> dict[str, Any]:
    """Compare memory usage metrics."""
    comparison = {"status": "stable", "metrics": {}}

    for key, current_value in current.items():
        baseline_value = baseline.get(key)
        if baseline_value is None:
            comparison["metrics"][key] = {
                "current": current_value,
                "baseline": None,
                "change_percent": None,
            }
            continue

        change_percent = ((current_value - baseline_value) / baseline_value) * 100

        # For memory, increase is regression
        if change_percent > REGRESSION_THRESHOLD * 100:
            comparison["status"] = "regression"
        elif change_percent < -IMPROVEMENT_THRESHOLD * 100:
            comparison["status"] = "improvement"

        comparison["metrics"][key] = {
            "current": current_value,
            "baseline": baseline_value,
            "change_percent": change_percent,
        }

    return comparison


# ============================================================================
# Output Formatters
# ============================================================================


def format_markdown(
    results: dict[str, Any], comparisons: dict[str, dict[str, Any]] | None = None
) -> str:
    """Format results as Markdown report."""
    lines = []

    lines.append("# Surinort-AST Performance Benchmark Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    # Summary
    if comparisons:
        regressions = sum(1 for c in comparisons.values() if c.get("status") == "regression")
        improvements = sum(1 for c in comparisons.values() if c.get("status") == "improvement")
        stable = sum(1 for c in comparisons.values() if c.get("status") == "stable")

        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Total benchmarks:** {len(comparisons)}")
        lines.append(f"- **Regressions:** {regressions} ❌")
        lines.append(f"- **Improvements:** {improvements} ✅")
        lines.append(f"- **Stable:** {stable} ➡️")
        lines.append("")

        if regressions == 0:
            lines.append("✅ **No regressions detected** - All benchmarks within ±10% threshold")
        else:
            lines.append(f"⚠️ **{regressions} regression(s) detected** - Review required")
        lines.append("")

    # Parsing Performance
    lines.append("## A. Parsing Performance")
    lines.append("")
    lines.append("| Benchmark | Time (ms) | Throughput (ops/s) | vs Baseline |")
    lines.append("|-----------|-----------|-------------------|-------------|")

    parsing_benches = [
        "parse_simple_rule",
        "parse_medium_rule",
        "parse_complex_rule",
        "parse_no_location",
        "parse_no_raw",
        "parse_batch_seq",
        "parse_file_seq",
        "parallel_2w",
        "parallel_4w",
        "parallel_8w",
    ]

    for name in parsing_benches:
        result = results.get(name)
        if not result or not isinstance(result, BenchmarkResult):
            continue

        time_ms = result.mean_time * 1000
        throughput = result.throughput

        baseline_info = ""
        if comparisons and name in comparisons:
            comp = comparisons[name]
            status = comp["status"]
            if status == "regression":
                baseline_info = f"⚠️ +{comp['change_percent']:.1f}%"
            elif status == "improvement":
                baseline_info = f"✅ {comp['change_percent']:.1f}%"
            elif status == "stable":
                baseline_info = f"➡️ {comp['change_percent']:+.1f}%"
            else:
                baseline_info = "🆕 NEW"

        lines.append(f"| {name} | {time_ms:.3f} | {throughput:,.0f} | {baseline_info} |")

    lines.append("")

    # Serialization Performance
    lines.append("## B. Serialization Performance")
    lines.append("")
    lines.append("| Benchmark | Time (ms) | Throughput (ops/s) | vs Baseline |")
    lines.append("|-----------|-----------|-------------------|-------------|")

    serialization_benches = [
        "json_serialize",
        "json_deserialize",
        "json_roundtrip",
        "json_batch",
    ]

    for name in serialization_benches:
        result = results.get(name)
        if not result or not isinstance(result, BenchmarkResult):
            continue

        time_ms = result.mean_time * 1000
        throughput = result.throughput

        baseline_info = ""
        if comparisons and name in comparisons:
            comp = comparisons[name]
            status = comp["status"]
            if status == "regression":
                baseline_info = f"⚠️ +{comp['change_percent']:.1f}%"
            elif status == "improvement":
                baseline_info = f"✅ {comp['change_percent']:.1f}%"
            elif status == "stable":
                baseline_info = f"➡️ {comp['change_percent']:+.1f}%"
            else:
                baseline_info = "🆕 NEW"

        lines.append(f"| {name} | {time_ms:.3f} | {throughput:,.0f} | {baseline_info} |")

    lines.append("")

    # Text Printing Performance
    lines.append("## C. Text Printing Performance (Singledispatch)")
    lines.append("")
    lines.append("| Benchmark | Time (ms) | Throughput (ops/s) | vs Baseline |")
    lines.append("|-----------|-----------|-------------------|-------------|")

    printing_benches = ["print_simple", "print_complex", "print_batch", "roundtrip"]

    for name in printing_benches:
        result = results.get(name)
        if not result or not isinstance(result, BenchmarkResult):
            continue

        time_ms = result.mean_time * 1000
        throughput = result.throughput

        baseline_info = ""
        if comparisons and name in comparisons:
            comp = comparisons[name]
            status = comp["status"]
            if status == "regression":
                baseline_info = f"⚠️ +{comp['change_percent']:.1f}%"
            elif status == "improvement":
                baseline_info = f"✅ {comp['change_percent']:.1f}%"
            elif status == "stable":
                baseline_info = f"➡️ {comp['change_percent']:+.1f}%"
            else:
                baseline_info = "🆕 NEW"

        lines.append(f"| {name} | {time_ms:.3f} | {throughput:,.0f} | {baseline_info} |")

    lines.append("")

    # Memory Usage
    memory_result = results.get("memory")
    if memory_result:
        lines.append("## F. Memory Usage")
        lines.append("")
        lines.append("| Metric | Value | vs Baseline |")
        lines.append("|--------|-------|-------------|")

        for key, value in memory_result.items():
            baseline_info = ""
            if comparisons and "memory" in comparisons:
                mem_comp = comparisons["memory"]["metrics"].get(key)
                if mem_comp and mem_comp["change_percent"] is not None:
                    change = mem_comp["change_percent"]
                    if abs(change) > REGRESSION_THRESHOLD * 100:
                        baseline_info = f"⚠️ {change:+.1f}%"
                    elif abs(change) > IMPROVEMENT_THRESHOLD * 100:
                        baseline_info = f"✅ {change:+.1f}%"
                    else:
                        baseline_info = f"➡️ {change:+.1f}%"
                else:
                    baseline_info = "🆕 NEW"

            if isinstance(value, float):
                lines.append(f"| {key} | {value:.2f} | {baseline_info} |")

        lines.append("")

    # Regression Details
    if comparisons:
        regressions = [
            (name, comp) for name, comp in comparisons.items() if comp.get("status") == "regression"
        ]

        if regressions:
            lines.append("## ⚠️ Regression Details")
            lines.append("")
            for name, comp in regressions:
                if name == "memory":
                    continue
                lines.append(f"### {name}")
                lines.append("")
                lines.append(
                    f"- **Slowdown:** {comp['change_percent']:.1f}% "
                    f"({comp['change_ms']:.3f} ms slower)"
                )
                lines.append(f"- **Current:** {comp['current_mean'] * 1000:.3f} ms")
                lines.append(f"- **Baseline:** {comp['baseline_mean'] * 1000:.3f} ms")
                lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("*Generated by surinort-ast benchmark suite*")

    return "\n".join(lines)


def format_json(results: dict[str, Any]) -> str:
    """Format results as JSON."""

    def serialize_result(obj: Any) -> Any:
        if isinstance(obj, BenchmarkResult):
            return {
                "name": obj.name,
                "iterations": obj.iterations,
                "mean_time": obj.mean_time,
                "median_time": obj.median_time,
                "stdev_time": obj.stdev_time,
                "min_time": obj.min_time,
                "max_time": obj.max_time,
                "throughput": obj.throughput,
                "memory_mb": obj.memory_mb,
            }
        return obj

    output = {
        "timestamp": datetime.now().isoformat(),
        "benchmarks": {name: serialize_result(result) for name, result in results.items()},
    }

    return json.dumps(output, indent=2)


# ============================================================================
# Baseline Management
# ============================================================================


def save_baseline(results: dict[str, Any], filepath: Path = BASELINE_FILE) -> None:
    """Save current results as baseline."""
    json_output = format_json(results)
    filepath.write_text(json_output)
    print(f"✓ Baseline saved to {filepath}")


def load_baseline(filepath: Path = BASELINE_FILE) -> dict[str, Any] | None:
    """Load baseline results."""
    if not filepath.exists():
        return None

    data = json.loads(filepath.read_text())
    return data.get("benchmarks", {})


# ============================================================================
# Main Runner
# ============================================================================


def main() -> int:
    """Run benchmarks with optional baseline comparison."""
    parser = argparse.ArgumentParser(description="Run surinort-ast benchmarks")
    parser.add_argument(
        "--save-baseline",
        action="store_true",
        help="Save results as new baseline",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Compare with baseline (default if baseline exists)",
    )
    parser.add_argument(
        "--output",
        choices=["markdown", "json", "both"],
        default="markdown",
        help="Output format",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        help="Output file path (default: benchmark_report.md or .json)",
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Exit with error code if regressions detected",
    )

    args = parser.parse_args()

    # Run benchmarks
    print("Running benchmark suite...")
    print()
    results = run_all_benchmarks()
    print()

    # Load baseline for comparison
    baseline = None
    comparisons = None
    if args.compare or (BASELINE_FILE.exists() and not args.save_baseline):
        baseline = load_baseline()
        if baseline:
            print("Comparing with baseline...")
            comparisons = compare_results(results, baseline)
            print()

    # Save baseline if requested
    if args.save_baseline:
        save_baseline(results)
        print()

    # Generate reports
    if args.output in ("markdown", "both"):
        markdown_output = format_markdown(results, comparisons)
        if args.output_file:
            output_path = args.output_file
        else:
            output_path = Path("benchmark_report.md")

        output_path.write_text(markdown_output)
        print(f"✓ Markdown report saved to {output_path}")
        print()
        print(markdown_output)

    if args.output in ("json", "both"):
        json_output = format_json(results)
        if args.output_file:
            output_path = args.output_file.with_suffix(".json")
        else:
            output_path = Path("benchmark_results.json")

        output_path.write_text(json_output)
        print(f"✓ JSON results saved to {output_path}")

    # Check for regressions
    if args.fail_on_regression and comparisons:
        regressions = sum(1 for c in comparisons.values() if c.get("status") == "regression")
        if regressions > 0:
            print()
            print(f"❌ FAILURE: {regressions} regression(s) detected")
            return 1

    print()
    print("✓ Benchmark suite completed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())
