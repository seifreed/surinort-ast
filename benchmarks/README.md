# Surinort-AST Performance Benchmarks

Comprehensive performance benchmark suite for surinort-ast to verify no regression after refactoring and track performance over time.

## Overview

This benchmark suite provides:

- **Parsing benchmarks**: Simple, medium, and complex rules with various configurations
- **Serialization benchmarks**: JSON serialization/deserialization with dictionary dispatch optimization
- **Text printing benchmarks**: Singledispatch-based printing (CC 46 → 1)
- **Query API benchmarks**: CSS-style query execution
- **Parallel processing benchmarks**: Multi-worker file parsing
- **Memory profiling**: Memory usage analysis
- **CPU profiling**: Hotspot identification
- **Regression detection**: Automated comparison with baseline

## Quick Start

### Run All Benchmarks

```bash
cd benchmarks
python run_benchmarks.py
```

### Run with Baseline Comparison

```bash
# First time: save baseline
python run_benchmarks.py --save-baseline

# Later: compare with baseline
python run_benchmarks.py --compare --fail-on-regression
```

### Generate Reports

```bash
# Markdown report (default)
python run_benchmarks.py --output markdown

# JSON results
python run_benchmarks.py --output json

# Both formats
python run_benchmarks.py --output both --output-file my_report
```

## Benchmark Categories

### A. Parsing Benchmarks

Tests parsing performance with various rule complexities:

- `parse_simple_rule`: Baseline parsing (10,000 iterations)
- `parse_medium_rule`: Medium complexity (5,000 iterations)
- `parse_complex_rule`: Complex rules with many options (1,000 iterations)
- `parse_no_location_tracking`: Parsing without location tracking (~10% faster)
- `parse_no_raw_text`: Parsing without raw text storage (~50% memory reduction)
- `parse_batch_sequential`: Batch parsing (1,000 rules)
- `parse_file_sequential`: File parsing without parallelization
- `parse_file_parallel_Nw`: Parallel parsing with N workers (2, 4, 8)

### B. Serialization Benchmarks

Tests JSON serialization after dictionary dispatch refactoring:

- `json_serialize`: Serialize Rule to JSON (1,000 iterations)
- `json_deserialize`: Deserialize from JSON (1,000 iterations)
- `json_roundtrip`: Full serialize + deserialize cycle (500 iterations)
- `json_batch_serialize`: Batch serialization (100 rules)

**Expected improvement**: Deserialization should be faster after CC reduction (33 → 4)

### C. Text Printing Benchmarks

Tests text printing after singledispatch refactoring:

- `text_print_simple`: Simple rule printing (10,000 iterations)
- `text_print_complex`: Complex rule printing (1,000 iterations)
- `text_print_batch`: Batch printing (100 rules)
- `roundtrip_parse_print_parse`: Full roundtrip validation

**Expected improvement**: Printing should be faster due to O(1) dispatch vs O(n) if/elif chain

### D. Query API Benchmarks

Tests CSS-style query execution:

- `query_simple`: Simple attribute queries
- `query_complex`: Complex hierarchical queries

### E. API Function Benchmarks

Tests high-level API functions:

- `api_parse_rule`: API-level parsing
- `api_full_workflow`: Complete pipeline (parse → serialize → print)

### F. Memory Benchmarks

Memory usage measurements:

- `parse_1000_rules_mb`: Memory for 1,000 parsed rules
- `parse_1000_rules_no_raw_mb`: Memory without raw text
- `memory_reduction_percent`: Calculated reduction percentage

## Profiling Tools

### CPU Profiling

Identify hotspots and performance bottlenecks:

```bash
# Profile all operations
python profile_hotspots.py --operation all

# Profile specific operation
python profile_hotspots.py --operation parsing --iterations 5000

# Profile printing with singledispatch analysis
python profile_hotspots.py --operation printing --top 30

# Save profiling report
python profile_hotspots.py --output profiling_report.txt
```

### Memory Profiling

Analyze memory usage:

```bash
# Basic memory profiling (using tracemalloc)
python profile_hotspots.py --operation parsing --memory

# Advanced line-by-line profiling (requires memory-profiler)
pip install memory-profiler
python -m memory_profiler memory_profiler.py
```

### Detailed Memory Analysis

```bash
# Profile specific function
python -c "
from memory_profiler import profile
from benchmarks.memory_profiler import memory_benchmark_parsing

profile(memory_benchmark_parsing)()
"
```

## CI/CD Integration

### GitHub Actions / GitLab CI

Run benchmarks in CI and detect regressions:

```bash
# Run with regression detection
./ci_benchmark.sh

# Custom threshold (15% default for CI)
./ci_benchmark.sh --fail-threshold 20

# Save new baseline (on main branch)
./ci_benchmark.sh --save-baseline
```

### Exit Codes

- `0`: Success, no regressions
- `1`: Regressions detected
- `2`: Benchmark execution failed

### Example CI Configuration

```yaml
# .github/workflows/benchmarks.yml
name: Performance Benchmarks

on: [pull_request]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: pip install -e .
      - name: Run benchmarks
        run: |
          cd benchmarks
          ./ci_benchmark.sh --fail-threshold 15
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: benchmark-report
          path: benchmarks/benchmark_report.md
```

## Regression Detection

### Thresholds

- **Warning threshold**: 5% improvement (notable speedup)
- **Regression threshold**: 10% slowdown (triggers warning)
- **CI failure threshold**: 15% slowdown (fails CI)

### Status Indicators

- ✅ **Improvement**: >5% faster than baseline
- ➡️ **Stable**: Within ±5% of baseline
- ⚠️ **Regression**: >10% slower than baseline

## Baseline Management

### Save Current Results as Baseline

```bash
python run_benchmarks.py --save-baseline
```

This creates `baseline_results.json` with current performance metrics.

### Compare with Baseline

```bash
python run_benchmarks.py --compare
```

Automatically compares if `baseline_results.json` exists.

### Update Baseline After Refactoring

After verifying that refactoring didn't cause regressions:

```bash
# Run benchmarks and verify
python run_benchmarks.py --compare

# If results are good, update baseline
python run_benchmarks.py --save-baseline
git add benchmarks/baseline_results.json
git commit -m "chore: update performance baseline"
```

## Expected Results After Refactoring

Based on the recent refactorings:

### Singledispatch Pattern (Option Serialization)

- **Before**: CC 46 with O(n) if/elif chain
- **After**: CC 1 with O(1) dispatch
- **Expected**: 10-20% improvement in text printing

### Dictionary Dispatch (Deserialization)

- **Before**: CC 33 with long if/elif chain
- **After**: CC 4 with dictionary lookup
- **Expected**: 5-15% improvement in JSON deserialization

### Modular API Structure

- **Expected**: No performance change (architectural improvement)

### IParser Interface

- **Expected**: No performance change (enables dependency injection)

## Interpreting Results

### Sample Output

```
# Surinort-AST Performance Benchmark Report

**Generated:** 2025-12-25 10:00:00

## Summary

- **Total benchmarks:** 20
- **Regressions:** 0 ❌
- **Improvements:** 5 ✅
- **Stable:** 15 ➡️

✅ **No regressions detected** - All benchmarks within ±10% threshold

## A. Parsing Performance

| Benchmark | Time (ms) | Throughput (ops/s) | vs Baseline |
|-----------|-----------|-------------------|-------------|
| parse_simple_rule | 0.045 | 22,222 | ✅ -2.1% |
| parse_complex_rule | 0.180 | 5,556 | ➡️ +0.5% |
| parse_file_parallel_4w | 150.2 | 6,650 | ✅ -8.2% |

## C. Text Printing Performance (Singledispatch)

| Benchmark | Time (ms) | Throughput (ops/s) | vs Baseline |
| text_print_complex | 0.012 | 83,333 | ✅ -15.3% |
```

### What to Look For

1. **Improvements in printing benchmarks**: Singledispatch should show speedup
2. **Improvements in deserialization**: Dictionary dispatch should be faster
3. **No regressions in parsing**: Core parsing should be stable
4. **Memory reduction**: `include_raw_text=False` should show ~50% reduction

## Troubleshooting

### Benchmarks Running Slowly

- Reduce iteration counts in `benchmark_suite.py`
- Run specific benchmarks instead of all
- Check for background processes consuming CPU

### Memory Profiling Errors

If memory_profiler import fails:

```bash
pip install memory-profiler
```

### CI Benchmarks Flaky

- Increase `FAIL_THRESHOLD` in CI (15-20% recommended)
- Use dedicated CI runners for consistency
- Run multiple iterations and average results

## Development Workflow

### Before Refactoring

```bash
# Save baseline
python run_benchmarks.py --save-baseline
git add benchmarks/baseline_results.json
git commit -m "chore: save performance baseline before refactoring"
```

### After Refactoring

```bash
# Compare with baseline
python run_benchmarks.py --compare --fail-on-regression

# If no regressions, update baseline
python run_benchmarks.py --save-baseline
```

### Continuous Monitoring

```bash
# Run benchmarks regularly
python run_benchmarks.py --compare

# Profile if regressions detected
python profile_hotspots.py --operation all --memory
```

## Advanced Usage

### Custom Benchmarks

Add new benchmarks to `benchmark_suite.py`:

```python
def benchmark_my_feature(iterations: int = 1000) -> BenchmarkResult:
    """Benchmark my new feature."""
    def run() -> None:
        my_feature()

    return benchmark(run, iterations=iterations, name="my_feature")
```

### Custom Profiling

Profile specific code paths:

```python
import cProfile
import pstats

profiler = cProfile.Profile()
profiler.enable()

# Your code here

profiler.disable()
stats = pstats.Stats(profiler)
stats.print_stats(20)
```

## Performance Goals

### Target Metrics

- **Simple rule parsing**: >20,000 ops/sec
- **Complex rule parsing**: >5,000 ops/sec
- **Batch parsing**: >5,000 rules/sec
- **Text printing**: >80,000 ops/sec (simple rules)
- **JSON serialization**: >50,000 ops/sec
- **Memory usage**: <30 MB for 1,000 rules

### Optimization Priorities

1. **Parsing**: Most critical (hot path)
2. **Serialization**: Important for I/O
3. **Printing**: Moderate (less frequent)
4. **Memory**: Important for large rulesets

## Contributing

When adding benchmarks:

1. Follow existing naming conventions
2. Include docstrings with expected performance
3. Set appropriate iteration counts
4. Update this README

## License

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
