#!/usr/bin/env bash
#
# CI/CD Benchmark Integration Script
#
# This script runs benchmarks in CI/CD pipelines and detects regressions.
# It compares current performance against the main branch baseline.
#
# Copyright (c) Marc Rivero López
# Licensed under GPLv3
# https://www.gnu.org/licenses/gpl-3.0.html
#
# Usage:
#   ./ci_benchmark.sh [--fail-threshold PERCENT] [--save-baseline]
#
# Exit codes:
#   0 - Success (no regressions)
#   1 - Regressions detected
#   2 - Benchmark execution failed
#

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

BENCHMARK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$BENCHMARK_DIR")"
BASELINE_FILE="$BENCHMARK_DIR/baseline_results.json"
REPORT_FILE="$BENCHMARK_DIR/benchmark_report.md"
RESULTS_FILE="$BENCHMARK_DIR/benchmark_results.json"

# Default regression threshold (15% for CI to avoid flakiness)
FAIL_THRESHOLD="${FAIL_THRESHOLD:-15}"
SAVE_BASELINE=false

# ============================================================================
# Argument Parsing
# ============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --fail-threshold)
            FAIL_THRESHOLD="$2"
            shift 2
            ;;
        --save-baseline)
            SAVE_BASELINE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --fail-threshold PERCENT   Regression threshold (default: 15)"
            echo "  --save-baseline            Save results as new baseline"
            echo "  --help                     Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 2
            ;;
    esac
done

# ============================================================================
# Functions
# ============================================================================

log_info() {
    echo "[INFO] $*"
}

log_error() {
    echo "[ERROR] $*" >&2
}

log_success() {
    echo "[SUCCESS] $*"
}

check_dependencies() {
    log_info "Checking dependencies..."

    if ! command -v python3 &> /dev/null; then
        log_error "python3 not found"
        return 1
    fi

    if ! python3 -c "import surinort_ast" 2>/dev/null; then
        log_error "surinort_ast package not installed"
        log_info "Installing package..."
        pip install -e "$PROJECT_ROOT"
    fi

    log_success "Dependencies OK"
}

fetch_baseline_from_main() {
    log_info "Attempting to fetch baseline from main branch..."

    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        log_info "Not in a git repository, skipping baseline fetch"
        return 0
    fi

    # Check if baseline exists in main branch
    if git show main:benchmarks/baseline_results.json > "$BASELINE_FILE.tmp" 2>/dev/null; then
        mv "$BASELINE_FILE.tmp" "$BASELINE_FILE"
        log_success "Baseline fetched from main branch"
        return 0
    else
        log_info "No baseline found in main branch"
        return 0
    fi
}

run_benchmarks() {
    log_info "Running benchmark suite..."

    cd "$BENCHMARK_DIR"

    local args=("--output" "both" "--output-file" "$REPORT_FILE")

    if [[ "$SAVE_BASELINE" == "true" ]]; then
        args+=("--save-baseline")
    fi

    if [[ -f "$BASELINE_FILE" ]]; then
        args+=("--compare")
    fi

    if python3 run_benchmarks.py "${args[@]}"; then
        log_success "Benchmarks completed successfully"
        return 0
    else
        log_error "Benchmark execution failed"
        return 2
    fi
}

analyze_results() {
    log_info "Analyzing results for regressions..."

    if [[ ! -f "$RESULTS_FILE" ]]; then
        log_error "Results file not found: $RESULTS_FILE"
        return 2
    fi

    if [[ ! -f "$BASELINE_FILE" ]]; then
        log_info "No baseline available for comparison"
        return 0
    fi

    # Extract regression count using Python
    local regression_count
    regression_count=$(python3 -c "
import json
import sys

try:
    with open('$RESULTS_FILE') as f:
        results = json.load(f)

    with open('$BASELINE_FILE') as f:
        baseline = json.load(f)

    regressions = 0
    threshold = $FAIL_THRESHOLD / 100.0

    for name, current in results.get('benchmarks', {}).items():
        if name == 'memory' or not isinstance(current, dict):
            continue

        baseline_data = baseline.get('benchmarks', {}).get(name)
        if not baseline_data:
            continue

        current_mean = current.get('mean_time', 0)
        baseline_mean = baseline_data.get('mean_time', 0)

        if baseline_mean > 0:
            change = (current_mean - baseline_mean) / baseline_mean
            if change > threshold:
                regressions += 1
                print(f'Regression: {name} is {change*100:.1f}% slower', file=sys.stderr)

    print(regressions)
    sys.exit(0)
except Exception as e:
    print(f'Error analyzing results: {e}', file=sys.stderr)
    sys.exit(2)
" 2>&1)

    if [[ $? -ne 0 ]]; then
        log_error "Failed to analyze results"
        return 2
    fi

    if [[ "$regression_count" -gt 0 ]]; then
        log_error "Found $regression_count regression(s) exceeding $FAIL_THRESHOLD% threshold"
        return 1
    else
        log_success "No regressions detected (threshold: $FAIL_THRESHOLD%)"
        return 0
    fi
}

generate_summary() {
    log_info "Generating summary..."

    if [[ -f "$REPORT_FILE" ]]; then
        echo ""
        echo "=========================================="
        echo "BENCHMARK SUMMARY"
        echo "=========================================="

        # Extract summary from markdown report
        if command -v grep &> /dev/null; then
            grep -A 10 "## Summary" "$REPORT_FILE" 2>/dev/null || true
        fi

        echo ""
        echo "Full report: $REPORT_FILE"
        echo "Results JSON: $RESULTS_FILE"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    log_info "Starting CI benchmark suite..."
    log_info "Regression threshold: $FAIL_THRESHOLD%"

    # Check dependencies
    if ! check_dependencies; then
        return 2
    fi

    # Fetch baseline from main branch if not saving new baseline
    if [[ "$SAVE_BASELINE" != "true" ]] && [[ ! -f "$BASELINE_FILE" ]]; then
        fetch_baseline_from_main || true
    fi

    # Run benchmarks
    if ! run_benchmarks; then
        return 2
    fi

    # Generate summary
    generate_summary

    # Analyze results (only if not saving baseline)
    if [[ "$SAVE_BASELINE" != "true" ]]; then
        if ! analyze_results; then
            return 1
        fi
    fi

    log_success "CI benchmark suite completed successfully"
    return 0
}

# Run main function
main
exit $?
