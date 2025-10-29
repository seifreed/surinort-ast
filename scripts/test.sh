#!/usr/bin/env bash
# Copyright (c) Marc Rivero López
# Licensed under GNU General Public License v3.0
# See LICENSE file for full terms
#
# Test script for surinort-ast package
# Runs comprehensive test suite with coverage and security checks

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse command line arguments
COVERAGE=true
SECURITY=true
LINT=true
TYPE_CHECK=true
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --no-coverage)
            COVERAGE=false
            shift
            ;;
        --no-security)
            SECURITY=false
            shift
            ;;
        --no-lint)
            LINT=false
            shift
            ;;
        --no-type-check)
            TYPE_CHECK=false
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Usage: $0 [--no-coverage] [--no-security] [--no-lint] [--no-type-check] [-v|--verbose]"
            exit 1
            ;;
    esac
done

# Change to project root
cd "$PROJECT_ROOT"

log_info "Starting test suite for surinort-ast..."

# Check if virtual environment is activated
if [[ -z "${VIRTUAL_ENV:-}" ]]; then
    log_warning "Virtual environment not activated"
    if [[ -d "venv" ]]; then
        log_info "Activating venv..."
        source venv/bin/activate
    else
        log_error "No virtual environment found. Please create one first:"
        log_error "  python -m venv venv && source venv/bin/activate"
        exit 1
    fi
fi

log_info "Using Python: $(command -v python)"
log_info "Python version: $(python --version)"

# Install test dependencies
log_info "Installing test dependencies..."
pip install -e .[dev] --quiet

# Run linting if enabled
if [[ "$LINT" == "true" ]]; then
    log_info "Running Ruff linter..."
    ruff check src/ tests/ || {
        log_error "Linting failed!"
        exit 1
    }
    log_success "Linting passed"

    log_info "Running Ruff format check..."
    ruff format --check src/ tests/ || {
        log_error "Format check failed!"
        exit 1
    }
    log_success "Format check passed"
fi

# Run type checking if enabled
if [[ "$TYPE_CHECK" == "true" ]]; then
    log_info "Running MyPy type checker..."
    mypy src/ --strict || {
        log_error "Type checking failed!"
        exit 1
    }
    log_success "Type checking passed"
fi

# Run security checks if enabled
if [[ "$SECURITY" == "true" ]]; then
    log_info "Running Bandit security scan..."
    if ! pip show bandit &> /dev/null; then
        pip install bandit[toml]==1.8.0 --quiet
    fi
    bandit -r src/ -f screen -ll || log_warning "Bandit found security issues"

    log_info "Running Safety vulnerability scan..."
    if ! pip show safety &> /dev/null; then
        pip install safety==3.2.11 --quiet
    fi
    safety check || log_warning "Safety found vulnerabilities"
fi

# Clean previous test artifacts
log_info "Cleaning previous test artifacts..."
rm -rf .pytest_cache htmlcov .coverage coverage.xml
log_success "Test artifacts cleaned"

# Run tests
log_info "Running pytest test suite..."
PYTEST_ARGS="-v --tb=short --strict-markers"

if [[ "$COVERAGE" == "true" ]]; then
    PYTEST_ARGS="$PYTEST_ARGS --cov=surinort_ast --cov-report=term --cov-report=html --cov-report=xml"
fi

if [[ "$VERBOSE" == "true" ]]; then
    PYTEST_ARGS="$PYTEST_ARGS -vv"
fi

# Run pytest
pytest tests/ $PYTEST_ARGS || {
    log_error "Tests failed!"
    exit 1
}

log_success "All tests passed!"

# Display coverage report if enabled
if [[ "$COVERAGE" == "true" ]]; then
    echo ""
    log_info "Coverage Summary:"
    coverage report --skip-empty

    if [[ -f htmlcov/index.html ]]; then
        log_info "Detailed coverage report: htmlcov/index.html"
    fi
fi

# Run property-based tests if hypothesis is available
if pip show hypothesis &> /dev/null; then
    log_info "Running property-based tests with Hypothesis..."
    pytest tests/ -m "hypothesis" -v || log_warning "Property-based tests not found or failed"
fi

# Summary
echo ""
log_success "============================================"
log_success "Test suite completed successfully!"
log_success "============================================"
echo ""

if [[ "$COVERAGE" == "true" ]]; then
    log_info "Coverage reports generated:"
    echo "  - Terminal: See above"
    echo "  - HTML: htmlcov/index.html"
    echo "  - XML: coverage.xml"
    echo ""
fi

log_info "Next steps:"
echo "  1. Review coverage report: open htmlcov/index.html"
echo "  2. Run specific tests: pytest tests/test_specific.py -v"
echo "  3. Run with markers: pytest tests/ -m 'not slow' -v"
echo ""
