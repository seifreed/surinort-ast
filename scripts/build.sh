#!/usr/bin/env bash
# Copyright (c) Marc Rivero López
# Licensed under GNU General Public License v3.0
# See LICENSE file for full terms
#
# Build script for surinort-ast package
# Performs local build with validation and security checks

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

# Change to project root
cd "$PROJECT_ROOT"

log_info "Starting build process for surinort-ast..."

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

# Clean previous builds
log_info "Cleaning previous build artifacts..."
rm -rf dist/ build/ *.egg-info
rm -rf src/*.egg-info
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
log_success "Cleaned build artifacts"

# Upgrade build tools
log_info "Upgrading build tools..."
python -m pip install --upgrade pip==24.3.1
pip install --upgrade build==1.3.0 twine==6.2.0
log_success "Build tools upgraded"

# Run pre-build checks
log_info "Running pre-build security checks..."

# Check for secrets
if command -v gitleaks &> /dev/null; then
    log_info "Running gitleaks secret scan..."
    gitleaks detect --no-git --source . --verbose || log_warning "Gitleaks found potential secrets"
else
    log_warning "gitleaks not installed, skipping secret scan"
fi

# Run bandit security scan
log_info "Running Bandit security scan..."
if pip show bandit &> /dev/null; then
    bandit -r src/ -f screen -ll || log_warning "Bandit found security issues"
else
    log_warning "Bandit not installed, installing..."
    pip install bandit[toml]==1.8.0
    bandit -r src/ -f screen -ll || log_warning "Bandit found security issues"
fi

# Run linting
log_info "Running Ruff linter..."
if pip show ruff &> /dev/null; then
    ruff check src/ tests/ || log_warning "Ruff found linting issues"
    ruff format --check src/ tests/ || log_warning "Ruff format check found issues"
else
    log_warning "Ruff not installed, skipping linting"
fi

# Run type checking
log_info "Running MyPy type checker..."
if pip show mypy &> /dev/null; then
    mypy src/ --strict || log_warning "MyPy found type issues"
else
    log_warning "MyPy not installed, skipping type checking"
fi

# Run tests
log_info "Running test suite..."
if pip show pytest &> /dev/null; then
    pytest tests/ -v --tb=short || {
        log_error "Tests failed!"
        exit 1
    }
    log_success "All tests passed"
else
    log_warning "Pytest not installed, skipping tests"
fi

# Build source distribution and wheel
log_info "Building source distribution and wheel..."
python -m build --sdist --wheel --outdir dist/
log_success "Build completed"

# List built artifacts
log_info "Built artifacts:"
ls -lh dist/

# Verify package integrity
log_info "Verifying package integrity with twine..."
twine check dist/* --strict || {
    log_error "Package verification failed!"
    exit 1
}
log_success "Package verification passed"

# Display package contents
log_info "Package contents (source distribution):"
tar -tzf dist/*.tar.gz | head -30

log_info "Package contents (wheel):"
unzip -l dist/*.whl | head -30

# Generate checksums
log_info "Generating checksums..."
cd dist/
sha256sum * > SHA256SUMS
cat SHA256SUMS
cd ..
log_success "Checksums generated"

# Test installation in isolated environment
log_info "Testing installation in isolated environment..."
TEMP_VENV=$(mktemp -d)
python -m venv "$TEMP_VENV"
source "$TEMP_VENV/bin/activate"
pip install --upgrade pip
pip install dist/*.whl

log_info "Testing package import..."
python -c "import surinort_ast; print(f'Package version: {surinort_ast.__version__}')" || {
    log_error "Package import failed!"
    deactivate
    rm -rf "$TEMP_VENV"
    exit 1
}

log_info "Testing CLI..."
surinort-ast --help || log_warning "CLI test failed"

deactivate
rm -rf "$TEMP_VENV"
log_success "Installation test passed"

# Summary
echo ""
log_success "============================================"
log_success "Build process completed successfully!"
log_success "============================================"
echo ""
log_info "Built packages:"
ls -1 dist/
echo ""
log_info "Next steps:"
echo "  1. Review package contents: tar -tzf dist/*.tar.gz"
echo "  2. Test locally: pip install dist/*.whl"
echo "  3. Publish to TestPyPI: twine upload --repository testpypi dist/*"
echo "  4. Publish to PyPI: twine upload dist/*"
echo ""
