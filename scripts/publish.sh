#!/usr/bin/env bash
# Copyright (c) Marc Rivero López
# Licensed under GNU General Public License v3.0
# See LICENSE file for full terms
#
# Publish script for surinort-ast package
# Securely publishes package to PyPI or TestPyPI with validation

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
REPOSITORY="pypi"
DRY_RUN=false
SKIP_BUILD=false
SKIP_TESTS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --test)
            REPOSITORY="testpypi"
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Usage: $0 [--test] [--dry-run] [--skip-build] [--skip-tests]"
            echo ""
            echo "Options:"
            echo "  --test         Publish to TestPyPI instead of PyPI"
            echo "  --dry-run      Run all checks but don't publish"
            echo "  --skip-build   Skip building the package"
            echo "  --skip-tests   Skip running tests (not recommended)"
            exit 1
            ;;
    esac
done

# Change to project root
cd "$PROJECT_ROOT"

log_info "Starting publish process for surinort-ast..."
log_info "Target repository: $REPOSITORY"

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

# Install required tools
log_info "Installing/upgrading required tools..."
pip install --upgrade pip==24.3.1 --quiet
pip install --upgrade twine==6.2.0 --quiet

# Check git status
log_info "Checking git status..."
if [[ -n $(git status --porcelain) ]]; then
    log_error "Git working directory is not clean!"
    log_error "Please commit or stash your changes before publishing."
    git status --short
    exit 1
fi
log_success "Git working directory is clean"

# Verify on main branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$CURRENT_BRANCH" != "main" ]]; then
    log_warning "Not on main branch (current: $CURRENT_BRANCH)"
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_error "Aborted by user"
        exit 1
    fi
fi

# Extract version from pyproject.toml
VERSION=$(grep -E '^version = ' pyproject.toml | sed 's/version = "\(.*\)"/\1/')
log_info "Package version: $VERSION"

# Check if version tag exists
if git rev-parse "v$VERSION" >/dev/null 2>&1; then
    log_warning "Git tag v$VERSION already exists"
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_error "Aborted by user"
        exit 1
    fi
fi

# Run tests unless skipped
if [[ "$SKIP_TESTS" == "false" ]]; then
    log_info "Running test suite..."
    if [[ -f "$SCRIPT_DIR/test.sh" ]]; then
        "$SCRIPT_DIR/test.sh" || {
            log_error "Tests failed!"
            exit 1
        }
    else
        log_warning "test.sh not found, running pytest directly..."
        pip install -e .[dev] --quiet
        pytest tests/ -v || {
            log_error "Tests failed!"
            exit 1
        }
    fi
    log_success "Tests passed"
else
    log_warning "Skipping tests (--skip-tests flag)"
fi

# Build package unless skipped
if [[ "$SKIP_BUILD" == "false" ]]; then
    log_info "Building package..."
    if [[ -f "$SCRIPT_DIR/build.sh" ]]; then
        "$SCRIPT_DIR/build.sh" || {
            log_error "Build failed!"
            exit 1
        }
    else
        log_warning "build.sh not found, running build directly..."
        pip install build==1.3.0 --quiet
        rm -rf dist/
        python -m build --sdist --wheel --outdir dist/
    fi
    log_success "Build completed"
else
    log_warning "Skipping build (--skip-build flag)"
fi

# Verify dist directory exists and has files
if [[ ! -d "dist" ]] || [[ -z "$(ls -A dist/)" ]]; then
    log_error "No distribution files found in dist/"
    log_error "Please run the build first or remove --skip-build flag"
    exit 1
fi

# Verify package integrity
log_info "Verifying package integrity..."
twine check dist/* --strict || {
    log_error "Package verification failed!"
    exit 1
}
log_success "Package verification passed"

# Display package contents
log_info "Package contents:"
ls -lh dist/

# Check for existing version on PyPI
log_info "Checking if version exists on $REPOSITORY..."
PACKAGE_NAME="surinort-ast"

if [[ "$REPOSITORY" == "pypi" ]]; then
    PYPI_URL="https://pypi.org/pypi/$PACKAGE_NAME/json"
else
    PYPI_URL="https://test.pypi.org/pypi/$PACKAGE_NAME/json"
fi

if curl -sf "$PYPI_URL" | grep -q "\"$VERSION\""; then
    log_error "Version $VERSION already exists on $REPOSITORY!"
    log_error "Please update the version in pyproject.toml and try again."
    exit 1
else
    log_success "Version $VERSION not found on $REPOSITORY (good!)"
fi

# Dry run check
if [[ "$DRY_RUN" == "true" ]]; then
    log_warning "DRY RUN MODE - Not publishing"
    log_info "All checks passed. Package is ready for publication."
    log_info "To publish, run without --dry-run flag"
    exit 0
fi

# Final confirmation
echo ""
log_warning "============================================"
log_warning "READY TO PUBLISH"
log_warning "============================================"
log_info "Package: $PACKAGE_NAME"
log_info "Version: $VERSION"
log_info "Repository: $REPOSITORY"
log_info "Files:"
ls -1 dist/
echo ""
log_warning "This action cannot be undone!"
echo ""
read -p "Are you sure you want to publish? [y/N] " -n 1 -r
echo

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_error "Aborted by user"
    exit 1
fi

# Publish to repository
log_info "Publishing to $REPOSITORY..."

if [[ "$REPOSITORY" == "testpypi" ]]; then
    twine upload --repository testpypi dist/* || {
        log_error "Upload to TestPyPI failed!"
        exit 1
    }
    log_success "Package published to TestPyPI"
    echo ""
    log_info "View package: https://test.pypi.org/project/$PACKAGE_NAME/$VERSION/"
    log_info "Test installation: pip install --index-url https://test.pypi.org/simple/ $PACKAGE_NAME==$VERSION"
else
    twine upload dist/* || {
        log_error "Upload to PyPI failed!"
        exit 1
    }
    log_success "Package published to PyPI"
    echo ""
    log_info "View package: https://pypi.org/project/$PACKAGE_NAME/$VERSION/"
    log_info "Install: pip install $PACKAGE_NAME==$VERSION"
fi

# Create git tag
log_info "Creating git tag v$VERSION..."
git tag -a "v$VERSION" -m "Release version $VERSION"
log_success "Git tag created"

log_info "Pushing tag to remote..."
git push origin "v$VERSION"
log_success "Tag pushed to remote"

# Summary
echo ""
log_success "============================================"
log_success "PUBLISH COMPLETED SUCCESSFULLY!"
log_success "============================================"
echo ""
log_info "Package: $PACKAGE_NAME v$VERSION"
log_info "Repository: $REPOSITORY"
echo ""
log_info "Next steps:"
echo "  1. Verify package page: https://${REPOSITORY}.org/project/$PACKAGE_NAME/$VERSION/"
echo "  2. Test installation: pip install $PACKAGE_NAME==$VERSION"
echo "  3. Create GitHub release: https://github.com/seifreed/surinort-ast/releases/new?tag=v$VERSION"
echo "  4. Announce the release"
echo ""
