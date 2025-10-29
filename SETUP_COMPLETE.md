# Python Virtual Environment Setup - COMPLETE

**Project**: surisnort-ast
**Author**: Marc Rivero López
**License**: GNU General Public License v3 (GPLv3)
**Date**: 2025-10-29
**Platform**: darwin (macOS)

---

## Environment Status: ✓ READY FOR DEVELOPMENT

All validations passed. The virtual environment is configured correctly and all dependencies are installed.

## Environment Details

| Component | Value |
|-----------|-------|
| **Python Version** | 3.14.0 |
| **Pip Version** | 25.3 |
| **Project Root** | `/Users/seifreed/tools/malware/surinort-ast` |
| **Virtual Environment** | `/Users/seifreed/tools/malware/surinort-ast/venv` |
| **Total Packages** | 78 |
| **Isolation Status** | ✓ Complete (no system packages) |
| **Pre-commit Hooks** | ✓ Installed |

## Validation Results

```
✓ Virtual environment created and active
✓ Python 3.14.0 (exceeds minimum requirement of >=3.11)
✓ Complete isolation from system Python
✓ User site-packages disabled (ENABLE_USER_SITE: False)
✓ All dependencies installed successfully
✓ No dependency conflicts detected
✓ Pre-commit hooks configured and installed
✓ All binaries using project-local venv
```

## Critical Paths

### Python Interpreter
```bash
/Users/seifreed/tools/malware/surinort-ast/venv/bin/python
```

### Package Manager
```bash
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pip
```

### Development Tools
```bash
# Testing
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pytest

# Linting and Formatting
/Users/seifreed/tools/malware/surinort-ast/venv/bin/ruff

# Type Checking
/Users/seifreed/tools/malware/surinort-ast/venv/bin/mypy

# Pre-commit
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pre-commit

# Build
/Users/seifreed/tools/malware/surinort-ast/venv/bin/python -m build

# Documentation
/Users/seifreed/tools/malware/surinort-ast/venv/bin/mkdocs
```

## Installed Production Dependencies

```
lark==1.3.1              # Parser framework
pydantic==2.12.3         # Data validation
typer==0.20.0            # CLI framework
jsonschema==4.25.1       # JSON Schema validation
```

## Installed Development Dependencies

```
pytest==8.4.2            # Testing framework
pytest-cov==7.0.0        # Coverage plugin
hypothesis==6.142.4      # Property-based testing
ruff==0.14.2             # Linter and formatter
mypy==1.18.2             # Type checker
build==1.3.0             # Build tool
twine==6.2.0             # Publishing tool
pre-commit==4.3.0        # Git hooks
mkdocs-material==9.6.22  # Documentation
```

## Quick Start Commands

### Activate Virtual Environment

**Bash/Zsh:**
```bash
source /Users/seifreed/tools/malware/surinort-ast/venv/bin/activate
```

**Using helper script:**
```bash
/Users/seifreed/tools/malware/surinort-ast/activate_venv.sh
```

**Using direnv (recommended):**
```bash
cd /Users/seifreed/tools/malware/surinort-ast
direnv allow
```

### Run Tests
```bash
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pytest
```

### Run Linter
```bash
/Users/seifreed/tools/malware/surinort-ast/venv/bin/ruff check src tests
```

### Auto-fix Linting Issues
```bash
/Users/seifreed/tools/malware/surinort-ast/venv/bin/ruff check --fix src tests
```

### Format Code
```bash
/Users/seifreed/tools/malware/surinort-ast/venv/bin/ruff format src tests
```

### Type Check
```bash
/Users/seifreed/tools/malware/surinort-ast/venv/bin/mypy src
```

### Run Pre-commit on All Files
```bash
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pre-commit run --all-files
```

### Build Package
```bash
/Users/seifreed/tools/malware/surinort-ast/venv/bin/python -m build
```

### Verify Environment Integrity
```bash
/Users/seifreed/tools/malware/surinort-ast/venv/bin/python /Users/seifreed/tools/malware/surinort-ast/verify_venv.py
```

### Check for Dependency Conflicts
```bash
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pip check
```

## Configuration Files

| File | Purpose |
|------|---------|
| `pyproject.toml` | Project metadata and dependencies |
| `.pre-commit-config.yaml` | Pre-commit hooks configuration |
| `requirements.txt` | Production dependencies (placeholder) |
| `requirements-dev.txt` | Development dependencies (placeholder) |
| `.python-version` | Python version specification (3.14.0) |
| `.envrc` | direnv auto-activation |
| `.gitignore` | Git exclusions (includes venv/) |
| `verify_venv.py` | Environment verification script |
| `activate_venv.sh` | Manual activation helper |
| `ENVIRONMENT.md` | Detailed environment documentation |

## Project Configuration (pyproject.toml)

```toml
[project]
name = "surisnort-ast"
version = "0.1.0"
requires-python = ">=3.11"

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.mypy]
python_version = "3.11"
strict = true

[tool.pytest.ini_options]
minversion = "8.0"
testpaths = ["tests"]
pythonpath = ["src"]
```

## Environment Variables (When Activated)

```bash
VIRTUAL_ENV=/Users/seifreed/tools/malware/surinort-ast/venv
PATH=$VIRTUAL_ENV/bin:$PATH
```

## Security Considerations

### Hash Verification (Recommended for Production)

Generate locked requirements with hashes:
```bash
# Install pip-tools
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pip install pip-tools

# Generate locked requirements
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pip-compile --generate-hashes pyproject.toml -o requirements.lock
```

Install with hash verification:
```bash
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pip install -r requirements.lock --require-hashes
```

## Troubleshooting

### Verify Environment is Active
```bash
echo $VIRTUAL_ENV
# Expected: /Users/seifreed/tools/malware/surinort-ast/venv
```

### Check Python Path
```bash
which python
# Expected: /Users/seifreed/tools/malware/surinort-ast/venv/bin/python
```

### Recreate Virtual Environment
```bash
rm -rf /Users/seifreed/tools/malware/surinort-ast/venv
python3.14 -m venv /Users/seifreed/tools/malware/surinort-ast/venv
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pip install -e ".[dev]"
```

## Next Steps

1. **Start Development**: Environment is ready for coding
2. **Run Tests**: Execute `pytest` to ensure everything works
3. **Configure IDE**: Point your IDE to `/Users/seifreed/tools/malware/surinort-ast/venv/bin/python`
4. **Commit Changes**: Pre-commit hooks will run automatically on `git commit`

## License Notice

All environment configuration scripts and files are licensed under **GNU GPL v3**.

```
Copyright (C) Marc Rivero López
Licensed under GNU General Public License v3
https://www.gnu.org/licenses/gpl-3.0.html
```

Any modifications or derivative works must:
1. Attribute authorship to Marc Rivero López
2. Be distributed under the same GPLv3 license
3. Publish modified scripts if redistributed

---

**Environment Setup Date**: 2025-10-29
**Setup Verification**: ✓ PASSED
**Status**: READY FOR DEVELOPMENT

For detailed environment information, see `ENVIRONMENT.md`
