# Python Virtual Environment - surisnort-ast

**Copyright (C) Marc Rivero López**
**Licensed under GNU GPL v3**
https://www.gnu.org/licenses/gpl-3.0.html

---

## Environment Information

- **Project**: surisnort-ast
- **Location**: `/Users/seifreed/tools/malware/surinort-ast`
- **Python Version**: 3.14.0
- **Virtual Environment**: `/Users/seifreed/tools/malware/surinort-ast/venv`
- **Package Manager**: pip 25.3

## Environment Status

✓ Virtual environment created and configured
✓ Python 3.14.0 active (exceeds minimum requirement of 3.13+)
✓ Complete isolation from system packages
✓ User site-packages disabled
✓ All operations use project-local binaries

## Activation

### Manual Activation (bash/zsh)

```bash
source /Users/seifreed/tools/malware/surinort-ast/venv/bin/activate
```

### Using Helper Script

```bash
/Users/seifreed/tools/malware/surinort-ast/activate_venv.sh
```

### Using direnv (recommended)

```bash
cd /Users/seifreed/tools/malware/surinort-ast
direnv allow
```

The `.envrc` file will automatically activate the virtual environment when you enter the directory.

## Verification

Run the verification script to check environment integrity:

```bash
/Users/seifreed/tools/malware/surinort-ast/venv/bin/python /Users/seifreed/tools/malware/surinort-ast/verify_venv.py
```

## Dependency Management

### Install Production Dependencies

```bash
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pip install -r /Users/seifreed/tools/malware/surinort-ast/requirements.txt
```

### Install Development Dependencies

```bash
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pip install -r /Users/seifreed/tools/malware/surinort-ast/requirements-dev.txt
```

### Install with Hash Verification (production)

```bash
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pip install -r /Users/seifreed/tools/malware/surinort-ast/requirements.txt --require-hashes
```

Note: You'll need to generate hashes first using `pip-compile --generate-hashes`

## Path Validation

All Python operations MUST use the virtual environment binaries:

- **Python**: `/Users/seifreed/tools/malware/surinort-ast/venv/bin/python`
- **Pip**: `/Users/seifreed/tools/malware/surinort-ast/venv/bin/pip`
- **Pytest**: `/Users/seifreed/tools/malware/surinort-ast/venv/bin/pytest` (after installation)
- **Black**: `/Users/seifreed/tools/malware/surinort-ast/venv/bin/black` (after installation)
- **Flake8**: `/Users/seifreed/tools/malware/surinort-ast/venv/bin/flake8` (after installation)

## Environment Variables

When activated, the following environment variables are set:

- `VIRTUAL_ENV=/Users/seifreed/tools/malware/surinort-ast/venv`
- `PATH` is prepended with `$VIRTUAL_ENV/bin`

## Security and Reproducibility

### Lockfile Generation (recommended)

```bash
# Install pip-tools
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pip install pip-tools

# Generate locked requirements with hashes
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pip-compile --generate-hashes requirements.txt -o requirements.lock
```

### Verifying Installation Integrity

```bash
# Check for dependency conflicts
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pip check

# List all installed packages
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pip list --format=freeze
```

## Troubleshooting

### Environment Not Activating

If activation fails, verify:
1. Virtual environment exists: `ls -la /Users/seifreed/tools/malware/surinort-ast/venv`
2. Configuration file present: `cat /Users/seifreed/tools/malware/surinort-ast/venv/pyvenv.cfg`
3. Python binary exists: `test -f /Users/seifreed/tools/malware/surinort-ast/venv/bin/python && echo "OK"`

### Recreating Virtual Environment

If the environment becomes corrupted:

```bash
# Remove existing environment
rm -rf /Users/seifreed/tools/malware/surinort-ast/venv

# Create fresh environment
python3.14 -m venv /Users/seifreed/tools/malware/surinort-ast/venv

# Reinstall dependencies
/Users/seifreed/tools/malware/surinort-ast/venv/bin/pip install -r requirements-dev.txt
```

### Python Version Mismatch

If you need a different Python version:

```bash
# Example: Using Python 3.13
python3.13 -m venv /Users/seifreed/tools/malware/surinort-ast/venv
```

## Configuration Files

The following files control environment behavior:

- `.python-version` - Specifies required Python version (3.14.0)
- `.envrc` - direnv configuration for automatic activation
- `requirements.txt` - Production dependencies
- `requirements-dev.txt` - Development dependencies
- `verify_venv.py` - Comprehensive environment validation script
- `activate_venv.sh` - Manual activation helper

## License Notice

All environment management scripts and configurations in this project are licensed under GNU GPL v3.

Any modifications or derivative works must:
1. Attribute authorship to Marc Rivero López
2. Be distributed under the same GPLv3 license
3. Publish modified scripts if redistributed

---

**Created**: 2025-10-29
**Python Version**: 3.14.0
**Environment**: darwin (macOS)
