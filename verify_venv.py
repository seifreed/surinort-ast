#!/usr/bin/env python3
"""
Python Virtual Environment Verification Script
Copyright (C) Marc Rivero López
Licensed under GNU GPL v3
https://www.gnu.org/licenses/gpl-3.0.html
"""

import subprocess
import sys
from pathlib import Path


def verify_environment():
    """Comprehensive virtual environment verification"""

    project_root = Path("/Users/seifreed/tools/malware/surinort-ast")
    venv_path = project_root / "venv"

    print("=" * 70)
    print("PYTHON VIRTUAL ENVIRONMENT VERIFICATION")
    print("=" * 70)
    print()

    # Check 1: Virtual environment exists
    print("1. Virtual Environment Detection")
    if venv_path.exists():
        print(f"   ✓ Virtual environment found: {venv_path}")
    else:
        print(f"   ✗ Virtual environment NOT found: {venv_path}")
        return False
    print()

    # Check 2: Verify pyvenv.cfg
    print("2. Virtual Environment Configuration")
    pyvenv_cfg = venv_path / "pyvenv.cfg"
    if pyvenv_cfg.exists():
        print(f"   ✓ Configuration file exists: {pyvenv_cfg}")
        with open(pyvenv_cfg) as f:
            for line in f:
                print(f"     {line.strip()}")
    else:
        print(f"   ✗ Configuration file missing: {pyvenv_cfg}")
    print()

    # Check 3: Python interpreter validation
    print("3. Python Interpreter Validation")
    print(f"   sys.prefix: {sys.prefix}")
    print(f"   sys.base_prefix: {sys.base_prefix}")
    print(f"   sys.executable: {sys.executable}")

    if sys.prefix != sys.base_prefix:
        print("   ✓ Virtual environment is ACTIVE")
    else:
        print("   ✗ WARNING: Virtual environment NOT active")

    if str(venv_path) in sys.prefix:
        print("   ✓ Using project-local virtual environment")
    else:
        print("   ✗ WARNING: Not using project venv")
    print()

    # Check 4: Site packages isolation
    print("4. Site Packages Isolation")
    print(f"   ENABLE_USER_SITE: {sys.flags.no_user_site}")
    print("   sys.path entries:")
    for path in sys.path:
        marker = "   → " if "venv" in path else "     "
        print(f"{marker}{path}")
    print()

    # Check 5: Python version
    print("5. Python Version")
    print(f"   ✓ Version: {sys.version}")
    print(
        f"   ✓ Version info: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    print()

    # Check 6: Pip validation
    print("6. Pip Package Manager")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "--version"], capture_output=True, text=True, check=True
        )
        print(f"   ✓ {result.stdout.strip()}")
    except subprocess.CalledProcessError as e:
        print(f"   ✗ Pip error: {e}")
    print()

    # Check 7: Installed packages
    print("7. Installed Packages")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=freeze"],
            capture_output=True,
            text=True,
            check=True,
        )
        packages = result.stdout.strip().split("\n")
        print(f"   Total packages: {len(packages)}")
        for pkg in packages:
            print(f"     - {pkg}")
    except subprocess.CalledProcessError as e:
        print(f"   ✗ Error listing packages: {e}")
    print()

    # Check 8: Binary paths
    print("8. Binary Path Verification")
    python_bin = venv_path / "bin" / "python"
    pip_bin = venv_path / "bin" / "pip"
    print(f"   Python binary: {python_bin} - {'✓ exists' if python_bin.exists() else '✗ missing'}")
    print(f"   Pip binary: {pip_bin} - {'✓ exists' if pip_bin.exists() else '✗ missing'}")
    print()

    print("=" * 70)
    print("VERIFICATION COMPLETE")
    print("=" * 70)

    return True


if __name__ == "__main__":
    verify_environment()
