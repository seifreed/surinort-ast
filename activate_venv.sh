#!/bin/bash
# Python Environment Activation Script
# Copyright (C) Marc Rivero López
# Licensed under GNU GPL v3
# https://www.gnu.org/licenses/gpl-3.0.html

PROJECT_ROOT="/Users/seifreed/tools/malware/surinort-ast"
VENV_PATH="${PROJECT_ROOT}/venv"

if [ ! -d "$VENV_PATH" ]; then
    echo "Error: Virtual environment not found at $VENV_PATH"
    exit 1
fi

source "${VENV_PATH}/bin/activate"

echo "Virtual environment activated:"
echo "  Python: $(which python)"
echo "  Version: $(python --version)"
echo "  Pip: $(which pip)"
echo "  VIRTUAL_ENV: $VIRTUAL_ENV"
