"""
Rule-conflict detection for surinort-ast.

Detects duplicate SIDs, conflicting actions, shadowing, overlapping, and missing
flowbits dependencies across a set of IDS/IPS rules. The public entry point is
:func:`detect_conflicts`.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from .detector import ConflictDetector, detect_conflicts, filter_conflicts
from .models import (
    Conflict,
    ConflictDetectorConfig,
    ConflictReport,
    ConflictType,
    Severity,
)

__all__ = [
    "Conflict",
    "ConflictDetector",
    "ConflictDetectorConfig",
    "ConflictReport",
    "ConflictType",
    "Severity",
    "detect_conflicts",
    "filter_conflicts",
]
