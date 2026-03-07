"""
SARIF serializer entry points.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import json

from ...analysis.findings import Finding
from ...exceptions import SerializationError
from .mapper import findings_to_sarif_log


def to_sarif_log(findings: list[Finding]) -> dict[str, object]:
    """Serialize findings to SARIF log dictionary."""
    try:
        log = findings_to_sarif_log(findings)
        return log.to_dict()
    except Exception as e:
        raise SerializationError(f"Failed to serialize to SARIF log: {e}") from e


def to_sarif_json(findings: list[Finding], indent: int | None = 2) -> str:
    """Serialize findings to SARIF JSON text."""
    try:
        return json.dumps(to_sarif_log(findings), indent=indent)
    except Exception as e:
        raise SerializationError(f"Failed to serialize to SARIF JSON: {e}") from e


__all__ = ["to_sarif_json", "to_sarif_log"]
