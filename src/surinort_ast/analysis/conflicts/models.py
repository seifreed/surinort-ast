"""
Data models for rule-conflict detection.

These are the result and configuration types produced and consumed by the
conflict detector. They are plain dataclasses with no detection logic.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ConflictType(str, Enum):
    """Categories of rule conflict that can be detected."""

    DUPLICATE_SID = "duplicate_sid"
    SHADOWING = "shadowing"
    OVERLAPPING = "overlapping"
    CONFLICTING_ACTION = "conflicting_action"
    MISSING_DEPENDENCY = "missing_dependency"


class Severity(str, Enum):
    """Severity levels for detected conflicts (ordered low -> high)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(severity: Severity) -> int:
    """Return a numeric rank so severities can be compared/filtered."""
    return _SEVERITY_ORDER[severity]


@dataclass(frozen=True)
class Conflict:
    """A single detected conflict between two or more rules."""

    conflict_type: ConflictType
    severity: Severity
    rule_ids: list[int]
    description: str
    explanation: str
    recommendation: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "conflict_type": self.conflict_type.value,
            "severity": self.severity.value,
            "rule_ids": list(self.rule_ids),
            "description": self.description,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "metadata": dict(self.metadata),
        }

    def to_text(self, verbose: bool = False) -> str:
        sids = ", ".join(str(sid) for sid in self.rule_ids)
        lines = [f"[{self.severity.value.upper()}] {self.conflict_type.value}: {self.description}"]
        lines.append(f"  rules: {sids}")
        if verbose:
            lines.append(f"  explanation: {self.explanation}")
            lines.append(f"  recommendation: {self.recommendation}")
            if self.metadata:
                lines.append(f"  metadata: {self.metadata}")
        return "\n".join(lines)


@dataclass
class ConflictReport:
    """The full result of a conflict-detection run."""

    total_rules: int
    conflicts: list[Conflict]
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_conflicts(self) -> int:
        return len(self.conflicts)

    @property
    def conflicts_by_type(self) -> dict[ConflictType, list[Conflict]]:
        grouped: dict[ConflictType, list[Conflict]] = {ct: [] for ct in ConflictType}
        for conflict in self.conflicts:
            grouped[conflict.conflict_type].append(conflict)
        return grouped

    @property
    def conflicts_by_severity(self) -> dict[Severity, list[Conflict]]:
        grouped: dict[Severity, list[Conflict]] = {sev: [] for sev in Severity}
        for conflict in self.conflicts:
            grouped[conflict.severity].append(conflict)
        return grouped

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_rules": self.total_rules,
            "total_conflicts": self.total_conflicts,
            "conflicts_by_type": {
                ct.value: len(items) for ct, items in self.conflicts_by_type.items()
            },
            "conflicts_by_severity": {
                sev.value: len(items) for sev, items in self.conflicts_by_severity.items()
            },
            "conflicts": [conflict.to_dict() for conflict in self.conflicts],
            "metadata": dict(self.metadata),
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def to_text(self, verbose: bool = False) -> str:
        header = (
            f"Conflict report: {self.total_conflicts} conflict(s) across {self.total_rules} rule(s)"
        )
        if not self.conflicts:
            return header + "\n  No conflicts detected."
        body = "\n".join(conflict.to_text(verbose=verbose) for conflict in self.conflicts)
        return f"{header}\n{body}"

    def to_markdown(self) -> str:
        lines = [
            "# Conflict Report",
            "",
            f"- **Rules analyzed:** {self.total_rules}",
            f"- **Conflicts found:** {self.total_conflicts}",
            "",
        ]
        if not self.conflicts:
            lines.append("No conflicts detected.")
            return "\n".join(lines)
        lines += ["| Severity | Type | Rules | Description |", "| --- | --- | --- | --- |"]
        for conflict in self.conflicts:
            sids = ", ".join(str(sid) for sid in conflict.rule_ids)
            lines.append(
                f"| {conflict.severity.value} | {conflict.conflict_type.value} "
                f"| {sids} | {conflict.description} |"
            )
        return "\n".join(lines)


@dataclass
class ConflictDetectorConfig:
    """Configuration knobs for conflict detection."""

    min_severity: Severity = Severity.INFO
    ignore_sids: set[int] = field(default_factory=set)
    enabled_detectors: set[ConflictType] | None = None
    protocol_hierarchy: bool = False
    external_flowbits: set[str] = field(default_factory=set)
    max_pairwise_bucket: int = 2000

    def is_enabled(self, conflict_type: ConflictType) -> bool:
        return self.enabled_detectors is None or conflict_type in self.enabled_detectors
