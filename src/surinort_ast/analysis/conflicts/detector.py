"""
Conflict-detection orchestrator.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections.abc import Iterable

from ...core.nodes import Rule
from .detectors import DETECTORS
from .index import build_index
from .models import (
    Conflict,
    ConflictDetectorConfig,
    ConflictReport,
    ConflictType,
    Severity,
    severity_rank,
)


def detect_conflicts(
    rules: Iterable[Rule], config: ConflictDetectorConfig | None = None
) -> ConflictReport:
    """Analyze a rule set and return a :class:`ConflictReport`.

    Args:
        rules: Rules to analyze, in evaluation order.
        config: Detection configuration; defaults are used when omitted.

    Returns:
        A report filtered by ``config.min_severity`` and ``config.ignore_sids``.
    """
    config = config or ConflictDetectorConfig()
    rule_list = list(rules)

    index = build_index(rule_list)
    conflicts: list[Conflict] = []
    for conflict_type, detector in DETECTORS.items():
        if config.is_enabled(conflict_type):
            conflicts.extend(detector(index, config))

    report = ConflictReport(
        total_rules=len(rule_list),
        conflicts=conflicts,
        metadata={"protocol_hierarchy": config.protocol_hierarchy},
    )
    return filter_conflicts(
        report, min_severity=config.min_severity, ignore_sids=config.ignore_sids
    )


def filter_conflicts(
    report: ConflictReport,
    min_severity: Severity = Severity.INFO,
    ignore_sids: set[int] | None = None,
) -> ConflictReport:
    """Return a report keeping only conflicts at/above a severity and not ignored."""
    ignore = ignore_sids or set()
    threshold = severity_rank(min_severity)
    kept = [
        conflict
        for conflict in report.conflicts
        if severity_rank(conflict.severity) >= threshold and not (set(conflict.rule_ids) & ignore)
    ]
    return ConflictReport(
        total_rules=report.total_rules, conflicts=kept, metadata=dict(report.metadata)
    )


class ConflictDetector:
    """Stateful façade over :func:`detect_conflicts`."""

    def __init__(self, config: ConflictDetectorConfig | None = None) -> None:
        self.config = config or ConflictDetectorConfig()

    def detect(self, rules: Iterable[Rule]) -> ConflictReport:
        return detect_conflicts(rules, self.config)


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
