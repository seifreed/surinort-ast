"""
Rule analysis and optimization module.

This module provides tools for analyzing and optimizing IDS rules for
better performance without changing detection logic.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from .conflicts import (
    Conflict,
    ConflictDetector,
    ConflictDetectorConfig,
    ConflictReport,
    ConflictType,
    Severity,
    detect_conflicts,
    filter_conflicts,
)
from .coverage import CoverageAnalyzer, CoverageGap, CoverageReport
from .estimator import PerformanceEstimator
from .findings import (
    Finding,
    FindingLevel,
    FindingLocation,
    coverage_report_to_findings,
    diagnostic_to_finding,
    diagnostics_to_findings,
    optimization_results_to_findings,
)
from .optimizer import Optimization, RuleOptimizer
from .strategies import (
    FastPatternStrategy,
    OptimizationStrategy,
    OptionReorderStrategy,
    RedundancyRemovalStrategy,
)

__all__ = [
    "Conflict",
    "ConflictDetector",
    "ConflictDetectorConfig",
    "ConflictReport",
    "ConflictType",
    "CoverageAnalyzer",
    "CoverageGap",
    "CoverageReport",
    "FastPatternStrategy",
    "Finding",
    "FindingLevel",
    "FindingLocation",
    "Optimization",
    "OptimizationStrategy",
    "OptionReorderStrategy",
    "PerformanceEstimator",
    "RedundancyRemovalStrategy",
    "RuleOptimizer",
    "Severity",
    "coverage_report_to_findings",
    "detect_conflicts",
    "diagnostic_to_finding",
    "diagnostics_to_findings",
    "filter_conflicts",
    "optimization_results_to_findings",
]
