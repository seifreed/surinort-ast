"""
Rule analysis and optimization module.

This module provides tools for analyzing and optimizing IDS rules for
better performance without changing detection logic.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from .coverage import CoverageAnalyzer, CoverageGap, CoverageReport
from .estimator import PerformanceEstimator
from .optimizer import Optimization, RuleOptimizer
from .strategies import (
    FastPatternStrategy,
    OptimizationStrategy,
    OptionReorderStrategy,
    RedundancyRemovalStrategy,
)

__all__ = [
    "CoverageAnalyzer",
    "CoverageGap",
    "CoverageReport",
    "FastPatternStrategy",
    "Optimization",
    "OptimizationStrategy",
    "OptionReorderStrategy",
    "PerformanceEstimator",
    "RedundancyRemovalStrategy",
    "RuleOptimizer",
]
