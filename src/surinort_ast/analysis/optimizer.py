"""
Rule optimizer engine.

Main orchestration for applying optimization strategies to IDS rules.
Coordinates multiple strategies and tracks improvements.

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.nodes import Rule
    from .strategies import OptimizationStrategy


@dataclass(frozen=True)
class Optimization:
    """
    Record of a single optimization applied to a rule.

    Attributes:
        strategy: Name of optimization strategy
        description: Human-readable description
        estimated_gain: Estimated performance improvement (percentage)
        before: Rule text before optimization
        after: Rule text after optimization
        details: Additional details about the optimization
    """

    strategy: str
    description: str
    estimated_gain: float
    before: str
    after: str
    details: dict[str, str | int | float] | None = None

    def __str__(self) -> str:
        """Format optimization as readable string."""
        gain_str = f"{self.estimated_gain:+.1f}%" if self.estimated_gain != 0 else "0%"
        return f"{self.strategy}: {self.description} (estimated: {gain_str})"


@dataclass
class OptimizationResult:
    """
    Result of optimizing a single rule.

    Attributes:
        original: Original rule
        optimized: Optimized rule (may be same as original)
        optimizations: List of optimizations applied
        total_improvement: Total estimated improvement percentage
        was_modified: Whether any changes were made
    """

    original: Rule
    optimized: Rule
    optimizations: list[Optimization]
    total_improvement: float
    was_modified: bool

    @property
    def strategy_names(self) -> list[str]:
        """Get list of strategy names that were applied."""
        return [opt.strategy for opt in self.optimizations]


class RuleOptimizer:
    """
    Main optimization engine for IDS rules.

    Applies multiple optimization strategies in sequence to improve rule
    performance while preserving detection logic.

    Strategies are applied in order until no more optimizations are possible
    or a maximum iteration limit is reached.

    Example:
        >>> from surinort_ast.analysis import RuleOptimizer
        >>> from surinort_ast import parse_rule
        >>>
        >>> optimizer = RuleOptimizer()
        >>> rule = parse_rule('alert tcp any any -> any 80 (pcre:"/test/"; content:"GET"; sid:1;)')
        >>> result = optimizer.optimize(rule)
        >>>
        >>> if result.was_modified:
        ...     print(f"Improvement: {result.total_improvement:.1f}%")
        ...     for opt in result.optimizations:
        ...         print(f"  - {opt}")
    """

    def __init__(
        self,
        strategies: list[OptimizationStrategy] | None = None,
        max_iterations: int = 3,
    ) -> None:
        """
        Initialize optimizer with strategies.

        Args:
            strategies: List of optimization strategies to apply.
                       If None, uses default strategies.
            max_iterations: Maximum optimization iterations per rule.
                           Prevents infinite loops.
        """
        if strategies is None:
            # Import here to avoid circular dependency
            from .strategies import (
                FastPatternStrategy,
                OptionReorderStrategy,
                RedundancyRemovalStrategy,
            )

            strategies = [
                OptionReorderStrategy(),
                FastPatternStrategy(),
                RedundancyRemovalStrategy(),
            ]

        self.strategies = strategies
        self.max_iterations = max_iterations

        # Import estimator
        from .estimator import PerformanceEstimator

        self.estimator = PerformanceEstimator()

    def optimize(self, rule: Rule) -> OptimizationResult:
        """
        Optimize a single rule.

        Applies all strategies in sequence, potentially multiple times,
        until no more improvements are found or max iterations reached.

        Args:
            rule: Rule to optimize

        Returns:
            OptimizationResult with optimized rule and applied optimizations

        Example:
            >>> result = optimizer.optimize(rule)
            >>> if result.was_modified:
            ...     print(f"Applied {len(result.optimizations)} optimizations")
        """
        original_rule = rule
        current_rule = rule
        all_optimizations: list[Optimization] = []

        # Apply strategies iteratively
        for _iteration in range(self.max_iterations):
            modified_this_iteration = False

            for strategy in self.strategies:
                optimized_rule, optimizations = strategy.apply(current_rule)

                if optimized_rule is not None:
                    # Optimization was applied
                    current_rule = optimized_rule
                    all_optimizations.extend(optimizations)
                    modified_this_iteration = True

            # If no strategy modified the rule, we're done
            if not modified_this_iteration:
                break

        # Calculate total improvement
        total_improvement = 0.0
        if all_optimizations:
            total_improvement = self.estimator.estimate_improvement(original_rule, current_rule)

        return OptimizationResult(
            original=original_rule,
            optimized=current_rule,
            optimizations=all_optimizations,
            total_improvement=total_improvement,
            was_modified=len(all_optimizations) > 0,
        )

    def optimize_ruleset(
        self,
        rules: list[Rule],
        verbose: bool = False,
    ) -> list[OptimizationResult]:
        """
        Optimize multiple rules.

        Args:
            rules: List of rules to optimize
            verbose: If True, print progress information

        Returns:
            List of OptimizationResults, one per rule

        Example:
            >>> results = optimizer.optimize_ruleset(rules)
            >>> modified = [r for r in results if r.was_modified]
            >>> print(f"Optimized {len(modified)}/{len(results)} rules")
        """
        results: list[OptimizationResult] = []

        for i, rule in enumerate(rules):
            if verbose and i % 1000 == 0:
                print(f"Optimizing rule {i + 1}/{len(rules)}...")

            result = self.optimize(rule)
            results.append(result)

        return results

    def get_statistics(
        self, results: list[OptimizationResult]
    ) -> dict[str, float | int | dict[str, int]]:
        """
        Calculate statistics from optimization results.

        Args:
            results: List of optimization results

        Returns:
            Dictionary with statistics

        Example:
            >>> stats = optimizer.get_statistics(results)
            >>> print(f"Average improvement: {stats['avg_improvement']:.1f}%")
            >>> print(f"Rules modified: {stats['modified_count']}")
        """
        if not results:
            return {
                "total_rules": 0,
                "modified_count": 0,
                "modification_rate": 0.0,
                "avg_improvement": 0.0,
                "total_improvement": 0.0,
                "max_improvement": 0.0,
                "total_optimizations": 0,
            }

        modified = [r for r in results if r.was_modified]
        improvements = [r.total_improvement for r in modified if r.total_improvement > 0]

        # Count optimizations by strategy
        strategy_counts: dict[str, int] = {}
        for result in results:
            for opt in result.optimizations:
                strategy_counts[opt.strategy] = strategy_counts.get(opt.strategy, 0) + 1

        return {
            "total_rules": len(results),
            "modified_count": len(modified),
            "modification_rate": (len(modified) / len(results)) * 100.0,
            "avg_improvement": sum(improvements) / len(improvements) if improvements else 0.0,
            "total_improvement": sum(r.total_improvement for r in results),
            "max_improvement": max(improvements) if improvements else 0.0,
            "total_optimizations": sum(len(r.optimizations) for r in results),
            "strategy_counts": strategy_counts,
        }

    def estimate_improvement(self, original: Rule, optimized: Rule) -> float:
        """
        Estimate performance improvement between two rules.

        Args:
            original: Original rule
            optimized: Optimized rule

        Returns:
            Estimated improvement percentage

        Example:
            >>> improvement = optimizer.estimate_improvement(original, optimized)
            >>> print(f"Expected speedup: {improvement:.1f}%")
        """
        return self.estimator.estimate_improvement(original, optimized)
