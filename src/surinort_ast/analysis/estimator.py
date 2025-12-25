"""
Performance estimation for IDS rules.

Estimates the computational cost of rule evaluation based on option types
and complexity. Used to quantify optimization improvements.

Copyright (c) Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, cast

if TYPE_CHECKING:
    from ..core.nodes import ContentOption, Option, PcreOption, Rule


class PerformanceEstimator:
    """
    Estimates rule evaluation performance cost.

    Assigns computational cost weights to different option types based on
    their typical evaluation overhead in IDS engines like Suricata and Snort.

    Cost units are arbitrary but relative to each other, allowing comparison
    of rules before and after optimization.
    """

    # Base cost weights (arbitrary units)
    # Based on typical IDS engine evaluation overhead
    BASE_COSTS: ClassVar[dict[str, float]] = {
        # Very fast checks
        "FlowOption": 1.0,
        "FlowbitsOption": 1.5,
        "GidOption": 0.1,
        "SidOption": 0.1,
        "RevOption": 0.1,
        "MsgOption": 0.1,
        "ClasstypeOption": 0.1,
        "PriorityOption": 0.1,
        "ReferenceOption": 0.1,
        "MetadataOption": 0.1,
        # Fast pattern matching
        "ContentOption": 10.0,
        "FastPatternOption": 0.5,  # Optimization hint, minimal cost
        # Medium complexity
        "ByteTestOption": 20.0,
        "ByteJumpOption": 15.0,
        "ByteExtractOption": 18.0,
        "BufferSelectOption": 5.0,
        # Expensive operations
        "PcreOption": 100.0,  # PCRE is expensive
        # Modifiers (applied after base cost)
        "ThresholdOption": 2.0,
        "DetectionFilterOption": 2.0,
        "TagOption": 3.0,
        "FilestoreOption": 5.0,
        # Position modifiers (standalone options)
        "DepthOption": 0.5,
        "OffsetOption": 0.5,
        "DistanceOption": 0.5,
        "WithinOption": 0.5,
        "NocaseOption": 0.2,
        "RawbytesOption": 0.3,
        "StartswithOption": 0.3,
        "EndswithOption": 0.3,
        # Generic fallback
        "GenericOption": 5.0,
    }

    # Multipliers for content option modifiers
    CONTENT_MODIFIER_MULTIPLIERS: ClassVar[dict[str, float]] = {
        "nocase": 1.5,  # Case-insensitive matching is slower
        "depth": 0.9,  # Limits search space
        "offset": 0.9,  # Limits search space
        "distance": 0.95,  # Relative positioning
        "within": 0.95,  # Limits search window
        "fast_pattern": 0.7,  # Optimization hint reduces cost
        "rawbytes": 1.1,  # Additional processing
        "startswith": 0.8,  # Anchor reduces search
        "endswith": 0.8,  # Anchor reduces search
    }

    # PCRE complexity multipliers
    PCRE_FLAG_MULTIPLIERS: ClassVar[dict[str, float]] = {
        "i": 1.3,  # Case insensitive
        "s": 1.1,  # Dot matches newline
        "m": 1.1,  # Multiline
        "x": 1.0,  # Extended (comments, no perf impact)
        "U": 1.2,  # Ungreedy
        "R": 1.4,  # Relative matching
        "B": 1.3,  # PCRE body inspection
    }

    def estimate_cost(self, rule: Rule) -> float:
        """
        Estimate total computational cost for rule evaluation.

        Args:
            rule: Rule to estimate

        Returns:
            Estimated cost in arbitrary units (higher = slower)

        Example:
            >>> estimator = PerformanceEstimator()
            >>> cost = estimator.estimate_cost(rule)
            >>> print(f"Rule cost: {cost:.2f} units")
        """
        total_cost = 0.0

        # Track previous content option to apply following modifier costs
        prev_content: ContentOption | None = None

        for option in rule.options:
            option_type = option.node_type

            # Position modifiers and fast_pattern apply to the previous content option
            if (
                option_type
                in [
                    "DepthOption",
                    "OffsetOption",
                    "DistanceOption",
                    "WithinOption",
                    "FastPatternOption",
                ]
                and prev_content is not None
            ):
                # Apply multiplier to previous content option
                if option_type == "FastPatternOption":
                    modifier_name = "fast_pattern"
                else:
                    modifier_name = option_type.replace("Option", "").lower()
                multiplier = self.CONTENT_MODIFIER_MULTIPLIERS.get(modifier_name, 1.0)
                # Adjust total cost by applying modifier retroactively
                prev_content_base = self.BASE_COSTS["ContentOption"]
                # Subtract original content cost, add modified cost
                total_cost -= prev_content_base
                total_cost += prev_content_base * multiplier
            else:
                # Regular option cost
                total_cost += self._estimate_option_cost(option)

            # Track content options for following modifiers
            if option_type == "ContentOption":
                prev_content = cast("ContentOption", option)
            elif option_type not in [
                "DepthOption",
                "OffsetOption",
                "DistanceOption",
                "WithinOption",
                "NocaseOption",
                "RawbytesOption",
                "StartswithOption",
                "EndswithOption",
                "FastPatternOption",
            ]:
                # Non-modifier option breaks the content chain
                prev_content = None

        return total_cost

    def _estimate_option_cost(self, option: Option) -> float:
        """
        Estimate cost for a single option.

        Args:
            option: Option to estimate

        Returns:
            Estimated cost
        """
        option_type = option.node_type
        base_cost = self.BASE_COSTS.get(option_type, 5.0)

        # Apply specific logic for different option types
        # Runtime type check ensures safe casting - node_type is a discriminator
        if option_type == "ContentOption":
            return self._estimate_content_cost(cast("ContentOption", option))
        if option_type == "PcreOption":
            return self._estimate_pcre_cost(cast("PcreOption", option))
        return base_cost

    def _estimate_content_cost(self, content: ContentOption) -> float:
        """
        Estimate cost for content matching with modifiers.

        Args:
            content: ContentOption to estimate

        Returns:
            Estimated cost
        """
        base_cost = self.BASE_COSTS["ContentOption"]

        # Pattern length affects performance
        # Longer patterns are more distinctive but require more comparison
        pattern_len = len(content.pattern)
        if pattern_len > 20:
            base_cost *= 1.2
        elif pattern_len < 4:
            base_cost *= 1.3  # Short patterns match more often

        # Apply modifier multipliers
        multiplier = 1.0
        for modifier in content.modifiers:
            mod_name = (
                modifier.name.value if hasattr(modifier.name, "value") else str(modifier.name)
            )
            mod_mult = self.CONTENT_MODIFIER_MULTIPLIERS.get(mod_name, 1.0)
            multiplier *= mod_mult

        return base_cost * multiplier

    def _estimate_pcre_cost(self, pcre: PcreOption) -> float:
        """
        Estimate cost for PCRE matching.

        Args:
            pcre: PcreOption to estimate

        Returns:
            Estimated cost
        """
        base_cost = self.BASE_COSTS["PcreOption"]

        # Pattern complexity
        pattern_len = len(pcre.pattern)
        if pattern_len > 50:
            base_cost *= 1.5
        elif pattern_len > 100:
            base_cost *= 2.0

        # Detect expensive constructs
        if any(construct in pcre.pattern for construct in [".*", ".+", ".*?", ".+?"]):
            base_cost *= 1.4  # Greedy/lazy wildcards

        if "|" in pcre.pattern:
            # Alternation increases complexity
            alternations = pcre.pattern.count("|")
            base_cost *= 1.0 + (alternations * 0.1)

        if "(?:" in pcre.pattern or "(?=" in pcre.pattern or "(?!" in pcre.pattern:
            # Lookahead/lookbehind and non-capturing groups
            base_cost *= 1.3

        # Apply flag multipliers
        multiplier = 1.0
        for flag in pcre.flags:
            flag_mult = self.PCRE_FLAG_MULTIPLIERS.get(flag, 1.0)
            multiplier *= flag_mult

        return base_cost * multiplier

    def estimate_improvement(self, original: Rule, optimized: Rule) -> float:
        """
        Calculate estimated performance improvement percentage.

        Args:
            original: Original rule
            optimized: Optimized rule

        Returns:
            Improvement percentage (positive = better, negative = worse)

        Example:
            >>> improvement = estimator.estimate_improvement(original, optimized)
            >>> print(f"Expected improvement: {improvement:.1f}%")
        """
        original_cost = self.estimate_cost(original)
        optimized_cost = self.estimate_cost(optimized)

        if original_cost == 0:
            return 0.0

        return ((original_cost - optimized_cost) / original_cost) * 100.0

    def estimate_position_penalty(self, options: list[Option]) -> float:
        """
        Estimate penalty from suboptimal option ordering.

        Fast options should come first to enable early rejection.
        This estimates the cost of evaluating options in the given order.

        Args:
            options: List of options in current order

        Returns:
            Penalty score (0.0 = optimal, higher = worse)
        """
        penalty = 0.0
        cumulative_cost = 0.0

        for i, option in enumerate(options):
            option_cost = self._estimate_option_cost(option)

            # Expensive options late in the chain are good (low penalty)
            # Expensive options early in the chain are bad (high penalty)
            # Weight by position: early positions matter more
            position_weight = 1.0 / (i + 1)

            # High cost early = high penalty
            cumulative_cost += option_cost
            penalty += option_cost * position_weight

        return penalty

    def get_cost_breakdown(self, rule: Rule) -> dict[str, float]:
        """
        Get detailed cost breakdown by option type.

        Args:
            rule: Rule to analyze

        Returns:
            Dictionary mapping option type to total cost

        Example:
            >>> breakdown = estimator.get_cost_breakdown(rule)
            >>> for opt_type, cost in sorted(breakdown.items(), key=lambda x: -x[1]):
            ...     print(f"{opt_type}: {cost:.2f}")
        """
        breakdown: dict[str, float] = {}

        for option in rule.options:
            option_type = option.node_type
            cost = self._estimate_option_cost(option)

            if option_type in breakdown:
                breakdown[option_type] += cost
            else:
                breakdown[option_type] = cost

        return breakdown
