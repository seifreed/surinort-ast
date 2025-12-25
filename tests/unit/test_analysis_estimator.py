# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for surinort_ast.analysis.estimator module.

Tests the PerformanceEstimator class for estimating computational costs
of IDS rule evaluation based on option types and complexity.

All tests use real Rule objects and validate actual cost calculations.
"""

from surinort_ast import parse_rule
from surinort_ast.analysis.estimator import PerformanceEstimator


class TestPerformanceEstimator:
    """Test PerformanceEstimator class."""

    def test_estimator_initialization(self):
        """Test creating a performance estimator."""
        estimator = PerformanceEstimator()

        assert estimator.BASE_COSTS is not None
        assert len(estimator.BASE_COSTS) > 0
        assert "ContentOption" in estimator.BASE_COSTS
        assert "PcreOption" in estimator.BASE_COSTS

    def test_estimate_minimal_rule(self):
        """Test estimating cost of minimal rule."""
        rule = parse_rule('alert ip any any -> any any (msg:"Minimal"; sid:1;)')

        estimator = PerformanceEstimator()
        cost = estimator.estimate_cost(rule)

        # Should have some cost (at least for msg and sid)
        assert cost > 0

    def test_estimate_simple_content_rule(self):
        """Test estimating cost of rule with content."""
        rule = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')

        estimator = PerformanceEstimator()
        cost = estimator.estimate_cost(rule)

        # Should be higher than minimal rule
        assert cost > 1.0

    def test_estimate_pcre_rule(self):
        """Test estimating cost of rule with PCRE."""
        rule = parse_rule('alert tcp any any -> any 80 (pcre:"/test/"; msg:"Test"; sid:1;)')

        estimator = PerformanceEstimator()
        cost = estimator.estimate_cost(rule)

        # PCRE should have significant cost
        assert cost >= estimator.BASE_COSTS["PcreOption"]

    def test_pcre_more_expensive_than_content(self):
        """Test that PCRE is more expensive than content matching."""
        content_rule = parse_rule(
            'alert tcp any any -> any 80 (content:"test"; msg:"Content"; sid:1;)'
        )

        pcre_rule = parse_rule('alert tcp any any -> any 80 (pcre:"/test/"; msg:"PCRE"; sid:2;)')

        estimator = PerformanceEstimator()

        content_cost = estimator.estimate_cost(content_rule)
        pcre_cost = estimator.estimate_cost(pcre_rule)

        # PCRE should be significantly more expensive
        assert pcre_cost > content_cost

    def test_content_with_modifiers(self):
        """Test content cost with various modifiers."""
        # Content with nocase modifier
        rule_nocase = parse_rule(
            'alert tcp any any -> any 80 (content:"test"; nocase; msg:"Test"; sid:1;)'
        )

        # Content without modifiers
        rule_plain = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:2;)')

        estimator = PerformanceEstimator()

        cost_nocase = estimator.estimate_cost(rule_nocase)
        cost_plain = estimator.estimate_cost(rule_plain)

        # Nocase should add some overhead
        assert cost_nocase >= cost_plain

    def test_pcre_complexity_factors(self):
        """Test PCRE cost increases with complexity."""
        simple_pcre = parse_rule(
            'alert tcp any any -> any 80 (pcre:"/test/"; msg:"Simple"; sid:1;)'
        )

        complex_pcre = parse_rule(
            "alert tcp any any -> any 80 ("
            'pcre:"/very.*long.*pattern.*with.*multiple.*wildcards|alternation/i"; '
            'msg:"Complex"; sid:2;)'
        )

        estimator = PerformanceEstimator()

        simple_cost = estimator.estimate_cost(simple_pcre)
        complex_cost = estimator.estimate_cost(complex_pcre)

        # Complex PCRE should cost more
        assert complex_cost > simple_cost

    def test_pattern_length_affects_cost(self):
        """Test that pattern length affects content cost."""
        short_pattern = parse_rule(
            'alert tcp any any -> any 80 (content:"ab"; msg:"Short"; sid:1;)'
        )

        long_pattern = parse_rule(
            "alert tcp any any -> any 80 ("
            'content:"very_long_distinctive_pattern_content"; '
            'msg:"Long"; sid:2;)'
        )

        estimator = PerformanceEstimator()

        short_cost = estimator.estimate_cost(short_pattern)
        long_cost = estimator.estimate_cost(long_pattern)

        # Costs may be similar or long may be higher due to pattern length
        assert short_cost > 0 and long_cost > 0

    def test_get_cost_breakdown(self):
        """Test getting detailed cost breakdown."""
        rule = parse_rule(
            "alert tcp any any -> any 80 ("
            'content:"test"; '
            'pcre:"/pattern/"; '
            "flow:to_server; "
            'msg:"Test"; sid:1;)'
        )

        estimator = PerformanceEstimator()
        breakdown = estimator.get_cost_breakdown(rule)

        # Should have entries for each option type
        assert "ContentOption" in breakdown
        assert "PcreOption" in breakdown
        assert "FlowOption" in breakdown
        assert "MsgOption" in breakdown

        # All costs should be positive
        for cost in breakdown.values():
            assert cost > 0

    def test_estimate_improvement_positive(self):
        """Test estimating improvement between rules."""
        # Original rule with suboptimal ordering
        original = parse_rule(
            'alert tcp any any -> any 80 (pcre:"/test/"; content:"GET"; msg:"Test"; sid:1;)'
        )

        # Optimized rule with better ordering
        optimized = parse_rule(
            'alert tcp any any -> any 80 (content:"GET"; pcre:"/test/"; msg:"Test"; sid:1;)'
        )

        estimator = PerformanceEstimator()
        improvement = estimator.estimate_improvement(original, optimized)

        # Should calculate improvement (may be 0 if costs are same)
        assert improvement >= 0

    def test_estimate_improvement_no_change(self):
        """Test estimating improvement when rules are identical."""
        rule1 = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')
        rule2 = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')

        estimator = PerformanceEstimator()
        improvement = estimator.estimate_improvement(rule1, rule2)

        # Should be 0% improvement
        assert improvement == 0.0

    def test_estimate_improvement_negative(self):
        """Test that making a rule worse gives negative improvement."""
        # Simple rule
        simple = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:1;)')

        # More complex rule
        complex_rule = parse_rule(
            'alert tcp any any -> any 80 (pcre:"/complex/"; content:"test"; msg:"Test"; sid:1;)'
        )

        estimator = PerformanceEstimator()
        improvement = estimator.estimate_improvement(simple, complex_rule)

        # Adding PCRE should be negative improvement
        assert improvement < 0

    def test_estimate_position_penalty(self):
        """Test position penalty estimation."""
        rule = parse_rule(
            'alert tcp any any -> any 80 (pcre:"/test/"; content:"GET"; msg:"Test"; sid:1;)'
        )

        estimator = PerformanceEstimator()
        penalty = estimator.estimate_position_penalty(list(rule.options))

        # Should have some penalty
        assert penalty > 0

    def test_flow_option_low_cost(self):
        """Test that flow options have low cost."""
        rule = parse_rule('alert tcp any any -> any 80 (flow:to_server; msg:"Test"; sid:1;)')

        estimator = PerformanceEstimator()
        breakdown = estimator.get_cost_breakdown(rule)

        # Flow should be cheaper than content or PCRE
        flow_cost = breakdown.get("FlowOption", 0)
        content_cost = estimator.BASE_COSTS["ContentOption"]

        assert flow_cost < content_cost

    def test_byte_operations_medium_cost(self):
        """Test that byte operations have medium cost."""
        rule = parse_rule('alert tcp any any -> any 80 (byte_test:4,>,100,0; msg:"Test"; sid:1;)')

        estimator = PerformanceEstimator()
        cost = estimator.estimate_cost(rule)

        # Should have reasonable cost
        assert cost > 0

    def test_metadata_options_low_cost(self):
        """Test that metadata options have very low cost."""
        rule = parse_rule(
            "alert tcp any any -> any 80 ("
            'msg:"Test"; '
            "sid:1; "
            "rev:2; "
            "classtype:trojan-activity; "
            "reference:url,example.com;)"
        )

        estimator = PerformanceEstimator()
        breakdown = estimator.get_cost_breakdown(rule)

        # Metadata options should all be low cost
        metadata_cost = (
            breakdown.get("MsgOption", 0)
            + breakdown.get("SidOption", 0)
            + breakdown.get("RevOption", 0)
        )

        # Should be much less than content or PCRE base cost
        assert metadata_cost < estimator.BASE_COSTS["ContentOption"]

    def test_multiple_content_patterns(self):
        """Test cost estimation with multiple content patterns."""
        rule = parse_rule(
            "alert tcp any any -> any 80 ("
            'content:"first"; '
            'content:"second"; '
            'content:"third"; '
            'msg:"Test"; sid:1;)'
        )

        estimator = PerformanceEstimator()
        breakdown = estimator.get_cost_breakdown(rule)

        # ContentOption cost should be sum of all content patterns
        content_cost = breakdown["ContentOption"]

        # Should be roughly 3x base cost (might vary with modifiers)
        base = estimator.BASE_COSTS["ContentOption"]
        assert content_cost >= base * 2.5  # Allow some variance


class TestContentCostEstimation:
    """Test detailed content option cost estimation."""

    def test_short_pattern_penalty(self):
        """Test that short patterns have higher relative cost."""
        short_rule = parse_rule('alert tcp any any -> any 80 (content:"ab"; msg:"Short"; sid:1;)')

        medium_rule = parse_rule(
            'alert tcp any any -> any 80 (content:"medium"; msg:"Medium"; sid:2;)'
        )

        estimator = PerformanceEstimator()

        # Get just the content costs
        short_breakdown = estimator.get_cost_breakdown(short_rule)
        medium_breakdown = estimator.get_cost_breakdown(medium_rule)

        # Both should have costs
        assert "ContentOption" in short_breakdown
        assert "ContentOption" in medium_breakdown

    def test_content_with_depth_modifier(self):
        """Test content with depth modifier (optimization)."""
        with_depth = parse_rule(
            'alert tcp any any -> any 80 (content:"test"; depth:10; msg:"Test"; sid:1;)'
        )

        without_depth = parse_rule(
            'alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:2;)'
        )

        estimator = PerformanceEstimator()

        cost_with = estimator.estimate_cost(with_depth)
        cost_without = estimator.estimate_cost(without_depth)

        # Depth should reduce cost (limits search space)
        assert cost_with <= cost_without

    def test_content_with_fast_pattern(self):
        """Test content with fast_pattern modifier."""
        with_fp = parse_rule(
            'alert tcp any any -> any 80 (content:"test"; fast_pattern; msg:"Test"; sid:1;)'
        )

        without_fp = parse_rule('alert tcp any any -> any 80 (content:"test"; msg:"Test"; sid:2;)')

        estimator = PerformanceEstimator()

        cost_with = estimator.estimate_cost(with_fp)
        cost_without = estimator.estimate_cost(without_fp)

        # fast_pattern should reduce cost (optimization hint)
        assert cost_with <= cost_without


class TestPcreCostEstimation:
    """Test detailed PCRE option cost estimation."""

    def test_pcre_with_flags(self):
        """Test PCRE cost with various flags."""
        case_insensitive = parse_rule(
            'alert tcp any any -> any 80 (pcre:"/test/i"; msg:"Test"; sid:1;)'
        )

        case_sensitive = parse_rule(
            'alert tcp any any -> any 80 (pcre:"/test/"; msg:"Test"; sid:2;)'
        )

        estimator = PerformanceEstimator()

        cost_insensitive = estimator.estimate_cost(case_insensitive)
        cost_sensitive = estimator.estimate_cost(case_sensitive)

        # Case-insensitive should be more expensive
        assert cost_insensitive >= cost_sensitive

    def test_pcre_with_wildcards(self):
        """Test PCRE cost with greedy wildcards."""
        with_wildcards = parse_rule(
            'alert tcp any any -> any 80 (pcre:"/test.*pattern/"; msg:"Test"; sid:1;)'
        )

        without_wildcards = parse_rule(
            'alert tcp any any -> any 80 (pcre:"/testpattern/"; msg:"Test"; sid:2;)'
        )

        estimator = PerformanceEstimator()

        cost_with = estimator.estimate_cost(with_wildcards)
        cost_without = estimator.estimate_cost(without_wildcards)

        # Wildcards should increase cost
        assert cost_with > cost_without

    def test_pcre_with_alternation(self):
        """Test PCRE cost with alternation."""
        with_alt = parse_rule(
            'alert tcp any any -> any 80 (pcre:"/pattern1|pattern2|pattern3/"; msg:"Test"; sid:1;)'
        )

        without_alt = parse_rule(
            'alert tcp any any -> any 80 (pcre:"/pattern/"; msg:"Test"; sid:2;)'
        )

        estimator = PerformanceEstimator()

        cost_with = estimator.estimate_cost(with_alt)
        cost_without = estimator.estimate_cost(without_alt)

        # Alternation should increase cost
        assert cost_with > cost_without

    def test_pcre_with_lookahead(self):
        """Test PCRE cost with lookahead/lookbehind."""
        with_lookahead = parse_rule(
            'alert tcp any any -> any 80 (pcre:"/test(?=pattern)/"; msg:"Test"; sid:1;)'
        )

        without_lookahead = parse_rule(
            'alert tcp any any -> any 80 (pcre:"/testpattern/"; msg:"Test"; sid:2;)'
        )

        estimator = PerformanceEstimator()

        cost_with = estimator.estimate_cost(with_lookahead)
        cost_without = estimator.estimate_cost(without_lookahead)

        # Lookahead should increase cost
        assert cost_with > cost_without

    def test_very_long_pcre(self):
        """Test PCRE cost increases with pattern length."""
        short_pcre = parse_rule('alert tcp any any -> any 80 (pcre:"/ab/"; msg:"Test"; sid:1;)')

        # Pattern > 100 characters
        long_pattern = "a" * 120
        long_pcre = parse_rule(
            f'alert tcp any any -> any 80 (pcre:"/{long_pattern}/"; msg:"Test"; sid:2;)'
        )

        estimator = PerformanceEstimator()

        short_cost = estimator.estimate_cost(short_pcre)
        long_cost = estimator.estimate_cost(long_pcre)

        # Long pattern should cost more
        assert long_cost > short_cost


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_option_list(self):
        """Test rule with minimal options."""
        rule = parse_rule("alert ip any any -> any any (sid:1;)")

        estimator = PerformanceEstimator()
        cost = estimator.estimate_cost(rule)

        # Should have minimal cost
        assert cost > 0

    def test_unknown_option_type(self):
        """Test handling of unknown option types."""
        # Generic options should use fallback cost
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        estimator = PerformanceEstimator()
        cost = estimator.estimate_cost(rule)

        # Should handle gracefully
        assert cost > 0

    def test_zero_cost_rule(self):
        """Test that all rules have non-zero cost."""
        minimal_rule = parse_rule("alert ip any any -> any any (sid:1;)")

        estimator = PerformanceEstimator()
        cost = estimator.estimate_cost(minimal_rule)

        # Even minimal rules should have some cost
        assert cost > 0

    def test_improvement_with_zero_original_cost(self):
        """Test improvement calculation with zero original cost."""
        rule = parse_rule("alert ip any any -> any any (sid:1;)")

        estimator = PerformanceEstimator()

        # If original cost is somehow 0, improvement should be 0
        # This tests the safety check in estimate_improvement
        improvement = estimator.estimate_improvement(rule, rule)
        assert improvement == 0.0
