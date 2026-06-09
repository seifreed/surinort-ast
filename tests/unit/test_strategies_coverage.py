# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage tests for analysis/strategies.py.

Covers the order-significance relative-modifier branch, the FastPattern
no-candidate / zero-score / single-content paths, the distinctiveness scoring
penalties, and the division-by-zero guards in the reorder and redundancy gain
estimators. The guards are exercised by forcing the estimator to report a zero
penalty/cost (the only way they can be reached, since every real rule has a
positive penalty and cost).
"""

from __future__ import annotations

from surinort_ast import parse_rule
from surinort_ast.analysis.estimator import PerformanceEstimator
from surinort_ast.analysis.strategies import (
    FastPatternStrategy,
    OptionReorderStrategy,
    RedundancyRemovalStrategy,
    _is_order_significant,
)
from surinort_ast.core.nodes import (
    ContentModifier,
    ContentOption,
    FlowOption,
    GenericOption,
    SidOption,
)


def _rule_with_options(options):
    base = parse_rule('alert tcp any any -> any 80 (msg:"base"; sid:1;)')
    return base.model_copy(update={"options": options})


class TestOrderSignificance:
    def test_generic_relative_value_is_significant(self):
        opt = GenericOption(keyword="somekw", value="0,relative", raw="somekw:0,relative")
        assert _is_order_significant(opt) is True


class TestFastPatternApply:
    def test_all_negated_contents_no_candidate(self):
        rule = _rule_with_options(
            [
                ContentOption(pattern=b"aaaa", negated=True),
                ContentOption(pattern=b"bbbb", negated=True),
                SidOption(value=1),
            ]
        )

        result, opts = FastPatternStrategy().apply(rule)

        assert result is None
        assert opts == []

    def test_zero_score_contents_no_candidate(self):
        # Two empty-pattern contents score 0, so there is no good candidate.
        rule = _rule_with_options(
            [ContentOption(pattern=b""), ContentOption(pattern=b""), SidOption(value=1)]
        )

        result, opts = FastPatternStrategy().apply(rule)

        assert result is None
        assert opts == []

    def test_estimate_gain_requires_two_contents(self):
        rule = _rule_with_options([ContentOption(pattern=b"single"), SidOption(value=1)])

        assert FastPatternStrategy().estimate_gain(rule) == 0.0


class TestDistinctivenessScoring:
    def test_hex_wildcard_penalty(self):
        strategy = FastPatternStrategy()
        with_pipe = strategy._score_distinctiveness(ContentOption(pattern=b"abcd|62|efgh"))
        without_pipe = strategy._score_distinctiveness(ContentOption(pattern=b"abcdXXefgh"))
        assert with_pipe < without_pipe

    def test_nocase_penalty(self):
        strategy = FastPatternStrategy()
        content = ContentOption(pattern=b"longpattern", modifiers=(ContentModifier(name="nocase"),))
        assert strategy._score_distinctiveness(content) > 0

    def test_positional_modifier_penalty(self):
        strategy = FastPatternStrategy()
        content = ContentOption(
            pattern=b"longpattern", modifiers=(ContentModifier(name="offset", value=5),)
        )
        assert strategy._score_distinctiveness(content) > 0

    def test_fast_pattern_modifier_zero_score(self):
        strategy = FastPatternStrategy()
        content = ContentOption(
            pattern=b"longpattern", modifiers=(ContentModifier(name="fast_pattern"),)
        )
        assert strategy._score_distinctiveness(content) == 0.0


class TestGainDivisionGuards:
    def test_reorder_gain_zero_penalty(self, monkeypatch):
        rule = parse_rule('alert tcp any any -> any 80 (msg:"x"; sid:1;)')
        monkeypatch.setattr(
            PerformanceEstimator, "estimate_position_penalty", lambda self, options: 0.0
        )

        assert OptionReorderStrategy().estimate_gain(rule) == 0.0

    def test_redundancy_gain_zero_total_cost(self, monkeypatch):
        # Two identical flow options form a costed, removable duplicate; forcing
        # the total cost to zero exercises the division-by-zero guard.
        rule = _rule_with_options(
            [
                FlowOption(directions=[], states=[]),
                FlowOption(directions=[], states=[]),
                SidOption(value=1),
            ]
        )
        monkeypatch.setattr(PerformanceEstimator, "estimate_cost", lambda self, r: 0.0)

        assert RedundancyRemovalStrategy().estimate_gain(rule) == 0.0
