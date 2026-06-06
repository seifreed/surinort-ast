"""Tests for indexed/streaming executors and the query cost/optimization utilities."""

from __future__ import annotations

import pytest

from surinort_ast import parse_rule
from surinort_ast.query.executor import (
    IndexedQueryExecutor,
    QueryExecutor,
    StreamingQueryExecutor,
    estimate_query_cost,
    optimize_selector_chain,
)
from surinort_ast.query.parser import QueryParser

RULE = 'alert tcp 1.2.3.4 any -> any 80 (msg:"t"; content:"a"; content:"b"; sid:1000001; rev:1;)'

SELECTORS = [
    "ContentOption",
    "Option",
    "SidOption",
    "SidOption[value>1]",
    "Rule",
    "Header",
    "Rule > Header",
    "Rule ContentOption",
    "ContentOption, SidOption",
    "*",
]


@pytest.fixture
def rule():
    return parse_rule(RULE)


@pytest.fixture
def parser():
    return QueryParser()


class TestIndexedQueryExecutor:
    @pytest.mark.parametrize("selector", SELECTORS)
    def test_identical_to_base(self, rule, parser, selector):
        chain = parser.parse(selector)
        base = QueryExecutor(chain).execute(rule)
        indexed = IndexedQueryExecutor(parser.parse(selector)).execute(rule)
        assert indexed == base

    def test_index_method_returns_self(self, rule, parser):
        ex = IndexedQueryExecutor(parser.parse("ContentOption"))
        assert ex.index(rule) is ex

    def test_index_reused_across_calls(self, rule, parser):
        ex = IndexedQueryExecutor(parser.parse("ContentOption")).index(rule)
        first = ex.execute(rule)
        second = ex.execute(rule)
        assert first == second == QueryExecutor(parser.parse("ContentOption")).execute(rule)

    def test_subclass_query_delegates_and_matches(self, rule, parser):
        # match_subclasses can't use the exact-type index; must still be correct
        from surinort_ast.query.selectors import TypeSelector

        chain_cls = parser.parse("Option")  # exact -> 0 results
        assert IndexedQueryExecutor(chain_cls).execute(rule) == []
        # build a subclass-matching chain manually
        sub_chain = parser.parse("SidOption")
        sub_chain.selectors[0] = TypeSelector("Option", match_subclasses=True)
        indexed = IndexedQueryExecutor(sub_chain).execute(rule)
        base = QueryExecutor(sub_chain).execute(rule)
        assert indexed == base
        assert len(indexed) > 0


class TestStreamingQueryExecutor:
    @pytest.mark.parametrize("selector", SELECTORS)
    def test_identical_to_base(self, rule, parser, selector):
        base = QueryExecutor(parser.parse(selector)).execute(rule)
        streamed = list(StreamingQueryExecutor(parser.parse(selector)).execute_stream(rule))
        assert streamed == base

    def test_returns_iterator(self, rule, parser):
        stream = StreamingQueryExecutor(parser.parse("ContentOption")).execute_stream(rule)
        assert iter(stream) is stream  # generator is its own iterator
        assert len(list(stream)) == 2

    def test_lazy_first_match(self, rule, parser):
        stream = StreamingQueryExecutor(parser.parse("ContentOption")).execute_stream(rule)
        first = next(stream)
        assert first.node_type == "ContentOption"


class TestEstimateQueryCost:
    def test_zero_for_non_chain(self):
        assert estimate_query_cost(object()) == 0

    def test_adding_selector_increases_cost(self, parser):
        c1 = estimate_query_cost(parser.parse("ContentOption"))
        c2 = estimate_query_cost(parser.parse("Rule ContentOption"))
        assert c2 > c1

    def test_descendant_costs_more_than_child(self, parser):
        descendant = estimate_query_cost(parser.parse("Rule ContentOption"))
        child = estimate_query_cost(parser.parse("Rule > ContentOption"))
        assert descendant > child

    def test_string_operator_costs_more_than_equality(self, parser):
        eq = estimate_query_cost(parser.parse("MsgOption[text=x]"))
        contains = estimate_query_cost(parser.parse("MsgOption[text*='x']"))
        assert contains > eq

    def test_union_sums_subchains(self, parser):
        single = estimate_query_cost(parser.parse("ContentOption"))
        union = estimate_query_cost(parser.parse("ContentOption, SidOption"))
        assert union >= single


class TestOptimizeSelectorChain:
    @pytest.mark.parametrize(
        "selector",
        [
            "Rule[action=alert]",
            "SidOption[value>1]",
            "Rule ContentOption",
            "Rule > Header[protocol=tcp]",
            "ContentOption, SidOption",
        ],
    )
    def test_preserves_result_set(self, rule, parser, selector):
        original = QueryExecutor(parser.parse(selector)).execute(rule)
        optimized = QueryExecutor(optimize_selector_chain(parser.parse(selector))).execute(rule)
        assert optimized == original

    def test_non_chain_passthrough(self):
        sentinel = object()
        assert optimize_selector_chain(sentinel) is sentinel

    def test_compound_dedup_and_reorder(self, parser):
        # A compound with a universal + a type: type is more selective and should come first.
        from surinort_ast.query.parser import SelectorChain
        from surinort_ast.query.selectors import (
            CompoundSelector,
            TypeSelector,
            UniversalSelector,
        )

        compound = CompoundSelector(
            [UniversalSelector(), TypeSelector("Rule"), TypeSelector("Rule")]
        )
        chain = SelectorChain([compound], [])
        optimized = optimize_selector_chain(chain)
        inner = optimized.selectors[0].selectors
        # duplicate TypeSelector removed (3 -> 2) and TypeSelector ordered before UniversalSelector
        assert len(inner) == 2
        assert isinstance(inner[0], TypeSelector)
        assert isinstance(inner[1], UniversalSelector)
