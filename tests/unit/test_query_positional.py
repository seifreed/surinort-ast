"""
Tests for positional query pseudo-selectors.

Covers the two positional families:

- Result-set (jQuery-style): ``:first``, ``:last``, ``:even``, ``:odd``,
  ``:nth(n)``, ``:within(n)`` narrow the ordered list of matched nodes.
- Child-position (CSS-style): ``:first-child``, ``:last-child`` test whether a
  node is the first/last child of its parent.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

import pytest

from surinort_ast import parse_rule
from surinort_ast.query import QueryResult, QuerySyntaxError, query, query_first


def _patterns(nodes):
    """Decoded content patterns for the matched ContentOption nodes."""
    return [node.pattern.decode() for node in nodes]


@pytest.fixture
def three_contents():
    """A rule whose options contain three ordered content patterns."""
    return parse_rule('alert tcp any any -> any 80 (content:"x"; content:"y"; content:"z"; sid:1;)')


class TestResultSetPseudoSelectors:
    """jQuery-style selection from the ordered set of matched nodes."""

    def test_first_selects_single_match(self, three_contents):
        assert _patterns(query(three_contents, "ContentOption:first")) == ["x"]

    def test_last_selects_single_match(self, three_contents):
        assert _patterns(query(three_contents, "ContentOption:last")) == ["z"]

    def test_nth_selects_by_zero_based_index(self, three_contents):
        assert _patterns(query(three_contents, "ContentOption:nth(0)")) == ["x"]
        assert _patterns(query(three_contents, "ContentOption:nth(1)")) == ["y"]
        assert _patterns(query(three_contents, "ContentOption:nth(2)")) == ["z"]

    def test_nth_out_of_range_matches_nothing(self, three_contents):
        assert query(three_contents, "ContentOption:nth(3)") == []

    def test_even_selects_even_result_indices(self, three_contents):
        assert _patterns(query(three_contents, "ContentOption:even")) == ["x", "z"]

    def test_odd_selects_odd_result_indices(self, three_contents):
        assert _patterns(query(three_contents, "ContentOption:odd")) == ["y"]

    def test_within_selects_first_n_matches(self, three_contents):
        assert _patterns(query(three_contents, "ContentOption:within(2)")) == ["x", "y"]

    def test_within_zero_matches_nothing(self, three_contents):
        assert query(three_contents, "ContentOption:within(0)") == []

    def test_first_on_bare_pseudo_returns_root(self, three_contents):
        results = query(three_contents, ":first")
        assert len(results) == 1
        assert results[0].node_type == "Rule"

    def test_last_on_bare_pseudo_returns_final_node(self, three_contents):
        results = query(three_contents, ":last")
        assert len(results) == 1
        assert results[0].node_type == "SidOption"

    def test_first_does_not_confuse_value_equal_siblings(self):
        """Two ``any`` addresses must not both count as the first address."""
        rule = parse_rule("alert tcp any any -> any any (sid:1;)")
        # Four address/port slots are all "any"; :first keeps exactly one node.
        assert len(query(rule, "AnyAddress:first")) == 1
        assert len(query(rule, "AnyAddress")) == 2

    def test_query_first_applies_result_set_narrowing(self, three_contents):
        node = query_first(three_contents, "ContentOption:last")
        assert node is not None
        assert node.pattern.decode() == "z"


class TestChildPositionPseudoSelectors:
    """CSS-style :first-child / :last-child per-node position tests."""

    def test_header_is_first_child_of_rule(self, three_contents):
        assert len(query(three_contents, "Header:first-child")) == 1

    def test_option_is_never_first_child_of_rule(self, three_contents):
        # The Header always precedes the options, so no option is first-child.
        assert query(three_contents, "ContentOption:first-child") == []

    def test_last_option_is_last_child(self):
        rule = parse_rule('alert tcp any any -> any 80 (msg:"m"; sid:1;)')
        results = query(rule, "Rule > SidOption:last-child")
        assert len(results) == 1
        assert results[0].node_type == "SidOption"

    def test_non_last_option_is_not_last_child(self):
        rule = parse_rule('alert tcp any any -> any 80 (msg:"m"; sid:1;)')
        assert query(rule, "Rule > MsgOption:last-child") == []


class TestResultSetFilterOnQueryResult:
    """QueryResult.filter() applies result-set narrowing to a collected set."""

    def test_filter_first(self, three_contents):
        contents = QueryResult(query(three_contents, "ContentOption"))
        assert _patterns(contents.filter("ContentOption:first").nodes) == ["x"]

    def test_filter_nth(self, three_contents):
        contents = QueryResult(query(three_contents, "ContentOption"))
        assert _patterns(contents.filter(":nth(2)").nodes) == ["z"]


class TestPositionalParsing:
    """Grammar/parser handling of index-argument pseudo-functions."""

    def test_nth_requires_integer(self, three_contents):
        with pytest.raises(QuerySyntaxError):
            query(three_contents, "ContentOption:nth(1.5)")

    def test_within_requires_integer(self, three_contents):
        with pytest.raises(QuerySyntaxError):
            query(three_contents, "ContentOption:within(2.0)")
