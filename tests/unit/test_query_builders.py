"""Tests for the query selector factory, subclass matching, QueryResult, and Q builder."""

from __future__ import annotations

import pytest

from surinort_ast import parse_rule
from surinort_ast.query import (
    InvalidSelectorError,
    Q,
    QueryResult,
    QuerySyntaxError,
    create_selector,
    query,
)
from surinort_ast.query.selectors import (
    AttributeSelector,
    CompoundSelector,
    PseudoSelector,
    TypeSelector,
    UnionSelector,
    UniversalSelector,
)

RULE_TEXT = 'alert tcp any any -> any 80 (msg:"t"; content:"admin"; sid:1000001; rev:1;)'


@pytest.fixture
def rule():
    return parse_rule(RULE_TEXT)


class TestCreateSelector:
    def test_type(self):
        sel = create_selector("type", type_name="Rule")
        assert isinstance(sel, TypeSelector)
        assert sel.type_name == "Rule"
        assert sel.match_subclasses is False

    def test_type_with_subclasses(self):
        sel = create_selector("type", type_name="Option", match_subclasses=True)
        assert isinstance(sel, TypeSelector)
        assert sel.match_subclasses is True

    def test_universal(self):
        assert isinstance(create_selector("universal"), UniversalSelector)

    def test_attribute(self):
        sel = create_selector("attribute", attribute="value", operator=">", value=1)
        assert isinstance(sel, AttributeSelector)
        assert sel.attribute == "value"
        assert sel.operator == ">"
        assert sel.value == 1

    def test_compound(self):
        inner = [TypeSelector("Rule"), AttributeSelector("action", "=", "alert")]
        sel = create_selector("compound", selectors=inner)
        assert isinstance(sel, CompoundSelector)

    def test_union(self):
        inner = [TypeSelector("ContentOption"), TypeSelector("PcreOption")]
        assert isinstance(create_selector("union", selectors=inner), UnionSelector)

    def test_pseudo(self):
        assert isinstance(create_selector("pseudo", pseudo_type="first"), PseudoSelector)

    def test_unknown_type_raises(self):
        with pytest.raises(InvalidSelectorError):
            create_selector("bogus")

    def test_missing_required_kwargs_raises(self):
        with pytest.raises(InvalidSelectorError):
            create_selector("type")
        with pytest.raises(InvalidSelectorError):
            create_selector("attribute", attribute="value")  # missing operator
        with pytest.raises(InvalidSelectorError):
            create_selector("pseudo")

    def test_invalid_pseudo_type_raises(self):
        with pytest.raises(InvalidSelectorError):
            create_selector("pseudo", pseudo_type="not-a-pseudo")

    def test_invalid_operator_raises(self):
        with pytest.raises(InvalidSelectorError):
            create_selector("attribute", attribute="value", operator="~~")


class TestSubclassMatching:
    def test_exact_does_not_match_base(self, rule):
        sid = query(rule, "SidOption")[0]
        assert TypeSelector("Option").matches(sid) is False

    def test_subclass_matches_base(self, rule):
        sid = query(rule, "SidOption")[0]
        assert TypeSelector("Option", match_subclasses=True).matches(sid) is True

    def test_subclass_address_hierarchy(self, rule):
        # Header src_addr is an AddressExpr subclass (AnyAddress here)
        addr = rule.header.src_addr
        assert TypeSelector("AddressExpr", match_subclasses=True).matches(addr) is True
        assert TypeSelector("AddressExpr").matches(addr) is False

    def test_unknown_type_name_falls_back_to_exact(self, rule):
        sid = query(rule, "SidOption")[0]
        sel = TypeSelector("DefinitelyNotARealType", match_subclasses=True)
        assert sel.matches(sid) is False

    def test_subclass_flag_in_equality_and_hash(self):
        a = TypeSelector("Option", match_subclasses=True)
        b = TypeSelector("Option", match_subclasses=True)
        c = TypeSelector("Option", match_subclasses=False)
        assert a == b
        assert a != c
        assert hash(a) == hash(b)


class TestQueryResult:
    def test_basic_accessors(self, rule):
        res = QueryResult(query(rule, "ContentOption, SidOption"), root=rule)
        assert res.count() == 2
        assert len(res) == 2
        assert res.exists() is True
        assert res.first().node_type == "ContentOption"
        assert res.last().node_type == "SidOption"
        assert res[0].node_type == "ContentOption"
        assert [n.node_type for n in res] == ["ContentOption", "SidOption"]
        assert len(res.nodes) == 2

    def test_empty(self):
        res = QueryResult([])
        assert res.count() == 0
        assert res.exists() is False
        assert res.first() is None
        assert res.last() is None

    def test_filter_narrows(self, rule):
        res = QueryResult(query(rule, "ContentOption, SidOption"), root=rule)
        filtered = res.filter("SidOption")
        assert filtered.count() == 1
        assert filtered.first().node_type == "SidOption"

    def test_filter_attribute(self, rule):
        res = QueryResult(query(rule, "SidOption"), root=rule)
        assert res.filter("SidOption[value=1000001]").exists() is True
        assert res.filter("SidOption[value=999]").exists() is False

    def test_filter_rejects_combinators(self, rule):
        res = QueryResult(query(rule, "SidOption"))
        with pytest.raises(QuerySyntaxError):
            res.filter("Rule > Header")

    def test_repr(self):
        assert "2 nodes" in repr(QueryResult([object(), object()]))  # type: ignore[list-item]


class TestQBuilder:
    def test_simple_type(self):
        assert Q("Rule").build() == "Rule"

    def test_with_attr_equals(self):
        assert Q("Rule").with_attr("action", "alert").build() == "Rule[action='alert']"

    def test_with_attr_numeric(self):
        assert Q("SidOption").with_attr("value", 1000, "gt").build() == "SidOption[value>1000]"

    def test_with_attr_existence(self):
        assert Q("ContentOption").with_attr("modifiers").build() == "ContentOption[modifiers]"

    def test_operator_aliases(self):
        assert Q("M").with_attr("text", "x", "contains").build() == "M[text*='x']"
        assert Q("M").with_attr("text", "x", "startswith").build() == "M[text^='x']"
        assert Q("M").with_attr("text", "x", "endswith").build() == "M[text$='x']"

    def test_combinators(self):
        assert Q("Rule").descendant(Q("ContentOption")).build() == "Rule ContentOption"
        assert Q("Rule").child(Q("Header")).build() == "Rule > Header"
        assert Q("A").adjacent(Q("B")).build() == "A + B"
        assert Q("A").sibling(Q("B")).build() == "A ~ B"
        assert Q("A").or_(Q("B")).build() == "A, B"

    def test_combinator_accepts_string(self):
        assert Q("Rule").descendant("ContentOption").build() == "Rule ContentOption"

    def test_str_and_repr(self):
        q = Q("Rule")
        assert str(q) == "Rule"
        assert repr(q) == "Q('Rule')"

    def test_roundtrip_through_query(self, rule):
        built = Q("ContentOption").build()
        assert len(query(rule, built)) == len(query(rule, "ContentOption"))

    def test_roundtrip_attribute_through_query(self, rule):
        built = Q("SidOption").with_attr("value", 1000001).build()
        results = query(rule, built)
        assert len(results) == 1
        assert results[0].node_type == "SidOption"

    def test_roundtrip_descendant_through_query(self, rule):
        built = Q("Rule").descendant(Q("ContentOption")).build()
        assert len(query(rule, built)) == 1
