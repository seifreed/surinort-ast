# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.

"""
Coverage tests for query/parser.py.

Covers the SelectorTransformer fallback branches (combinator_chain with an
unrecognized item, operator with no token, attribute_value with a non-standard
token, pseudo_selector skipping anonymous tokens) and the semantic checks in
validate_selector_chain (union sub-chains, empty chain, combinator-count
mismatch, and a result-set pseudo before a combinator).
"""

from __future__ import annotations

import pytest
from lark import Token

from surinort_ast.query import InvalidSelectorError
from surinort_ast.query.parser import (
    SelectorChain,
    SelectorTransformer,
    validate_selector_chain,
)
from surinort_ast.query.selectors import (
    Combinator,
    PseudoSelector,
    TypeSelector,
    UnionSelector,
)


class TestSelectorTransformerFallbacks:
    def test_combinator_chain_with_unrecognized_item(self):
        # A middle item that is neither a selector nor a Combinator exercises the
        # "unknown item" branch and the alternating-items reinterpretation.
        chain = SelectorTransformer().combinator_chain(
            [TypeSelector("A"), "garbage", TypeSelector("B")]
        )

        assert isinstance(chain, SelectorChain)
        assert len(chain.selectors) == 2

    def test_operator_without_token_defaults_to_equals(self):
        assert SelectorTransformer().operator([]) == "="

    def test_attribute_value_passthrough_for_other_token(self):
        token = Token("OTHER", "raw_value")
        assert SelectorTransformer().attribute_value([token]) == "raw_value"

    def test_pseudo_selector_skips_anonymous_tokens(self):
        result = SelectorTransformer().pseudo_selector(
            [Token("WS", " "), Token("PSEUDO_CLASS", "first")]
        )

        assert isinstance(result, PseudoSelector)
        assert result.pseudo_type == "first"


class TestValidateSelectorChain:
    def test_union_validates_each_sub_chain(self):
        # A UnionSelector whose members are not SelectorChains is skipped cleanly.
        union = UnionSelector([TypeSelector("A")])

        # Should not raise.
        validate_selector_chain(union)

    def test_empty_chain_raises(self):
        # SelectorChain.__init__ rejects an empty chain, so reach the defensive
        # validation by emptying a valid chain after construction.
        chain = SelectorChain([TypeSelector("A")], [])
        chain.selectors = []

        with pytest.raises(InvalidSelectorError, match="empty"):
            validate_selector_chain(chain)

    def test_combinator_count_mismatch_raises(self):
        chain = SelectorChain([TypeSelector("A")], [])
        chain.combinators = [Combinator.DESCENDANT]

        with pytest.raises(InvalidSelectorError, match="combinators"):
            validate_selector_chain(chain)

    def test_result_set_pseudo_before_combinator_raises(self):
        chain = SelectorChain(
            [PseudoSelector("first"), TypeSelector("B")],
            [Combinator.DESCENDANT],
        )

        with pytest.raises(InvalidSelectorError, match="only valid on the final"):
            validate_selector_chain(chain)
