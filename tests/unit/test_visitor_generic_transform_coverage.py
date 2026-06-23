# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage tests for ASTTransformer.generic_visit in core/visitor.py.

generic_visit is the fallback that rebuilds a node when visiting its children
produces changes. These tests drive it directly with a transformer that
rewrites IPAddress leaves, covering both the single-ASTNode-field and the
sequence-field rebuild paths.
"""

from __future__ import annotations

from surinort_ast.core.nodes import AddressList, AddressNegation, IPAddress
from surinort_ast.core.visitor import ASTTransformer


class IPRewriter(ASTTransformer):
    """Rewrites every IPAddress value to a sentinel."""

    def visit_ipaddress(self, node: IPAddress) -> IPAddress:
        return node.model_copy(update={"value": "9.9.9.9"})


class TestGenericVisitRebuild:
    def test_single_astnode_field_is_rebuilt(self):
        negation = AddressNegation(expr=IPAddress(value="1.2.3.4", version=4))

        result = IPRewriter().generic_visit(negation)

        assert result is not negation
        assert result.expr.value == "9.9.9.9"

    def test_sequence_field_is_rebuilt_preserving_tuple(self):
        addr_list = AddressList(
            elements=(
                IPAddress(value="1.1.1.1", version=4),
                IPAddress(value="2.2.2.2", version=4),
            )
        )

        result = IPRewriter().generic_visit(addr_list)

        assert result is not addr_list
        assert isinstance(result.elements, tuple)
        assert [ip.value for ip in result.elements] == ["9.9.9.9", "9.9.9.9"]

    def test_unchanged_sequence_field_returns_original(self):
        # A transformer that changes nothing must return the original node.
        addr_list = AddressList(
            elements=(IPAddress(value="1.1.1.1", version=4),),
        )

        result = ASTTransformer().generic_visit(addr_list)

        assert result is addr_list

    def test_unchanged_single_astnode_field_returns_original(self):
        # The single-ASTNode-field branch with no change must not rebuild.
        negation = AddressNegation(expr=IPAddress(value="1.2.3.4", version=4))

        result = ASTTransformer().generic_visit(negation)

        assert result is negation
