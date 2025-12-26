# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for surinort_ast.query.protocols module.

Tests the protocol definitions used for breaking circular dependencies
in the query module. These are structural type definitions that enable
type checking and documentation.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

import pytest

from surinort_ast import parse_rule
from surinort_ast.query import query_first
from surinort_ast.query.executor import QueryExecutor
from surinort_ast.query.parser import QueryParser
from surinort_ast.query.protocols import (
    ExecutionContextProtocol,
    QueryExecutorProtocol,
    SelectorChainProtocol,
    SelectorProtocol,
)
from surinort_ast.query.selectors import AttributeSelector, TypeSelector


class TestSelectorProtocol:
    """Test SelectorProtocol structural interface."""

    def test_type_selector_implements_protocol(self):
        """Test that TypeSelector implements SelectorProtocol."""
        selector = TypeSelector("SidOption")

        # Check that it has the required matches method
        assert hasattr(selector, "matches")
        assert callable(selector.matches)

        # Test actual usage
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")
        sid_node = query_first(rule, "SidOption")

        assert selector.matches(sid_node) is True

    def test_attribute_selector_implements_protocol(self):
        """Test that AttributeSelector implements SelectorProtocol."""
        selector = AttributeSelector("value", "=", 1)

        # Check protocol conformance
        assert hasattr(selector, "matches")
        assert callable(selector.matches)

        # Test actual usage
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")
        sid_node = query_first(rule, "SidOption")

        assert selector.matches(sid_node) is True

    def test_selector_protocol_matches_signature(self):
        """Test that selector matches() has correct signature."""
        selector = TypeSelector("Rule")
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # Should accept ASTNode and return bool
        result = selector.matches(rule)
        assert isinstance(result, bool)


class TestSelectorChainProtocol:
    """Test SelectorChainProtocol structural interface."""

    def test_selector_chain_has_required_attributes(self):
        """Test that SelectorChain has required protocol attributes."""
        parser = QueryParser()
        chain = parser.parse("SidOption")

        # Check protocol conformance
        assert hasattr(chain, "selectors")
        assert hasattr(chain, "combinators")

        # Verify types
        assert isinstance(chain.selectors, list)
        assert isinstance(chain.combinators, list)

    def test_selector_chain_attributes_accessible(self):
        """Test that SelectorChain attributes are accessible."""
        parser = QueryParser()
        chain = parser.parse("SidOption[value=1]")

        # Access protocol-defined attributes
        assert len(chain.selectors) >= 1
        assert len(chain.combinators) >= 0

        # Selectors should contain selector objects
        for selector in chain.selectors:
            assert hasattr(selector, "matches") or hasattr(selector, "selectors")


class TestQueryExecutorProtocol:
    """Test QueryExecutorProtocol structural interface."""

    def test_executor_has_required_methods(self):
        """Test that QueryExecutor implements protocol methods."""
        parser = QueryParser()
        chain = parser.parse("SidOption")
        executor = QueryExecutor(chain)

        # Check protocol conformance
        assert hasattr(executor, "execute")
        assert callable(executor.execute)

    def test_executor_execute_signature(self):
        """Test that execute() method has correct signature."""
        parser = QueryParser()
        chain = parser.parse("SidOption")
        executor = QueryExecutor(chain)

        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # Should accept single node
        results = executor.execute(rule)
        assert isinstance(results, list)

        # Should accept list of nodes
        results = executor.execute([rule])
        assert isinstance(results, list)


class TestExecutionContextProtocol:
    """Test ExecutionContextProtocol structural interface."""

    def test_execution_context_from_executor(self):
        """Test that QueryExecutor creates context with protocol methods."""
        parser = QueryParser()
        chain = parser.parse("*")
        executor = QueryExecutor(chain)

        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")

        # Execute to trigger context creation
        _results = executor.execute(rule)

        # After execution, context_stack should exist
        assert hasattr(executor, "context_stack")
        assert isinstance(executor.context_stack, list)


class TestProtocolUsageInRealCode:
    """Test that protocols work correctly in real query scenarios."""

    def test_protocol_enables_circular_dependency_resolution(self):
        """Test that protocols successfully break circular dependencies."""
        # This test verifies that the protocol system allows the query
        # module to function without circular imports

        parser = QueryParser()
        chain = parser.parse("Rule SidOption[value>1000]")
        executor = QueryExecutor(chain)

        rules = [
            parse_rule("alert tcp any any -> any 80 (sid:1001;)"),
            parse_rule("alert tcp any any -> any 443 (sid:999;)"),
        ]

        results = executor.execute(rules)

        # Should find rule with sid > 1000
        assert len(results) == 1
        assert results[0].value == 1001

    def test_protocol_allows_multiple_selector_types(self):
        """Test that protocol works with different selector implementations."""
        # Create different selector types
        type_sel = TypeSelector("SidOption")
        attr_sel = AttributeSelector("value", "=", 1)

        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)")
        sid_node = query_first(rule, "SidOption")

        # Both should work through the protocol
        assert type_sel.matches(sid_node) is True
        assert attr_sel.matches(sid_node) is True

    def test_protocol_enables_executor_with_different_chains(self):
        """Test that executor protocol works with different chain types."""
        parser = QueryParser()

        # Different chain types
        simple_chain = parser.parse("SidOption")
        complex_chain = parser.parse("Rule > SidOption[value>100]")

        # Both should work through protocol
        executor1 = QueryExecutor(simple_chain)
        executor2 = QueryExecutor(complex_chain)

        rule = parse_rule("alert tcp any any -> any 80 (sid:101;)")

        results1 = executor1.execute(rule)
        results2 = executor2.execute(rule)

        assert len(results1) == 1
        assert len(results2) == 1


class TestProtocolDocumentation:
    """Test that protocol definitions are properly documented."""

    def test_selector_protocol_has_docstring(self):
        """Test that SelectorProtocol is documented."""
        assert SelectorProtocol.__doc__ is not None
        assert "selector" in SelectorProtocol.__doc__.lower()

    def test_selector_chain_protocol_has_docstring(self):
        """Test that SelectorChainProtocol is documented."""
        assert SelectorChainProtocol.__doc__ is not None
        assert "chain" in SelectorChainProtocol.__doc__.lower()

    def test_executor_protocol_has_docstring(self):
        """Test that QueryExecutorProtocol is documented."""
        assert QueryExecutorProtocol.__doc__ is not None
        assert "executor" in QueryExecutorProtocol.__doc__.lower()

    def test_execution_context_protocol_has_docstring(self):
        """Test that ExecutionContextProtocol is documented."""
        assert ExecutionContextProtocol.__doc__ is not None
        assert "context" in ExecutionContextProtocol.__doc__.lower()


class TestProtocolExports:
    """Test that protocols are properly exported from module."""

    def test_all_protocols_exported(self):
        """Test that __all__ includes all protocol classes."""
        from surinort_ast.query import protocols

        expected_protocols = [
            "SelectorProtocol",
            "PseudoSelectorProtocol",
            "SelectorChainProtocol",
            "ExecutionContextProtocol",
            "QueryExecutorProtocol",
        ]

        for protocol_name in expected_protocols:
            assert protocol_name in protocols.__all__
            assert hasattr(protocols, protocol_name)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
