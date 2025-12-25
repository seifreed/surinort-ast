"""
Protocol interfaces for query module to break circular dependencies.

This module defines Protocol (structural typing) interfaces that allow
different query components to reference each other without creating
circular imports.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from typing import Any, Protocol

from surinort_ast.core.nodes import ASTNode

# ============================================================================
# Selector Protocols
# ============================================================================


class SelectorProtocol(Protocol):
    """
    Protocol for selector objects.

    All selectors must implement a matches() method to test nodes.
    This protocol allows executor to work with selectors without
    importing concrete selector classes.
    """

    def matches(self, node: ASTNode) -> bool:
        """
        Test if AST node matches this selector.

        Args:
            node: AST node to test

        Returns:
            True if node matches, False otherwise
        """
        ...


class PseudoSelectorProtocol(Protocol):
    """
    Protocol for pseudo-selectors that require execution context.

    Pseudo-selectors need context (parent, siblings) from the executor
    during matching.
    """

    def matches(self, node: ASTNode, context: Any = None) -> bool:
        """
        Test if node matches pseudo-selector with context.

        Args:
            node: AST node to test
            context: Execution context (ExecutionContext instance)

        Returns:
            True if matches
        """
        ...


# ============================================================================
# Selector Chain Protocol
# ============================================================================


class SelectorChainProtocol(Protocol):
    """
    Protocol for selector chain objects.

    Allows executor to work with selector chains without importing
    the concrete SelectorChain class from parser module.
    """

    selectors: list[Any]
    """List of selector objects in the chain."""

    combinators: list[Any]
    """List of combinator enums between selectors."""


# ============================================================================
# Execution Context Protocol
# ============================================================================


class ExecutionContextProtocol(Protocol):
    """
    Protocol for execution context during query evaluation.

    Allows selectors (especially pseudo-selectors) to access context
    without importing from executor module.
    """

    ancestors: list[ASTNode]
    """Stack of ancestor nodes during traversal."""

    previous_match: ASTNode | None
    """Last node that matched in selector chain."""

    def push_ancestor(self, node: ASTNode) -> None:
        """Add ancestor to stack."""
        ...

    def pop_ancestor(self) -> ASTNode | None:
        """Remove and return top ancestor."""
        ...

    def get_parent(self) -> ASTNode | None:
        """Get immediate parent of current node."""
        ...

    def is_descendant_of(self, node: ASTNode, ancestor: ASTNode) -> bool:
        """Check if node is descendant of ancestor."""
        ...

    def is_child_of(self, node: ASTNode, parent: ASTNode) -> bool:
        """Check if node is direct child of parent."""
        ...


# ============================================================================
# Query Executor Protocol
# ============================================================================


class QueryExecutorProtocol(Protocol):
    """
    Protocol for query executor.

    Allows selectors to create sub-executors (e.g., for :has() pseudo-selector)
    without importing concrete QueryExecutor class.
    """

    def __init__(self, selector_chain: Any) -> None:
        """
        Initialize executor with selector chain.

        Args:
            selector_chain: SelectorChain or compatible object
        """
        ...

    def execute(self, root: ASTNode | list[ASTNode]) -> list[ASTNode]:
        """
        Execute query and return matching nodes.

        Args:
            root: Single AST node or list of nodes

        Returns:
            List of matching AST nodes
        """
        ...


# ============================================================================
# License Information
# ============================================================================

__all__ = [
    "ExecutionContextProtocol",
    "PseudoSelectorProtocol",
    "QueryExecutorProtocol",
    "SelectorChainProtocol",
    "SelectorProtocol",
]

# All code in this module is released under GNU General Public License v3.0
# Copyright (c) Marc Rivero López
# For full license text, see: https://www.gnu.org/licenses/gpl-3.0.html
