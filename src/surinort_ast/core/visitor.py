"""
Visitor and Transformer patterns for AST traversal.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from typing import Any, Generic, TypeVar, cast

from .nodes import (
    AddressList,
    AddressNegation,
    ASTNode,
    Header,
    PortList,
    PortNegation,
    Rule,
    iter_child_nodes,
)

T = TypeVar("T")
# Covariant TypeVar for nodes - allows ASTNode subtype returns
ASTNodeT_co = TypeVar("ASTNodeT_co", bound=ASTNode, covariant=True)


class ASTVisitor(Generic[T]):
    """
    Base visitor for AST traversal.

    Implements the Visitor pattern for traversing the AST without modifying it.
    Subclasses can override visit_* methods for specific node types.

    Example:
        >>> class SIDCollector(ASTVisitor[list[int]]):
        ...     def __init__(self):
        ...         self.sids = []
        ...
        ...     def visit_sidoption(self, node):
        ...         self.sids.append(node.value)
        ...         return None
        ...
        ...     def default_return(self):
        ...         return self.sids
        ...
        >>> collector = SIDCollector()
        >>> collector.visit(rule)
        >>> print(collector.sids)
        [1000001, 1000002]
    """

    def visit(self, node: ASTNode | None) -> T:
        """
        Dispatch to specific visit method based on node type.

        Args:
            node: AST node to visit

        Returns:
            Result from visit method or generic_visit
        """
        if node is None:
            return self.default_return()

        method_name = f"visit_{node.node_type.lower()}"
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node: ASTNode) -> T:
        """
        Default behavior: visit all child nodes.

        Override this to change default traversal behavior.

        Args:
            node: AST node to visit

        Returns:
            Result from default_return()
        """
        # Visit all fields that are ASTNodes or sequences of ASTNodes
        for child in iter_child_nodes(node):
            self.visit(child)

        return self.default_return()

    def default_return(self) -> T:
        """
        Override to provide custom default return value.

        Subclasses MUST override this method if T does not include None.
        The base implementation returns None, which is safe for visitors
        that use Optional[T] or when T is a concrete nullable type.

        Returns:
            Default return value for visit methods
        """
        # Safe cast: Visitor pattern allows None returns during traversal.
        # Subclasses using non-nullable T must override this method.
        return cast(T, None)

    # Per-type traversal hooks. Each delegates to generic_visit so that
    # generic_visit is the single source of default traversal: a subclass
    # overriding ONLY generic_visit observes every node type (these methods used
    # to do their own traversal, silently shadowing such an override for
    # Rule/Header/Address*/Port* — e.g. an ASTTransformer rewriting via
    # generic_visit no-op'd on those container nodes). Subclasses may still
    # override a single visit_<type> and call super().visit_<type>() for
    # default child traversal.
    def visit_rule(self, node: Rule) -> T:
        """Visit Rule node (delegates to generic_visit)."""
        return self.generic_visit(node)

    def visit_header(self, node: Header) -> T:
        """Visit Header node (delegates to generic_visit)."""
        return self.generic_visit(node)

    def visit_addresslist(self, node: AddressList) -> T:
        """Visit AddressList node (delegates to generic_visit)."""
        return self.generic_visit(node)

    def visit_addressnegation(self, node: AddressNegation) -> T:
        """Visit AddressNegation node (delegates to generic_visit)."""
        return self.generic_visit(node)

    def visit_portlist(self, node: PortList) -> T:
        """Visit PortList node (delegates to generic_visit)."""
        return self.generic_visit(node)

    def visit_portnegation(self, node: PortNegation) -> T:
        """Visit PortNegation node (delegates to generic_visit)."""
        return self.generic_visit(node)


class ASTTransformer(ASTVisitor[ASTNode]):
    """
    Transformer that returns modified AST nodes.

    Unlike ASTVisitor, this returns new AST nodes, allowing tree transformation.
    All nodes are immutable, so transformations create new nodes.

    Example:
        >>> class SIDRewriter(ASTTransformer):
        ...     def visit_sidoption(self, node):
        ...         # Add 1000000 to all SIDs
        ...         return node.model_copy(update={'value': node.value + 1000000})
        ...
        >>> transformer = SIDRewriter()
        >>> new_rule = transformer.visit(rule)
    """

    def default_return(self) -> ASTNode:
        """
        Return None for transformer (will be filtered).

        Transformers can return None to indicate no transformation needed.
        The generic_visit method handles None returns appropriately by
        preserving the original node.
        """
        # Safe cast: Transformer pattern allows None to signal no change.
        # generic_visit() handles None by keeping the original node.
        return cast(ASTNode, None)

    def _visit_child(self, child: ASTNode) -> ASTNode:
        """Visit a child node, preserving the original when the visit returns
        None (the documented "no change" signal)."""
        result = self.visit(child)
        return result if result is not None else child

    def generic_visit(self, node: ASTNode) -> ASTNode:
        """
        Transform node by visiting children and creating new node if changed.

        Args:
            node: AST node to transform

        Returns:
            Transformed node (or original if no changes)
        """
        # Type as dict[str, Any] to allow heterogeneous field updates
        # Pydantic's model_copy will validate types at runtime
        updates: dict[str, Any] = {}
        changed = False

        for field_name in node.__class__.model_fields:
            field_value = getattr(node, field_name)

            if isinstance(field_value, ASTNode):
                new_value = self._visit_child(field_value)
                if new_value != field_value:
                    updates[field_name] = new_value
                    changed = True
            elif isinstance(field_value, (list, tuple)):
                new_items: list[Any] = [
                    self._visit_child(item) if isinstance(item, ASTNode) else item
                    for item in field_value
                ]
                if new_items != list(field_value):
                    # Preserve the original container type. The AST declares
                    # sequence fields as tuples; model_copy() does not re-validate,
                    # so a list would be stored verbatim and break serialization
                    # and equality.
                    updates[field_name] = (
                        tuple(new_items) if isinstance(field_value, tuple) else new_items
                    )
                    changed = True

        if changed:
            return node.model_copy(update=updates)
        return node


class ASTWalker:
    """
    Simple AST walker without return values.

    Useful for side-effect operations like printing or collecting stats.

    Example:
        >>> class RulePrinter(ASTWalker):
        ...     def visit_rule(self, node):
        ...         print(f"Rule: {node.action} {node.header.protocol}")
        ...         super().visit_rule(node)
        ...
        >>> printer = RulePrinter()
        >>> printer.walk(rule)
    """

    def walk(self, node: ASTNode | None) -> None:
        """
        Walk the AST starting from node.

        Args:
            node: AST node to start walking from
        """
        if node is None:
            return

        method_name = f"visit_{node.node_type.lower()}"
        visitor = getattr(self, method_name, self.generic_visit)
        visitor(node)

    def generic_visit(self, node: ASTNode) -> None:
        """
        Default visit: walk all child nodes.

        Args:
            node: AST node to visit
        """
        for child in iter_child_nodes(node):
            self.walk(child)

    def visit_rule(self, node: Rule) -> None:
        """Visit Rule node (delegates to generic_visit)."""
        self.generic_visit(node)

    def visit_header(self, node: Header) -> None:
        """Visit Header node (delegates to generic_visit)."""
        self.generic_visit(node)
