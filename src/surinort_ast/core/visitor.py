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
        ...     def visit_SidOption(self, node):
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

        method_name = f"visit_{node.node_type}"
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
        for field_name in node.__class__.model_fields:
            field_value = getattr(node, field_name)

            if isinstance(field_value, ASTNode):
                self.visit(field_value)
            elif isinstance(field_value, (list, tuple)):
                for item in field_value:
                    if isinstance(item, ASTNode):
                        self.visit(item)

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

    # Specialized visit methods for common nodes
    def visit_Rule(self, node: Rule) -> T:  # noqa: N802 - Visitor pattern method name
        """Visit Rule node."""
        self.visit(node.header)
        for option in node.options:
            self.visit(option)
        return self.default_return()

    def visit_Header(self, node: Header) -> T:  # noqa: N802 - Visitor pattern method name
        """Visit Header node."""
        self.visit(node.src_addr)
        self.visit(node.src_port)
        self.visit(node.dst_addr)
        self.visit(node.dst_port)
        return self.default_return()

    def visit_AddressList(self, node: AddressList) -> T:  # noqa: N802 - Visitor pattern method name
        """Visit AddressList node."""
        for addr in node.elements:
            self.visit(addr)
        return self.default_return()

    def visit_AddressNegation(self, node: AddressNegation) -> T:  # noqa: N802 - Visitor pattern method name
        """Visit AddressNegation node."""
        self.visit(node.expr)
        return self.default_return()

    def visit_PortList(self, node: PortList) -> T:  # noqa: N802 - Visitor pattern method name
        """Visit PortList node."""
        for port in node.elements:
            self.visit(port)
        return self.default_return()

    def visit_PortNegation(self, node: PortNegation) -> T:  # noqa: N802 - Visitor pattern method name
        """Visit PortNegation node."""
        self.visit(node.expr)
        return self.default_return()


class ASTTransformer(ASTVisitor[ASTNode]):
    """
    Transformer that returns modified AST nodes.

    Unlike ASTVisitor, this returns new AST nodes, allowing tree transformation.
    All nodes are immutable, so transformations create new nodes.

    Example:
        >>> class SIDRewriter(ASTTransformer):
        ...     def visit_SidOption(self, node):
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
                new_value = self.visit(field_value)
                if new_value is not None and new_value != field_value:
                    updates[field_name] = new_value
                    changed = True
            elif isinstance(field_value, (list, tuple)):
                new_list: list[Any] = []
                for item in field_value:
                    if isinstance(item, ASTNode):
                        new_item = self.visit(item)
                        new_list.append(new_item if new_item is not None else item)
                    else:
                        new_list.append(item)

                if new_list != list(field_value):
                    # Safe: Pydantic validates field types at runtime
                    updates[field_name] = new_list
                    changed = True

        if changed:
            return node.model_copy(update=updates)
        return node

    def visit_Rule(self, node: Rule) -> Rule:  # noqa: N802 - Visitor pattern method name
        """Transform Rule node."""
        new_header = self.visit(node.header)
        new_options = [self.visit(opt) for opt in node.options]

        if new_header != node.header or new_options != list(node.options):
            return node.model_copy(
                update={
                    "header": new_header,
                    "options": new_options,
                }
            )
        return node

    def visit_Header(self, node: Header) -> Header:  # noqa: N802 - Visitor pattern method name
        """Transform Header node."""
        new_src_addr = self.visit(node.src_addr)
        new_src_port = self.visit(node.src_port)
        new_dst_addr = self.visit(node.dst_addr)
        new_dst_port = self.visit(node.dst_port)

        if (
            new_src_addr != node.src_addr
            or new_src_port != node.src_port
            or new_dst_addr != node.dst_addr
            or new_dst_port != node.dst_port
        ):
            return node.model_copy(
                update={
                    "src_addr": new_src_addr,
                    "src_port": new_src_port,
                    "dst_addr": new_dst_addr,
                    "dst_port": new_dst_port,
                }
            )
        return node

    def visit_AddressList(self, node: AddressList) -> AddressList:  # noqa: N802 - Visitor pattern method name
        """Transform AddressList node."""
        new_elements = [self.visit(addr) for addr in node.elements]
        if new_elements != list(node.elements):
            return node.model_copy(update={"elements": new_elements})
        return node

    def visit_AddressNegation(self, node: AddressNegation) -> AddressNegation:  # noqa: N802 - Visitor pattern method name
        """Transform AddressNegation node."""
        new_expr = self.visit(node.expr)
        if new_expr != node.expr:
            return node.model_copy(update={"expr": new_expr})
        return node

    def visit_PortList(self, node: PortList) -> PortList:  # noqa: N802 - Visitor pattern method name
        """Transform PortList node."""
        new_elements = [self.visit(port) for port in node.elements]
        if new_elements != list(node.elements):
            return node.model_copy(update={"elements": new_elements})
        return node

    def visit_PortNegation(self, node: PortNegation) -> PortNegation:  # noqa: N802 - Visitor pattern method name
        """Transform PortNegation node."""
        new_expr = self.visit(node.expr)
        if new_expr != node.expr:
            return node.model_copy(update={"expr": new_expr})
        return node


class ASTWalker:
    """
    Simple AST walker without return values.

    Useful for side-effect operations like printing or collecting stats.

    Example:
        >>> class RulePrinter(ASTWalker):
        ...     def visit_Rule(self, node):
        ...         print(f"Rule: {node.action} {node.header.protocol}")
        ...         super().visit_Rule(node)
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

        method_name = f"visit_{node.node_type}"
        visitor = getattr(self, method_name, self.generic_visit)
        visitor(node)

    def generic_visit(self, node: ASTNode) -> None:
        """
        Default visit: walk all child nodes.

        Args:
            node: AST node to visit
        """
        for field_name in node.__class__.model_fields:
            field_value = getattr(node, field_name)

            if isinstance(field_value, ASTNode):
                self.walk(field_value)
            elif isinstance(field_value, (list, tuple)):
                for item in field_value:
                    if isinstance(item, ASTNode):
                        self.walk(item)

    def visit_Rule(self, node: Rule) -> None:  # noqa: N802 - Visitor pattern method name
        """Visit Rule node."""
        self.walk(node.header)
        for option in node.options:
            self.walk(option)

    def visit_Header(self, node: Header) -> None:  # noqa: N802 - Visitor pattern method name
        """Visit Header node."""
        self.walk(node.src_addr)
        self.walk(node.src_port)
        self.walk(node.dst_addr)
        self.walk(node.dst_port)
