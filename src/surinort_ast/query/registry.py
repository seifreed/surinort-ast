"""
Runtime registry mapping AST node type names to their classes.

The query engine identifies nodes by ``node.node_type`` (the class name).
For subclass-aware matching and indexed execution it also needs to resolve a
type name back to its Python class so that ``isinstance`` checks can include
derived types. This module builds that mapping once by introspecting the
``ASTNode`` class hierarchy defined in :mod:`surinort_ast.core.nodes`, so it
never drifts from the node definitions.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from ..core.nodes import ASTNode


def _build_registry() -> dict[str, type[ASTNode]]:
    """Walk the ASTNode subclass tree and map class name -> class."""
    registry: dict[str, type[ASTNode]] = {}
    stack: list[type[ASTNode]] = [ASTNode]
    seen: set[type[ASTNode]] = set()
    while stack:
        cls = stack.pop()
        if cls in seen:
            continue
        seen.add(cls)
        registry[cls.__name__] = cls
        stack.extend(cls.__subclasses__())
    return registry


NODE_TYPE_REGISTRY: dict[str, type[ASTNode]] = _build_registry()


def resolve_node_type(name: str) -> type[ASTNode] | None:
    """Return the AST node class for ``name``, or None if it is unknown."""
    return NODE_TYPE_REGISTRY.get(name)


__all__ = ["NODE_TYPE_REGISTRY", "resolve_node_type"]
