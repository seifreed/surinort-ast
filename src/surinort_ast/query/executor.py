"""
Query Executor - Executes queries against AST using visitor pattern.

This module implements the query execution engine that traverses the AST
to find nodes matching a selector chain. It extends the existing ASTVisitor
pattern for consistency and performance.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence

# Import only what's needed at module level to avoid circular dependency
# Combinator enum and other selector classes imported locally where used
from typing import TYPE_CHECKING, Any

from surinort_ast.core.nodes import ASTNode
from surinort_ast.core.visitor import ASTVisitor

if TYPE_CHECKING:
    pass

# ============================================================================
# Query Executor (Phase 1)
# ============================================================================


class QueryExecutor(ASTVisitor[list[ASTNode]]):
    """
    Executes selector chains against AST using visitor pattern.

    Extends ASTVisitor to traverse the AST and collect nodes matching
    the selector chain. Maintains execution context for hierarchical
    selectors and combinators.

    Architecture:
        1. Receives SelectorChain from parser
        2. Traverses AST using visitor pattern
        3. Tests each node against current selector
        4. Manages context stack for hierarchical queries
        5. Collects matching nodes

    Attributes:
        selector_chain: Parsed selector chain to execute
        results: List of matching nodes (accumulated during traversal)
        context_stack: Stack of ancestor nodes for hierarchical queries
        current_selector_index: Current position in selector chain

    Example:
        >>> from surinort_ast import parse_rule
        >>> rule = parse_rule('alert tcp any any -> any 80 (sid:1;)')
        >>>
        >>> parser = QueryParser()
        >>> chain = parser.parse("SidOption[value>1000000]")
        >>>
        >>> executor = QueryExecutor(chain)
        >>> results = executor.execute(rule)

    Implementation Plan:
        Phase 1:
            - Basic type selector matching
            - Simple attribute equality
            - Descendant combinator (implicit)
            - Single-selector chains

        Phase 2:
            - All combinators (>, +, ~)
            - Multi-selector chains
            - Context stack management
            - Sibling navigation

        Phase 3:
            - Pseudo-selector support
            - Early exit optimizations
            - Result caching
            - Parallel execution hints
    """

    def __init__(self, selector_chain: Any) -> None:
        """
        Initialize query executor.

        Args:
            selector_chain: Parsed selector chain or union selector to execute
        """
        # Handle UnionSelector specially
        from .parser import SelectorChain
        from .selectors import UnionSelector

        # Handle case where selector_chain might be a raw result from parser
        # that needs to be wrapped in SelectorChain
        if not isinstance(selector_chain, (UnionSelector, SelectorChain)):
            # Wrap in SelectorChain
            selector_chain = SelectorChain([selector_chain], [])

        if isinstance(selector_chain, UnionSelector):
            self.is_union = True
            self.union_chains = selector_chain.selectors
            # Use first chain for initialization
            self.selector_chain = (
                self.union_chains[0] if self.union_chains else SelectorChain([], [])
            )
        else:
            self.is_union = False
            self.union_chains = []
            self.selector_chain = selector_chain

        self.results: list[ASTNode] = []
        self.context_stack: list[ASTNode] = []
        self.current_selector_index = 0
        self.execution_context = ExecutionContext()

    def execute(self, root: ASTNode | Sequence[ASTNode]) -> list[ASTNode]:
        """
        Execute query and return matching nodes.

        Args:
            root: Single AST node or sequence of nodes

        Returns:
            List of matching AST nodes

        Example:
            >>> executor = QueryExecutor(chain)
            >>> results = executor.execute(rule)
            >>> len(results)
            5

        Implementation:
            1. Reset state (results, context)
            2. If root is sequence, visit each node
            3. If root is single node, visit it
            4. Return accumulated results
        """
        # Handle UnionSelector by executing each chain and merging results
        if self.is_union:
            all_results = []
            seen = set()
            for chain in self.union_chains:
                sub_executor = QueryExecutor(chain)
                sub_results = sub_executor.execute(root)
                # Deduplicate results
                for result in sub_results:
                    if id(result) not in seen:
                        seen.add(id(result))
                        all_results.append(result)
            return all_results

        # Reset state
        self.results = []
        self.context_stack = []
        self.current_selector_index = 0
        self.execution_context = ExecutionContext()

        # Visit root node(s)
        # Note: visit() calls generic_visit() which handles the root node check
        if isinstance(root, Sequence):
            for node in root:
                self.visit(node)
        else:
            self.visit(root)

        return self.results

    def generic_visit(self, node: ASTNode) -> list[ASTNode]:
        """
        Visit node and check against current selector.

        This is called for every node during traversal. It:
        1. Tests node against current selector
        2. Updates context stack
        3. Continues traversal to children
        4. Restores context

        Args:
            node: AST node to visit

        Returns:
            Empty list (results accumulated in self.results)

        Implementation:
            Phase 2: Context-aware matching with combinators
            Phase 3: Optimization and early exit
        """
        # Update context stack and execution context
        self.context_stack.append(node)
        self.execution_context.push_ancestor(node)

        # Check if node matches current selector
        if self._matches_current_selector(node):
            self.results.append(node)

        # Continue traversal to children
        super().generic_visit(node)

        # Restore context
        self.context_stack.pop()
        self.execution_context.pop_ancestor()

        return []

    def visit_Rule(self, node: Any) -> list[ASTNode]:  # noqa: N802
        """Visit Rule node - override to check Rule itself."""
        self.context_stack.append(node)
        self.execution_context.push_ancestor(node)

        # Check Rule node itself
        if self._matches_current_selector(node):
            self.results.append(node)

        # Visit header and options
        self.visit(node.header)
        for option in node.options:
            self.visit(option)

        self.context_stack.pop()
        self.execution_context.pop_ancestor()
        return []

    def visit_Header(self, node: Any) -> list[ASTNode]:  # noqa: N802
        """Visit Header node - override to check Header itself."""
        self.context_stack.append(node)
        self.execution_context.push_ancestor(node)

        # Check Header node itself
        if self._matches_current_selector(node):
            self.results.append(node)

        # Visit address and port nodes
        self.visit(node.src_addr)
        self.visit(node.src_port)
        self.visit(node.dst_addr)
        self.visit(node.dst_port)

        self.context_stack.pop()
        self.execution_context.pop_ancestor()
        return []

    def _matches_current_selector(self, node: ASTNode) -> bool:
        """
        Test if node matches current selector in chain.

        For single-selector chains, matches directly.
        For multi-selector chains with combinators, only the last selector
        produces results, but must validate combinator relationships.

        Args:
            node: Node to test

        Returns:
            True if node matches (and should be added to results)
        """
        if not self.selector_chain.selectors:
            return False

        # Single selector - simple match
        if len(self.selector_chain.selectors) == 1:
            selector = self.selector_chain.selectors[0]
            from .selectors import PseudoSelector

            if isinstance(selector, PseudoSelector):
                return selector.matches(node, self.execution_context)
            return bool(selector.matches(node))

        # Multi-selector chain with combinators
        # We only match the LAST selector in the chain, but we must verify
        # the entire chain of combinators holds true
        #
        # For example: "Rule > Header" should match Header nodes that are
        # direct children of Rule nodes.
        #
        # Strategy: Match against the last selector, then walk back through
        # the chain validating combinators.

        last_selector = self.selector_chain.selectors[-1]
        from .selectors import PseudoSelector

        # Check if node matches the final selector
        if isinstance(last_selector, PseudoSelector):
            if not last_selector.matches(node, self.execution_context):
                return False
        elif not last_selector.matches(node):
            return False

        # Node matches final selector - now validate the chain
        # Walk backwards through the chain
        current_node = node
        for i in range(len(self.selector_chain.selectors) - 1, 0, -1):
            combinator = self.selector_chain.combinators[i - 1]
            required_selector = self.selector_chain.selectors[i - 1]

            # Find a matching ancestor/sibling based on combinator
            candidate = self._find_related_node(current_node, combinator, required_selector)
            if candidate is None:
                return False

            current_node = candidate

        return True

    def _find_related_node(self, node: ASTNode, combinator: Any, selector: Any) -> ASTNode | None:
        """
        Find a node related to the given node by the combinator that matches the selector.

        Args:
            node: Starting node
            combinator: Relationship type
            selector: Selector the related node must match

        Returns:
            Matching related node or None
        """
        from .selectors import Combinator

        if combinator == Combinator.DESCENDANT:
            # Find any ancestor that matches selector
            for ancestor in reversed(self.execution_context.ancestors):
                if ancestor == node:
                    continue
                if selector.matches(ancestor):
                    return ancestor
            return None

        if combinator == Combinator.CHILD:
            # Find immediate parent that matches selector.
            # Search backwards through ancestors to find this node, then check its parent.
            ancestors = self.execution_context.ancestors
            for idx in range(len(ancestors) - 1, -1, -1):
                if ancestors[idx] is node and idx > 0:
                    parent = ancestors[idx - 1]
                    if selector.matches(parent):
                        return parent
                    break
            return None

        if combinator == Combinator.ADJACENT:
            # Find immediately preceding sibling that matches selector.
            ancestors = self.execution_context.ancestors
            parent = None
            for idx in range(len(ancestors) - 1, -1, -1):
                if ancestors[idx] is node and idx > 0:
                    parent = ancestors[idx - 1]
                    break
            if parent is None:
                return None

            siblings = self._get_children(parent)
            try:
                sibling_index = siblings.index(node)
                if sibling_index > 0:
                    prev_sibling = siblings[sibling_index - 1]
                    if selector.matches(prev_sibling):
                        return prev_sibling
            except ValueError:
                pass
            return None

        if combinator == Combinator.GENERAL:
            # Find any preceding sibling that matches selector.
            ancestors = self.execution_context.ancestors
            parent = None
            for idx in range(len(ancestors) - 1, -1, -1):
                if ancestors[idx] is node and idx > 0:
                    parent = ancestors[idx - 1]
                    break
            if parent is None:
                return None

            siblings = self._get_children(parent)
            try:
                sibling_index = siblings.index(node)
                for i in range(sibling_index - 1, -1, -1):
                    if selector.matches(siblings[i]):
                        return siblings[i]
            except ValueError:
                pass
            return None

        return None

    def _get_children(self, node: ASTNode) -> list[ASTNode]:
        """Get all children of a node."""
        children = []
        # For Rule nodes, header comes first, then options
        if hasattr(node, "header") and node.header is not None:
            children.append(node.header)
        if hasattr(node, "options") and node.options:
            children.extend(node.options)
        # For Header nodes, include address and port children
        if hasattr(node, "src_addr") and node.src_addr is not None:
            children.append(node.src_addr)
        if hasattr(node, "src_port") and node.src_port is not None:
            children.append(node.src_port)
        if hasattr(node, "dst_addr") and node.dst_addr is not None:
            children.append(node.dst_addr)
        if hasattr(node, "dst_port") and node.dst_port is not None:
            children.append(node.dst_port)
        return children

    def default_return(self) -> list[ASTNode]:
        """
        Return accumulated results.

        Returns:
            List of matching nodes
        """
        return self.results


# ============================================================================
# Optimized Executors
# ============================================================================


class IndexedQueryExecutor(QueryExecutor):
    """
    Query executor with a pre-computed node-type index for fast lookups.

    Builds a ``node_type -> [nodes]`` index over the root once, so that a query
    consisting of a single exact :class:`TypeSelector` is answered by an index
    lookup instead of a full traversal. Repeated queries against the same root
    reuse the index. All other queries (attributes, combinators, subclass
    matching, unions) delegate to the base traversal so results are identical.

    Example:
        >>> executor = IndexedQueryExecutor(chain).index(rules)
        >>> results = executor.execute(rules)
    """

    def __init__(self, selector_chain: Any) -> None:
        super().__init__(selector_chain)
        self._indexed_root_id: int | None = None
        self._type_index: dict[str, list[ASTNode]] = {}

    def index(self, root: ASTNode | Sequence[ASTNode]) -> IndexedQueryExecutor:
        """Pre-build the index for ``root`` and return self for chaining."""
        self._build_index(root)
        return self

    def _build_index(self, root: ASTNode | Sequence[ASTNode]) -> None:
        self._type_index = {}
        nodes = root if isinstance(root, Sequence) else [root]
        for node in nodes:
            self._index_node(node)
        self._indexed_root_id = id(root)

    def _index_node(self, node: ASTNode) -> None:
        # Pre-order, mirroring the base traversal so result order is identical.
        self._type_index.setdefault(node.node_type, []).append(node)
        for child in self._get_children(node):
            self._index_node(child)

    def execute(self, root: ASTNode | Sequence[ASTNode]) -> list[ASTNode]:
        type_name = self._indexable_type()
        if type_name is None:
            return super().execute(root)
        if self._indexed_root_id != id(root):
            self._build_index(root)
        return list(self._type_index.get(type_name, []))

    def _indexable_type(self) -> str | None:
        """Return the type name if this query is a single exact TypeSelector."""
        from .selectors import TypeSelector

        if self.is_union:
            return None
        selectors = self.selector_chain.selectors
        if len(selectors) != 1:
            return None
        selector = selectors[0]
        if not isinstance(selector, TypeSelector) or selector.match_subclasses:
            return None
        return selector.type_name


class StreamingQueryExecutor(QueryExecutor):
    """
    Query executor that yields results incrementally.

    For a single, non-pseudo selector the matching nodes are yielded as they are
    encountered during traversal, so a consumer can start processing before the
    whole tree is walked. Combinator chains, unions, and pseudo-selectors need
    full execution context and fall back to eager evaluation, yielding from the
    completed result list.

    Example:
        >>> executor = StreamingQueryExecutor(chain)
        >>> for node in executor.execute_stream(rule):
        ...     process(node)  # Process incrementally
    """

    def execute_stream(self, root: ASTNode | Sequence[ASTNode]) -> Iterator[ASTNode]:
        """Yield matching nodes, incrementally where possible."""
        from .selectors import PseudoSelector

        selectors = None if self.is_union else self.selector_chain.selectors
        if selectors and len(selectors) == 1 and not isinstance(selectors[0], PseudoSelector):
            selector = selectors[0]
            nodes = root if isinstance(root, Sequence) else [root]
            for node in nodes:
                yield from self._stream_node(node, selector)
        else:
            yield from self.execute(root)

    def _stream_node(self, node: ASTNode, selector: Any) -> Iterator[ASTNode]:
        if selector.matches(node):
            yield node
        for child in self._get_children(node):
            yield from self._stream_node(child, selector)


# ============================================================================
# Helper Functions
# ============================================================================


def execute_query(
    root: ASTNode | Sequence[ASTNode],
    selector_chain: Any,  # SelectorChain type
) -> list[ASTNode]:
    """
    Execute query against AST (convenience function).

    Args:
        root: Single node or sequence of nodes
        selector_chain: Parsed selector chain

    Returns:
        List of matching nodes

    Example:
        >>> chain = parser.parse("Rule[action=alert]")
        >>> results = execute_query(rules, chain)

    Implementation:
        Phase 1: Wrapper around QueryExecutor
    """
    executor = QueryExecutor(selector_chain)
    return executor.execute(root)


def execute_query_first(
    root: ASTNode | Sequence[ASTNode],
    selector_chain: Any,  # SelectorChain type
) -> ASTNode | None:
    """
    Execute query and return first match.

    More efficient than execute_query() when only first result needed.
    Uses early exit optimization.

    Args:
        root: Single node or sequence of nodes
        selector_chain: Parsed selector chain

    Returns:
        First matching node or None

    Example:
        >>> chain = parser.parse("SidOption")
        >>> sid_node = execute_query_first(rule, chain)

    Implementation:
        Phase 1: Execute with early exit flag
    """
    # TODO: Implement early exit in Phase 1
    results = execute_query(root, selector_chain)
    return results[0] if results else None


def execute_query_exists(
    root: ASTNode | Sequence[ASTNode],
    selector_chain: Any,  # SelectorChain type
) -> bool:
    """
    Check if any node matches selector.

    Most efficient existence check with immediate early exit.

    Args:
        root: Single node or sequence of nodes
        selector_chain: Parsed selector chain

    Returns:
        True if at least one match exists

    Example:
        >>> chain = parser.parse("PcreOption")
        >>> has_pcre = execute_query_exists(rule, chain)

    Implementation:
        Phase 1: Execute with exists flag for fastest early exit
    """
    # TODO: Implement in Phase 1
    return len(execute_query(root, selector_chain)) > 0


# ============================================================================
# Context Management (Phase 2)
# ============================================================================


class ExecutionContext:
    """
    Execution context for hierarchical queries.

    Maintains state during query execution including:
        - Ancestor stack
        - Sibling information
        - Previous matches
        - Current combinator

    Attributes:
        ancestors: Stack of ancestor nodes
        previous_match: Last node that matched
        combinator: Current combinator to apply

    Implementation:
        Phase 2: For combinator support
        Phase 3: Add optimization hints and caching
    """

    def __init__(self) -> None:
        """Initialize execution context."""
        self.ancestors: list[ASTNode] = []
        self.previous_match: ASTNode | None = None
        self.combinator: Any = None  # Combinator enum, using Any to avoid import

    def push_ancestor(self, node: ASTNode) -> None:
        """Add ancestor to stack."""
        self.ancestors.append(node)

    def pop_ancestor(self) -> ASTNode | None:
        """Remove and return top ancestor."""
        return self.ancestors.pop() if self.ancestors else None

    def get_parent(self) -> ASTNode | None:
        """
        Get immediate parent of current node.

        When checking a node, that node has already been pushed to the ancestor stack.
        So the parent is the second-to-last item in the stack.
        """
        return self.ancestors[-2] if len(self.ancestors) >= 2 else None

    def is_descendant_of(self, node: ASTNode, ancestor: ASTNode) -> bool:
        """Check if node is descendant of ancestor."""
        return ancestor in self.ancestors

    def is_child_of(self, node: ASTNode, parent: ASTNode) -> bool:
        """Check if node is direct child of parent."""
        return self.get_parent() == parent


# ============================================================================
# Performance Utilities
# ============================================================================


# Relative cost weights used by estimate_query_cost (higher = more expensive).
_COMPARISON_OPERATORS = frozenset({">", "<", ">=", "<="})
_STRING_OPERATORS = frozenset({"*=", "^=", "$="})
_COMBINATOR_WEIGHTS = {" ": 3, ">": 1, "+": 1, "~": 2}
# Selectivity rank for fail-fast ordering (lower = more selective, evaluated first).
_SELECTIVITY_RANK = {"type": 0, "attribute_eq": 1, "attribute_cmp": 2, "pseudo": 3, "universal": 4}


def _selector_cost(selector: Any) -> int:
    from .selectors import (
        AttributeSelector,
        CompoundSelector,
        PseudoSelector,
        TypeSelector,
        UniversalSelector,
    )

    if isinstance(selector, TypeSelector):
        return 2 if selector.match_subclasses else 1
    if isinstance(selector, UniversalSelector):
        return 5
    if isinstance(selector, AttributeSelector):
        if selector.operator in _STRING_OPERATORS:
            return 4
        if selector.operator in _COMPARISON_OPERATORS:
            return 3
        return 2
    if isinstance(selector, PseudoSelector):
        return 5
    if isinstance(selector, CompoundSelector):
        return sum(_selector_cost(inner) for inner in selector.selectors)
    return 1


def estimate_query_cost(selector_chain: Any) -> int:
    """
    Estimate the relative computational cost of executing a query.

    The estimate is a heuristic: each selector contributes a base cost (cheap
    exact type matches up to expensive string/pseudo matches), scaled by the
    weight of the combinator that follows it (a descendant combinator walks the
    whole subtree and so costs more than a child/adjacent combinator). Higher
    means more expensive. Useful for comparing alternative formulations of the
    same query.

    Args:
        selector_chain: A SelectorChain or UnionSelector.

    Returns:
        A non-negative cost estimate.
    """
    from .parser import SelectorChain
    from .selectors import UnionSelector

    if isinstance(selector_chain, UnionSelector):
        return sum(estimate_query_cost(sub) for sub in selector_chain.selectors)
    if not isinstance(selector_chain, SelectorChain):
        return 0

    total = 0
    combinators = selector_chain.combinators
    for index, selector in enumerate(selector_chain.selectors):
        cost = _selector_cost(selector)
        if index < len(combinators):
            cost *= _COMBINATOR_WEIGHTS.get(_combinator_symbol(combinators[index]), 1)
        total += cost
    return total


def _combinator_symbol(combinator: Any) -> str:
    return getattr(combinator, "value", str(combinator))


def _selectivity_key(selector: Any) -> int:
    from .selectors import (
        AttributeSelector,
        PseudoSelector,
        TypeSelector,
        UniversalSelector,
    )

    if isinstance(selector, TypeSelector):
        return _SELECTIVITY_RANK["type"]
    if isinstance(selector, AttributeSelector):
        if selector.operator == "=":
            return _SELECTIVITY_RANK["attribute_eq"]
        return _SELECTIVITY_RANK["attribute_cmp"]
    if isinstance(selector, PseudoSelector):
        return _SELECTIVITY_RANK["pseudo"]
    if isinstance(selector, UniversalSelector):
        return _SELECTIVITY_RANK["universal"]
    return _SELECTIVITY_RANK["attribute_cmp"]


def _optimize_compound(selector: Any) -> Any:
    """Reorder a compound selector fail-fast first and drop duplicates (AND commutes)."""
    from .selectors import CompoundSelector

    if not isinstance(selector, CompoundSelector):
        return selector
    unique: list[Any] = []
    for inner in selector.selectors:
        if inner not in unique:
            unique.append(inner)
    unique.sort(key=_selectivity_key)
    return CompoundSelector(unique)


def optimize_selector_chain(selector_chain: Any) -> Any:
    """
    Rewrite a selector chain for cheaper execution, preserving its result set.

    Only semantics-preserving transformations are applied: within each compound
    selector (a logical AND, which commutes) the most selective sub-selectors
    are evaluated first and exact duplicates are removed. The order of selectors
    across combinators is never changed.

    Args:
        selector_chain: A SelectorChain or UnionSelector.

    Returns:
        An equivalent, optimized selector chain.
    """
    from .parser import SelectorChain
    from .selectors import UnionSelector

    if isinstance(selector_chain, UnionSelector):
        return UnionSelector([optimize_selector_chain(sub) for sub in selector_chain.selectors])
    if not isinstance(selector_chain, SelectorChain):
        return selector_chain

    optimized = [_optimize_compound(selector) for selector in selector_chain.selectors]
    return SelectorChain(optimized, list(selector_chain.combinators))
