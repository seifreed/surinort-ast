"""
Query API for surinort-ast - CSS/XPath-style selectors for IDS rules.

**STATUS**: Phase 1-3 implementation is COMPLETE and production-ready. The Query
API provides full hierarchical navigation, comparison operators, string operators,
pseudo-selectors, and union queries. Tested with 75+ tests covering all features.

This module provides a powerful query interface for searching and filtering
AST nodes using CSS-inspired selector syntax.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com

Usage:
    >>> from surinort_ast import parse_rule
    >>> from surinort_ast.query import query, query_all, query_first
    >>>
    >>> # Parse a rule
    >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
    >>>
    >>> # Query for specific node types
    >>> options = query(rule, "Option")
    >>> content = query(rule, "ContentOption")
    >>>
    >>> # Query with attribute filters
    >>> alert_rules = query_all(rules, "Rule[action=alert]")
    >>> high_sids = query(rule, "SidOption[value>1000000]")
    >>>
    >>> # Query with hierarchical selectors
    >>> tcp_headers = query(rule, "Rule > Header[protocol=tcp]")
    >>> all_contents = query(rule, "Rule ContentOption")
    >>>
    >>> # Query first match
    >>> first_sid = query_first(rule, "SidOption")
    >>>
    >>> # Check existence
    >>> has_pcre = query_exists(rule, "PcreOption")

Query Syntax:
    Type Selectors:
        "Rule"                      - Select all Rule nodes
        "ContentOption"             - Select all ContentOption nodes
        "Option"                    - Select all Option nodes (any type)

    Attribute Selectors:
        "Rule[action=alert]"        - Exact match
        "SidOption[value>1000000]"  - Comparison (>, <, >=, <=)
        "ContentOption[pattern*='admin']"  - Contains substring
        "MsgOption[text^='MALWARE']"       - Starts with
        "MsgOption[text$='detected']"      - Ends with
        "ContentOption[modifiers]"         - Attribute exists

    Hierarchical Selectors:
        "Rule ContentOption"                    - Descendant (any depth)
        "Rule > Header"                         - Direct child only
        "ContentOption + NocaseOption"          - Adjacent sibling
        "ContentOption ~ DepthOption"           - General sibling

    Pseudo-Selectors:
        "Rule > Option:first"               - First child
        "Rule > Option:last"                - Last child
        "Rule:empty"                        - No children
        "Rule:has(PcreOption)"              - Has descendant
        "Rule:not([action=alert])"          - Negation

    Compound Selectors:
        "Rule[action=alert] > Header[protocol=tcp]"  - Chained
        "ContentOption, PcreOption"                  - Union (OR)

Design Principles:
    1. Immutability: Queries never modify AST nodes
    2. Type Safety: Full type annotations and mypy compliance
    3. Performance: Optimized for 30K+ rule corpora
    4. Integration: Extends existing visitor pattern
    5. Extensibility: Easy to add new selector types

Architecture:
    query/
    ├── __init__.py          # Public API (this file)
    ├── parser.py            # Query string parser (Lark grammar)
    ├── selectors.py         # Selector AST nodes (TypeSelector, AttributeSelector, etc.)
    ├── executor.py          # Query execution engine (extends ASTVisitor)
    ├── matchers.py          # Attribute matching logic
    ├── combinators.py       # Hierarchical navigation logic
    └── grammar.lark         # Query grammar definition

Implementation Status:
    Phase 1 (MVP - Foundation) - ✅ COMPLETE:
        [✓] Basic type selectors (e.g., "ContentOption")
        [✓] Attribute equality selectors (e.g., "[value=1]")
        [✓] Universal selector ("*")
        [✓] Simple query execution
        [✓] Public API: query(), query_all(), query_first(), query_exists()
        [✓] Comprehensive test suite (31 tests)
        [✓] Usage examples and documentation

    Phase 2 (Hierarchical Navigation) - ✅ COMPLETE:
        [✓] Descendant combinator (space) - "Rule SidOption"
        [✓] Child combinator (>) - "Rule > Header"
        [✓] Sibling combinators (+, ~) - "ContentOption + NocaseOption"
        [✓] Compound selectors (AND) - "Rule[action=alert]"
        [✓] Union selectors (OR via comma) - "ContentOption, PcreOption"

    Phase 3 (Advanced Features) - ✅ COMPLETE:
        [✓] Comparison operators (>, <, >=, <=) - "SidOption[value>1000000]"
        [✓] String operators (*=, ^=, $=) - "MsgOption[text*='admin']"
        [✓] Pseudo-selectors (:first, :last, :has, :not, :empty)
        [✓] 45+ additional tests for Phase 2-3
        [✓] Performance optimizations for combinator chains

    Future Enhancements - 💡 IDEAS:
        [ ] Index-based execution
        [ ] Compiled queries
        [ ] Parallel execution
        [ ] Statistical queries
        [ ] CLI integration

Examples:
    Basic usage examples: examples/query_basic.py
    Advanced patterns: examples/query_advanced.py
    See also: QUERY_API_DESIGN.md for design documentation

Public API Overview:
    Core Functions:
        query()         - Query descendants of single node
        query_all()     - Query multiple nodes (collection)
        query_first()   - Query for first match
        query_exists()  - Check if any match exists

    Classes:
        QueryResult     - Wrapper for query results with convenience methods
        Q               - Fluent query builder

    Factory:
        create_selector - Build a selector object from a type + kwargs

    Exceptions:
        QueryError              - Base exception
        QuerySyntaxError        - Invalid query syntax
        QueryExecutionError     - Error during execution
        InvalidSelectorError    - Invalid selector configuration

Performance Targets:
    - Simple queries: <50ms for 30K rules
    - Complex queries: <100ms for 30K rules
    - Memory: <5MB overhead for query engine

Thread Safety:
    - Queries are thread-safe (read-only operations)
    - Multiple queries can run in parallel
    - Results are immutable (nodes are frozen Pydantic models)

See Also:
    - QUERY_API_DESIGN.md: Complete design documentation
    - examples/query_examples.py: Usage examples
    - tests/unit/query/: Test suite
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence

from surinort_ast.core.nodes import ASTNode

from .selectors import create_selector

# ============================================================================
# Module Status - EXPERIMENTAL/ALPHA
# ============================================================================

__status__ = "stable"  # Phase 1-3 complete
__version__ = "1.1.0"  # Phase 2-3 release

# Phase 2-3 features are now available!
# Note: Some edge cases and advanced features may still be in development

# ============================================================================
# Public API - Core Query Functions
# ============================================================================


def query(node: ASTNode, selector: str) -> list[ASTNode]:
    """
    Query descendants of a single AST node.

    This is the primary query function for searching within a single rule
    or node. It returns all descendants that match the selector.

    Args:
        node: Root AST node to query
        selector: CSS-style selector string

    Returns:
        List of matching AST nodes (may be empty)

    Raises:
        QuerySyntaxError: If selector syntax is invalid
        QueryExecutionError: If execution fails

    Example:
        >>> from surinort_ast import parse_rule
        >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
        >>>
        >>> # Find all options
        >>> options = query(rule, "Option")
        >>> len(options)  # 2 (MsgOption and SidOption)
        2
        >>>
        >>> # Find content patterns
        >>> contents = query(rule, "ContentOption")
        >>>
        >>> # Find specific SIDs
        >>> high_sids = query(rule, "SidOption[value>1000000]")
        >>>
        >>> # Complex hierarchical query
        >>> tcp_rules = query(rule, "Rule > Header[protocol=tcp]")

    Performance:
        - Simple type selectors: O(n) where n = number of nodes
        - Attribute filters: O(n * k) where k = attribute check cost
        - Target: <10ms for typical rule (~50 nodes)

    Thread Safety:
        Thread-safe (read-only operation on immutable nodes)

    See Also:
        query_all(): Query multiple nodes (e.g., rule collection)
        query_first(): Get only first match
        query_exists(): Check if any matches exist
    """
    from .executor import execute_query
    from .parser import QueryParser

    try:
        # Parse selector string
        parser = QueryParser()
        selector_chain = parser.parse(selector)

        # Execute query
        return execute_query(node, selector_chain)

    except QuerySyntaxError:
        raise
    except Exception as e:
        raise QueryExecutionError(f"Query execution failed: {e}") from e


def query_all(nodes: Sequence[ASTNode], selector: str) -> list[ASTNode]:
    """
    Query multiple AST nodes (e.g., a collection of rules).

    This function queries across a collection of nodes, useful for
    searching entire rule corpora or file contents.

    Args:
        nodes: Sequence of AST nodes to query
        selector: CSS-style selector string

    Returns:
        List of matching AST nodes from all input nodes

    Raises:
        QuerySyntaxError: If selector syntax is invalid
        QueryExecutionError: If execution fails

    Example:
        >>> from surinort_ast import parse_file
        >>> rules = parse_file("rules.rules")
        >>>
        >>> # Find all alert rules
        >>> alerts = query_all(rules, "Rule[action=alert]")
        >>>
        >>> # Find all rules with PCRE
        >>> pcre_rules = query_all(rules, "Rule:has(PcreOption)")
        >>>
        >>> # Find high-priority content patterns
        >>> patterns = query_all(
        ...     rules,
        ...     "Rule PriorityOption[value<=2] ~ ContentOption"
        ... )
        >>>
        >>> # Find rules targeting HTTP
        >>> http_rules = query_all(rules, "Rule > Header[protocol=http]")

    Performance:
        - Target: <100ms for 30K rules with simple selectors
        - Optimized for batch processing
        - Consider indexed execution for repeated queries (future)

    Thread Safety:
        Thread-safe (read-only operation on immutable nodes)

    See Also:
        query(): Query single node
        query_first(): Get only first match across collection
        query_exists(): Check if any matches exist in collection
    """
    from .executor import execute_query
    from .parser import QueryParser

    try:
        # Parse selector string
        parser = QueryParser()
        selector_chain = parser.parse(selector)

        # Execute query on all nodes
        return execute_query(nodes, selector_chain)

    except QuerySyntaxError:
        raise
    except Exception as e:
        raise QueryExecutionError(f"Query execution failed: {e}") from e


def query_first(node: ASTNode | Sequence[ASTNode], selector: str) -> ASTNode | None:
    """
    Query for the first matching descendant.

    Returns the first node that matches the selector, or None if no matches.
    More efficient than query() when only one result is needed.

    Args:
        node: Single AST node or sequence of nodes
        selector: CSS-style selector string

    Returns:
        First matching AST node, or None if no matches

    Raises:
        QuerySyntaxError: If selector syntax is invalid
        QueryExecutionError: If execution fails

    Example:
        >>> from surinort_ast import parse_rule
        >>> rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
        >>>
        >>> # Get SID (typically only one per rule)
        >>> sid = query_first(rule, "SidOption")
        >>> if sid:
        ...     print(sid.value)
        1
        >>>
        >>> # Check for first content pattern
        >>> content = query_first(rule, "ContentOption")
        >>>
        >>> # Get first high-priority rule from corpus
        >>> rules = parse_file("rules.rules")
        >>> high_pri = query_first(rules, "Rule PriorityOption[value=1]")

    Performance:
        - Stops at first match (early exit optimization)
        - Faster than query() when only one result needed
        - Target: <5ms for typical rule

    Thread Safety:
        Thread-safe (read-only operation on immutable nodes)

    See Also:
        query(): Get all matches
        query_exists(): Only check existence (even faster)
    """
    from .executor import execute_query_first
    from .parser import QueryParser

    try:
        # Parse selector string
        parser = QueryParser()
        selector_chain = parser.parse(selector)

        # Execute query and return first result
        return execute_query_first(node, selector_chain)

    except QuerySyntaxError:
        raise
    except Exception as e:
        raise QueryExecutionError(f"Query execution failed: {e}") from e


def query_exists(node: ASTNode | Sequence[ASTNode], selector: str) -> bool:
    """
    Check if any descendant matches the selector.

    More efficient than query() or query_first() when only existence
    check is needed. Returns immediately upon first match.

    Args:
        node: Single AST node or sequence of nodes
        selector: CSS-style selector string

    Returns:
        True if at least one match exists, False otherwise

    Raises:
        QuerySyntaxError: If selector syntax is invalid
        QueryExecutionError: If execution fails

    Example:
        >>> from surinort_ast import parse_rule
        >>> rule = parse_rule('alert tcp any any -> any 80 (pcre:"/test/"; sid:1;)')
        >>>
        >>> # Check if rule has PCRE
        >>> if query_exists(rule, "PcreOption"):
        ...     print("Rule uses PCRE patterns")
        Rule uses PCRE patterns
        >>>
        >>> # Check if rule has fast_pattern optimization
        >>> optimized = query_exists(rule, "FastPatternOption")
        >>>
        >>> # Check corpus for specific patterns
        >>> rules = parse_file("rules.rules")
        >>> has_admin = query_exists(rules, "ContentOption[pattern*='admin']")

    Performance:
        - Fastest query operation (early exit on first match)
        - Target: <3ms for typical rule
        - Preferred over query() when only checking existence

    Thread Safety:
        Thread-safe (read-only operation on immutable nodes)

    See Also:
        query_first(): Get the first match
        query(): Get all matches
    """
    from .executor import execute_query_exists
    from .parser import QueryParser

    try:
        # Parse selector string
        parser = QueryParser()
        selector_chain = parser.parse(selector)

        # Check existence
        return execute_query_exists(node, selector_chain)

    except QuerySyntaxError:
        raise
    except Exception as e:
        raise QueryExecutionError(f"Query execution failed: {e}") from e


# ============================================================================
# Result wrapper and fluent builder
# ============================================================================


class QueryResult:
    """
    Wrapper for query results with convenience methods.

    Provides a fluent interface for working with query results, including
    counting, first/last access, existence checks, and further filtering.

    Example:
        >>> result = QueryResult(query(rule, "ContentOption, SidOption"))
        >>> result.count()
        2
        >>> result.first() is not None
        True
        >>> result.filter("SidOption").exists()
        True
    """

    def __init__(self, nodes: Sequence[ASTNode], root: ASTNode | None = None) -> None:
        """
        Args:
            nodes: Matched AST nodes.
            root: Optional root the nodes were queried from (unused by the
                current convenience methods; kept for future re-querying).
        """
        self._nodes: list[ASTNode] = list(nodes)
        self._root = root

    @property
    def nodes(self) -> list[ASTNode]:
        """Return a copy of the matched nodes."""
        return list(self._nodes)

    def first(self) -> ASTNode | None:
        """Return the first matched node, or None."""
        return self._nodes[0] if self._nodes else None

    def last(self) -> ASTNode | None:
        """Return the last matched node, or None."""
        return self._nodes[-1] if self._nodes else None

    def count(self) -> int:
        """Return the number of matched nodes."""
        return len(self._nodes)

    def exists(self) -> bool:
        """Return True if there is at least one matched node."""
        return bool(self._nodes)

    def filter(self, selector: str) -> QueryResult:
        """
        Narrow the result to nodes matching a simple selector.

        The node is tested per-element against the base selector; result-set
        pseudo-selectors (:first/:last/:even/:odd/:nth/:within) then narrow the
        surviving ordered list, so ``filter("ContentOption:first")`` keeps the
        first matched content option.

        Args:
            selector: A simple selector (type/attribute/compound, no combinators).

        Returns:
            A new QueryResult with the surviving nodes.

        Raises:
            QuerySyntaxError: If the selector uses combinators.
        """
        from .parser import QueryParser
        from .selectors import apply_result_set_pseudos, split_result_set_pseudos

        chain = QueryParser().parse(selector)
        if getattr(chain, "combinators", None):
            raise QuerySyntaxError(
                "QueryResult.filter() supports only simple selectors (no combinators)"
            )

        base, pseudos = split_result_set_pseudos(chain.selectors[0])
        # Pseudo-selectors require an execution context, which a standalone node
        # test cannot provide; the base predicate ignores it.
        survivors = [node for node in self._nodes if bool(base.matches(node, None))]
        return QueryResult(apply_result_set_pseudos(survivors, pseudos), self._root)

    def __iter__(self) -> Iterator[ASTNode]:
        return iter(self._nodes)

    def __len__(self) -> int:
        return len(self._nodes)

    def __getitem__(self, index: int) -> ASTNode:
        return self._nodes[index]

    def __repr__(self) -> str:
        return f"QueryResult({len(self._nodes)} nodes)"


# Friendly operator aliases accepted by Q.with_attr, mapped to grammar operators.
_ATTR_OPERATORS = {
    "equals": "=",
    "eq": "=",
    "not_equals": "!=",
    "ne": "!=",
    "gt": ">",
    "lt": "<",
    "gte": ">=",
    "lte": "<=",
    "contains": "*=",
    "startswith": "^=",
    "endswith": "$=",
}


def _format_attr_value(value: object) -> str:
    """Format a Python value as a selector attribute value (STRING/NUMBER/IDENT)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    text = str(value)
    if "'" not in text:
        return f"'{text}'"
    if '"' not in text:
        return f'"{text}"'
    # The selector grammar has no string-escape mechanism, so a value containing
    # both quote characters cannot be represented. Fail loudly rather than emit a
    # selector that silently drops the apostrophes and matches the wrong node.
    raise ValueError(
        "attribute value cannot contain both single and double quotes: "
        f"{text!r} is not representable as a selector string"
    )


class Q:
    """
    Fluent query builder for programmatic selector construction.

    Builds a selector string without manual string manipulation; the result of
    :meth:`build` round-trips through :func:`query`.

    Example:
        >>> selector = (
        ...     Q("Rule")
        ...     .with_attr("action", "alert")
        ...     .descendant(Q("ContentOption"))
        ...     .build()
        ... )
        >>> selector
        "Rule[action='alert'] ContentOption"
    """

    def __init__(self, type_name: str | None = None) -> None:
        """
        Args:
            type_name: Optional initial type selector (e.g. "Rule"). Omit for
                a universal-style start built up purely from attributes.
        """
        self._selector = "" if type_name is None else str(type_name)

    def with_attr(self, name: str, value: object = None, operator: str = "=") -> Q:
        """
        Append an attribute filter ``[name op value]`` (or ``[name]`` for existence).

        Args:
            name: Attribute name.
            value: Value to compare; omit for an existence check.
            operator: Grammar operator ("=", "!=", ">", ...) or a friendly
                alias ("equals", "contains", "startswith", ...).
        """
        op = _ATTR_OPERATORS.get(operator, operator)
        if value is None:
            self._selector += f"[{name}]"
        else:
            self._selector += f"[{name}{op}{_format_attr_value(value)}]"
        return self

    def descendant(self, other: Q | str) -> Q:
        """Append a descendant combinator (space) followed by ``other``."""
        return self._combine(" ", other)

    def child(self, other: Q | str) -> Q:
        """Append a child combinator (>) followed by ``other``."""
        return self._combine(" > ", other)

    def adjacent(self, other: Q | str) -> Q:
        """Append an adjacent-sibling combinator (+) followed by ``other``."""
        return self._combine(" + ", other)

    def sibling(self, other: Q | str) -> Q:
        """Append a general-sibling combinator (~) followed by ``other``."""
        return self._combine(" ~ ", other)

    def or_(self, other: Q | str) -> Q:
        """Append a union (comma) followed by ``other``."""
        return self._combine(", ", other)

    def _combine(self, combinator: str, other: Q | str) -> Q:
        self._selector += f"{combinator}{other.build() if isinstance(other, Q) else other}"
        return self

    def build(self) -> str:
        """Return the assembled selector string."""
        return self._selector

    def __str__(self) -> str:
        return self._selector

    def __repr__(self) -> str:
        return f"Q({self._selector!r})"


# ============================================================================
# Exceptions
# ============================================================================


class QueryError(Exception):
    """
    Base exception for all query-related errors.

    All query exceptions inherit from this class, allowing
    catch-all error handling for query operations.

    Example:
        >>> try:
        ...     results = query(rule, "InvalidSelector[")
        ... except QueryError as e:
        ...     print(f"Query failed: {e}")
    """


class QuerySyntaxError(QueryError):
    """
    Raised when query selector syntax is invalid.

    This exception indicates a parsing error in the selector string.
    The error message should include the invalid syntax and position.

    Example:
        >>> try:
        ...     query(rule, "Rule[action=")  # Incomplete attribute selector
        ... except QuerySyntaxError as e:
        ...     print(f"Syntax error: {e}")
        Syntax error: Expected closing bracket ']' at position 12
    """


class QueryExecutionError(QueryError):
    """
    Raised when query execution fails.

    This exception indicates an error during query execution,
    such as invalid attribute access or unexpected node types.

    Example:
        >>> try:
        ...     query(rule, "Rule[nonexistent_attr=value]")
        ... except QueryExecutionError as e:
        ...     print(f"Execution error: {e}")
    """


class InvalidSelectorError(QueryError):
    """
    Raised when selector configuration is invalid.

    This exception indicates a semantic error in the selector,
    such as invalid operator combinations or logical errors.

    Example:
        >>> try:
        ...     query(rule, "Rule[value>string_value]")  # Type mismatch
        ... except InvalidSelectorError as e:
        ...     print(f"Invalid selector: {e}")
    """


# ============================================================================
# Public API Exports
# ============================================================================

__all__ = [
    "InvalidSelectorError",
    "Q",
    "QueryError",
    "QueryExecutionError",
    "QueryResult",
    "QuerySyntaxError",
    "create_selector",
    "query",
    "query_all",
    "query_exists",
    "query_first",
]

# ============================================================================
# Module Metadata
# ============================================================================

# Note: __version__ and __status__ are defined at top of file
__author__ = "Marc Rivero López"
__license__ = "GPL-3.0"

# Implementation notes:
#
# Phase 1 (MVP - Foundation):
# - Implement parser.py with basic Lark grammar
# - Implement selectors.py with TypeSelector and AttributeSelector
# - Implement executor.py with QueryExecutor(ASTVisitor)
# - Implement query(), query_all(), query_first() functions
# - Unit tests for basic functionality
#
# Phase 2 (Hierarchical Navigation):
# - Add combinators.py for hierarchical logic
# - Extend executor.py with context stack
# - Support descendant, child, sibling combinators
# - Integration tests with real corpus
#
# Phase 3 (Advanced Features):
# - Add matchers.py for advanced attribute matching
# - Implement pseudo-selectors
# - Add QueryResult wrapper class
# - Add Q fluent builder
# - Performance optimizations
# - Comprehensive documentation
#
# Design constraints:
# - Must work with frozen Pydantic models
# - Must be thread-safe (read-only)
# - Must integrate with existing visitor pattern
# - Must have full type annotations
# - Must target <100ms for 30K rules
#
# See QUERY_API_DESIGN.md for complete design documentation.
