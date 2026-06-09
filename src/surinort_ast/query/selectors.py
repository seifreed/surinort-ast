"""
Selector Classes - AST nodes for query selectors.

This module defines the selector class hierarchy used to represent
parsed query selectors. Each selector type implements a matches()
method to test if an AST node satisfies the selector criteria.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING, Any

from surinort_ast.core.nodes import ASTNode

from .registry import resolve_node_type

# Avoid circular imports - ExecutionContext, QueryExecutor, SelectorChain
# are imported locally where needed
if TYPE_CHECKING:
    pass

# ============================================================================
# Selector Base Class
# ============================================================================


class Selector(ABC):
    """
    Abstract base class for all selector types.

    All selectors implement the matches() method to test if an AST node
    satisfies the selector criteria. Selectors are immutable and thread-safe.

    Subclasses:
        - TypeSelector: Matches by node type
        - UniversalSelector: Matches any node
        - AttributeSelector: Matches by attribute value
        - CompoundSelector: Combines multiple selectors (AND)
        - UnionSelector: Combines multiple selectors (OR)
        - PseudoSelector: Special matching logic (:first, :has, etc.)

    Design:
        - Immutable: Selectors never change after construction
        - Composable: Selectors can be combined via CompoundSelector
        - Type-safe: Full type annotations and mypy compliance
    """

    @abstractmethod
    def matches(self, node: ASTNode, context: Any = None) -> bool:
        """
        Test if AST node matches this selector.

        Args:
            node: AST node to test
            context: Execution context (parent/sibling position) for selectors
                that need it; ignored by selectors that match on the node alone.

        Returns:
            True if node matches, False otherwise

        Example:
            >>> selector = TypeSelector("ContentOption")
            >>> node = ContentOption(pattern=b"test")
            >>> selector.matches(node)
            True
        """

    @abstractmethod
    def __repr__(self) -> str:
        """String representation for debugging."""

    @abstractmethod
    def __eq__(self, other: object) -> bool:
        """Equality comparison for selectors."""

    @abstractmethod
    def __hash__(self) -> int:
        """Hash value for selectors."""


# ============================================================================
# Basic Selectors (Phase 1)
# ============================================================================


class TypeSelector(Selector):
    """
    Selects nodes by type name.

    Matches nodes where node.node_type equals the specified type name.
    Optionally matches base classes (e.g., "AddressExpr" matches all
    address types).

    Attributes:
        type_name: Node type to match (e.g., "ContentOption")
        match_subclasses: If True, match derived types too

    Example:
        >>> # Exact type match
        >>> selector = TypeSelector("ContentOption")
        >>> selector.matches(ContentOption(pattern=b"test"))
        True
        >>>
        >>> # Base class match
        >>> selector = TypeSelector("AddressExpr", match_subclasses=True)
        >>> selector.matches(IPAddress(value="192.168.1.1", version=4))
        True
    """

    def __init__(self, type_name: str, match_subclasses: bool = False) -> None:
        """
        Initialize type selector.

        Args:
            type_name: Node type name to match
            match_subclasses: Match derived types if True
        """
        self.type_name = type_name
        self.match_subclasses = match_subclasses

    def matches(self, node: ASTNode, context: Any = None) -> bool:
        """
        Test if node type matches.

        With ``match_subclasses`` the node matches the named type or any of
        its AST subclasses (e.g. ``TypeSelector("Option", match_subclasses=True)``
        matches ``SidOption``, ``MsgOption``, ...). Otherwise the match is on the
        exact ``node_type`` name.

        Args:
            node: AST node to test

        Returns:
            True if node type matches
        """
        if self.match_subclasses:
            target = resolve_node_type(self.type_name)
            if target is not None:
                return isinstance(node, target)
            # Unknown type name: fall back to exact-name matching.
            return node.node_type == self.type_name
        return node.node_type == self.type_name

    def __repr__(self) -> str:
        """String representation."""
        subclass_marker = "~" if self.match_subclasses else ""
        return f"TypeSelector({subclass_marker}{self.type_name})"

    def __eq__(self, other: object) -> bool:
        """Equality comparison."""
        if not isinstance(other, TypeSelector):
            return False
        return self.type_name == other.type_name and self.match_subclasses == other.match_subclasses

    def __hash__(self) -> int:
        """Hash value based on type_name and match_subclasses."""
        return hash((self.type_name, self.match_subclasses))


class UniversalSelector(Selector):
    """
    Matches any node (wildcard selector "*").

    Always returns True for any AST node. Useful for debugging
    or as part of compound selectors.

    Example:
        >>> selector = UniversalSelector()
        >>> selector.matches(any_node)
        True
        >>>
        >>> # As part of compound: "*[location]" matches any node with location
        >>> compound = CompoundSelector([
        ...     UniversalSelector(),
        ...     AttributeSelector("location", "exists")
        ... ])

    Implementation:
        Phase 1: Simple always-true matcher
    """

    def matches(self, node: ASTNode, context: Any = None) -> bool:
        """Always matches."""
        return True

    def __repr__(self) -> str:
        """String representation."""
        return "UniversalSelector(*)"

    def __eq__(self, other: object) -> bool:
        """All universal selectors are equal."""
        return isinstance(other, UniversalSelector)

    def __hash__(self) -> int:
        """Hash value - all universal selectors hash the same."""
        return hash(UniversalSelector)


class AttributeSelector(Selector):
    """
    Selects nodes by attribute values.

    Matches nodes based on attribute existence and/or value comparison.
    Supports multiple operators: =, !=, >, <, >=, <=, *=, ^=, $=.

    Attributes:
        attribute: Attribute name to check
        operator: Comparison operator
        value: Value to compare against (None for existence check)

    Operators:
        =   : Exact equality
        !=  : Not equal
        >   : Greater than (numeric)
        <   : Less than (numeric)
        >=  : Greater than or equal (numeric)
        <=  : Less than or equal (numeric)
        *=  : Contains substring (string)
        ^=  : Starts with (string)
        $=  : Ends with (string)
        (exists): Attribute exists (value=None)

    Example:
        >>> # Equality
        >>> selector = AttributeSelector("value", "=", 1000001)
        >>> selector.matches(SidOption(value=1000001))
        True
        >>>
        >>> # Comparison
        >>> selector = AttributeSelector("value", ">", 1000000)
        >>> selector.matches(SidOption(value=1000001))
        True
        >>>
        >>> # Substring
        >>> selector = AttributeSelector("text", "*=", "admin")
        >>> selector.matches(MsgOption(text="Admin login detected"))
        True
        >>>
        >>> # Existence
        >>> selector = AttributeSelector("location", "exists")
        >>> selector.matches(node_with_location)
        True

    Implementation:
        Phase 1: Equality operator (=) only
        Phase 2: Comparison operators (>, <, >=, <=)
        Phase 3: String operators (*=, ^=, $=) and existence check
    """

    def __init__(self, attribute: str, operator: str, value: Any = None) -> None:
        """
        Initialize attribute selector.

        Args:
            attribute: Attribute name to check
            operator: Comparison operator
            value: Value to compare (None for existence check)

        Raises:
            InvalidSelectorError: If operator is invalid
        """
        self.attribute = attribute
        self.operator = operator
        self.value = value

        # Validate operator
        valid_operators = {"=", "!=", ">", "<", ">=", "<=", "*=", "^=", "$=", "exists"}
        if operator not in valid_operators:
            from . import InvalidSelectorError

            raise InvalidSelectorError(f"Invalid operator: {operator}")

    @staticmethod
    def _values_equal(node_value: Any, query_value: Any) -> bool:
        """Compare an attribute value to a query value.

        Boolean attributes are compared against the conventional lowercase
        ``true``/``false`` (Python's ``str(bool)`` is capitalized), so both
        casings match; everything else falls back to string comparison.
        """
        if isinstance(node_value, bool):
            return ("true" if node_value else "false") == str(query_value).lower()
        # Compare numbers numerically so 100 == 100.0, consistent with the
        # >/</>=/<= operators; otherwise "100" != "100.0" would make = and >=
        # disagree on equality.
        try:
            return float(node_value) == float(query_value)
        except (ValueError, TypeError):
            return str(node_value) == str(query_value)

    def matches(self, node: ASTNode, context: Any = None) -> bool:
        """
        Test if node attribute matches criteria.

        Args:
            node: AST node to test

        Returns:
            True if attribute matches

        Implementation:
            1. Check if attribute exists on node
            2. Get attribute value
            3. Apply operator-specific comparison
            4. Handle type conversions and special cases
        """
        # Resolve the (possibly dotted) attribute path, e.g.
        # "location.span.start.line"; a flat getattr would never match a dotted
        # path the grammar accepts.
        node_value: Any = node
        for part in self.attribute.split("."):
            if not hasattr(node_value, part):
                return False
            node_value = getattr(node_value, part)

        # Handle existence check
        if self.operator == "exists":
            return node_value is not None

        # Normalize node value for comparison
        if hasattr(node_value, "value"):
            # It's an enum - use its value
            node_value = node_value.value

        # Decode bytes attributes (e.g. ContentOption.pattern) so comparisons
        # run against the textual content rather than the b'...' repr.
        if isinstance(node_value, bytes):
            node_value = node_value.decode("utf-8", errors="replace")

        # Equality operators
        if self.operator == "=":
            return self._values_equal(node_value, self.value)

        if self.operator == "!=":
            return not self._values_equal(node_value, self.value)

        # Comparison operators (Phase 3) - numeric only
        if self.operator in {">", "<", ">=", "<="}:
            try:
                node_num = (
                    float(node_value)
                    if isinstance(node_value, (int, float, str))
                    else float(str(node_value))
                )
                value_num = (
                    float(self.value)
                    if isinstance(self.value, (int, float, str))
                    else float(str(self.value))
                )

                if self.operator == ">":
                    return node_num > value_num
                if self.operator == "<":
                    return node_num < value_num
                if self.operator == ">=":
                    return node_num >= value_num
                if self.operator == "<=":
                    return node_num <= value_num
            except (ValueError, TypeError):
                # If conversion fails, comparison is false
                return False

        # String operators (Phase 3)
        if self.operator in {"*=", "^=", "$="}:
            node_str = str(node_value)
            value_str = str(self.value)

            if self.operator == "*=":
                # Contains substring
                return value_str in node_str
            if self.operator == "^=":
                # Starts with
                return node_str.startswith(value_str)
            if self.operator == "$=":
                # Ends with
                return node_str.endswith(value_str)

        # Unknown operator
        return False

    def __repr__(self) -> str:
        """String representation."""
        if self.operator == "exists":
            return f"AttributeSelector([{self.attribute}])"
        return f"AttributeSelector([{self.attribute}{self.operator}{self.value}])"

    def __eq__(self, other: object) -> bool:
        """Equality comparison."""
        if not isinstance(other, AttributeSelector):
            return False
        return (
            self.attribute == other.attribute
            and self.operator == other.operator
            and self.value == other.value
        )

    def __hash__(self) -> int:
        """Hash value based on attribute, operator, and value."""
        # Handle unhashable values (like lists) by converting to string
        try:
            value_hash = hash(self.value)
        except TypeError:
            value_hash = hash(str(self.value))
        return hash((self.attribute, self.operator, value_hash))


# ============================================================================
# Compound Selectors (Phase 2)
# ============================================================================


class CompoundSelector(Selector):
    """
    Combines multiple selectors with AND logic.

    Matches nodes that satisfy ALL contained selectors.
    Used for queries like "Rule[action=alert][protocol=tcp]".

    Attributes:
        selectors: List of selectors to combine

    Example:
        >>> # "Rule[action=alert]" becomes CompoundSelector
        >>> compound = CompoundSelector([
        ...     TypeSelector("Rule"),
        ...     AttributeSelector("action", "=", "alert")
        ... ])
        >>> compound.matches(alert_rule)
        True

    Implementation:
        Phase 2: Basic AND logic
        Phase 3: Optimization (early exit, reordering)
    """

    def __init__(self, selectors: list[Selector]) -> None:
        """
        Initialize compound selector.

        Args:
            selectors: List of selectors to combine with AND

        Raises:
            InvalidSelectorError: If selectors list is empty
        """
        if not selectors:
            from . import InvalidSelectorError

            raise InvalidSelectorError("CompoundSelector requires at least one selector")
        self.selectors = selectors

    def matches(self, node: ASTNode, context: Any = None) -> bool:
        """
        Test if node matches all selectors.

        The execution context is threaded to every member selector so that a
        positional pseudo-selector combined with a type selector
        (e.g. ``ContentOption:first``) can resolve the node's sibling position.

        Args:
            node: AST node to test
            context: Execution context passed through to member selectors.

        Returns:
            True if all selectors match
        """
        return all(selector.matches(node, context) for selector in self.selectors)

    def __repr__(self) -> str:
        """String representation."""
        return f"CompoundSelector({self.selectors})"

    def __eq__(self, other: object) -> bool:
        """Equality comparison."""
        if not isinstance(other, CompoundSelector):
            return False
        return self.selectors == other.selectors

    # Explicitly unhashable due to mutable list of selectors
    __hash__ = None  # type: ignore[assignment]


class UnionSelector(Selector):
    """
    Combines multiple selectors with OR logic.

    Matches nodes that satisfy ANY contained selector.
    Used for queries like "ContentOption, PcreOption".

    Attributes:
        selectors: List of selectors to combine

    Example:
        >>> # "ContentOption, PcreOption" becomes UnionSelector
        >>> union = UnionSelector([
        ...     TypeSelector("ContentOption"),
        ...     TypeSelector("PcreOption")
        ... ])
        >>> union.matches(content_node)
        True
        >>> union.matches(pcre_node)
        True

    Implementation:
        Phase 2: Basic OR logic
        Phase 3: Optimization (early exit on first match)
    """

    def __init__(self, selectors: list[Selector]) -> None:
        """
        Initialize union selector.

        Args:
            selectors: List of selectors to combine with OR

        Raises:
            InvalidSelectorError: If selectors list is empty
        """
        if not selectors:
            from . import InvalidSelectorError

            raise InvalidSelectorError("UnionSelector requires at least one selector")
        self.selectors = selectors

    def matches(self, node: ASTNode, context: Any = None) -> bool:
        """
        Test if node matches any selector.

        Args:
            node: AST node to test
            context: Execution context passed through to member selectors.

        Returns:
            True if any selector matches
        """
        # Early exit optimization: return True on first match
        return any(selector.matches(node, context) for selector in self.selectors)

    def __repr__(self) -> str:
        """String representation."""
        return f"UnionSelector({self.selectors})"

    def __eq__(self, other: object) -> bool:
        """Equality comparison."""
        if not isinstance(other, UnionSelector):
            return False
        return self.selectors == other.selectors

    # Explicitly unhashable due to mutable list of selectors
    __hash__ = None  # type: ignore[assignment]


# ============================================================================
# Pseudo-Selectors (Phase 3)
# ============================================================================


# CSS-style positional pseudo-selectors: a per-node test against the node's
# index among its parent's children.
_CHILD_POSITION_PSEUDO = frozenset({"first-child", "last-child"})

# jQuery-style positional pseudo-selectors: they narrow the ordered set of
# matched nodes rather than testing a single node. The executor applies them to
# the result list; per node they are always satisfied (see PseudoSelector.matches).
_RESULT_SET_PSEUDO = frozenset({"first", "last", "even", "odd", "nth", "within"})


class PseudoSelector(Selector):
    """
    Special selector types with custom matching logic.

    Implements pseudo-selectors like :first, :last, :has(), :not().
    These selectors require context information beyond the node itself.

    Types:
        :first                - First node in the matched set (jQuery-style)
        :last                 - Last node in the matched set
        :even                 - Matches at even 0-based result index (0, 2, 4, ...)
        :odd                  - Matches at odd 0-based result index (1, 3, 5, ...)
        :nth(n)               - Match at exactly result index n (0-based)
        :within(n)            - The first n matches (result index < n)
        :first-child          - First child of its parent (CSS-style, per-node)
        :last-child           - Last child of its parent (CSS-style, per-node)
        :empty                - No child nodes
        :not-empty            - Has child nodes
        :has(selector)        - Has descendant matching selector
        :not(selector)        - Does not match selector

    Two positional families with different scopes:

    - Result-set (:first, :last, :even, :odd, :nth, :within) narrow the ordered
      list of nodes the rest of the selector matched, like jQuery. They are not
      a per-node test; the executor applies them to the collected result set, so
      ``ContentOption:first`` is the first matched content option.
    - Child-position (:first-child, :last-child) test whether the node is the
      first/last child of its parent. Position comes from the execution
      context's ancestor stack and the node is found among its siblings by
      identity, so value-equal siblings (e.g. two ``any`` addresses) are never
      confused. The root node, which has no parent, is treated as a sole child.

    Attributes:
        pseudo_type: Type of pseudo-selector
        argument: Optional argument (e.g., selector for :has)

    Example:
        >>> # First option in rule
        >>> selector = PseudoSelector("first")
        >>> # Used in context: "Rule > Option:first"
        >>>
        >>> # Has descendant
        >>> selector = PseudoSelector("has", TypeSelector("PcreOption"))
        >>> # Used as: "Rule:has(PcreOption)"

    Implementation:
        Phase 3: All pseudo-selector types
        Note: Some pseudo-selectors require executor context
    """

    def __init__(self, pseudo_type: str, argument: Any = None) -> None:
        """
        Initialize pseudo-selector.

        Args:
            pseudo_type: Type of pseudo-selector
            argument: Optional argument (e.g., nested selector)
        """
        self.pseudo_type = pseudo_type
        self.argument = argument

    def matches(self, node: ASTNode, context: Any = None) -> bool:
        """
        Test if node matches pseudo-selector.

        Args:
            node: AST node to test
            context: Execution context (parent, siblings, etc.)

        Returns:
            True if matches

        Note:
            Many pseudo-selectors require context from executor.
            The context provides parent/sibling information.
        """
        from .executor import ExecutionContext

        # Context is required for most pseudo-selectors
        if context is None:
            context = ExecutionContext()

        # Simple pseudo-selectors
        if self.pseudo_type == "empty":
            # Node has no children
            return not self._has_children(node)

        if self.pseudo_type == "not-empty":
            # Node has children
            return self._has_children(node)

        # CSS-style positional pseudo-selectors test this node's position.
        if self.pseudo_type in _CHILD_POSITION_PSEUDO:
            return self._matches_position(node, context)

        # jQuery-style positional pseudo-selectors narrow the matched set; a
        # single node always satisfies them and the executor applies the actual
        # selection to the ordered result list.
        if self.pseudo_type in _RESULT_SET_PSEUDO:
            return True

        # Functional pseudo-selectors (require argument)
        if self.pseudo_type == "has":
            # Node has descendant matching selector
            if self.argument is None:
                return False
            return self._has_descendant(node, self.argument)

        if self.pseudo_type == "not":
            # Node does not match selector
            if self.argument is None:
                return True
            # Execute the argument selector chain against the node
            from .parser import SelectorChain

            # Wrap single selector in a chain if needed
            if not isinstance(self.argument, SelectorChain):
                chain = SelectorChain([self.argument], [])
            else:
                chain = self.argument

            if not chain.selectors:
                return True
            # Single selector with no combinator: test it directly against this node.
            if len(chain.selectors) == 1 and not chain.combinators:
                return not chain.selectors[0].matches(node, context)
            # Combinator chain (e.g. :not(Rule > ContentOption)): the relationship
            # matters, so run the chain against the traversal root and check whether
            # this node is among its matches (by identity).
            from .executor import QueryExecutor

            ancestors = getattr(context, "ancestors", None)
            root = ancestors[0] if ancestors else node
            matches = QueryExecutor(chain).execute(root)
            return not any(match is node for match in matches)

        # Unknown pseudo-selector
        return False

    def _has_children(self, node: ASTNode) -> bool:
        """Check if node has any children."""
        for attr_name, attr_value in node.__dict__.items():
            if attr_name.startswith("_"):
                continue
            if isinstance(attr_value, list | tuple) and attr_value:
                if any(hasattr(item, "node_type") for item in attr_value):
                    return True
            elif hasattr(attr_value, "node_type"):
                return True
        return False

    def _matches_position(self, node: ASTNode, context: Any) -> bool:
        """Match :first-child / :last-child against the node's sibling index.

        The 0-based index and sibling count come from the execution context,
        which locates the node by identity among its parent's query children.
        """
        position: tuple[int, int] | None = (
            context.child_position(node) if hasattr(context, "child_position") else None
        )
        if position is None:
            return False

        index, count = position
        if self.pseudo_type == "first-child":
            return index == 0
        if self.pseudo_type == "last-child":
            return index == count - 1
        return False

    def _has_descendant(self, node: ASTNode, selector: Any) -> bool:
        """Check if node has any descendant matching selector."""
        # Use a simple visitor to check descendants
        from .executor import QueryExecutor
        from .parser import SelectorChain

        # Create a temporary selector chain
        if not isinstance(selector, SelectorChain):
            # Wrap single selector in a chain
            chain = SelectorChain([selector], [])
        else:
            chain = selector

        # Execute query on this node
        executor = QueryExecutor(chain)
        results = executor.execute(node)

        # Check if any results (excluding the node itself)
        return any(r != node for r in results)

    def __repr__(self) -> str:
        """String representation."""
        if self.argument:
            return f"PseudoSelector(:{self.pseudo_type}({self.argument}))"
        return f"PseudoSelector(:{self.pseudo_type})"

    def __eq__(self, other: object) -> bool:
        """Equality comparison."""
        if not isinstance(other, PseudoSelector):
            return False
        return self.pseudo_type == other.pseudo_type and self.argument == other.argument

    def __hash__(self) -> int:
        """Hash value based on pseudo_type and argument."""
        # Handle unhashable arguments by converting to string
        try:
            arg_hash = hash(self.argument)
        except TypeError:
            arg_hash = hash(str(self.argument)) if self.argument is not None else 0
        return hash((self.pseudo_type, arg_hash))


# ============================================================================
# Result-set Pseudo-selector Support
# ============================================================================


def split_result_set_pseudos(
    selector: "Selector",
) -> tuple["Selector", list[PseudoSelector]]:
    """Partition a combinator-free selector into a per-node base and result-set pseudos.

    Result-set pseudo-selectors (:first/:last/:even/:odd/:nth/:within) are not a
    per-node predicate; they select from the ordered set of matched nodes. This
    splits them off so the executor can match every node against ``base`` and
    then narrow the collected results with ``pseudos`` (in source order).

    Args:
        selector: The result-producing selector of a chain (no combinators).

    Returns:
        ``(base, pseudos)``. ``base`` is matched per node and is a
        :class:`UniversalSelector` when the selector consisted solely of
        result-set pseudos. ``pseudos`` is empty when there is nothing to narrow.
    """
    if isinstance(selector, PseudoSelector):
        if selector.pseudo_type in _RESULT_SET_PSEUDO:
            return UniversalSelector(), [selector]
        return selector, []

    if isinstance(selector, CompoundSelector):
        base_members: list[Selector] = []
        pseudos: list[PseudoSelector] = []
        for member in selector.selectors:
            if isinstance(member, PseudoSelector) and member.pseudo_type in _RESULT_SET_PSEUDO:
                pseudos.append(member)
            else:
                base_members.append(member)
        if not pseudos:
            return selector, []
        if not base_members:
            return UniversalSelector(), pseudos
        if len(base_members) == 1:
            return base_members[0], pseudos
        return CompoundSelector(base_members), pseudos

    return selector, []


def apply_result_set_pseudos(nodes: list[ASTNode], pseudos: list[PseudoSelector]) -> list[ASTNode]:
    """Narrow an ordered list of matched nodes by result-set pseudo-selectors.

    Each pseudo is applied in turn to the surviving nodes, so combinations like
    ``:even:first`` compose left to right.
    """
    for pseudo in pseudos:
        nodes = _select_result_subset(nodes, pseudo)
    return nodes


def _select_result_subset(nodes: list[ASTNode], pseudo: PseudoSelector) -> list[ASTNode]:
    """Apply a single result-set pseudo-selector to an ordered list of nodes."""
    pseudo_type = pseudo.pseudo_type
    if pseudo_type == "first":
        return nodes[:1]
    if pseudo_type == "last":
        return nodes[-1:]
    if pseudo_type == "even":
        return nodes[0::2]
    if pseudo_type == "odd":
        return nodes[1::2]
    index = pseudo.argument
    if not isinstance(index, int) or index < 0:
        return []
    if pseudo_type == "nth":
        return [nodes[index]] if index < len(nodes) else []
    if pseudo_type == "within":
        return nodes[:index]
    return nodes


def selector_contains_pseudo(selector: "Selector") -> bool:
    """Return True if ``selector`` is or contains any pseudo-selector."""
    if isinstance(selector, PseudoSelector):
        return True
    if isinstance(selector, (CompoundSelector, UnionSelector)):
        return any(selector_contains_pseudo(member) for member in selector.selectors)
    return False


# ============================================================================
# Combinator Enum (Phase 2)
# ============================================================================


class Combinator(Enum):
    """
    Hierarchical relationship types between selectors.

    Defines how to navigate from one selector match to the next
    in a selector chain.

    Values:
        DESCENDANT (" "):    Any descendant at any depth
        CHILD (">"):         Direct child only
        ADJACENT ("+"):      Immediately following sibling
        GENERAL ("~"):       Any following sibling

    Example:
        >>> # "Rule > Header" uses CHILD combinator
        >>> combinator = Combinator.CHILD
        >>>
        >>> # "ContentOption + NocaseOption" uses ADJACENT combinator
        >>> combinator = Combinator.ADJACENT

    Implementation:
        Phase 2: All combinator types
        Phase 3: Optimization hints
    """

    DESCENDANT = " "  # Space: any descendant
    CHILD = ">"  # Direct child only
    ADJACENT = "+"  # Immediately following sibling
    GENERAL = "~"  # Any following sibling


# ============================================================================
# Helper Functions
# ============================================================================


_VALID_PSEUDO_TYPES = frozenset(
    {
        "first",
        "first-child",
        "last",
        "last-child",
        "empty",
        "not-empty",
        "even",
        "odd",
        "has",
        "not",
        "within",
        "nth",
    }
)


def create_selector(selector_type: str, **kwargs: Any) -> Selector:
    """
    Factory for creating selectors from a type string and keyword arguments.

    Supported ``selector_type`` values and their required kwargs:

    - ``"type"``: ``type_name`` (optional ``match_subclasses``)
    - ``"universal"``: none
    - ``"attribute"``: ``attribute``, ``operator`` (optional ``value``)
    - ``"compound"``: ``selectors``
    - ``"union"``: ``selectors``
    - ``"pseudo"``: ``pseudo_type`` (optional ``argument``)

    Args:
        selector_type: Type of selector to create
        **kwargs: Selector-specific arguments

    Returns:
        Selector instance

    Raises:
        InvalidSelectorError: If ``selector_type`` is unknown, required
            arguments are missing, or an argument is invalid.

    Example:
        >>> selector = create_selector("type", type_name="Rule")
        >>> selector = create_selector("attribute", attribute="value", operator=">", value=1)
    """
    from . import InvalidSelectorError

    def _require(*names: str) -> None:
        missing = [name for name in names if name not in kwargs]
        if missing:
            raise InvalidSelectorError(
                f"create_selector({selector_type!r}) requires: {', '.join(missing)}"
            )

    if selector_type == "type":
        _require("type_name")
        return TypeSelector(kwargs["type_name"], kwargs.get("match_subclasses", False))
    if selector_type == "universal":
        return UniversalSelector()
    if selector_type == "attribute":
        _require("attribute", "operator")
        return AttributeSelector(kwargs["attribute"], kwargs["operator"], kwargs.get("value"))
    if selector_type == "compound":
        _require("selectors")
        return CompoundSelector(kwargs["selectors"])
    if selector_type == "union":
        _require("selectors")
        return UnionSelector(kwargs["selectors"])
    if selector_type == "pseudo":
        _require("pseudo_type")
        pseudo_type = kwargs["pseudo_type"]
        if pseudo_type not in _VALID_PSEUDO_TYPES:
            raise InvalidSelectorError(f"Invalid pseudo-selector type: {pseudo_type}")
        return PseudoSelector(pseudo_type, kwargs.get("argument"))

    raise InvalidSelectorError(f"Unknown selector type: {selector_type}")
