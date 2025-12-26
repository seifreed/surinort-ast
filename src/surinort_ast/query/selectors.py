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
    def matches(self, node: ASTNode) -> bool:
        """
        Test if AST node matches this selector.

        Args:
            node: AST node to test

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

    Implementation:
        Phase 1: Exact type matching only
        Phase 2: Subclass matching with isinstance()
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

    def matches(self, node: ASTNode) -> bool:
        """
        Test if node type matches.

        Args:
            node: AST node to test

        Returns:
            True if node type matches

        Implementation:
            Phase 1: Simple string comparison with node.node_type
            Phase 2: Add isinstance() check for subclass matching
        """
        # Phase 1: Simple exact type matching
        if self.match_subclasses:
            # Phase 2 feature - not implemented yet
            raise NotImplementedError("Subclass matching not yet implemented")
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

    def matches(self, node: ASTNode) -> bool:
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

    def matches(self, node: ASTNode) -> bool:
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
        # Check if attribute exists on node
        if not hasattr(node, self.attribute):
            return False

        # Get attribute value
        node_value = getattr(node, self.attribute)

        # Handle existence check
        if self.operator == "exists":
            return node_value is not None

        # Normalize node value for comparison
        if hasattr(node_value, "value"):
            # It's an enum - use its value
            node_value = node_value.value

        # Equality operators
        if self.operator == "=":
            return str(node_value) == str(self.value)

        if self.operator == "!=":
            return str(node_value) != str(self.value)

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

    def matches(self, node: ASTNode) -> bool:
        """
        Test if node matches all selectors.

        Args:
            node: AST node to test

        Returns:
            True if all selectors match

        Implementation:
            Phase 2: Simple all() check
            Phase 3: Optimize order (fail-fast selectors first)
        """
        # Phase 1: Simple AND logic
        return all(selector.matches(node) for selector in self.selectors)

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

    def matches(self, node: ASTNode) -> bool:
        """
        Test if node matches any selector.

        Args:
            node: AST node to test

        Returns:
            True if any selector matches

        Implementation:
            Phase 2: Simple any() check with early exit
        """
        # Early exit optimization: return True on first match
        return any(selector.matches(node) for selector in self.selectors)

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


class PseudoSelector(Selector):
    """
    Special selector types with custom matching logic.

    Implements pseudo-selectors like :first, :last, :has(), :not().
    These selectors require context information beyond the node itself.

    Types:
        :first              - First child in parent
        :last               - Last child in parent
        :nth(n)             - Nth child (0-indexed)
        :empty              - No children
        :not-empty          - Has children
        :has(selector)      - Has descendant matching selector
        :not(selector)      - Does not match selector

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

        # Positional pseudo-selectors (require context)
        if self.pseudo_type in {"first", "first-child"}:
            return self._is_first_child(node, context)

        if self.pseudo_type in {"last", "last-child"}:
            return self._is_last_child(node, context)

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

            # Check if the node matches the selector
            # We test if the selector matches THIS node specifically
            # For this, we need to test the selector directly
            # If argument is a selector, test it; if it's a chain with just one selector, test that
            if len(chain.selectors) == 1 and not chain.combinators:
                selector = chain.selectors[0]
                # Single selector - test directly
                if hasattr(selector, "matches"):
                    # Handle different selector signatures
                    try:
                        matches = selector.matches(node, context)
                    except TypeError:
                        matches = selector.matches(node)
                    return not matches
            # For complex chains, we can't easily test them
            # For now, just test the last selector
            return not chain.selectors[-1].matches(node) if chain.selectors else True

        # Unknown pseudo-selector
        return False

    def _has_children(self, node: ASTNode) -> bool:
        """Check if node has any children."""
        # Check common child attributes
        if hasattr(node, "options") and node.options:
            return True
        if hasattr(node, "header") and node.header is not None:
            return True
        # Check if node has any attribute that is a list with items or a non-None node
        for attr_name in dir(node):
            if attr_name.startswith("_"):
                continue
            try:
                attr_value = getattr(node, attr_name)
                if isinstance(attr_value, list) and attr_value:
                    return True
                if hasattr(attr_value, "node_type"):
                    return True
            except AttributeError:
                continue
        return False

    def _is_first_child(self, node: ASTNode, context: Any) -> bool:
        """Check if node is first child of parent."""
        parent = context.get_parent() if hasattr(context, "get_parent") else None
        if parent is None:
            return True  # Root node is considered first

        # Get children from parent
        children = self._get_children(parent)
        if not children:
            return False

        return children[0] == node

    def _is_last_child(self, node: ASTNode, context: Any) -> bool:
        """Check if node is last child of parent."""
        parent = context.get_parent() if hasattr(context, "get_parent") else None
        if parent is None:
            return True  # Root node is considered last

        # Get children from parent
        children = self._get_children(parent)
        if not children:
            return False

        return children[-1] == node

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


def create_selector(selector_type: str, **kwargs: Any) -> Selector:
    """
    Factory function for creating selectors.

    Args:
        selector_type: Type of selector to create
        **kwargs: Selector-specific arguments

    Returns:
        Selector instance

    Raises:
        InvalidSelectorError: If selector_type is unknown

    Example:
        >>> selector = create_selector("type", type_name="Rule")
        >>> selector = create_selector("attribute", attribute="value", operator="=", value=1)

    Implementation:
        Phase 1: Basic factory for type and attribute selectors
        Phase 3: Complete factory for all selector types
    """
    # TODO: Implement in Phase 1
    raise NotImplementedError("create_selector not yet implemented")
