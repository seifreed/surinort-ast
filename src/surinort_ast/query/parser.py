"""
Query Parser - Parses CSS-style selector strings into selector AST.

This module implements the query string parser using Lark grammar.
It transforms selector strings into a structured SelectorChain that
can be executed by the QueryExecutor.

Licensed under GNU General Public License v3.0
Author: Marc Rivero López | @seifreed | mriverolopez@gmail.com
"""

from pathlib import Path
from typing import Any

from lark import Lark, Token, Transformer

# ============================================================================
# Parser Implementation (Phase 1)
# ============================================================================


class QueryParser:
    """
    Parses CSS-style selector strings into SelectorChain objects.

    Uses Lark parser with custom grammar defined in grammar.lark.
    Transforms parse tree into selector AST for execution.

    Architecture:
        1. Lark parser: Tokenizes and parses selector string
        2. Transformer: Converts parse tree to selector objects
        3. Validator: Checks semantic validity of selector chain

    Example:
        >>> parser = QueryParser()
        >>> chain = parser.parse("Rule[action=alert] > Header")
        >>> isinstance(chain, SelectorChain)
        True

    Grammar Overview (see grammar.lark for details):
        selector_chain: compound_selector (combinator compound_selector)*
        compound_selector: simple_selector+
        simple_selector: type_selector | universal_selector | attribute_selector | pseudo_selector
        attribute_selector: "[" attribute_name operator value "]"
        combinator: " " | ">" | "+" | "~"

    Implementation Plan:
        Phase 1:
            - Basic type selectors: "ContentOption"
            - Universal selector: "*"
            - Attribute equality: "[value=1]"
            - Simple combinator: space (descendant)

        Phase 2:
            - All combinators: >, +, ~
            - Compound selectors: type + attributes
            - Union selectors: comma-separated

        Phase 3:
            - Comparison operators: >, <, >=, <=
            - String operators: *=, ^=, $=
            - Pseudo-selectors: :first, :last, :has, :not
    """

    def __init__(self) -> None:
        """
        Initialize parser with Lark grammar.

        Loads grammar from grammar.lark file and creates Lark parser instance.
        Parser is cached for reuse across multiple parse operations.
        """
        # Load grammar from query/grammar.lark
        grammar_path = Path(__file__).parent / "grammar.lark"
        self._parser = Lark.open(
            str(grammar_path),
            parser="lalr",
            start="selector_chain",
            propagate_positions=True,
        )
        self._transformer = SelectorTransformer()

    def parse(self, selector: str) -> "SelectorChain":
        """
        Parse selector string into SelectorChain.

        Args:
            selector: CSS-style selector string

        Returns:
            SelectorChain object ready for execution

        Raises:
            QuerySyntaxError: If selector syntax is invalid

        Example:
            >>> parser = QueryParser()
            >>> chain = parser.parse("Rule[action=alert]")
            >>> chain = parser.parse("Rule > Header[protocol=tcp]")
            >>> chain = parser.parse("ContentOption + NocaseOption")

        Implementation:
            1. Tokenize selector string using Lark
            2. Build parse tree
            3. Transform parse tree to selector objects
            4. Validate semantic correctness
            5. Return SelectorChain
        """
        from . import QuerySyntaxError

        try:
            # Normalize selector
            selector = normalize_selector(selector)

            # Parse to tree
            tree = self._parser.parse(selector)

            # Transform to selector chain
            from typing import cast

            chain = cast(SelectorChain, self._transformer.transform(tree))

            # Validate semantic correctness
            validate_selector_chain(chain)

            return chain

        except Exception as e:
            # Wrap Lark exceptions in QuerySyntaxError
            raise QuerySyntaxError(f"Invalid selector syntax: {e}") from e


class SelectorChain:
    """
    Represents a parsed selector chain ready for execution.

    A selector chain consists of one or more selectors connected by
    combinators (space, >, +, ~). The chain represents the complete
    query to be executed against the AST.

    Attributes:
        selectors: List of selector objects
        combinators: List of combinator types between selectors

    Example:
        "Rule[action=alert] > Header" becomes:
            SelectorChain(
                selectors=[
                    TypeSelector("Rule") + AttributeSelector("action", "=", "alert"),
                    TypeSelector("Header")
                ],
                combinators=[Combinator.CHILD]
            )

    Structure:
        selector1 combinator1 selector2 combinator2 selector3
        [    0   ]    [0]     [   1   ]    [1]     [   2   ]

    Implementation:
        Phase 1: Simple chains with descendant combinator only
        Phase 2: Full combinator support
        Phase 3: Optimization and caching
    """

    def __init__(self, selectors: list[Any], combinators: list[Any]) -> None:
        """
        Initialize selector chain.

        Args:
            selectors: List of selector objects
            combinators: List of combinator enums (len = len(selectors) - 1)

        Raises:
            InvalidSelectorError: If combinators length doesn't match selectors
        """
        self.selectors = selectors
        self.combinators = combinators

        # Validate chain structure
        if len(combinators) != len(selectors) - 1:
            from . import InvalidSelectorError

            raise InvalidSelectorError(
                f"Invalid chain: {len(selectors)} selectors but {len(combinators)} combinators"
            )

    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"SelectorChain(selectors={self.selectors}, combinators={self.combinators})"


# ============================================================================
# Lark Transformer (Phase 1)
# ============================================================================


class SelectorTransformer(Transformer[Any, Any]):
    """
    Lark transformer that converts parse tree to selector objects.

    Implements visitor methods for each grammar rule, building the
    selector AST bottom-up.

    Methods correspond to grammar rules:
        - selector_chain() -> SelectorChain
        - compound_selector() -> CompoundSelector
        - type_selector() -> TypeSelector
        - attribute_selector() -> AttributeSelector
        - etc.

    Example:
        >>> transformer = SelectorTransformer()
        >>> tree = parser.parse("Rule[action=alert]")
        >>> chain = transformer.transform(tree)

    Implementation:
        Phase 1: Basic transformers for type and attribute selectors
        Phase 2: All combinator transformers
        Phase 3: Pseudo-selector transformers
    """

    def selector_chain(self, items: list[Any]) -> Any:
        """
        Transform selector_chain (top level).

        Grammar: union_selector

        Returns either a SelectorChain or UnionSelector
        """
        # selector_chain just wraps union_selector
        return items[0] if items else SelectorChain([], [])

    def union_selector(self, items: list[Any]) -> Any:
        """
        Transform union_selector (OR logic with commas).

        Grammar: combinator_chain ("," combinator_chain)*

        Returns UnionSelector if multiple chains, otherwise single chain
        """
        from lark import Token

        from .selectors import UnionSelector

        # Filter out tokens (whitespace, commas) - keep only SelectorChain objects
        chains = [item for item in items if not isinstance(item, Token)]

        if len(chains) == 1:
            # Single chain - return it directly
            return chains[0]

        # Multiple chains - wrap in UnionSelector
        # Each item is a SelectorChain
        return UnionSelector(chains)

    def combinator_chain(self, items: list[Any]) -> SelectorChain:
        """
        Transform combinator_chain to SelectorChain.

        Grammar: compound_selector (combinator compound_selector)*

        Phase 2: Support for all combinators
        """
        from .selectors import Combinator

        # Parse items into selectors and combinators
        selectors = []
        combinators = []

        i = 0
        while i < len(items):
            item = items[i]

            # Check if this is a compound selector
            if hasattr(item, "matches") or isinstance(item, (list, tuple)):
                # It's a selector
                selectors.append(item)
                i += 1
            elif isinstance(item, Combinator):
                # It's a combinator
                combinators.append(item)
                i += 1
            else:
                # Unknown item type - try to interpret it
                # Could be a combinator token
                i += 1

        # If we didn't find explicit combinators, all items are selectors
        if not combinators and len(items) > 1:
            # Items alternate: selector, combinator, selector, combinator, ...
            selectors = [items[i] for i in range(0, len(items), 2)]
            combinators = [items[i] for i in range(1, len(items), 2)]

        # Single selector case
        if len(selectors) == 1:
            return SelectorChain([selectors[0]], [])

        # Multiple selectors with combinators
        return SelectorChain(selectors, combinators)

    def compound_selector(self, items: list[Any]) -> Any:
        """
        Transform compound_selector.

        Grammar: simple_selector+

        Phase 1: Single simple selector or type + attribute
        """
        from .selectors import CompoundSelector

        if len(items) == 1:
            # Single simple selector
            return items[0]
        # Multiple simple selectors - combine with AND logic
        return CompoundSelector(items)

    def simple_selector(self, items: list[Any]) -> Any:
        """Pass through simple selector."""
        return items[0]

    def type_selector(self, items: list[Token]) -> Any:
        """
        Transform type_selector to TypeSelector.

        Grammar: IDENTIFIER
        """
        from .selectors import TypeSelector

        type_name = items[0].value
        return TypeSelector(type_name)

    def universal_selector(self, items: list[Any]) -> Any:
        """
        Transform universal_selector to UniversalSelector.

        Grammar: "*"
        """
        from .selectors import UniversalSelector

        return UniversalSelector()

    def attribute_selector(self, items: list[Any]) -> Any:
        """
        Transform attribute_selector to AttributeSelector.

        Grammar: "[" attribute_filter "]"
        """
        # attribute_filter returns a dict with attribute, operator, value
        filter_dict = items[0]
        from .selectors import AttributeSelector

        return AttributeSelector(
            attribute=filter_dict["attribute"],
            operator=filter_dict["operator"],
            value=filter_dict.get("value"),
        )

    def attribute_filter(self, items: list[Any]) -> dict[str, Any]:
        """
        Transform attribute_filter.

        Grammar: attribute_name (operator attribute_value)?

        Returns dict with attribute, operator, value
        """
        attribute_name = items[0]

        if len(items) == 1:
            # No operator/value - existence check
            return {
                "attribute": attribute_name,
                "operator": "exists",
                "value": None,
            }
        # Has operator and value
        operator = items[1]
        value = items[2] if len(items) > 2 else None
        return {
            "attribute": attribute_name,
            "operator": operator,
            "value": value,
        }

    def attribute_name(self, items: list[Token]) -> str:
        """
        Transform attribute_name.

        Grammar: IDENTIFIER ("." IDENTIFIER)*
        """
        # Join dotted identifiers
        return ".".join(item.value for item in items)

    def operator(self, items: list[Token]) -> str:
        """Transform operator to string."""
        if not items:
            # This shouldn't happen, but handle gracefully
            return "="

        token = items[0]
        # Map token types to operator strings
        operator_map = {
            "OP_EQ": "=",
            "OP_NEQ": "!=",
            "OP_GT": ">",
            "OP_LT": "<",
            "OP_GTE": ">=",
            "OP_LTE": "<=",
            "OP_CONTAINS": "*=",
            "OP_STARTS": "^=",
            "OP_ENDS": "$=",
        }
        return operator_map.get(token.type, str(token))

    def attribute_value(self, items: list[Token]) -> Any:
        """
        Transform attribute_value.

        Grammar: STRING | NUMBER | IDENTIFIER
        """
        token = items[0]

        if token.type == "STRING":
            # Remove quotes from string
            return token.value[1:-1]  # Strip quotes
        if token.type == "NUMBER":
            # Parse as int or float
            value = token.value
            return int(value) if "." not in value else float(value)
        if token.type == "IDENTIFIER":
            # Keep as string
            return token.value
        return token.value

    def combinator(self, items: list[Any]) -> Any:
        """
        Transform combinator.

        Grammar: descendant | child | adjacent | general
        """
        # combinator rule returns the specific combinator type
        return items[0] if items else None

    def descendant_combinator(self, items: list[Any]) -> Any:
        """Transform descendant combinator (space)."""
        from .selectors import Combinator

        return Combinator.DESCENDANT

    def child_combinator(self, items: list[Any]) -> Any:
        """Transform child combinator (>)."""
        from .selectors import Combinator

        return Combinator.CHILD

    def adjacent_combinator(self, items: list[Any]) -> Any:
        """Transform adjacent sibling combinator (+)."""
        from .selectors import Combinator

        return Combinator.ADJACENT

    def general_combinator(self, items: list[Any]) -> Any:
        """Transform general sibling combinator (~)."""
        from .selectors import Combinator

        return Combinator.GENERAL

    def pseudo_selector(self, items: list[Any]) -> Any:
        """
        Transform pseudo_selector.

        Grammar: ":" PSEUDO_CLASS | ":" PSEUDO_FUNCTION "(" selector_chain ")"
        """
        from .selectors import PseudoSelector

        if len(items) == 1:
            # Simple pseudo-class: items[0] is the PSEUDO_CLASS token
            pseudo_type = items[0].value if hasattr(items[0], "value") else str(items[0])
            return PseudoSelector(pseudo_type, None)
        # Pseudo-function with argument
        # items[0] is PSEUDO_FUNCTION token, items[1] is selector_chain
        pseudo_type = items[0].value if hasattr(items[0], "value") else str(items[0])
        argument = items[1]  # selector_chain
        return PseudoSelector(pseudo_type, argument)


# ============================================================================
# Helper Functions
# ============================================================================


def validate_selector_chain(chain: SelectorChain) -> None:
    """
    Validate semantic correctness of selector chain.

    Checks for:
        - Invalid combinator sequences
        - Impossible selector combinations
        - Type mismatches in attribute operators

    Args:
        chain: Parsed selector chain

    Raises:
        InvalidSelectorError: If chain has semantic errors

    Example:
        >>> chain = parser.parse("Rule[value>string]")  # Type mismatch
        >>> validate_selector_chain(chain)  # Raises InvalidSelectorError
    """
    # TODO: Implement validation in Phase 1


def normalize_selector(selector: str) -> str:
    """
    Normalize selector string for consistent parsing.

    Performs:
        - Whitespace normalization
        - Quote normalization
        - Escape sequence handling

    Args:
        selector: Raw selector string

    Returns:
        Normalized selector string

    Example:
        >>> normalize_selector("  Rule  [  action = alert  ]  ")
        "Rule[action=alert]"
    """
    # TODO: Implement in Phase 1
    return selector.strip()


# ============================================================================
# Grammar Notes
# ============================================================================

"""
Grammar Structure (see grammar.lark for implementation):

selector_chain:
    compound_selector (combinator compound_selector)*

compound_selector:
    simple_selector+

simple_selector:
    type_selector
    | universal_selector
    | attribute_selector
    | pseudo_selector

type_selector:
    IDENTIFIER

universal_selector:
    "*"

attribute_selector:
    "[" attribute_name operator value? "]"

operator:
    "=" | "!=" | ">" | "<" | ">=" | "<="
    | "*=" | "^=" | "$="

pseudo_selector:
    ":" pseudo_class
    | ":" pseudo_class "(" selector_chain ")"

combinator:
    " " | ">" | "+" | "~"

Implementation priorities:
    Phase 1: type_selector, universal_selector, attribute_selector with "="
    Phase 2: All combinators, compound_selector
    Phase 3: All operators, pseudo_selector
"""
