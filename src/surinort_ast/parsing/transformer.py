"""
Lark Transformer for converting parse trees to AST nodes.

This module transforms Lark parse trees into our typed AST nodes defined
in surinort_ast.core.nodes. It handles location tracking, error recovery,
and semantic validation during transformation.

The transformer uses mixin composition for modular transformation logic:
- AddressTransformerMixin: IP addresses, ranges, variables, lists
- PortTransformerMixin: Port expressions, ranges, variables, lists
- HeaderTransformerMixin: Actions, protocols, directions, headers
- ContentTransformerMixin: Content patterns, modifiers, byte operations
- OptionTransformerMixin: Rule options, metadata, flow tracking, etc.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import logging
from typing import Any

from lark import Token
from lark.visitors import Transformer, v_args

from ..core.diagnostics import Diagnostic, DiagnosticLevel
from ..core.enums import Dialect, Direction
from ..core.location import Location
from ..core.nodes import AnyAddress, AnyPort, Header, Rule
from .helpers import token_to_location
from .mixins.address_transformer import AddressTransformerMixin
from .mixins.content_transformer import (
    ContentTransformerMixin,
    parse_hex_string,
)
from .mixins.header_transformer import HeaderTransformerMixin
from .mixins.option_transformer import (
    OptionTransformerMixin,
    parse_pcre_pattern,
    parse_pcre_pattern_cached,
    parse_quoted_string,
    parse_quoted_string_cached,
)
from .mixins.port_transformer import PortTransformerMixin
from .parser_config import ParserConfig

logger = logging.getLogger(__name__)


# Re-export helper functions for backward compatibility with tests
__all__ = [
    "RuleTransformer",
    "parse_hex_string",
    "parse_pcre_pattern",
    "parse_pcre_pattern_cached",
    "parse_quoted_string",
    "parse_quoted_string_cached",
    "token_to_location",
]


# ============================================================================
# AST Transformer
# ============================================================================


class RuleTransformer(
    AddressTransformerMixin,
    PortTransformerMixin,
    HeaderTransformerMixin,
    ContentTransformerMixin,
    OptionTransformerMixin,
    Transformer[Token, Any],
):
    """
    Transform Lark parse tree to AST nodes.

    This transformer converts the Lark parse tree into our strongly-typed
    AST node hierarchy using mixin composition for modular transformation logic.

    Mixins (in MRO order):
        1. AddressTransformerMixin: Handles IP addresses, CIDR ranges, IP ranges,
                                    address variables, lists, and negations
        2. PortTransformerMixin: Handles port expressions, ranges, variables,
                                 lists, and negations
        3. HeaderTransformerMixin: Handles actions, protocols, directions, and
                                   complete header assembly
        4. ContentTransformerMixin: Handles content patterns, content modifiers,
                                    inline modifiers, and byte operations
        5. OptionTransformerMixin: Handles all rule options including metadata,
                                   flow tracking, thresholds, buffers, and scripting

    Core Responsibilities:
        - Rule assembly (combining action, header, and options)
        - Rule file parsing (multiple rules)
        - Diagnostic collection and reporting
        - Location tracking for all nodes
        - Resource limit enforcement (nesting depth, etc.)

    Architecture:
        The transformer uses composition over inheritance through mixins.
        Each mixin handles a specific domain of transformation, making the
        codebase modular, testable, and maintainable. Mixins communicate
        through well-defined interfaces (file_path, add_diagnostic, config).

    Performance:
        - Uses __slots__ for memory efficiency
        - Mixins avoid redundant validations
        - Resource limits prevent DoS attacks
    """

    # Use __slots__ for memory efficiency
    __slots__ = ("_nesting_depth", "config", "diagnostics", "dialect", "file_path")

    def __init__(
        self,
        file_path: str | None = None,
        dialect: Dialect = Dialect.SURICATA,
        config: ParserConfig | None = None,
    ):
        """
        Initialize transformer.

        Args:
            file_path: Source file path for location tracking
            dialect: Target IDS dialect (Suricata, Snort2, Snort3)
            config: Parser configuration with resource limits

        Performance:
            Uses __slots__ for reduced memory overhead.
        """
        super().__init__()
        self.file_path = file_path
        self.dialect = dialect
        self.config = config or ParserConfig.default()
        self.diagnostics: list[Diagnostic] = []
        self._nesting_depth = 0  # Track nesting depth for DoS prevention

    def add_diagnostic(
        self,
        level: DiagnosticLevel,
        message: str,
        location: Location | None = None,
        code: str | None = None,
        hint: str | None = None,
    ) -> None:
        """
        Add a diagnostic message.

        Args:
            level: Diagnostic severity level
            message: Diagnostic message
            location: Source location (optional)
            code: Diagnostic code (optional)
            hint: Hint for resolution (optional)

        Usage:
            Called by mixins to report warnings and errors during transformation.
        """
        diag = Diagnostic(level=level, message=message, location=location, code=code, hint=hint)
        self.diagnostics.append(diag)
        logger.debug(f"Diagnostic: {diag}")

    # ========================================================================
    # Top-Level Rule Assembly
    # ========================================================================

    @v_args(inline=True)
    def rule(self, *args: Any) -> Rule:
        """
        Transform rule in full or short form.

        Forms:
            - action header (options)           [Standard form]
            - action protocol (options)         [Snort3 short form]

        Args:
            *args: Variable length args depending on form:
                   - Full: [action, header, options]
                   - Short: [action, protocol, options]

        Returns:
            Rule node with complete rule structure

        Short Form:
            The short form is a Snort3 convenience syntax where only the
            protocol is specified. It's expanded to a full header with:
            - Source: any any
            - Direction: ->
            - Destination: any any

        Diagnostic Handling:
            Diagnostics accumulated during option transformation are attached
            to the rule and then cleared for the next rule.
        """
        # Unpack arguments
        action = args[0]
        second = args[1]
        options = args[2] if len(args) > 2 else []

        if isinstance(second, Header):
            # Full form: action header (options)
            header = second
        else:
            # Short form: action protocol (options)
            # Build a minimal header with any addresses/ports and default direction
            protocol = second
            header = Header(
                protocol=protocol,
                src_addr=AnyAddress(),
                src_port=AnyPort(),
                direction=Direction.TO,
                dst_addr=AnyAddress(),
                dst_port=AnyPort(),
            )

        # Create rule with accumulated diagnostics
        location = header.location
        rule_obj = Rule(
            action=action,
            header=header,
            options=options,
            dialect=self.dialect,
            location=location,
            diagnostics=self.diagnostics.copy(),
        )

        # Clear diagnostics for next rule
        self.diagnostics = []

        return rule_obj

    @v_args(inline=True)
    def rule_file(self, *rules: Rule | None) -> list[Rule]:
        """
        Transform rule_file containing multiple rules.

        Args:
            *rules: Variable number of Rule nodes or None values

        Returns:
            List of Rule nodes (None values filtered out)

        None Filtering:
            None values can appear from:
            - Comment lines (transformed to None by mixins)
            - Blank lines (NEWLINE terminal transformed to None)
            - Ignored grammar elements

        Usage:
            This is the top-level transformation for parsing rule files
            containing multiple rules.
        """
        # Filter out None values (from comments/newlines)
        return [r for r in rules if r is not None]

    # ========================================================================
    # Address and Port List Overrides (Nesting Depth Validation)
    # ========================================================================
    # These methods override the base implementations from mixins to add
    # nesting depth validation for DoS prevention

    def address_list(self, items: Any) -> Any:
        """
        Transform address list with nesting depth validation.

        Args:
            items: Sequence of address expressions

        Returns:
            AddressList node

        DoS Prevention:
            Validates nesting depth to prevent stack overflow from deeply
            nested structures like [[[[[...]]]]].
        """
        self._nesting_depth += 1
        try:
            self.config.validate_nesting_depth(self._nesting_depth)
            # Filter to AddressExpr types
            from ..core.nodes import AddressExpr, AddressList

            elements = [item for item in items if isinstance(item, AddressExpr)]
            return AddressList(elements=elements)
        finally:
            self._nesting_depth -= 1

    @v_args(inline=True)
    def address_negation(self, addr: Any) -> Any:
        """
        Transform address negation with nesting depth validation.

        Args:
            addr: Address expression to negate

        Returns:
            AddressNegation node

        DoS Prevention:
            Validates nesting depth to prevent stack overflow from deeply
            nested negations like !!!!!!!!addr.
        """
        self._nesting_depth += 1
        try:
            self.config.validate_nesting_depth(self._nesting_depth)
            from ..core.nodes import AddressNegation

            return AddressNegation(expr=addr)
        finally:
            self._nesting_depth -= 1
