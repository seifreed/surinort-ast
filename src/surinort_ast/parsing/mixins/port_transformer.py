"""
Port transformation mixin for IDS rule parser.

This mixin handles transformation of port-related AST nodes including:
- Port wildcards (any)
- Port variables ($HTTP_PORTS)
- Single ports (80)
- Port ranges (1024:65535, 1024:)
- Port lists ([80,443,8080])
- Port negations (!80)

The mixin is designed to be composed with other transformer mixins in RuleTransformer.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from lark import Token
from lark.visitors import v_args

from ...core.diagnostics import DiagnosticLevel
from ...core.nodes import (
    AnyPort,
    Port,
    PortList,
    PortNegation,
    PortRange,
    PortVariable,
)
from ..helpers import token_to_location


class PortTransformerMixin:
    """
    Mixin for transforming port-related AST nodes.

    This mixin provides methods for transforming Lark parse tree nodes into
    typed port expression AST nodes. It handles:
    - Any port wildcard (any)
    - Port variables (e.g., $HTTP_PORTS)
    - Single port numbers (e.g., 80)
    - Port ranges with optional end (e.g., 1024:65535, 1024:)
    - Port lists (e.g., [80,443,8080])
    - Port negations (e.g., !80)

    Defensive Validations:
        While the grammar enforces syntactic correctness, this mixin maintains
        defensive validations for semantic correctness (e.g., port range 0-65535,
        start <= end). These validations:
        1. Provide clear error messages for malformed rules
        2. Add diagnostics for out-of-range values
        3. Serve as documentation of expected ranges
        4. Protect against grammar changes or parser bugs

    Dependencies:
        This mixin expects the following attributes/methods on the parent class:
        - file_path: str | None - Source file path for location tracking
        - add_diagnostic(level, message, location) - Diagnostic reporting method
        - config: ParserConfig - Parser configuration with resource limits
        - _nesting_depth: int - Current nesting depth for DoS prevention
    """

    # Declare expected attributes for type checking
    file_path: str | None
    add_diagnostic: Any  # Method signature varies by parent class
    config: Any  # ParserConfig instance
    _nesting_depth: int

    def port_any(self, _: Any) -> AnyPort:
        """
        Transform 'any' port wildcard.

        Args:
            _: Unused parse tree items

        Returns:
            AnyPort node representing the wildcard port
        """
        return AnyPort()

    @v_args(inline=True)
    def port_var(self, var_token: Token) -> PortVariable:
        """
        Transform port variable (e.g., $HTTP_PORTS).

        Args:
            var_token: Token containing the variable name (with leading $)

        Returns:
            PortVariable node with variable name (without leading $)

        Note:
            The leading $ is stripped from the variable name as it's a syntax
            marker, not part of the actual variable identifier.
        """
        name = str(var_token.value)
        # Remove leading $ - it's a syntax marker, not part of the identifier
        if name.startswith("$"):
            name = name[1:]
        return PortVariable(name=name, location=token_to_location(var_token, self.file_path))

    @v_args(inline=True)
    def port_negation(self, port: Any) -> PortNegation:
        """
        Transform negated port (e.g., !80).

        Args:
            port: Port expression to negate

        Returns:
            PortNegation node wrapping the port expression

        DoS Prevention:
            Tracks nesting depth to prevent deeply nested structures that
            could cause stack overflow or excessive memory usage.
        """
        self._nesting_depth += 1
        try:
            self.config.validate_nesting_depth(self._nesting_depth)
            return PortNegation(expr=port)
        finally:
            self._nesting_depth -= 1

    def port_list(self, items: Sequence[Any]) -> PortList:
        """
        Transform port list (e.g., [80,443,8080]).

        Args:
            items: Sequence of port expressions

        Returns:
            PortList node containing all port expressions

        DoS Prevention:
            Tracks nesting depth to prevent deeply nested structures that
            could cause stack overflow or excessive memory usage.

        Note:
            Empty lists are allowed by the grammar and represent no ports.
        """
        self._nesting_depth += 1
        try:
            self.config.validate_nesting_depth(self._nesting_depth)
            return PortList(elements=list(items))
        finally:
            self._nesting_depth -= 1

    def port_range(self, args: list[Any]) -> PortRange:
        """
        Transform port range (e.g., 1024:65535 or open-ended 1024:).

        Args:
            args: List containing [start_token] or [start_token, end_token]

        Returns:
            PortRange node representing the port range

        Defensive Validation:
            The grammar ensures valid port numbers, but we validate:
            - Port range 0-65535 (standard TCP/UDP range)
            - Start port <= end port (semantic correctness)
            - Open-ended ranges default to 65535

        Note:
            Open-ended ranges (e.g., "1024:") default the end port to 65535.
        """
        start_token = args[0]
        start = int(start_token.value)

        # Check if end port is provided (may be open-ended like "1024:")
        if len(args) > 1 and args[1] is not None:
            end_token = args[1]
            end = int(end_token.value)
        else:
            # Open-ended range, default to max port
            end = 65535
            end_token = None

        # Grammar ensures port is 0-65535, but validate for safety and clear error messages
        # These validations provide better diagnostics even though grammar enforces constraints
        if start < 0 or start > 65535:
            self.add_diagnostic(
                DiagnosticLevel.ERROR,
                f"Port range start {start} out of range (0-65535)",
                token_to_location(start_token, self.file_path),
            )

        if (end < 0 or end > 65535) and end_token:
            self.add_diagnostic(
                DiagnosticLevel.ERROR,
                f"Port range end {end} out of range (0-65535)",
                token_to_location(end_token, self.file_path),
            )

        if start > end:
            self.add_diagnostic(
                DiagnosticLevel.ERROR,
                f"Port range start {start} > end {end}",
                token_to_location(start_token, self.file_path),
            )

        return PortRange(start=start, end=end)

    @v_args(inline=True)
    def port_single(self, port_token: Token) -> Port:
        """
        Transform single port number (e.g., 80).

        Args:
            port_token: Token containing the port number

        Returns:
            Port node representing the single port

        Defensive Validation:
            The grammar ensures valid integers, but we validate the port range
            (0-65535) to provide clear error messages and protect against
            malformed input.
        """
        port_num = int(port_token.value)

        # Grammar ensures port is 0-65535, but validate for safety and clear error messages
        # This validation provides better diagnostics even though grammar enforces constraints
        if port_num < 0 or port_num > 65535:
            self.add_diagnostic(
                DiagnosticLevel.ERROR,
                f"Port {port_num} out of range (0-65535)",
                token_to_location(port_token, self.file_path),
            )

        return Port(value=port_num, location=token_to_location(port_token, self.file_path))

    def port_elem(self, items: Sequence[Any]) -> Any:
        """
        Transform port list element (variable, range, or single port).

        Args:
            items: Sequence containing a single item (variable, range, or port)

        Returns:
            PortVariable, PortRange, or Port node

        Note:
            This method handles the grammar rule for port list elements, which
            can be variables, ranges, or single ports. Variables need special
            handling to convert from Token to PortVariable node.
        """
        if not items:
            return None

        item = items[0]

        # Handle VARIABLE token - transform to PortVariable
        if isinstance(item, Token) and item.type == "VARIABLE":
            name = str(item.value)
            if name.startswith("$"):
                name = name[1:]
            return PortVariable(name=name, location=token_to_location(item, self.file_path))

        # Otherwise, it's already transformed (Port or PortRange)
        return item
