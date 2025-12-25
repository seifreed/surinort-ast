"""
Address transformation mixin for IDS rule parser.

This mixin handles transformation of address-related AST nodes including:
- IP addresses (IPv4/IPv6)
- CIDR ranges
- IP ranges
- Address variables
- Address lists and negations

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
    AddressList,
    AddressNegation,
    AddressVariable,
    AnyAddress,
    IPAddress,
    IPCIDRRange,
    IPRange,
)
from ..helpers import token_to_location


class AddressTransformerMixin:
    """
    Mixin for transforming address-related AST nodes.

    This mixin provides methods for transforming Lark parse tree nodes into
    typed address expression AST nodes. It handles:
    - Individual IP addresses (IPv4 and IPv6)
    - CIDR notation (e.g., 192.168.1.0/24)
    - IP ranges (e.g., [192.168.1.1-192.168.1.254])
    - Address variables (e.g., $HOME_NET)
    - Address lists (e.g., [192.168.1.0/24,$HOME_NET])
    - Address negations (e.g., !192.168.1.1)
    - Any address wildcard (any)

    Defensive Validations:
        While the grammar enforces syntactic correctness, this mixin maintains
        defensive validations for semantic correctness (e.g., CIDR prefix ranges,
        IP version detection). These validations:
        1. Provide clear error messages for malformed rules
        2. Add diagnostics for out-of-range values
        3. Serve as documentation of expected ranges
        4. Protect against grammar changes or parser bugs

    Dependencies:
        This mixin expects the following attributes/methods on the parent class:
        - file_path: str | None - Source file path for location tracking
        - add_diagnostic(level, message, location) - Diagnostic reporting method
    """

    # Declare expected attributes for type checking
    file_path: str | None
    add_diagnostic: Any  # Method signature varies by parent class

    def address_any(self, _: Any) -> AnyAddress:
        """
        Transform 'any' address.

        Args:
            _: Unused parse tree items

        Returns:
            AnyAddress node representing the wildcard address
        """
        return AnyAddress()

    @v_args(inline=True)
    def address_var(self, var_token: Token) -> AddressVariable:
        """
        Transform address variable (e.g., $HOME_NET).

        Args:
            var_token: Token containing the variable name (with leading $)

        Returns:
            AddressVariable node with variable name (without leading $)

        Note:
            The leading $ is stripped from the variable name as it's a syntax
            marker, not part of the actual variable identifier.
        """
        name = str(var_token.value)
        # Remove leading $ - it's a syntax marker, not part of the identifier
        if name.startswith("$"):
            name = name[1:]
        return AddressVariable(name=name, location=token_to_location(var_token, self.file_path))

    @v_args(inline=True)
    def address_negation(self, addr: Any) -> AddressNegation:
        """
        Transform negated address (e.g., !192.168.1.1).

        Args:
            addr: Address expression to negate

        Returns:
            AddressNegation node wrapping the address expression
        """
        return AddressNegation(expr=addr)

    def address_list(self, items: Sequence[Any]) -> AddressList:
        """
        Transform address list (e.g., [192.168.1.0/24,$HOME_NET]).

        Args:
            items: Sequence of address expressions

        Returns:
            AddressList node containing all address expressions

        Note:
            Empty lists are allowed by the grammar and represent no addresses.
        """
        return AddressList(elements=list(items))

    @v_args(inline=True)
    def ipv4_cidr(self, ip_token: Token, prefix_token: Token) -> IPCIDRRange:
        """
        Transform IPv4 CIDR notation (e.g., 192.168.1.0/24).

        Args:
            ip_token: Token containing the IPv4 network address
            prefix_token: Token containing the prefix length (0-32)

        Returns:
            IPCIDRRange node representing the CIDR block

        Defensive Validation:
            The grammar ensures prefix_token contains a valid integer, but we
            validate the range (0-32) for IPv4 to provide clear error messages
            and protect against malformed input. This is defensive programming
            despite grammar guarantees.
        """
        network = str(ip_token.value)
        prefix_len = int(prefix_token.value)

        # Defensive validation: Grammar enforces integer, we enforce IPv4 range (0-32)
        # This provides clear diagnostics and documents expected range
        if prefix_len < 0 or prefix_len > 32:
            self.add_diagnostic(
                DiagnosticLevel.WARNING,
                f"IPv4 CIDR prefix length {prefix_len} out of range (0-32)",
                token_to_location(prefix_token, self.file_path),
            )

        return IPCIDRRange(
            network=network,
            prefix_len=prefix_len,
            location=token_to_location(ip_token, self.file_path),
        )

    @v_args(inline=True)
    def ipv6_cidr(self, ip_token: Token, prefix_token: Token) -> IPCIDRRange:
        """
        Transform IPv6 CIDR notation (e.g., 2001:db8::/32).

        Args:
            ip_token: Token containing the IPv6 network address
            prefix_token: Token containing the prefix length (0-128)

        Returns:
            IPCIDRRange node representing the CIDR block

        Defensive Validation:
            The grammar ensures prefix_token contains a valid integer, but we
            validate the range (0-128) for IPv6 to provide clear error messages
            and protect against malformed input. This is defensive programming
            despite grammar guarantees.
        """
        network = str(ip_token.value)
        prefix_len = int(prefix_token.value)

        # Defensive validation: Grammar enforces integer, we enforce IPv6 range (0-128)
        # This provides clear diagnostics and documents expected range
        if prefix_len < 0 or prefix_len > 128:
            self.add_diagnostic(
                DiagnosticLevel.WARNING,
                f"IPv6 CIDR prefix length {prefix_len} out of range (0-128)",
                token_to_location(prefix_token, self.file_path),
            )

        return IPCIDRRange(
            network=network,
            prefix_len=prefix_len,
            location=token_to_location(ip_token, self.file_path),
        )

    @v_args(inline=True)
    def address_range(self, start: Any, end: Any) -> IPRange:
        """
        Transform IP address range (e.g., [192.168.1.1-192.168.1.254]).

        Args:
            start: Starting IP address (IPAddress node or token)
            end: Ending IP address (IPAddress node or token)

        Returns:
            IPRange node representing the address range

        Note:
            The method handles both IPAddress nodes and raw tokens, extracting
            the IP string value appropriately. This flexibility is needed due
            to how the grammar parses range expressions.
        """
        # Extract IP address strings - handle both IPAddress nodes and tokens
        start_ip = start.value if isinstance(start, IPAddress) else str(start)
        end_ip = end.value if isinstance(end, IPAddress) else str(end)

        return IPRange(start=start_ip, end=end_ip)

    @v_args(inline=True)
    def address_ip(self, ip_token: Token) -> IPAddress:
        """
        Transform single IP address (IPv4 or IPv6).

        Args:
            ip_token: Token containing the IP address string

        Returns:
            IPAddress node with IP version automatically detected

        Version Detection:
            IPv6 addresses are detected by the presence of colons (:).
            This heuristic works because:
            - IPv4: dotted decimal notation (e.g., 192.168.1.1)
            - IPv6: colon-separated hex notation (e.g., 2001:db8::1)
        """
        ip_str = str(ip_token.value)

        # Detect IP version: IPv6 contains colons, IPv4 does not
        # This heuristic is reliable because the grammar ensures valid IP syntax
        version: int = 6 if ":" in ip_str else 4

        return IPAddress(
            value=ip_str,
            version=version,
            location=token_to_location(ip_token, self.file_path),
        )
