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
from typing import TYPE_CHECKING, Any

from lark import Token
from lark.visitors import v_args

if TYPE_CHECKING:
    from ...core.location import Location
    from . import DiagnosticReporter

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
from ..helpers import strip_variable_marker, token_to_location


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
    add_diagnostic: DiagnosticReporter

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
        name = strip_variable_marker(var_token)
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

    def _check_ipv4_octets(self, ip_str: str, location: Location | None) -> None:
        """
        Emit a WARNING for any IPv4 octet outside the valid 0-255 range.

        The grammar guarantees dotted-decimal syntax (four 1-3 digit groups) but
        not octet magnitude, so addresses like 999.999.999.999 reach this point
        structurally valid yet semantically impossible. This mirrors the CIDR
        prefix-range check, keeping address validation consistent.
        """
        for octet in ip_str.split("."):
            value = int(octet)
            if value > 255:
                self.add_diagnostic(
                    DiagnosticLevel.WARNING,
                    f"IPv4 octet {value} out of range (0-255) in address {ip_str}",
                    location,
                )
                return

    def _build_cidr(self, ip_token: Token, prefix_token: Token, ip_version: int) -> IPCIDRRange:
        """
        Build an :class:`IPCIDRRange`, validating the prefix for the IP version.

        Args:
            ip_token: Token containing the network address.
            prefix_token: Token containing the prefix length.
            ip_version: 4 or 6; determines the valid prefix range (0-32 / 0-128).

        Defensive Validation:
            The grammar ensures ``prefix_token`` is a valid integer, but the
            magnitude is validated here so an out-of-range prefix yields a clear
            diagnostic and is clamped to a usable value instead of producing a
            structurally invalid node.
        """
        max_prefix = 32 if ip_version == 4 else 128
        network = str(ip_token.value)
        prefix_len = int(prefix_token.value)

        if prefix_len < 0 or prefix_len > max_prefix:
            self.add_diagnostic(
                DiagnosticLevel.WARNING,
                f"IPv{ip_version} CIDR prefix length {prefix_len} out of range (0-{max_prefix})",
                token_to_location(prefix_token, self.file_path),
            )
            prefix_len = max(0, min(prefix_len, max_prefix))

        return IPCIDRRange(
            network=network,
            prefix_len=prefix_len,
            location=token_to_location(ip_token, self.file_path),
        )

    @v_args(inline=True)
    def ipv4_cidr(self, ip_token: Token, prefix_token: Token) -> IPCIDRRange:
        """
        Transform IPv4 CIDR notation (e.g., 192.168.1.0/24).

        Args:
            ip_token: Token containing the IPv4 network address
            prefix_token: Token containing the prefix length (0-32)

        Returns:
            IPCIDRRange node representing the CIDR block
        """
        self._check_ipv4_octets(str(ip_token.value), token_to_location(ip_token, self.file_path))
        return self._build_cidr(ip_token, prefix_token, ip_version=4)

    @v_args(inline=True)
    def ipv6_cidr(self, ip_token: Token, prefix_token: Token) -> IPCIDRRange:
        """
        Transform IPv6 CIDR notation (e.g., 2001:db8::/32).

        Args:
            ip_token: Token containing the IPv6 network address
            prefix_token: Token containing the prefix length (0-128)

        Returns:
            IPCIDRRange node representing the CIDR block
        """
        return self._build_cidr(ip_token, prefix_token, ip_version=6)

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

        if version == 4:
            self._check_ipv4_octets(ip_str, token_to_location(ip_token, self.file_path))

        return IPAddress(
            value=ip_str,
            version=version,
            location=token_to_location(ip_token, self.file_path),
        )
