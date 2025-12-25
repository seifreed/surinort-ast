"""
Unit tests for AddressTransformerMixin.

Tests address transformation methods in isolation, including:
- IPv4 and IPv6 addresses
- CIDR notation (IPv4 and IPv6)
- IP ranges
- Address variables
- Address lists and negations
- Any address wildcard
- Edge cases and error conditions
- Defensive validations

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import pytest
from lark import Token

from surinort_ast.core.diagnostics import DiagnosticLevel
from surinort_ast.core.nodes import (
    AddressList,
    AddressNegation,
    AddressVariable,
    AnyAddress,
    IPAddress,
    IPCIDRRange,
    IPRange,
)
from surinort_ast.parsing.mixins.address_transformer import AddressTransformerMixin


class MockTransformer(AddressTransformerMixin):
    """Mock transformer for testing AddressTransformerMixin in isolation."""

    def __init__(self, file_path: str | None = None):
        """Initialize mock transformer."""
        self.file_path = file_path
        self.diagnostics: list[tuple[DiagnosticLevel, str]] = []

    def add_diagnostic(
        self,
        level: DiagnosticLevel,
        message: str,
        location=None,
        code: str | None = None,
        hint: str | None = None,
    ) -> None:
        """Record diagnostic for testing."""
        self.diagnostics.append((level, message))


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def transformer():
    """Create a mock transformer instance."""
    return MockTransformer(file_path="test.rules")


def create_token(value: str, line: int = 1, column: int = 0, start_pos: int = 0) -> Token:
    """Create a mock Lark token for testing."""
    token = Token("TEST", value)
    token.line = line
    token.column = column
    token.start_pos = start_pos
    token.end_pos = start_pos + len(str(value))
    token.end_line = line
    token.end_column = column + len(str(value))
    return token


# ============================================================================
# Test: Any Address
# ============================================================================


def test_address_any(transformer):
    """Test transformation of 'any' address."""
    result = transformer.address_any(None)
    assert isinstance(result, AnyAddress)


# ============================================================================
# Test: Address Variables
# ============================================================================


def test_address_var_with_dollar_sign(transformer):
    """Test address variable transformation with leading $."""
    token = create_token("$HOME_NET")
    result = transformer.address_var(token)

    assert isinstance(result, AddressVariable)
    assert result.name == "HOME_NET"  # $ should be stripped
    assert result.location is not None
    assert result.location.file_path == "test.rules"


def test_address_var_without_dollar_sign(transformer):
    """Test address variable without leading $ (edge case)."""
    token = create_token("HOME_NET")
    result = transformer.address_var(token)

    assert isinstance(result, AddressVariable)
    assert result.name == "HOME_NET"


def test_address_var_location_tracking(transformer):
    """Test that location information is correctly tracked for variables."""
    token = create_token("$EXTERNAL_NET", line=5, column=10, start_pos=100)
    result = transformer.address_var(token)

    assert result.location is not None
    assert result.location.span.start.line == 5
    assert result.location.span.start.column == 11  # Column is 1-indexed


# ============================================================================
# Test: Address Negation
# ============================================================================


def test_address_negation_with_ip(transformer):
    """Test negation of IP address."""
    ip_token = create_token("192.168.1.1")
    ip_addr = transformer.address_ip(ip_token)
    result = transformer.address_negation(ip_addr)

    assert isinstance(result, AddressNegation)
    assert isinstance(result.expr, IPAddress)
    assert result.expr.value == "192.168.1.1"


def test_address_negation_with_variable(transformer):
    """Test negation of address variable."""
    var_token = create_token("$HOME_NET")
    var_addr = transformer.address_var(var_token)
    result = transformer.address_negation(var_addr)

    assert isinstance(result, AddressNegation)
    assert isinstance(result.expr, AddressVariable)
    assert result.expr.name == "HOME_NET"


# ============================================================================
# Test: Address Lists
# ============================================================================


def test_address_list_empty(transformer):
    """Test empty address list."""
    result = transformer.address_list([])

    assert isinstance(result, AddressList)
    assert len(result.elements) == 0


def test_address_list_single_element(transformer):
    """Test address list with single element."""
    ip_token = create_token("192.168.1.1")
    ip_addr = transformer.address_ip(ip_token)
    result = transformer.address_list([ip_addr])

    assert isinstance(result, AddressList)
    assert len(result.elements) == 1
    assert result.elements[0].value == "192.168.1.1"


def test_address_list_multiple_elements(transformer):
    """Test address list with multiple elements."""
    ip1 = transformer.address_ip(create_token("192.168.1.1"))
    ip2 = transformer.address_ip(create_token("10.0.0.1"))
    var = transformer.address_var(create_token("$HOME_NET"))

    result = transformer.address_list([ip1, ip2, var])

    assert isinstance(result, AddressList)
    assert len(result.elements) == 3
    assert isinstance(result.elements[0], IPAddress)
    assert isinstance(result.elements[1], IPAddress)
    assert isinstance(result.elements[2], AddressVariable)


# ============================================================================
# Test: IPv4 Addresses
# ============================================================================


def test_address_ip_ipv4(transformer):
    """Test IPv4 address transformation."""
    token = create_token("192.168.1.1")
    result = transformer.address_ip(token)

    assert isinstance(result, IPAddress)
    assert result.value == "192.168.1.1"
    assert result.version == 4


def test_address_ip_ipv4_edge_cases(transformer):
    """Test IPv4 edge cases (0.0.0.0, 255.255.255.255)."""
    # Minimum IPv4
    result1 = transformer.address_ip(create_token("0.0.0.0"))
    assert result1.value == "0.0.0.0"
    assert result1.version == 4

    # Maximum IPv4
    result2 = transformer.address_ip(create_token("255.255.255.255"))
    assert result2.value == "255.255.255.255"
    assert result2.version == 4


# ============================================================================
# Test: IPv6 Addresses
# ============================================================================


def test_address_ip_ipv6_full(transformer):
    """Test full IPv6 address transformation."""
    token = create_token("2001:0db8:0000:0000:0000:0000:0000:0001")
    result = transformer.address_ip(token)

    assert isinstance(result, IPAddress)
    assert result.value == "2001:0db8:0000:0000:0000:0000:0000:0001"
    assert result.version == 6


def test_address_ip_ipv6_compressed(transformer):
    """Test compressed IPv6 address transformation."""
    token = create_token("2001:db8::1")
    result = transformer.address_ip(token)

    assert isinstance(result, IPAddress)
    assert result.value == "2001:db8::1"
    assert result.version == 6


def test_address_ip_ipv6_loopback(transformer):
    """Test IPv6 loopback address."""
    token = create_token("::1")
    result = transformer.address_ip(token)

    assert result.value == "::1"
    assert result.version == 6


def test_address_ip_ipv6_unspecified(transformer):
    """Test IPv6 unspecified address."""
    token = create_token("::")
    result = transformer.address_ip(token)

    assert result.value == "::"
    assert result.version == 6


# ============================================================================
# Test: IPv4 CIDR
# ============================================================================


def test_ipv4_cidr_valid(transformer):
    """Test valid IPv4 CIDR transformation."""
    ip_token = create_token("192.168.1.0")
    prefix_token = create_token("24")
    result = transformer.ipv4_cidr(ip_token, prefix_token)

    assert isinstance(result, IPCIDRRange)
    assert result.network == "192.168.1.0"
    assert result.prefix_len == 24
    assert len(transformer.diagnostics) == 0


def test_ipv4_cidr_edge_cases(transformer):
    """Test IPv4 CIDR edge cases (0, 32)."""
    # /0 - entire IPv4 space
    result1 = transformer.ipv4_cidr(create_token("0.0.0.0"), create_token("0"))
    assert result1.prefix_len == 0
    assert len(transformer.diagnostics) == 0

    # /32 - single host
    result2 = transformer.ipv4_cidr(create_token("192.168.1.1"), create_token("32"))
    assert result2.prefix_len == 32
    assert len(transformer.diagnostics) == 0


def test_ipv4_cidr_invalid_prefix_negative(transformer):
    """Test IPv4 CIDR with negative prefix raises Pydantic validation error."""
    from pydantic_core import ValidationError

    ip_token = create_token("192.168.1.0")
    prefix_token = create_token("-1")

    # Pydantic enforces prefix_len >= 0, so this should raise ValidationError
    with pytest.raises(ValidationError):
        transformer.ipv4_cidr(ip_token, prefix_token)


def test_ipv4_cidr_invalid_prefix_too_large(transformer):
    """Test IPv4 CIDR with prefix > 32 (defensive validation with diagnostic)."""
    ip_token = create_token("192.168.1.0")
    prefix_token = create_token("33")
    result = transformer.ipv4_cidr(ip_token, prefix_token)

    # Pydantic allows 0-128, but we add diagnostic for IPv4-specific range
    assert isinstance(result, IPCIDRRange)
    assert result.prefix_len == 33
    assert len(transformer.diagnostics) == 1
    assert transformer.diagnostics[0][0] == DiagnosticLevel.WARNING
    assert "0-32" in transformer.diagnostics[0][1]


# ============================================================================
# Test: IPv6 CIDR
# ============================================================================


def test_ipv6_cidr_valid(transformer):
    """Test valid IPv6 CIDR transformation."""
    ip_token = create_token("2001:db8::")
    prefix_token = create_token("32")
    result = transformer.ipv6_cidr(ip_token, prefix_token)

    assert isinstance(result, IPCIDRRange)
    assert result.network == "2001:db8::"
    assert result.prefix_len == 32
    assert len(transformer.diagnostics) == 0


def test_ipv6_cidr_edge_cases(transformer):
    """Test IPv6 CIDR edge cases (0, 128)."""
    # /0 - entire IPv6 space
    result1 = transformer.ipv6_cidr(create_token("::"), create_token("0"))
    assert result1.prefix_len == 0
    assert len(transformer.diagnostics) == 0

    # /128 - single host
    result2 = transformer.ipv6_cidr(create_token("2001:db8::1"), create_token("128"))
    assert result2.prefix_len == 128
    assert len(transformer.diagnostics) == 0


def test_ipv6_cidr_invalid_prefix_negative(transformer):
    """Test IPv6 CIDR with negative prefix raises Pydantic validation error."""
    from pydantic_core import ValidationError

    ip_token = create_token("2001:db8::")
    prefix_token = create_token("-1")

    # Pydantic enforces prefix_len >= 0, so this should raise ValidationError
    with pytest.raises(ValidationError):
        transformer.ipv6_cidr(ip_token, prefix_token)


def test_ipv6_cidr_invalid_prefix_too_large(transformer):
    """Test IPv6 CIDR with prefix > 128 raises Pydantic validation error."""
    from pydantic_core import ValidationError

    ip_token = create_token("2001:db8::")
    prefix_token = create_token("129")

    # Pydantic enforces prefix_len <= 128, so this should raise ValidationError
    with pytest.raises(ValidationError):
        transformer.ipv6_cidr(ip_token, prefix_token)


# ============================================================================
# Test: IP Ranges
# ============================================================================


def test_address_range_ipv4(transformer):
    """Test IPv4 address range."""
    start = transformer.address_ip(create_token("192.168.1.1"))
    end = transformer.address_ip(create_token("192.168.1.254"))
    result = transformer.address_range(start, end)

    assert isinstance(result, IPRange)
    assert result.start == "192.168.1.1"
    assert result.end == "192.168.1.254"


def test_address_range_ipv6(transformer):
    """Test IPv6 address range."""
    start = transformer.address_ip(create_token("2001:db8::1"))
    end = transformer.address_ip(create_token("2001:db8::ffff"))
    result = transformer.address_range(start, end)

    assert isinstance(result, IPRange)
    assert result.start == "2001:db8::1"
    assert result.end == "2001:db8::ffff"


def test_address_range_with_token_input(transformer):
    """Test address range with raw token input (alternative grammar path)."""
    # Simulate case where grammar passes tokens directly
    start_token = create_token("10.0.0.1")
    end_token = create_token("10.0.0.255")
    result = transformer.address_range(start_token, end_token)

    assert isinstance(result, IPRange)
    assert result.start == "10.0.0.1"
    assert result.end == "10.0.0.255"


# ============================================================================
# Test: Complex Compositions
# ============================================================================


def test_negated_cidr_in_list(transformer):
    """Test complex case: negated CIDR in address list."""
    cidr = transformer.ipv4_cidr(create_token("192.168.1.0"), create_token("24"))
    negated_cidr = transformer.address_negation(cidr)
    any_addr = transformer.address_any(None)

    result = transformer.address_list([any_addr, negated_cidr])

    assert isinstance(result, AddressList)
    assert len(result.elements) == 2
    assert isinstance(result.elements[0], AnyAddress)
    assert isinstance(result.elements[1], AddressNegation)
    assert isinstance(result.elements[1].expr, IPCIDRRange)


def test_multiple_negations(transformer):
    """Test nested negations (though rare in practice)."""
    var = transformer.address_var(create_token("$HOME_NET"))
    neg1 = transformer.address_negation(var)
    neg2 = transformer.address_negation(neg1)

    assert isinstance(neg2, AddressNegation)
    assert isinstance(neg2.expr, AddressNegation)
    assert isinstance(neg2.expr.expr, AddressVariable)


# ============================================================================
# Test: Location Tracking
# ============================================================================


def test_location_tracking_preserved(transformer):
    """Test that location information is preserved through transformations."""
    token = create_token("192.168.1.1", line=10, column=20, start_pos=500)
    result = transformer.address_ip(token)

    assert result.location is not None
    assert result.location.span.start.line == 10
    assert result.location.span.start.column == 21  # 1-indexed
    assert result.location.span.start.offset == 500
    assert result.location.file_path == "test.rules"


def test_cidr_location_from_network_token(transformer):
    """Test that CIDR range location comes from network token."""
    ip_token = create_token("10.0.0.0", line=5, column=10, start_pos=100)
    prefix_token = create_token("8")
    result = transformer.ipv4_cidr(ip_token, prefix_token)

    # Location should come from IP token
    assert result.location is not None
    assert result.location.span.start.line == 5
    assert result.location.span.start.column == 11  # 1-indexed


# ============================================================================
# Test: Documentation Compliance
# ============================================================================


def test_defensive_validations_document_intent(transformer):
    """Test that defensive validations serve documentation purpose."""
    # For IPv4, values 33-128 are valid for Pydantic (which allows 0-128)
    # but should generate warnings since they're outside IPv4's valid range
    result = transformer.ipv4_cidr(create_token("192.168.1.0"), create_token("64"))

    assert isinstance(result, IPCIDRRange)
    assert len(transformer.diagnostics) > 0
    # The diagnostic message should document the IPv4-specific valid range
    diagnostic_msg = transformer.diagnostics[0][1]
    assert "0-32" in diagnostic_msg  # Documents IPv4 range


def test_mixin_requires_parent_attributes(transformer):
    """Test that mixin correctly uses parent class attributes."""
    # file_path should be used in location tracking
    assert transformer.file_path == "test.rules"

    token = create_token("192.168.1.1")
    result = transformer.address_ip(token)

    # Location should include file_path from parent
    assert result.location.file_path == "test.rules"
