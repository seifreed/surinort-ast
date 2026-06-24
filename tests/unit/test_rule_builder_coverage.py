# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage-gap tests for builder/rule_builder.py.

Each test class targets a specific cluster of uncovered lines/branches.
All tests execute real production code paths via the public fluent API
and assert on the resulting AST state. No mocks, stubs, or suppression
markers are used.

Uncovered lines targeted:
    80->84  _normalize_pcre: non-flag chars after closing slash → fallthrough
    203     icmp() convenience method
    281-282 direction() with string argument
    467-468 content() sticky_buffers kwarg (enabled branch)
    475     content() nocase modifier branch
    477     content() rawbytes modifier branch
    479     content() offset modifier branch
    481     content() depth modifier branch
    483     content() distance modifier branch
    485     content() within modifier branch
    487     content() startswith modifier branch
    489     content() endswith modifier branch
    491     content() fast_pattern modifier branch
    772-773 option() raw Option insertion
    844     _parse_address() with an AddressExpr node passed directly
    869     _parse_address() invalid CIDR (more than one slash)
    873-874 _parse_address() non-integer CIDR prefix length
    895     _parse_ip_range() with a range string containing more than one dash
    920     _parse_port() with a PortExpr node passed directly
    954-955 _parse_port() invalid port string (non-numeric)
    975     _parse_port_range() port range with embedded second colon
    978     _parse_port_range() upper-bounded range (:end form)
    980     _parse_port_range() open-ended range (start: form)
    982-983 _parse_port_range() non-numeric port range values
    984-985 _parse_port_range() reversed range auto-swap
"""

import pytest

from surinort_ast.builder import RuleBuilder
from surinort_ast.builder.rule_builder import BuilderError, _normalize_pcre
from surinort_ast.core.enums import Direction, Protocol
from surinort_ast.core.nodes import (
    AnyAddress,
    AnyPort,
    BufferSelectOption,
    ContentOption,
    DepthOption,
    DistanceOption,
    EndswithOption,
    FastPatternOption,
    GidOption,
    IPAddress,
    NocaseOption,
    OffsetOption,
    Port,
    PortRange,
    RawbytesOption,
    StartswithOption,
    WithinOption,
)

# ---------------------------------------------------------------------------
# Helper: minimal builder pre-configured with header fields.
# ---------------------------------------------------------------------------


def _base() -> RuleBuilder:
    """Return a RuleBuilder with all header fields set, ready for options."""
    return (
        RuleBuilder().alert().tcp().source_ip("any").source_port("any").dest_ip("any").dest_port(80)
    )


# ---------------------------------------------------------------------------
# _normalize_pcre — line 80->84 fallthrough
# ---------------------------------------------------------------------------


class TestNormalizePcreFallthrough:
    """_normalize_pcre must NOT treat a /body/X string as delimited when
    X contains characters outside the legal PCRE flag set."""

    def test_invalid_flag_chars_return_pattern_unchanged(self) -> None:
        # 'z' is not in _PCRE_FLAG_CHARS, so the whole string is preserved.
        body, flags = _normalize_pcre("/admin/z")
        assert body == "/admin/z"
        assert flags == ""

    def test_only_one_slash_returns_pattern_unchanged(self) -> None:
        # A string that starts with '/' but has no second slash falls through.
        body, flags = _normalize_pcre("/noclose")
        assert body == "/noclose"
        assert flags == ""

    def test_valid_flags_still_unwrap(self) -> None:
        # Positive control: valid flags still unwrap correctly.
        body, flags = _normalize_pcre("/admin/is")
        assert body == "admin"
        assert flags == "is"


# ---------------------------------------------------------------------------
# icmp() convenience method — line 203
# ---------------------------------------------------------------------------


class TestIcmpProtocol:
    """icmp() must set the protocol to ICMP."""

    def test_icmp_sets_protocol(self) -> None:
        rule = (
            RuleBuilder()
            .alert()
            .icmp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port("any")
            .sid(1)
            .build()
        )
        assert rule.header.protocol == Protocol.ICMP


# ---------------------------------------------------------------------------
# direction() with a string argument — lines 281-282
# ---------------------------------------------------------------------------


class TestDirectionFromString:
    """direction() must accept string values and convert them to Direction."""

    def test_direction_string_to(self) -> None:
        rule = _base().direction("->").sid(1).build()
        assert rule.header.direction == Direction.TO

    def test_direction_string_bidirectional(self) -> None:
        rule = _base().direction("<>").sid(1).build()
        assert rule.header.direction == Direction.BIDIRECTIONAL

    def test_direction_enum_passthrough(self) -> None:
        # Passing an enum directly must also work (the else branch).
        rule = _base().direction(Direction.FROM).sid(1).build()
        assert rule.header.direction == Direction.FROM


# ---------------------------------------------------------------------------
# content() modifier branches — lines 467-491
# ---------------------------------------------------------------------------


class TestContentModifierBranches:
    """Each keyword argument branch inside content() must emit the correct
    modifier option node immediately after the ContentOption."""

    def test_sticky_buffer_kwarg_enabled(self) -> None:
        """http_uri=True must prepend a BufferSelectOption before ContentOption."""
        rule = _base().sid(1).content(b"GET", http_uri=True).build()
        buf_idx = next(i for i, o in enumerate(rule.options) if isinstance(o, BufferSelectOption))
        content_idx = next(i for i, o in enumerate(rule.options) if isinstance(o, ContentOption))
        assert buf_idx < content_idx
        buf_opts = [o for o in rule.options if isinstance(o, BufferSelectOption)]
        assert buf_opts[0].buffer_name == "http_uri"

    def test_sticky_buffer_kwarg_disabled_not_added(self) -> None:
        """http_uri=False must NOT add a BufferSelectOption."""
        rule = _base().sid(1).content(b"GET", http_uri=False).build()
        buf_opts = [o for o in rule.options if isinstance(o, BufferSelectOption)]
        assert buf_opts == []

    def test_nocase_modifier(self) -> None:
        rule = _base().sid(1).content(b"GET", nocase=True).build()
        pos = [type(o).__name__ for o in rule.options]
        assert "NocaseOption" in pos
        nc_idx = next(i for i, o in enumerate(rule.options) if isinstance(o, NocaseOption))
        ct_idx = next(i for i, o in enumerate(rule.options) if isinstance(o, ContentOption))
        assert nc_idx > ct_idx

    def test_rawbytes_modifier(self) -> None:
        rule = _base().sid(1).content(b"GET", rawbytes=True).build()
        assert any(isinstance(o, RawbytesOption) for o in rule.options)

    def test_offset_modifier(self) -> None:
        rule = _base().sid(1).content(b"GET", offset=5).build()
        offset_opts = [o for o in rule.options if isinstance(o, OffsetOption)]
        assert len(offset_opts) == 1
        assert offset_opts[0].value == 5

    def test_depth_modifier(self) -> None:
        rule = _base().sid(1).content(b"GET", depth=100).build()
        depth_opts = [o for o in rule.options if isinstance(o, DepthOption)]
        assert len(depth_opts) == 1
        assert depth_opts[0].value == 100

    def test_distance_modifier(self) -> None:
        rule = _base().sid(1).content(b"GET", distance=3).build()
        dist_opts = [o for o in rule.options if isinstance(o, DistanceOption)]
        assert len(dist_opts) == 1
        assert dist_opts[0].value == 3

    def test_within_modifier(self) -> None:
        rule = _base().sid(1).content(b"GET", within=20).build()
        within_opts = [o for o in rule.options if isinstance(o, WithinOption)]
        assert len(within_opts) == 1
        assert within_opts[0].value == 20

    def test_startswith_modifier(self) -> None:
        rule = _base().sid(1).content(b"GET", startswith=True).build()
        assert any(isinstance(o, StartswithOption) for o in rule.options)

    def test_endswith_modifier(self) -> None:
        rule = _base().sid(1).content(b"GET", endswith=True).build()
        assert any(isinstance(o, EndswithOption) for o in rule.options)

    def test_fast_pattern_modifier(self) -> None:
        rule = _base().sid(1).content(b"GET", fast_pattern=True).build()
        assert any(isinstance(o, FastPatternOption) for o in rule.options)

    def test_all_modifiers_combined(self) -> None:
        """All modifier branches fire together with a single content() call."""
        rule = (
            _base()
            .sid(1)
            .content(
                b"GET",
                nocase=True,
                rawbytes=True,
                offset=0,
                depth=50,
                distance=1,
                within=10,
                startswith=True,
                endswith=True,
                fast_pattern=True,
                file_data=True,
            )
            .build()
        )
        option_types = {type(o).__name__ for o in rule.options}
        assert "NocaseOption" in option_types
        assert "RawbytesOption" in option_types
        assert "OffsetOption" in option_types
        assert "DepthOption" in option_types
        assert "DistanceOption" in option_types
        assert "WithinOption" in option_types
        assert "StartswithOption" in option_types
        assert "EndswithOption" in option_types
        assert "FastPatternOption" in option_types
        assert "BufferSelectOption" in option_types


# ---------------------------------------------------------------------------
# option() raw insertion — lines 772-773
# ---------------------------------------------------------------------------


class TestRawOptionInsertion:
    """option() must append the given Option node verbatim."""

    def test_raw_option_appended(self) -> None:
        gid = GidOption(value=1)
        rule = _base().sid(1).option(gid).build()
        gid_opts = [o for o in rule.options if isinstance(o, GidOption)]
        assert len(gid_opts) == 1
        assert gid_opts[0].value == 1

    def test_raw_option_returns_self(self) -> None:
        builder = _base().sid(1)
        result = builder.option(GidOption(value=1))
        assert result is builder


# ---------------------------------------------------------------------------
# _parse_address() — lines 844, 869, 873-874, 895
# ---------------------------------------------------------------------------


class TestParseAddressEdgeCases:
    """Edge-case paths in _parse_address() and _parse_ip_range()."""

    def test_address_expr_passed_directly(self) -> None:
        """Passing an AddressExpr node must be returned unchanged (line 844)."""
        node = AnyAddress()
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip(node)
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .sid(1)
            .build()
        )
        assert rule.header.src_addr is node

    def test_cidr_with_multiple_slashes_raises(self) -> None:
        """A CIDR string with more than one slash must raise BuilderError (line 869)."""
        with pytest.raises(BuilderError, match="Invalid CIDR format"):
            _base().source_ip("10.0.0.0/8/extra").sid(1).build()

    def test_cidr_with_non_integer_prefix_raises(self) -> None:
        """A non-integer prefix length must raise BuilderError (lines 873-874)."""
        with pytest.raises(BuilderError, match="Invalid CIDR prefix length"):
            _base().source_ip("10.0.0.0/bad").sid(1).build()

    def test_ipv4_cidr_prefix_above_32_raises(self) -> None:
        """An IPv4 CIDR prefix above 32 is invalid and must raise, not build silently."""
        with pytest.raises(BuilderError, match="out of range for IPv4"):
            _base().source_ip("10.0.0.0/33").sid(1).build()

    def test_ipv6_cidr_prefix_above_128_raises(self) -> None:
        """An IPv6 CIDR prefix above 128 is invalid and must raise."""
        with pytest.raises(BuilderError, match="out of range for IPv6"):
            _base().source_ip("2001:db8::/129").sid(1).build()

    def test_valid_cidr_prefixes_build(self) -> None:
        """Boundary prefixes (IPv4 /32, IPv6 /128) remain valid."""
        rule = _base().source_ip("10.0.0.0/32").sid(1).build()
        assert rule is not None
        rule6 = _base().source_ip("2001:db8::/128").sid(2).build()
        assert rule6 is not None

    def test_ip_range_with_multiple_dashes_raises(self) -> None:
        """An unbracketed string with more than one dash raises BuilderError (line 895).

        The string must not contain '/' (CIDR branch), '[' (bracket branch), or ':'
        (IPv6 branch) to reach _parse_ip_range. 'a-b-c' satisfies all constraints.
        """
        with pytest.raises(BuilderError, match="Invalid IP range format"):
            _base().source_ip("a-b-c").sid(1).build()


# ---------------------------------------------------------------------------
# _parse_port() — lines 920, 954-955
# ---------------------------------------------------------------------------


class TestParsePortEdgeCases:
    """Edge-case paths in _parse_port()."""

    def test_port_expr_passed_directly(self) -> None:
        """Passing a PortExpr node must be returned unchanged (line 920)."""
        node = AnyPort()
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port(node)
            .dest_ip("any")
            .dest_port(80)
            .sid(1)
            .build()
        )
        assert rule.header.src_port is node

    def test_invalid_port_string_raises(self) -> None:
        """A non-numeric port string must raise BuilderError (lines 954-955)."""
        with pytest.raises(BuilderError, match="Invalid port format"):
            _base().source_port("notaport").sid(1).build()


# ---------------------------------------------------------------------------
# _parse_port_range() — lines 975, 978, 980, 982-983, 984-985
# ---------------------------------------------------------------------------


class TestParsePortRange:
    """Every branch inside _parse_port_range()."""

    def test_double_colon_raises(self) -> None:
        """A port expression with two colons must raise BuilderError (line 975)."""
        with pytest.raises(BuilderError, match="Invalid port range format"):
            _base().source_port("1:2:3").sid(1).build()

    def test_upper_bounded_range(self) -> None:
        """':end' form must produce PortRange(start=0, end=N) (line 978)."""
        rule = _base().source_port(":1024").sid(1).build()
        assert isinstance(rule.header.src_port, PortRange)
        assert rule.header.src_port.start == 0
        assert rule.header.src_port.end == 1024

    def test_open_ended_range(self) -> None:
        """'start:' form must produce PortRange(start=N, end=65535) (line 980)."""
        rule = _base().source_port("1024:").sid(1).build()
        assert isinstance(rule.header.src_port, PortRange)
        assert rule.header.src_port.start == 1024
        assert rule.header.src_port.end == 65535

    def test_non_numeric_range_values_raises(self) -> None:
        """Non-numeric tokens in a range must raise BuilderError (lines 982-983)."""
        with pytest.raises(BuilderError, match="Invalid port range values"):
            _base().source_port("abc:def").sid(1).build()

    def test_reversed_range_is_auto_swapped(self) -> None:
        """A reversed range (high:low) must be silently swapped (lines 984-985)."""
        rule = _base().source_port("5000:1000").sid(1).build()
        assert isinstance(rule.header.src_port, PortRange)
        assert rule.header.src_port.start == 1000
        assert rule.header.src_port.end == 5000

    def test_open_ended_range_non_numeric_tail_raises(self) -> None:
        """'start:' form with non-numeric start must raise BuilderError."""
        with pytest.raises(BuilderError, match="Invalid port range values"):
            _base().source_port("abc:").sid(1).build()

    def test_upper_bounded_range_non_numeric_end_raises(self) -> None:
        """':end' form with non-numeric end must raise BuilderError."""
        with pytest.raises(BuilderError, match="Invalid port range values"):
            _base().source_port(":xyz").sid(1).build()


# ---------------------------------------------------------------------------
# Port node passed directly to dest_port (exercises _parse_port line 920
# on the dest side as well)
# ---------------------------------------------------------------------------


class TestPortExprPassthrough:
    """A PortExpr passed to dest_port must also short-circuit correctly."""

    def test_port_node_to_dest_port(self) -> None:
        node = Port(value=443)
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(node)
            .sid(1)
            .build()
        )
        assert rule.header.dst_port is node


# ---------------------------------------------------------------------------
# AddressExpr passed directly to dest_ip (exercises _parse_address line 844
# on the dest side)
# ---------------------------------------------------------------------------


class TestAddressExprPassthrough:
    """An AddressExpr passed to dest_ip must also short-circuit correctly."""

    def test_address_node_to_dest_ip(self) -> None:
        node = IPAddress(value="10.0.0.1", version=4)
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip(node)
            .dest_port(80)
            .sid(1)
            .build()
        )
        assert rule.header.dst_addr is node
