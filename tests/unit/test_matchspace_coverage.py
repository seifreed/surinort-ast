# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage tests for analysis/conflicts/matchspace.py.

The match-space algebra is a set of pure functions over AST address/port/content
nodes; these tests drive the interval, address-set, port-set, orientation, and
content-constraint branches directly with real AST nodes.
"""

from __future__ import annotations

from surinort_ast import parse_rule
from surinort_ast.analysis.conflicts.matchspace import (
    AddrSet,
    ContentConstraint,
    PortSet,
    Tri,
    _concrete_ip_interval,
    _concrete_port_interval,
    _content_is_positioned,
    _merge,
    _union_addr_sets,
    _union_port_sets,
    build_addr_set,
    build_content_constraint,
    build_port_set,
    content_intersects,
    oriented_headers,
)
from surinort_ast.core.enums import Direction, Protocol
from surinort_ast.core.nodes import (
    AddressList,
    AddressNegation,
    AddressVariable,
    AnyAddress,
    AnyPort,
    ContentModifier,
    ContentOption,
    Header,
    IPAddress,
    IPRange,
    Port,
    PortList,
    PortNegation,
    PortRange,
    PortVariable,
)


class TestIntervalHelpers:
    def test_merge_empty(self):
        assert _merge([]) == []

    def test_merge_coalesces_overlapping(self):
        assert _merge([(1, 5), (3, 8), (20, 25)]) == [(1, 8), (20, 25)]


class TestConcreteIpInterval:
    def test_ip_range(self):
        interval, version = _concrete_ip_interval(IPRange(start="10.0.0.1", end="10.0.0.5"))
        assert version == 4
        assert interval[0] < interval[1]

    def test_non_concrete_returns_none(self):
        assert _concrete_ip_interval(AddressVariable(name="HOME_NET")) is None


class TestBuildAddrSet:
    def test_negation_is_opaque(self):
        result = build_addr_set(AddressNegation(expr=IPAddress(value="1.2.3.4", version=4)))
        assert result.opaque

    def test_address_list_unions(self):
        result = build_addr_set(
            AddressList(
                elements=[
                    IPAddress(value="1.2.3.4", version=4),
                    IPAddress(value="5.6.7.8", version=4),
                ]
            )
        )
        assert len(result.v4) == 2

    def test_unknown_node_is_opaque(self):
        # The closed AST union is exhaustively handled; the catch-all keeps the
        # function total and conservatively treats any unrecognized node as
        # opaque. An object outside the union exercises that documented path.
        result = build_addr_set(object())  # type: ignore[arg-type]
        assert result.opaque


class TestUnionAddrSets:
    def test_any_dominates(self):
        result = _union_addr_sets([AddrSet(any_=True), AddrSet(v4=((1, 2),))])
        assert result.any_

    def test_merges_intervals_and_opaque(self):
        result = _union_addr_sets(
            [
                AddrSet(v4=((1, 5),), opaque=frozenset({"x"})),
                AddrSet(v4=((3, 9),), opaque=frozenset({"y"})),
            ]
        )
        assert result.v4 == ((1, 9),)
        assert result.opaque == frozenset({"x", "y"})


class TestPortSets:
    def test_is_pure_token(self):
        assert PortSet(opaque=frozenset({"$HTTP_PORTS"})).is_pure_token is True
        assert PortSet(intervals=((1, 2),)).is_pure_token is False

    def test_concrete_port_range(self):
        assert _concrete_port_interval(PortRange(start=1024, end=2048)) == (1024, 2048)

    def test_concrete_port_non_concrete(self):
        assert _concrete_port_interval(PortVariable(name="HTTP_PORTS")) is None

    def test_port_variable_opaque(self):
        assert build_port_set(PortVariable(name="HTTP_PORTS")).opaque

    def test_port_negation_opaque(self):
        assert build_port_set(PortNegation(expr=Port(value=80))).opaque

    def test_unknown_port_node_opaque(self):
        result = build_port_set(object())  # type: ignore[arg-type]
        assert result.opaque

    def test_union_port_any_dominates(self):
        result = build_port_set(PortList(elements=[AnyPort(), Port(value=80)]))
        assert result.any_

    def test_union_port_merges(self):
        result = _union_port_sets([PortSet(intervals=((1, 5),)), PortSet(intervals=((4, 9),))])
        assert result.intervals == ((1, 9),)


class TestOrientedHeaders:
    def test_bidirectional_yields_two_orientations(self):
        rule = parse_rule('alert tcp 1.1.1.1 80 <> 2.2.2.2 90 (msg:"x"; sid:1;)')

        oriented = oriented_headers(rule.header)

        assert len(oriented) == 2
        assert oriented[0].src_addr == oriented[1].dst_addr

    def test_from_direction_reverses(self):
        header = Header(
            protocol=Protocol.TCP,
            src_addr=IPAddress(value="1.1.1.1", version=4),
            src_port=Port(value=80),
            direction=Direction.FROM,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        oriented = oriented_headers(header)

        assert len(oriented) == 1
        # FROM flips the orientation: the header's dst becomes the oriented src.
        assert oriented[0].src_addr.any_ is True


class TestContentConstraints:
    def test_content_is_positioned(self):
        positioned = ContentOption(
            pattern=b"GET", modifiers=(ContentModifier(name="offset", value=5),)
        )
        # A non-positional modifier makes the loop iterate and fall through.
        non_positional = ContentOption(pattern=b"GET", modifiers=(ContentModifier(name="nocase"),))

        assert _content_is_positioned(positioned) is True
        assert _content_is_positioned(non_positional) is False

    def test_pcre_makes_constraint_opaque(self):
        rule = parse_rule('alert tcp any any -> any any (msg:"x"; pcre:"/abc/"; sid:1;)')

        constraint = build_content_constraint(rule)

        assert constraint.opaque is True

    def test_distinct_literals_intersect_unknown(self):
        a = ContentConstraint(literals=frozenset({b"AAA"}), opaque=False)
        b = ContentConstraint(literals=frozenset({b"BBB"}), opaque=False)

        assert content_intersects(a, b) is Tri.UNKNOWN
