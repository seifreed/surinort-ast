"""
Match-space algebra for rule-conflict detection.

This module is the load-bearing core of conflict detection: it decides whether
two rules can match the same traffic by comparing their address sets, port sets,
protocols, directions, and content constraints.

Every comparison returns a tri-state :class:`Tri` (``TRUE``/``FALSE``/
``UNKNOWN``) so the detectors can be honest about undecidable cases (named
variables like ``$HOME_NET``, PCRE payloads, negations) instead of guessing.
Concrete addresses and ports are compared exactly via integer intervals; named
variables are compared by name only; negations and PCRE are treated as opaque.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum

from ...core.enums import Direction, Protocol
from ...core.nodes import (
    AddressExpr,
    AddressList,
    AddressNegation,
    AddressVariable,
    AnyAddress,
    AnyPort,
    ContentOption,
    Header,
    IPAddress,
    IPCIDRRange,
    IPRange,
    PcreOption,
    Port,
    PortExpr,
    PortList,
    PortNegation,
    PortRange,
    PortVariable,
    Rule,
)

Interval = tuple[int, int]


class Tri(Enum):
    """Three-valued logic result."""

    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


def tri_and(*values: Tri) -> Tri:
    """Conjunction: FALSE dominates, then UNKNOWN, then TRUE."""
    if Tri.FALSE in values:
        return Tri.FALSE
    if Tri.UNKNOWN in values:
        return Tri.UNKNOWN
    return Tri.TRUE


def tri_or(*values: Tri) -> Tri:
    """Disjunction: TRUE dominates, then UNKNOWN, then FALSE."""
    if Tri.TRUE in values:
        return Tri.TRUE
    if Tri.UNKNOWN in values:
        return Tri.UNKNOWN
    return Tri.FALSE


# ---------------------------------------------------------------------------
# Interval helpers
# ---------------------------------------------------------------------------


def _merge(intervals: list[Interval]) -> list[Interval]:
    """Sort and coalesce overlapping/adjacent integer intervals."""
    if not intervals:
        return []
    ordered = sorted(intervals)
    merged = [ordered[0]]
    for lo, hi in ordered[1:]:
        last_lo, last_hi = merged[-1]
        if lo <= last_hi + 1:
            merged[-1] = (last_lo, max(last_hi, hi))
        else:
            merged.append((lo, hi))
    return merged


def _intervals_overlap(a: list[Interval], b: list[Interval]) -> bool:
    for a_lo, a_hi in a:
        for b_lo, b_hi in b:
            if a_lo <= b_hi and b_lo <= a_hi:
                return True
    return False


def _intervals_cover(small: list[Interval], big: list[Interval]) -> bool:
    """True if every point of ``small`` lies within the union of ``big``."""
    return all(_interval_covered(lo, hi, big) for lo, hi in small)


def _interval_covered(lo: int, hi: int, big: list[Interval]) -> bool:
    cursor = lo
    for b_lo, b_hi in sorted(big):
        if b_lo > cursor:
            return False
        if b_hi >= cursor:
            cursor = b_hi + 1
        if cursor > hi:
            return True
    return cursor > hi


# ---------------------------------------------------------------------------
# Address sets
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AddrSet:
    """An abstract set of addresses split by IP version, with opaque tokens.

    ``any_`` means the whole address universe. ``opaque`` holds named variables
    and negations whose true extent is unknown; their presence forces UNKNOWN
    against concrete sets (but same-token comparisons are decidable).
    """

    any_: bool = False
    v4: tuple[Interval, ...] = ()
    v6: tuple[Interval, ...] = ()
    opaque: frozenset[str] = field(default_factory=frozenset)

    @property
    def is_pure_token(self) -> bool:
        return not self.any_ and not self.v4 and not self.v6 and bool(self.opaque)


def _concrete_ip_interval(expr: AddressExpr) -> tuple[Interval, int] | None:
    """Return ((lo, hi), version) for a concrete IP address node, else None."""
    if isinstance(expr, IPAddress):
        ip = int(ipaddress.ip_address(expr.value))
        return (ip, ip), expr.version
    if isinstance(expr, IPCIDRRange):
        net = ipaddress.ip_network(f"{expr.network}/{expr.prefix_len}", strict=False)
        return (int(net.network_address), int(net.broadcast_address)), net.version
    if isinstance(expr, IPRange):
        start = ipaddress.ip_address(expr.start)
        end = ipaddress.ip_address(expr.end)
        return (int(start), int(end)), start.version
    return None


def build_addr_set(expr: AddressExpr) -> AddrSet:
    """Convert an AddressExpr into an :class:`AddrSet`."""
    if isinstance(expr, AnyAddress):
        return AddrSet(any_=True)
    if isinstance(expr, AddressVariable):
        return AddrSet(opaque=frozenset({expr.name}))
    if isinstance(expr, AddressNegation):
        # Conservative: treat any negation as opaque so it never proves shadowing.
        return AddrSet(opaque=frozenset({f"!{expr.expr!r}"}))
    if isinstance(expr, AddressList):
        return _union_addr_sets([build_addr_set(e) for e in expr.elements])
    concrete = _concrete_ip_interval(expr)
    if concrete is not None:
        interval, version = concrete
        return AddrSet(v6=(interval,)) if version == 6 else AddrSet(v4=(interval,))
    # Unknown address node: opaque.
    return AddrSet(opaque=frozenset({repr(expr)}))


def _union_addr_sets(sets: list[AddrSet]) -> AddrSet:
    if any(s.any_ for s in sets):
        return AddrSet(any_=True)
    v4: list[Interval] = []
    v6: list[Interval] = []
    opaque: set[str] = set()
    for s in sets:
        v4.extend(s.v4)
        v6.extend(s.v6)
        opaque |= s.opaque
    return AddrSet(v4=tuple(_merge(v4)), v6=tuple(_merge(v6)), opaque=frozenset(opaque))


def addr_intersects(a: AddrSet, b: AddrSet) -> Tri:
    if a.any_ or b.any_:
        return Tri.TRUE
    if a.opaque or b.opaque:
        if a.opaque & b.opaque:
            return Tri.TRUE
        return Tri.UNKNOWN
    if _intervals_overlap(list(a.v4), list(b.v4)) or _intervals_overlap(list(a.v6), list(b.v6)):
        return Tri.TRUE
    return Tri.FALSE


def addr_subset(a: AddrSet, b: AddrSet) -> Tri:
    """Is ``a`` a subset of ``b``?"""
    if b.any_:
        return Tri.TRUE
    if a.any_:
        return Tri.FALSE
    if a.opaque or b.opaque:
        if a.is_pure_token and b.is_pure_token and a.opaque <= b.opaque:
            return Tri.TRUE
        return Tri.UNKNOWN
    v4_ok = _intervals_cover(list(a.v4), list(b.v4))
    v6_ok = _intervals_cover(list(a.v6), list(b.v6))
    return Tri.TRUE if v4_ok and v6_ok else Tri.FALSE


# ---------------------------------------------------------------------------
# Port sets
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PortSet:
    """An abstract set of ports over 0..65535, with opaque tokens for variables."""

    any_: bool = False
    intervals: tuple[Interval, ...] = ()
    opaque: frozenset[str] = field(default_factory=frozenset)

    @property
    def is_pure_token(self) -> bool:
        return not self.any_ and not self.intervals and bool(self.opaque)


def _concrete_port_interval(expr: PortExpr) -> Interval | None:
    """Return (lo, hi) for a concrete port node, else None."""
    if isinstance(expr, Port):
        return (expr.value, expr.value)
    if isinstance(expr, PortRange):
        lo, hi = sorted((expr.start, expr.end))
        return (lo, hi)
    return None


def build_port_set(expr: PortExpr) -> PortSet:
    """Convert a PortExpr into a :class:`PortSet`."""
    if isinstance(expr, AnyPort):
        return PortSet(any_=True)
    if isinstance(expr, PortVariable):
        return PortSet(opaque=frozenset({expr.name}))
    if isinstance(expr, PortNegation):
        return PortSet(opaque=frozenset({f"!{expr.expr!r}"}))
    if isinstance(expr, PortList):
        return _union_port_sets([build_port_set(e) for e in expr.elements])
    interval = _concrete_port_interval(expr)
    if interval is not None:
        return PortSet(intervals=(interval,))
    return PortSet(opaque=frozenset({repr(expr)}))


def _union_port_sets(sets: list[PortSet]) -> PortSet:
    if any(s.any_ for s in sets):
        return PortSet(any_=True)
    intervals: list[Interval] = []
    opaque: set[str] = set()
    for s in sets:
        intervals.extend(s.intervals)
        opaque |= s.opaque
    return PortSet(intervals=tuple(_merge(intervals)), opaque=frozenset(opaque))


def port_intersects(a: PortSet, b: PortSet) -> Tri:
    if a.any_ or b.any_:
        return Tri.TRUE
    if a.opaque or b.opaque:
        if a.opaque & b.opaque:
            return Tri.TRUE
        return Tri.UNKNOWN
    return Tri.TRUE if _intervals_overlap(list(a.intervals), list(b.intervals)) else Tri.FALSE


def port_subset(a: PortSet, b: PortSet) -> Tri:
    if b.any_:
        return Tri.TRUE
    if a.any_:
        return Tri.FALSE
    if a.opaque or b.opaque:
        if a.is_pure_token and b.is_pure_token and a.opaque <= b.opaque:
            return Tri.TRUE
        return Tri.UNKNOWN
    return Tri.TRUE if _intervals_cover(list(a.intervals), list(b.intervals)) else Tri.FALSE


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------

# Unambiguous app-layer-over-transport relations, used only when the caller
# opts into hierarchy comparison. Ambiguous protocols (dns/sip over tcp+udp)
# are intentionally omitted so they fall back to equality.
PROTOCOL_HIERARCHY: dict[Protocol, frozenset[Protocol]] = {
    Protocol.IP: frozenset({Protocol.TCP, Protocol.TCP_PKT, Protocol.UDP, Protocol.ICMP}),
    Protocol.TCP: frozenset(
        {
            Protocol.TCP_PKT,
            Protocol.HTTP,
            Protocol.TLS,
            Protocol.SSH,
            Protocol.FTP,
            Protocol.FTP_DATA,
            Protocol.SMB,
            Protocol.SMTP,
            Protocol.IMAP,
            Protocol.DCERPC,
            Protocol.RDP,
            Protocol.MODBUS,
            Protocol.ENIP,
        }
    ),
    Protocol.UDP: frozenset(
        {Protocol.DHCP, Protocol.NTP, Protocol.SNMP, Protocol.TFTP, Protocol.IKE}
    ),
}


def proto_subset(general: Protocol, specific: Protocol, *, hierarchy: bool = False) -> bool:
    """True if every packet matching ``specific`` also matches ``general``."""
    if general == specific:
        return True
    if not hierarchy:
        return False
    return specific in PROTOCOL_HIERARCHY.get(general, frozenset())


def proto_intersects(a: Protocol, b: Protocol, *, hierarchy: bool = False) -> bool:
    return (
        a == b or proto_subset(a, b, hierarchy=hierarchy) or proto_subset(b, a, hierarchy=hierarchy)
    )


# ---------------------------------------------------------------------------
# Direction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OrientedHeader:
    """A header normalized to a single ``src -> dst`` orientation."""

    protocol: Protocol
    src_addr: AddrSet
    src_port: PortSet
    dst_addr: AddrSet
    dst_port: PortSet


def oriented_headers(header: Header) -> list[OrientedHeader]:
    """Normalize a header to one (or two, for bidirectional) oriented forms."""
    src_addr = build_addr_set(header.src_addr)
    src_port = build_port_set(header.src_port)
    dst_addr = build_addr_set(header.dst_addr)
    dst_port = build_port_set(header.dst_port)
    forward = OrientedHeader(header.protocol, src_addr, src_port, dst_addr, dst_port)
    if header.direction == Direction.BIDIRECTIONAL:
        backward = OrientedHeader(header.protocol, dst_addr, dst_port, src_addr, src_port)
        return [forward, backward]
    if header.direction == Direction.FROM:
        return [OrientedHeader(header.protocol, dst_addr, dst_port, src_addr, src_port)]
    return [forward]


# ---------------------------------------------------------------------------
# Content constraints
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContentConstraint:
    """The payload requirements of a rule, for shadowing/overlap reasoning."""

    literals: frozenset[bytes]
    opaque: bool  # True if a PCRE / undecidable matcher is present

    @property
    def is_empty(self) -> bool:
        return not self.literals and not self.opaque


_POSITIONAL_MODIFIER_NAMES = frozenset({"offset", "depth", "distance", "within"})
_POSITIONAL_MODIFIER_TYPES = frozenset(
    {"OffsetOption", "DepthOption", "DistanceOption", "WithinOption"}
)
_PAYLOAD_BYTE_KEYWORDS = frozenset(
    {"byte_test", "byte_jump", "byte_extract", "byte_math", "isdataat"}
)


def _content_is_positioned(content: ContentOption) -> bool:
    """True if an inline offset/depth/distance/within modifier anchors where the
    content must appear, so its literal alone no longer describes the match."""
    for modifier in content.modifiers:
        name = modifier.name.value if hasattr(modifier.name, "value") else str(modifier.name)
        if name in _POSITIONAL_MODIFIER_NAMES:
            return True
    return False


def build_content_constraint(rule: Rule) -> ContentConstraint:
    literals: set[bytes] = set()
    opaque = False
    for option in rule.options:
        if isinstance(option, ContentOption):
            # A negated content ("content:!...") constrains the payload to the
            # complement of the literal; an inline offset/depth/distance/within
            # modifier anchors *where* the literal must appear. Neither is
            # expressible as a bare required literal, so treat them as opaque
            # rather than inverting or over-broadening the match-space (which
            # produced false shadows/subsumption between rules that actually
            # match different traffic).
            if option.negated or _content_is_positioned(option):
                opaque = True
            else:
                literals.add(option.pattern)
        elif isinstance(option, PcreOption):
            opaque = True
        elif option.node_type in _POSITIONAL_MODIFIER_TYPES:
            # Standalone offset/depth/distance/within options position the
            # preceding content match.
            opaque = True
        elif option.node_type == "GenericOption" and (
            getattr(option, "keyword", "") in _PAYLOAD_BYTE_KEYWORDS
        ):
            # byte_test/byte_jump/byte_extract/byte_math/isdataat impose payload
            # constraints beyond the content literals.
            opaque = True
    return ContentConstraint(literals=frozenset(literals), opaque=opaque)


def content_more_general(general: ContentConstraint, specific: ContentConstraint) -> Tri:
    """Does every payload satisfying ``specific`` also satisfy ``general``?"""
    if general.is_empty:
        return Tri.TRUE
    if general.opaque:
        return Tri.UNKNOWN
    if general.literals <= specific.literals:
        return Tri.TRUE
    # General requires a literal the specific rule does not declare: not provable.
    return Tri.UNKNOWN


def content_intersects(a: ContentConstraint, b: ContentConstraint) -> Tri:
    if a.is_empty or b.is_empty:
        return Tri.TRUE
    if a.literals & b.literals:
        return Tri.TRUE
    if a.opaque or b.opaque:
        return Tri.UNKNOWN
    # Distinct literals can still co-occur in one payload; be conservative.
    return Tri.UNKNOWN
