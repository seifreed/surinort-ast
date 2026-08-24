"""
Indexing for conflict detection.

Builds the lookup structures the detectors need: SID buckets for duplicate
detection, flowbits setter/checker maps for dependency detection, and protocol
+ destination-port candidate buckets so the header-overlap detectors only
compare rules that can possibly conflict (instead of all O(n^2) pairs).

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ...core.enums import Protocol
from ...core.nodes import Rule
from . import extractors
from .matchspace import (
    ContentConstraint,
    OrientedHeader,
    build_content_constraint,
    oriented_headers,
    proto_intersects,
)

# Special bucket key for rules whose destination port is wide/variable and must
# therefore be compared against every other bucket of the same protocol.
WILDCARD_PORT = "*"


@dataclass
class PreparedRule:
    """A rule with its match-space projections computed once."""

    rule: Rule
    index: int  # position in the input (evaluation order)
    sid: int | None
    oriented: list[OrientedHeader]
    content: ContentConstraint
    specificity: int


def prepare_rule(rule: Rule, index: int) -> PreparedRule:
    return PreparedRule(
        rule=rule,
        index=index,
        sid=extractors.extract_sid(rule),
        oriented=oriented_headers(rule.header) if rule.header is not None else [],
        content=build_content_constraint(rule),
        specificity=extractors.compute_specificity(rule),
    )


@dataclass
class RuleIndex:
    """Lookup structures over a prepared rule set."""

    prepared: list[PreparedRule]
    by_sid: dict[int, list[PreparedRule]] = field(default_factory=lambda: defaultdict(list))
    flowbits_setters: dict[str, list[PreparedRule]] = field(
        default_factory=lambda: defaultdict(list)
    )
    flowbits_checkers: dict[str, list[PreparedRule]] = field(
        default_factory=lambda: defaultdict(list)
    )
    # protocol -> port-bucket key -> rules
    buckets: dict[Protocol, dict[str, list[PreparedRule]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(list))
    )


_FLOWBITS_SET = {"set", "toggle"}
_FLOWBITS_CHECK = {"isset", "isnotset"}


def _port_bucket_keys(prepared: PreparedRule) -> set[str]:
    """Destination-port bucket keys for a rule (one per concrete port, else WILDCARD)."""
    keys: set[str] = set()
    for oriented in prepared.oriented:
        dport = oriented.dst_port
        if dport.any_ or dport.opaque or not dport.intervals:
            keys.add(WILDCARD_PORT)
            continue
        width = sum(hi - lo + 1 for lo, hi in dport.intervals)
        if width > 1024:  # treat very wide ranges as wildcard to bound bucket count
            keys.add(WILDCARD_PORT)
        else:
            for lo, hi in dport.intervals:
                keys.update(str(port) for port in range(lo, hi + 1))
    return keys or {WILDCARD_PORT}


def build_index(rules: list[Rule]) -> RuleIndex:
    """Build a :class:`RuleIndex` from rules in evaluation order."""
    prepared = [prepare_rule(rule, position) for position, rule in enumerate(rules)]
    index = RuleIndex(prepared=prepared)

    for item in prepared:
        if item.sid is not None:
            index.by_sid[item.sid].append(item)

        for action, name in extractors.extract_flowbits(item.rule):
            if action in _FLOWBITS_SET:
                index.flowbits_setters[name].append(item)
            elif action in _FLOWBITS_CHECK:
                index.flowbits_checkers[name].append(item)

        for oriented in item.oriented:
            proto = oriented.protocol
            for key in _port_bucket_keys(item):
                index.buckets[proto][key].append(item)

    return index


def _record_pair(
    a: PreparedRule,
    b: PreparedRule,
    pairs: list[tuple[PreparedRule, PreparedRule]],
    seen: set[tuple[int, int]],
) -> None:
    if a.index == b.index:
        return
    pair_key = (min(a.index, b.index), max(a.index, b.index))
    if pair_key in seen:
        return
    seen.add(pair_key)
    pairs.append((a, b) if a.index < b.index else (b, a))


def _emit_within(
    port_buckets: dict[str, list[PreparedRule]],
    pairs: list[tuple[PreparedRule, PreparedRule]],
    seen: set[tuple[int, int]],
) -> None:
    """Pair rules of one protocol that share a destination-port bucket."""
    wildcard = port_buckets.get(WILDCARD_PORT, [])
    for key, members in port_buckets.items():
        group = members if key == WILDCARD_PORT else members + wildcard
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                _record_pair(group[i], group[j], pairs, seen)


def _emit_across(
    left_buckets: dict[str, list[PreparedRule]],
    right_buckets: dict[str, list[PreparedRule]],
    pairs: list[tuple[PreparedRule, PreparedRule]],
    seen: set[tuple[int, int]],
) -> None:
    """Pair rules of two different protocols that share a destination-port bucket."""
    left_wild = left_buckets.get(WILDCARD_PORT, [])
    right_wild = right_buckets.get(WILDCARD_PORT, [])
    for key in set(left_buckets) | set(right_buckets):
        if key == WILDCARD_PORT:
            continue
        left = left_buckets.get(key, []) + left_wild
        right = right_buckets.get(key, []) + right_wild
        for a in left:
            for b in right:
                _record_pair(a, b, pairs, seen)
    # Wide-port rules on both sides overlap regardless of concrete ports.
    for a in left_wild:
        for b in right_wild:
            _record_pair(a, b, pairs, seen)


def candidate_pairs(
    index: RuleIndex, *, hierarchy: bool = False
) -> list[tuple[PreparedRule, PreparedRule]]:
    """Yield candidate rule pairs that share a destination-port bucket.

    Each unordered pair is produced once. Rules in the WILDCARD port bucket are
    compared against every other port bucket. By default only rules of the same
    protocol are paired; when ``hierarchy`` is set, rules whose protocols are
    related in the protocol hierarchy (e.g. ``tcp`` and ``http``) are paired too,
    so cross-protocol conflicts are not missed.
    """
    pairs: list[tuple[PreparedRule, PreparedRule]] = []
    seen: set[tuple[int, int]] = set()

    protocols = list(index.buckets)
    for i, proto_a in enumerate(protocols):
        _emit_within(index.buckets[proto_a], pairs, seen)
        if not hierarchy:
            continue
        for proto_b in protocols[i + 1 :]:
            if proto_intersects(proto_a, proto_b, hierarchy=True):
                _emit_across(index.buckets[proto_a], index.buckets[proto_b], pairs, seen)
    return pairs
