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

from ...core.nodes import Rule
from . import extractors
from .matchspace import (
    ContentConstraint,
    OrientedHeader,
    build_content_constraint,
    oriented_headers,
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
        oriented=oriented_headers(rule.header),
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
    # protocol value -> port-bucket key -> rules
    buckets: dict[str, dict[str, list[PreparedRule]]] = field(
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
            proto = oriented.protocol.value
            for key in _port_bucket_keys(item):
                index.buckets[proto][key].append(item)

    return index


def candidate_pairs(index: RuleIndex) -> list[tuple[PreparedRule, PreparedRule]]:
    """Yield candidate rule pairs that share a protocol + destination-port bucket.

    Each unordered pair is produced once. Rules in the WILDCARD port bucket are
    compared against every other bucket of the same protocol.
    """
    pairs: list[tuple[PreparedRule, PreparedRule]] = []
    seen: set[tuple[int, int]] = set()

    for port_buckets in index.buckets.values():
        wildcard = port_buckets.get(WILDCARD_PORT, [])
        for key, members in port_buckets.items():
            group = members if key == WILDCARD_PORT else members + wildcard
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    a, b = group[i], group[j]
                    if a.index == b.index:
                        continue
                    pair_key = (min(a.index, b.index), max(a.index, b.index))
                    if pair_key in seen:
                        continue
                    seen.add(pair_key)
                    pairs.append((a, b) if a.index < b.index else (b, a))
    return pairs
