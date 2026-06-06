"""
The conflict detectors.

Each detector consumes a :class:`RuleIndex` and emits :class:`Conflict` objects.
The cheap, exact detectors (duplicate SID, flowbits dependency) run in O(n); the
header-overlap detectors compare only candidate pairs from the index buckets and
rely on the tri-state :mod:`matchspace` algebra so that undecidable cases
(variables, PCRE) are reported conservatively rather than asserted.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from ...core.enums import Action
from .index import PreparedRule, RuleIndex, candidate_pairs
from .matchspace import (
    OrientedHeader,
    Tri,
    addr_intersects,
    addr_subset,
    content_intersects,
    content_more_general,
    port_intersects,
    port_subset,
    proto_intersects,
    proto_subset,
    tri_and,
    tri_or,
)
from .models import Conflict, ConflictDetectorConfig, ConflictType, Severity

_BLOCK_ACTIONS = {Action.DROP, Action.REJECT, Action.SDROP}
_PASS_ACTIONS = {Action.PASS}


def _action_class(action: Action) -> str:
    if action in _BLOCK_ACTIONS:
        return "block"
    if action in _PASS_ACTIONS:
        return "pass"
    return "log"  # alert, log


def _is_terminating(action: Action) -> bool:
    return action in _BLOCK_ACTIONS or action in _PASS_ACTIONS


def _sid_label(prepared: PreparedRule) -> int:
    return prepared.sid if prepared.sid is not None else -1


# ---------------------------------------------------------------------------
# Rule-level match-space comparisons
# ---------------------------------------------------------------------------


def _oriented_intersect(a: OrientedHeader, b: OrientedHeader, hierarchy: bool) -> Tri:
    if not proto_intersects(a.protocol, b.protocol, hierarchy=hierarchy):
        return Tri.FALSE
    return tri_and(
        addr_intersects(a.src_addr, b.src_addr),
        port_intersects(a.src_port, b.src_port),
        addr_intersects(a.dst_addr, b.dst_addr),
        port_intersects(a.dst_port, b.dst_port),
    )


def _headers_intersect(a: PreparedRule, b: PreparedRule, hierarchy: bool) -> Tri:
    results = [_oriented_intersect(oa, ob, hierarchy) for oa in a.oriented for ob in b.oriented]
    return tri_or(*results) if results else Tri.FALSE


def match_intersect(a: PreparedRule, b: PreparedRule, hierarchy: bool) -> Tri:
    """Tri: can these two rules match the same packet?"""
    return tri_and(
        _headers_intersect(a, b, hierarchy),
        content_intersects(a.content, b.content),
    )


def _oriented_subset(general: OrientedHeader, specific: OrientedHeader, hierarchy: bool) -> Tri:
    if not proto_subset(general.protocol, specific.protocol, hierarchy=hierarchy):
        return Tri.FALSE
    return tri_and(
        addr_subset(specific.src_addr, general.src_addr),
        port_subset(specific.src_port, general.src_port),
        addr_subset(specific.dst_addr, general.dst_addr),
        port_subset(specific.dst_port, general.dst_port),
    )


def header_subset(general: PreparedRule, specific: PreparedRule, hierarchy: bool) -> Tri:
    """Tri: is ``specific``'s header match-space contained in ``general``'s?"""
    per_specific: list[Tri] = []
    for os_ in specific.oriented:
        covers = [_oriented_subset(og, os_, hierarchy) for og in general.oriented]
        per_specific.append(tri_or(*covers) if covers else Tri.FALSE)
    return tri_and(*per_specific) if per_specific else Tri.FALSE


def match_subsumes(general: PreparedRule, specific: PreparedRule, hierarchy: bool) -> Tri:
    """Tri: does ``general`` match every packet ``specific`` matches?"""
    return tri_and(
        header_subset(general, specific, hierarchy),
        content_more_general(general.content, specific.content),
    )


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def detect_duplicate_sid(index: RuleIndex, config: ConflictDetectorConfig) -> list[Conflict]:
    conflicts: list[Conflict] = []
    for sid, rules in index.by_sid.items():
        if len(rules) < 2:
            continue
        sids = [_sid_label(r) for r in rules]
        conflicts.append(
            Conflict(
                conflict_type=ConflictType.DUPLICATE_SID,
                severity=Severity.HIGH,
                rule_ids=sids,
                description=f"SID {sid} is used by {len(rules)} rules",
                explanation=(
                    "Multiple rules share the same signature ID. SIDs must be unique; "
                    "duplicates make alerts ambiguous and can break rule management."
                ),
                recommendation="Assign a unique SID to each rule.",
                metadata={"sid": sid, "count": len(rules)},
            )
        )
    return conflicts


def detect_missing_dependency(index: RuleIndex, config: ConflictDetectorConfig) -> list[Conflict]:
    conflicts: list[Conflict] = []
    for name, checkers in index.flowbits_checkers.items():
        if name in index.flowbits_setters or name in config.external_flowbits:
            continue
        sids = sorted({_sid_label(r) for r in checkers})
        conflicts.append(
            Conflict(
                conflict_type=ConflictType.MISSING_DEPENDENCY,
                severity=Severity.HIGH,
                rule_ids=sids,
                description=f"Flowbit '{name}' is checked but never set",
                explanation=(
                    f"{len(checkers)} rule(s) test flowbit '{name}' (isset/isnotset) but no "
                    "rule in the analyzed set sets it; the dependent rules can never fire as "
                    "intended."
                ),
                recommendation=(
                    f"Add a rule that sets '{name}', or add it to external_flowbits if it is "
                    "set in another ruleset."
                ),
                metadata={"flowbit": name, "checkers": len(checkers)},
            )
        )
    return conflicts


def detect_conflicting_action(index: RuleIndex, config: ConflictDetectorConfig) -> list[Conflict]:
    conflicts: list[Conflict] = []
    for a, b in candidate_pairs(index):
        if _action_class(a.rule.action) == _action_class(b.rule.action):
            continue
        intersect = match_intersect(a, b, config.protocol_hierarchy)
        if intersect == Tri.FALSE:
            continue
        certain = intersect == Tri.TRUE
        conflicts.append(
            Conflict(
                conflict_type=ConflictType.CONFLICTING_ACTION,
                severity=Severity.HIGH if certain else Severity.MEDIUM,
                rule_ids=[_sid_label(a), _sid_label(b)],
                description=(
                    f"Rules with conflicting actions ({a.rule.action.value} vs "
                    f"{b.rule.action.value}) match overlapping traffic"
                ),
                explanation=(
                    "The two rules' match-spaces overlap but their actions diverge, so one "
                    "rule's effect (e.g. a pass disabling an alert, or a drop vs a log) may "
                    "override the other's."
                ),
                recommendation=(
                    "Confirm the intended precedence; narrow the rules so they do not overlap, "
                    "or order them explicitly."
                ),
                metadata={"confidence": "certain" if certain else "unknown"},
            )
        )
    return conflicts


def detect_shadowing(index: RuleIndex, config: ConflictDetectorConfig) -> list[Conflict]:
    conflicts: list[Conflict] = []
    hierarchy = config.protocol_hierarchy
    for a, b in candidate_pairs(index):
        earlier, later = (a, b) if a.index < b.index else (b, a)
        if not _shadows(earlier, later, hierarchy):
            continue
        conflicts.append(
            Conflict(
                conflict_type=ConflictType.SHADOWING,
                severity=Severity.HIGH,
                rule_ids=[_sid_label(earlier), _sid_label(later)],
                description=(f"Rule {_sid_label(earlier)} shadows rule {_sid_label(later)}"),
                explanation=(
                    "An earlier, more general rule matches every packet the later rule would, "
                    "and its action terminates evaluation (or is the identical action), so the "
                    "later rule can never fire."
                ),
                recommendation=(
                    "Reorder so the specific rule precedes the general one, or remove the "
                    "redundant rule."
                ),
                metadata={
                    "shadowing_rule": _sid_label(earlier),
                    "shadowed_rule": _sid_label(later),
                },
            )
        )
    return conflicts


def _shadows(earlier: PreparedRule, later: PreparedRule, hierarchy: bool) -> bool:
    # Earlier must provably subsume later (no UNKNOWN -> never claim a rule is dead).
    if match_subsumes(earlier, later, hierarchy) != Tri.TRUE:
        return False
    earlier_action = earlier.rule.action
    later_action = later.rule.action
    if _is_terminating(earlier_action):
        return True
    # Non-terminating (alert/log): only a redundant identical-action subset is dead.
    return earlier_action == later_action


def detect_overlapping(index: RuleIndex, config: ConflictDetectorConfig) -> list[Conflict]:
    conflicts: list[Conflict] = []
    hierarchy = config.protocol_hierarchy
    for a, b in candidate_pairs(index):
        if _action_class(a.rule.action) != _action_class(b.rule.action):
            continue  # cross-class overlap is reported as CONFLICTING_ACTION
        intersect = match_intersect(a, b, hierarchy)
        if intersect == Tri.FALSE:
            continue
        # Skip strict subsets (those are shadowing/duplicate territory).
        if (
            match_subsumes(a, b, hierarchy) == Tri.TRUE
            or match_subsumes(b, a, hierarchy) == Tri.TRUE
        ):
            continue
        certain = intersect == Tri.TRUE
        conflicts.append(
            Conflict(
                conflict_type=ConflictType.OVERLAPPING,
                severity=Severity.MEDIUM if certain else Severity.LOW,
                rule_ids=[_sid_label(a), _sid_label(b)],
                description="Rules match partially overlapping traffic",
                explanation=(
                    "The two rules' match-spaces intersect but neither contains the other; "
                    "they may both fire on shared traffic."
                ),
                recommendation=(
                    "Verify this overlap is intended; consider consolidating or narrowing the "
                    "rules."
                ),
                metadata={"confidence": "certain" if certain else "unknown"},
            )
        )
    return conflicts


DETECTORS = {
    ConflictType.DUPLICATE_SID: detect_duplicate_sid,
    ConflictType.MISSING_DEPENDENCY: detect_missing_dependency,
    ConflictType.CONFLICTING_ACTION: detect_conflicting_action,
    ConflictType.SHADOWING: detect_shadowing,
    ConflictType.OVERLAPPING: detect_overlapping,
}
