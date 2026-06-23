# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage tests for the conflict-detection cluster.

Covers extractors.compute_specificity for a fully-specific rule, the
ConflictDetector façade, the protocol-mismatch FALSE branches in the oriented
header predicates, the no-intersection continue in the detectors, and the
empty-report / non-verbose rendering in the conflict models.
"""

from __future__ import annotations

from surinort_ast import parse_rule
from surinort_ast.analysis.conflicts import ConflictDetector, ConflictReport, detect_conflicts
from surinort_ast.analysis.conflicts.detectors import _oriented_intersect, _oriented_subset
from surinort_ast.analysis.conflicts.extractors import compute_specificity
from surinort_ast.analysis.conflicts.matchspace import AddrSet, OrientedHeader, PortSet, Tri
from surinort_ast.analysis.conflicts.models import Conflict, ConflictType, Severity
from surinort_ast.core.enums import Protocol


def _any_oriented(protocol: Protocol) -> OrientedHeader:
    return OrientedHeader(
        protocol,
        AddrSet(any_=True),
        PortSet(any_=True),
        AddrSet(any_=True),
        PortSet(any_=True),
    )


class TestComputeSpecificity:
    def test_fully_specific_rule_scores_all_dimensions(self):
        rule = parse_rule(
            'alert tcp 1.2.3.4 1024 -> 5.6.7.8 80 (msg:"x"; content:"a"; pcre:"/x/"; sid:1;)'
        )

        # Specific src/dst addr + src/dst port + content + pcre.
        assert compute_specificity(rule) >= 6


class TestConflictDetectorFacade:
    def test_detect_returns_report(self):
        rules = [
            parse_rule('alert tcp any any -> any 80 (msg:"a"; sid:1;)'),
            parse_rule('alert tcp any any -> any 80 (msg:"b"; sid:1;)'),  # duplicate SID
        ]

        report = ConflictDetector().detect(rules)

        assert isinstance(report, ConflictReport)
        assert report.total_conflicts >= 1


class TestOrientedPredicatesProtocolMismatch:
    def test_intersect_false_on_unrelated_protocols(self):
        result = _oriented_intersect(
            _any_oriented(Protocol.TCP), _any_oriented(Protocol.ICMP), hierarchy=False
        )
        assert result is Tri.FALSE

    def test_subset_false_on_unrelated_protocols(self):
        result = _oriented_subset(
            _any_oriented(Protocol.TCP), _any_oriented(Protocol.ICMP), hierarchy=False
        )
        assert result is Tri.FALSE


class TestNonIntersectingCandidates:
    def test_disjoint_address_different_action_no_intersection(self):
        # Different action classes (so the conflicting-action detector considers
        # them) on the same destination port but disjoint source addresses, so
        # the pair is skipped on no-intersection.
        rules = [
            parse_rule('alert tcp 10.0.0.1 any -> any 80 (msg:"a"; content:"x"; sid:1;)'),
            parse_rule('drop tcp 10.0.0.2 any -> any 80 (msg:"b"; content:"y"; sid:2;)'),
        ]

        report = detect_conflicts(rules)

        assert all(set(c.rule_ids) != {1, 2} for c in report.conflicts)

    def test_disjoint_address_same_action_no_overlap(self):
        # Same action on the same destination port but disjoint source addresses,
        # so the overlapping detector skips the pair on no-intersection.
        rules = [
            parse_rule('alert tcp 10.0.0.1 any -> any 80 (msg:"a"; content:"x"; sid:1;)'),
            parse_rule('alert tcp 10.0.0.2 any -> any 80 (msg:"b"; content:"y"; sid:2;)'),
        ]

        report = detect_conflicts(rules)

        assert all(set(c.rule_ids) != {1, 2} for c in report.conflicts)


class TestConflictModelsRendering:
    def _report_with_conflict(self) -> ConflictReport:
        rules = [
            parse_rule('alert tcp any any -> any 80 (msg:"a"; sid:1;)'),
            parse_rule('alert tcp any any -> any 80 (msg:"b"; sid:1;)'),
        ]
        return detect_conflicts(rules)

    def test_conflict_to_text_non_verbose_and_verbose(self):
        report = self._report_with_conflict()
        conflict = report.conflicts[0]

        non_verbose = conflict.to_text(verbose=False)
        verbose = conflict.to_text(verbose=True)

        assert "rules:" in non_verbose
        assert len(verbose) >= len(non_verbose)

    def test_empty_report_text_and_markdown(self):
        empty = ConflictReport(total_rules=0, conflicts=[])

        assert "No conflicts detected" in empty.to_text()
        assert "No conflicts detected" in empty.to_markdown()

    def test_conflict_to_text_verbose_without_metadata(self):
        # A conflict with empty metadata skips the metadata line in verbose mode.
        conflict = Conflict(
            conflict_type=ConflictType.DUPLICATE_SID,
            severity=Severity.HIGH,
            rule_ids=["1", "2"],
            description="d",
            explanation="e",
            recommendation="r",
            metadata={},
        )

        text = conflict.to_text(verbose=True)

        assert "metadata:" not in text
