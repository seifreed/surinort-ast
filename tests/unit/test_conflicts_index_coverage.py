# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage tests for analysis/conflicts/index.py.

Covers the wide-port-range wildcard bucketing, the no-SID and flowbits
set/check/other branches of build_index, the _record_pair self/duplicate
guards, and the cross-protocol _emit_across path reached via hierarchy pairing.
Real rules and the real index are used throughout.
"""

from __future__ import annotations

from surinort_ast import parse_rule
from surinort_ast.analysis.conflicts.index import (
    WILDCARD_PORT,
    _record_pair,
    build_index,
    candidate_pairs,
    prepare_rule,
)
from surinort_ast.core.nodes import MsgOption


class TestBuildIndex:
    def test_wide_port_range_becomes_wildcard(self):
        rule = parse_rule('alert tcp any any -> any 1:2000 (msg:"x"; sid:1;)')

        index = build_index([rule])

        # A >1024-wide range is bucketed as the wildcard port.
        proto_buckets = next(iter(index.buckets.values()))
        assert WILDCARD_PORT in proto_buckets

    def test_rule_without_sid(self):
        base = parse_rule('alert tcp any any -> any 80 (msg:"x"; sid:1;)')
        sidless = base.model_copy(update={"options": [MsgOption(text="no sid")]})

        index = build_index([sidless])

        assert not index.by_sid  # nothing recorded under a SID

    def test_flowbits_setters_checkers_and_other(self):
        setter = parse_rule('alert tcp any any -> any 80 (msg:"s"; flowbits:set,a; sid:1;)')
        checker = parse_rule('alert tcp any any -> any 80 (msg:"c"; flowbits:isset,a; sid:2;)')
        other = parse_rule('alert tcp any any -> any 80 (msg:"o"; flowbits:unset,a; sid:3;)')

        index = build_index([setter, checker, other])

        assert "a" in index.flowbits_setters
        assert "a" in index.flowbits_checkers


class TestRecordPair:
    def test_self_pair_is_skipped(self):
        rule = parse_rule('alert tcp any any -> any 80 (msg:"x"; sid:1;)')
        prepared = prepare_rule(rule, 0)
        pairs: list = []
        seen: set = set()

        _record_pair(prepared, prepared, pairs, seen)

        assert pairs == []

    def test_duplicate_pair_is_skipped(self):
        rule = parse_rule('alert tcp any any -> any 80 (msg:"x"; sid:1;)')
        a = prepare_rule(rule, 0)
        b = prepare_rule(rule, 1)
        pairs: list = []
        seen: set = set()

        _record_pair(a, b, pairs, seen)
        _record_pair(a, b, pairs, seen)  # duplicate

        assert len(pairs) == 1


class TestEmitAcross:
    def test_cross_protocol_pairing_with_hierarchy(self):
        tcp_rule = parse_rule('alert tcp any any -> any 80 (msg:"t"; sid:1;)')
        http_rule = parse_rule('alert http any any -> any 80 (msg:"h"; sid:2;)')

        index = build_index([tcp_rule, http_rule])
        pairs = candidate_pairs(index, hierarchy=True)

        # tcp and http share port bucket 80 and are hierarchy-related, so the
        # cross-protocol pair is emitted.
        assert any({a.sid, b.sid} == {1, 2} for a, b in pairs)
