# Copyright (c) 2026 Marc Rivero Lopez
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""
Coverage-completion tests for defensive branches that survive normal use.

These paths are real safety nets (a multiple-inheritance dedup guard, a
process-pool worker's failure handling, and an attribute scan over non-node
collections). They are exercised here with genuine inputs rather than removed,
because each protects a real boundary.
"""

from __future__ import annotations

import pytest

from surinort_ast.core.enums import Dialect
from surinort_ast.core.nodes import ASTNode, ByteTestOption, Rule
from surinort_ast.query.registry import _build_registry
from surinort_ast.query.selectors import PseudoSelector
from surinort_ast.streaming import parser as streaming_parser
from surinort_ast.streaming.parser import _iter_chunk_results, _parse_chunk_worker


class TestRegistryDiamondInheritance:
    """The ``seen`` guard in ``_build_registry`` skips classes reached twice."""

    def test_diamond_hierarchy_visits_shared_class_once(self) -> None:
        class _Base(ASTNode):
            pass

        class _Left(_Base):
            pass

        class _Right(_Base):
            pass

        class _Diamond(_Left, _Right):
            pass

        registry = _build_registry(root=_Base)

        # _Diamond is reachable via both _Left and _Right; it appears exactly
        # once and the traversal terminates instead of recording duplicates.
        assert registry["_Diamond"] is _Diamond
        assert registry["_Base"] is _Base
        assert registry["_Left"] is _Left
        assert registry["_Right"] is _Right


class TestHasChildrenWithNonNodeCollection:
    """A non-empty collection of non-nodes does not count as having children."""

    def test_collection_of_plain_values_is_not_children(self) -> None:
        # ``flags`` is a non-empty tuple of strings; none expose ``node_type``,
        # so the ``any(...)`` check is False and the scan continues past it.
        option = ByteTestOption(
            bytes_to_extract=4,
            operator="=",
            value=0,
            offset=0,
            flags=("S", "A"),
        )

        selector = PseudoSelector("not-empty")

        assert selector._has_children(option) is False


class TestIterChunkResults:
    """``_iter_chunk_results`` yields rules and logs worker error entries."""

    def test_yields_rules_and_skips_errors(self) -> None:
        # Deliberately build a field-less Rule to exercise defensive branches;
        # model_construct skips validation, so the missing required fields are
        # intentional here.
        rule = Rule.model_construct()  # type: ignore[call-arg]
        chunk_results: list[tuple[int, Rule | None, str | None]] = [
            (1, rule, None),
            (2, None, "boom"),
            (3, None, None),
        ]

        yielded = list(_iter_chunk_results(chunk_results))

        assert yielded == [rule]


class TestParseChunkWorkerFailure:
    """The worker converts an unexpected parser failure into an error tuple."""

    def test_unexpected_exception_becomes_error_entry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _FailingParser:
            def __init__(self, **_: object) -> None:
                pass

            def parse(self, *_: object, **__: object) -> Rule:
                raise RuntimeError("worker boom")

        monkeypatch.setattr(streaming_parser, "LarkRuleParser", _FailingParser)

        results = _parse_chunk_worker(
            (
                [(7, "alert tcp any any -> any any (sid:1;)")],
                Dialect.SURICATA,
                True,
                True,
                "test.rules",
            )
        )

        assert results == [(7, None, "worker boom")]
