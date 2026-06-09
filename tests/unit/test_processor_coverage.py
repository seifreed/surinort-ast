# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Coverage tests for streaming/processor.py.

Covers the ValidateProcessor custom-validator error handling, strict-mode error
filtering, and duplicate-SID detection, plus the AggregateProcessor diagnostic
counting and custom-aggregator error handling. Real Rule objects and real
diagnostics are used throughout.
"""

from __future__ import annotations

from surinort_ast import parse_rule
from surinort_ast.core.diagnostics import Diagnostic, DiagnosticLevel
from surinort_ast.streaming.processor import AggregateProcessor, ValidateProcessor

_RULE = 'alert tcp any any -> any 80 (msg:"x"; sid:42; rev:1;)'


def _rule():
    return parse_rule(_RULE)


class TestValidateProcessor:
    def test_custom_validator_error_is_logged_not_raised(self):
        def boom(rule):
            raise RuntimeError("validator boom")

        processor = ValidateProcessor(custom_validators=[boom])

        result = processor.process(_rule())

        # The failing validator is swallowed; processing still yields a rule.
        assert result is not None

    def test_strict_mode_filters_error_rules(self):
        def add_error(rule):
            return [Diagnostic(level=DiagnosticLevel.ERROR, message="bad", code="X")]

        processor = ValidateProcessor(strict=True, custom_validators=[add_error])

        assert processor.process(_rule()) is None

    def test_duplicate_sid_is_flagged(self):
        processor = ValidateProcessor()

        processor.process(_rule())  # seeds SID 42
        second = processor.process(_rule())  # same SID again

        assert second is not None
        assert any(d.code == "duplicate_sid" for d in second.diagnostics)

    def test_rule_without_sid_is_skipped(self):
        from surinort_ast.core.nodes import MsgOption

        processor = ValidateProcessor()
        sidless = _rule().model_copy(update={"options": [MsgOption(text="no sid")]})

        # No SID -> no uniqueness diagnostic, no crash.
        result = processor.process(sidless)
        assert result is not None
        assert not any(d.code == "duplicate_sid" for d in result.diagnostics)


class TestAggregateProcessor:
    def test_counts_error_and_warning_rules(self):
        processor = AggregateProcessor()
        diagnosed = _rule().model_copy(
            update={
                "diagnostics": [
                    Diagnostic(level=DiagnosticLevel.ERROR, message="e", code="E"),
                    Diagnostic(level=DiagnosticLevel.WARNING, message="w", code="W"),
                ]
            }
        )

        processor.process(diagnosed)

        assert processor.stats.rules_with_errors == 1
        assert processor.stats.rules_with_warnings == 1

    def test_custom_aggregator_error_is_logged_not_raised(self):
        def boom(stats, rule):
            raise RuntimeError("aggregator boom")

        processor = AggregateProcessor(custom_aggregators=[boom])

        result = processor.process(_rule())

        assert result is not None
        assert processor.stats.total_rules == 1
