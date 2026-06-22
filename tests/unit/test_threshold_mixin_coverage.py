# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for ThresholdOptionsMixin to achieve full code coverage.

The mixin's structured-parse happy paths are exercised by the parser-level
tests. This suite targets the diagnostic, fallback, and defensive branches:

- Duplicate threshold parameter warning.
- Non-numeric count/seconds (int() failure -> generic fallback).
- Missing required fields -> generic fallback.
- Non-tuple parameter items -> token_to_str passthrough.
- Short parameter lists in threshold_param / detection_param.

All tests drive the real RuleTransformer methods directly with real Lark
tokens; no mocks or stubs are used.
"""

from surinort_ast.core.diagnostics import DiagnosticLevel
from surinort_ast.core.enums import Dialect
from surinort_ast.core.nodes import (
    DetectionFilterOption,
    GenericOption,
    ThresholdOption,
)
from surinort_ast.parsing.transformer import RuleTransformer
from tests.unit._token_helpers import create_token


def _warnings(transformer: RuleTransformer) -> list[str]:
    return [d.message for d in transformer.diagnostics if d.level == DiagnosticLevel.WARNING]


class TestThresholdOption:
    """Cover threshold_option diagnostic and fallback branches."""

    def test_duplicate_parameter_emits_warning(self):
        """A repeated parameter key emits a duplicate warning but still parses."""
        transformer = RuleTransformer(dialect=Dialect.SURICATA)
        params = [
            ("type", "limit"),
            ("type", "both"),
            ("track", "by_src"),
            ("count", "1"),
            ("seconds", "1"),
        ]

        result = transformer.threshold_option([params])

        assert isinstance(result, ThresholdOption)
        # The later value wins.
        assert result.threshold_type == "both"
        assert any("Duplicate threshold parameter 'type'" in w for w in _warnings(transformer))

    def test_non_numeric_count_falls_back_to_generic(self):
        """A non-numeric count makes int() fail and falls back to a generic option."""
        transformer = RuleTransformer(dialect=Dialect.SURICATA)
        params = [
            ("type", "limit"),
            ("track", "by_src"),
            ("count", "abc"),
            ("seconds", "60"),
        ]

        result = transformer.threshold_option([params])

        assert isinstance(result, GenericOption)
        assert any("structured option" in w for w in _warnings(transformer))

    def test_missing_required_fields_falls_back_to_generic(self):
        """Missing required fields produce a generic option with a warning."""
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        result = transformer.threshold_option([[("type", "limit")]])

        assert isinstance(result, GenericOption)
        assert any("missing required fields" in w for w in _warnings(transformer))

    def test_non_tuple_parameter_item_is_stringified(self):
        """A non-tuple parameter item is passed through token_to_str."""
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        result = transformer.threshold_option([[create_token("WORD", "garbage")]])

        assert isinstance(result, GenericOption)
        assert "garbage" in result.value

    def test_empty_items_yields_generic(self):
        """No items at all still yields a generic fallback."""
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        result = transformer.threshold_option([])

        assert isinstance(result, GenericOption)


class TestThresholdParam:
    """Cover threshold_param branches."""

    def test_key_value_pair(self):
        transformer = RuleTransformer(dialect=Dialect.SURICATA)
        items = [create_token("WORD", "count"), create_token("INT", "10")]

        assert transformer.threshold_param(items) == ("count", "10")

    def test_single_item_yields_empty_value(self):
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        assert transformer.threshold_param([create_token("WORD", "track")]) == ("track", "")

    def test_empty_items_yields_empty_pair(self):
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        assert transformer.threshold_param([]) == ("", "")

    def test_threshold_params_passthrough(self):
        transformer = RuleTransformer(dialect=Dialect.SURICATA)
        params = [("type", "limit"), ("track", "by_src")]

        assert transformer.threshold_params(params) == params


class TestDetectionFilterOption:
    """Cover detection_filter_option diagnostic and fallback branches."""

    def test_non_numeric_count_falls_back_to_generic(self):
        transformer = RuleTransformer(dialect=Dialect.SURICATA)
        params = [
            ("track", "by_src"),
            ("count", "abc"),
            ("seconds", "60"),
        ]

        result = transformer.detection_filter_option([params])

        assert isinstance(result, GenericOption)
        assert any("structured option" in w for w in _warnings(transformer))

    def test_non_tuple_parameter_item_is_stringified(self):
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        result = transformer.detection_filter_option([[create_token("WORD", "garbage")]])

        assert isinstance(result, GenericOption)
        assert "garbage" in result.value
        assert any("missing required fields" in w for w in _warnings(transformer))

    def test_structured_parse_succeeds(self):
        transformer = RuleTransformer(dialect=Dialect.SURICATA)
        params = [
            ("track", "by_src"),
            ("count", "5"),
            ("seconds", "60"),
        ]

        result = transformer.detection_filter_option([params])

        assert isinstance(result, DetectionFilterOption)
        assert result.count == 5
        assert result.seconds == 60


class TestDetectionParam:
    """Cover detection_param branches."""

    def test_key_value_pair(self):
        transformer = RuleTransformer(dialect=Dialect.SURICATA)
        items = [create_token("WORD", "track"), create_token("WORD", "by_src")]

        assert transformer.detection_param(items) == ("track", "by_src")

    def test_short_items_yield_empty_pair(self):
        transformer = RuleTransformer(dialect=Dialect.SURICATA)

        assert transformer.detection_param([create_token("WORD", "track")]) == ("", "")
        assert transformer.detection_param([]) == ("", "")

    def test_detection_params_passthrough(self):
        transformer = RuleTransformer(dialect=Dialect.SURICATA)
        params = [("track", "by_src"), ("count", "5")]

        assert transformer.detection_params(params) == params
