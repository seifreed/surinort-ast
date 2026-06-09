# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for the fluent sub-builders in builder/option_builders.py.

Covers every content modifier, sticky-buffer selector, flow direction/state,
and the missing-field ``done()`` validation errors in FlowBuilder and
ThresholdBuilder. All tests build real rules through the public fluent API.
"""

import pytest

from surinort_ast.builder import RuleBuilder
from surinort_ast.builder.rule_builder import BuilderError
from surinort_ast.core.enums import FlowDirection, FlowState
from surinort_ast.core.nodes import (
    BufferSelectOption,
    ContentOption,
    DepthOption,
    DistanceOption,
    EndswithOption,
    FastPatternOption,
    FlowOption,
    NocaseOption,
    OffsetOption,
    RawbytesOption,
    StartswithOption,
    ThresholdOption,
    WithinOption,
)


def _base() -> RuleBuilder:
    """A RuleBuilder with all required header/meta fields set."""
    return (
        RuleBuilder()
        .alert()
        .tcp()
        .source_ip("any")
        .source_port("any")
        .dest_ip("any")
        .dest_port(80)
        .msg("coverage")
        .sid(1)
    )


class TestContentBuilderModifiers:
    """Every content modifier appends its option type."""

    def test_all_modifiers(self):
        rule = (
            _base()
            .content_builder()
            .pattern(b"GET")
            .nocase()
            .rawbytes()
            .depth(10)
            .offset(2)
            .distance(3)
            .within(4)
            .fast_pattern()
            .startswith()
            .endswith()
            .done()
            .build()
        )

        types = [type(opt) for opt in rule.options]
        assert ContentOption in types
        for modifier in (
            NocaseOption,
            RawbytesOption,
            DepthOption,
            OffsetOption,
            DistanceOption,
            WithinOption,
            FastPatternOption,
            StartswithOption,
            EndswithOption,
        ):
            assert modifier in types


class TestContentBuilderStickyBuffers:
    """Every sticky-buffer selector appends a BufferSelectOption."""

    def test_all_sticky_buffers(self):
        rule = (
            _base()
            .content_builder()
            .http_uri()
            .http_header()
            .http_method()
            .http_cookie()
            .dns_query()
            .tls_sni()
            .file_data()
            .pattern(b"x")
            .done()
            .build()
        )

        buffers = [opt.buffer_name for opt in rule.options if isinstance(opt, BufferSelectOption)]
        assert buffers == [
            "http_uri",
            "http_header",
            "http_method",
            "http_cookie",
            "dns_query",
            "tls.sni",
            "file_data",
        ]

    def test_done_requires_pattern(self):
        with pytest.raises(BuilderError, match="pattern must be set"):
            RuleBuilder().content_builder().done()


class TestFlowBuilderDirectionsAndStates:
    """Each flow direction and state method is exercised individually."""

    @pytest.mark.parametrize(
        ("method", "expected"),
        [
            ("to_server", FlowDirection.TO_SERVER),
            ("to_client", FlowDirection.TO_CLIENT),
            ("from_server", FlowDirection.FROM_SERVER),
            ("from_client", FlowDirection.FROM_CLIENT),
        ],
    )
    def test_directions(self, method, expected):
        flow = _base().flow_builder()
        getattr(flow, method)()
        rule = flow.done().build()

        flow_opt = next(opt for opt in rule.options if isinstance(opt, FlowOption))
        assert expected in flow_opt.directions

    @pytest.mark.parametrize(
        ("method", "expected"),
        [
            ("established", FlowState.ESTABLISHED),
            ("stateless", FlowState.STATELESS),
            ("not_established", FlowState.NOT_ESTABLISHED),
        ],
    )
    def test_states(self, method, expected):
        flow = _base().flow_builder()
        getattr(flow, method)()
        rule = flow.done().build()

        flow_opt = next(opt for opt in rule.options if isinstance(opt, FlowOption))
        assert expected in flow_opt.states

    def test_done_requires_direction_or_state(self):
        with pytest.raises(BuilderError, match="direction or state"):
            RuleBuilder().flow_builder().done()


class TestThresholdBuilderValidation:
    """ThresholdBuilder.done() validates every required field."""

    def test_valid_threshold(self):
        rule = (
            _base()
            .threshold_builder()
            .threshold_type("limit")
            .track("by_src")
            .count(5)
            .seconds(60)
            .done()
            .build()
        )
        assert any(isinstance(opt, ThresholdOption) for opt in rule.options)

    def test_missing_type(self):
        with pytest.raises(BuilderError, match="type"):
            RuleBuilder().threshold_builder().done()

    def test_missing_track(self):
        with pytest.raises(BuilderError, match="track"):
            RuleBuilder().threshold_builder().threshold_type("limit").done()

    def test_missing_count(self):
        with pytest.raises(BuilderError, match="count"):
            RuleBuilder().threshold_builder().threshold_type("limit").track("by_src").done()

    def test_missing_seconds(self):
        with pytest.raises(BuilderError, match="seconds"):
            (
                RuleBuilder()
                .threshold_builder()
                .threshold_type("limit")
                .track("by_src")
                .count(5)
                .done()
            )
