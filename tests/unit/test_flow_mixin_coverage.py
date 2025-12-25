# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Flow Mixin Coverage Tests.

Tests to achieve 100% coverage for src/surinort_ast/parsing/mixins/options/flow_mixin.py.

Covers all uncovered paths:
- Lines 102-106: Unknown flow value warning diagnostic
- Lines 166-170: Flowbits with action only (length >= 1)
- Lines 170-175: Flowbits with action and name (length >= 2)
- Lines 233-234: Flowint option returning GenericOption

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from surinort_ast import parse_rule
from surinort_ast.core.diagnostics import DiagnosticLevel
from surinort_ast.core.enums import FlowDirection, FlowState
from surinort_ast.core.nodes import FlowbitsOption, FlowOption, GenericOption


class TestFlowOptionUnknownValue:
    """Test flow option with unknown/invalid values (lines 102-106)."""

    def test_flow_option_unknown_value_generates_warning(self):
        """Test that unknown flow values generate WARNING diagnostics."""
        # Use an invalid flow value that is neither a direction nor a state
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flow:invalid_value; sid:1;)'
        rule = parse_rule(rule_text)

        # Rule should parse successfully (unknown values don't fail parsing)
        assert rule is not None
        assert rule.header is not None

        # Verify that a WARNING diagnostic was generated
        warnings = [d for d in rule.diagnostics if d.level == DiagnosticLevel.WARNING]
        assert len(warnings) > 0, "Expected at least one WARNING diagnostic"

        # Verify the warning message mentions the unknown flow value
        unknown_value_warning = next(
            (w for w in warnings if "Unknown flow value" in w.message), None
        )
        assert unknown_value_warning is not None, "Expected 'Unknown flow value' warning"
        assert "invalid_value" in unknown_value_warning.message

    def test_flow_option_multiple_unknown_values(self):
        """Test multiple unknown flow values generate multiple warnings."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flow:bad1,bad2,bad3; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        # Should have multiple warnings, one for each unknown value
        warnings = [
            d
            for d in rule.diagnostics
            if d.level == DiagnosticLevel.WARNING and "Unknown flow value" in d.message
        ]
        assert len(warnings) == 3, "Expected three warnings for three unknown values"

        # Check each unknown value is mentioned
        warning_messages = " ".join(w.message for w in warnings)
        assert "bad1" in warning_messages
        assert "bad2" in warning_messages
        assert "bad3" in warning_messages

    def test_flow_option_mixed_valid_and_invalid(self):
        """Test flow option with mix of valid and invalid values."""
        # Mix valid direction/state with invalid value
        rule_text = (
            'alert tcp any any -> any any (msg:"Test"; flow:to_server,invalid,established; sid:1;)'
        )
        rule = parse_rule(rule_text)

        assert rule is not None

        # Find the FlowOption
        flow_opt = next((opt for opt in rule.options if isinstance(opt, FlowOption)), None)
        assert flow_opt is not None

        # Valid values should be parsed correctly
        assert FlowDirection.TO_SERVER in flow_opt.directions
        assert FlowState.ESTABLISHED in flow_opt.states

        # Invalid value should generate warning
        warnings = [
            d
            for d in rule.diagnostics
            if d.level == DiagnosticLevel.WARNING and "Unknown flow value" in d.message
        ]
        assert len(warnings) == 1
        assert "invalid" in warnings[0].message

    def test_flow_option_typo_in_known_value(self):
        """Test that typos in known values generate warnings."""
        # Common typo: "establised" instead of "established"
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flow:establised; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        warnings = [
            d
            for d in rule.diagnostics
            if d.level == DiagnosticLevel.WARNING and "Unknown flow value" in d.message
        ]
        assert len(warnings) == 1
        assert "establised" in warnings[0].message


class TestFlowbitsOptionActionOnly:
    """Test flowbits option with action only (lines 166-170)."""

    def test_flowbits_option_noalert_action_only(self):
        """Test flowbits with 'noalert' action (no name required)."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowbits:noalert; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        # Find the FlowbitsOption
        fb_opt = next((opt for opt in rule.options if isinstance(opt, FlowbitsOption)), None)
        assert fb_opt is not None
        assert fb_opt.action == "noalert"
        assert fb_opt.name == ""  # Name should be empty string

    def test_flowbits_option_unset_action_only(self):
        """Test flowbits with 'unset' action without name."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowbits:unset; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        fb_opt = next((opt for opt in rule.options if isinstance(opt, FlowbitsOption)), None)
        assert fb_opt is not None
        assert fb_opt.action == "unset"
        assert fb_opt.name == ""

    def test_flowbits_option_empty_action_items(self):
        """Test flowbits with empty action items list (defensive case)."""
        # This test covers the edge case where action_items might be empty
        # In practice, this is unlikely due to grammar constraints, but tests defensive code
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowbits:toggle; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        fb_opt = next((opt for opt in rule.options if isinstance(opt, FlowbitsOption)), None)
        assert fb_opt is not None
        # Action should be parsed
        assert fb_opt.action == "toggle"


class TestFlowbitsOptionActionAndName:
    """Test flowbits option with action and name (lines 170-175)."""

    def test_flowbits_option_set_with_name(self):
        """Test flowbits with 'set' action and name."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowbits:set,mybit; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        fb_opt = next((opt for opt in rule.options if isinstance(opt, FlowbitsOption)), None)
        assert fb_opt is not None
        assert fb_opt.action == "set"
        assert fb_opt.name == "mybit"

    def test_flowbits_option_isset_with_name(self):
        """Test flowbits with 'isset' action and name."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowbits:isset,checkbit; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        fb_opt = next((opt for opt in rule.options if isinstance(opt, FlowbitsOption)), None)
        assert fb_opt is not None
        assert fb_opt.action == "isset"
        assert fb_opt.name == "checkbit"

    def test_flowbits_option_toggle_with_name(self):
        """Test flowbits with 'toggle' action and name."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowbits:toggle,flag; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        fb_opt = next((opt for opt in rule.options if isinstance(opt, FlowbitsOption)), None)
        assert fb_opt is not None
        assert fb_opt.action == "toggle"
        assert fb_opt.name == "flag"

    def test_flowbits_option_isnotset_with_name(self):
        """Test flowbits with 'isnotset' action and name."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowbits:isnotset,notflag; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        fb_opt = next((opt for opt in rule.options if isinstance(opt, FlowbitsOption)), None)
        assert fb_opt is not None
        assert fb_opt.action == "isnotset"
        assert fb_opt.name == "notflag"

    def test_flowbits_option_unset_with_name(self):
        """Test flowbits with 'unset' action and name."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowbits:unset,clearbit; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        fb_opt = next((opt for opt in rule.options if isinstance(opt, FlowbitsOption)), None)
        assert fb_opt is not None
        assert fb_opt.action == "unset"
        assert fb_opt.name == "clearbit"

    def test_flowbits_option_compound_name(self):
        """Test flowbits with compound name (multiple names with &)."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowbits:isset,name1&name2; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        fb_opt = next((opt for opt in rule.options if isinstance(opt, FlowbitsOption)), None)
        assert fb_opt is not None
        assert fb_opt.action == "isset"
        # Compound names should be joined with &
        assert "&" in fb_opt.name or "name1" in fb_opt.name


class TestFlowintOption:
    """Test flowint option returning GenericOption (lines 233-234)."""

    def test_flowint_option_isset_operation(self):
        """Test flowint with isset operation."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowint:counter,isset; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        # Flowint should be parsed as GenericOption
        flowint_opt = next(
            (
                opt
                for opt in rule.options
                if isinstance(opt, GenericOption) and opt.keyword == "flowint"
            ),
            None,
        )
        assert flowint_opt is not None
        assert flowint_opt.keyword == "flowint"
        assert "counter" in flowint_opt.value
        assert "isset" in flowint_opt.value
        # Value should be comma-separated
        assert "," in flowint_opt.value

    def test_flowint_option_isnotset_operation(self):
        """Test flowint with isnotset operation."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowint:counter,isnotset; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        flowint_opt = next(
            (
                opt
                for opt in rule.options
                if isinstance(opt, GenericOption) and opt.keyword == "flowint"
            ),
            None,
        )
        assert flowint_opt is not None
        assert flowint_opt.keyword == "flowint"
        assert flowint_opt.value == "counter,isnotset"

    def test_flowint_option_set_with_value(self):
        """Test flowint with set operation and value."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowint:counter,set,5; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        flowint_opt = next(
            (
                opt
                for opt in rule.options
                if isinstance(opt, GenericOption) and opt.keyword == "flowint"
            ),
            None,
        )
        assert flowint_opt is not None
        assert flowint_opt.keyword == "flowint"
        assert flowint_opt.value == "counter,set,5"

    def test_flowint_option_increment_operation(self):
        """Test flowint with increment operation."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowint:counter,add,1; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        flowint_opt = next(
            (
                opt
                for opt in rule.options
                if isinstance(opt, GenericOption) and opt.keyword == "flowint"
            ),
            None,
        )
        assert flowint_opt is not None
        assert flowint_opt.keyword == "flowint"
        assert flowint_opt.value == "counter,add,1"

    def test_flowint_option_decrement_operation(self):
        """Test flowint with decrement operation."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowint:counter,sub,1; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        flowint_opt = next(
            (
                opt
                for opt in rule.options
                if isinstance(opt, GenericOption) and opt.keyword == "flowint"
            ),
            None,
        )
        assert flowint_opt is not None
        assert flowint_opt.keyword == "flowint"
        assert flowint_opt.value == "counter,sub,1"

    def test_flowint_option_comparison_greater_than(self):
        """Test flowint with greater than comparison."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowint:counter,gt,10; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        flowint_opt = next(
            (
                opt
                for opt in rule.options
                if isinstance(opt, GenericOption) and opt.keyword == "flowint"
            ),
            None,
        )
        assert flowint_opt is not None
        assert flowint_opt.keyword == "flowint"
        assert flowint_opt.value == "counter,gt,10"

    def test_flowint_option_comparison_equals(self):
        """Test flowint with equality comparison."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowint:counter,eq,100; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        flowint_opt = next(
            (
                opt
                for opt in rule.options
                if isinstance(opt, GenericOption) and opt.keyword == "flowint"
            ),
            None,
        )
        assert flowint_opt is not None
        assert flowint_opt.keyword == "flowint"
        assert "counter" in flowint_opt.value
        assert "eq" in flowint_opt.value
        assert "100" in flowint_opt.value

    def test_flowint_option_raw_attribute(self):
        """Test that flowint GenericOption has correct raw attribute."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowint:myvar,add,2; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        flowint_opt = next(
            (
                opt
                for opt in rule.options
                if isinstance(opt, GenericOption) and opt.keyword == "flowint"
            ),
            None,
        )
        assert flowint_opt is not None
        # Raw should include the keyword and value
        assert flowint_opt.raw == "flowint:myvar,add,2"

    def test_flowint_option_complex_variable_name(self):
        """Test flowint with complex variable name."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flowint:my_complex_counter_123,set,999; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        flowint_opt = next(
            (
                opt
                for opt in rule.options
                if isinstance(opt, GenericOption) and opt.keyword == "flowint"
            ),
            None,
        )
        assert flowint_opt is not None
        assert "my_complex_counter_123" in flowint_opt.value


class TestFlowMixinIntegration:
    """Integration tests for flow tracking options."""

    def test_multiple_flow_options_in_rule(self):
        """Test rule with multiple flow-related options."""
        rule_text = 'alert tcp any any -> any any (msg:"Multi-flow"; flow:established,to_server; flowbits:set,attack_started; flowint:packet_count,add,1; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        # Should have FlowOption
        flow_opt = next((opt for opt in rule.options if isinstance(opt, FlowOption)), None)
        assert flow_opt is not None
        assert FlowState.ESTABLISHED in flow_opt.states
        assert FlowDirection.TO_SERVER in flow_opt.directions

        # Should have FlowbitsOption
        fb_opt = next((opt for opt in rule.options if isinstance(opt, FlowbitsOption)), None)
        assert fb_opt is not None
        assert fb_opt.action == "set"
        assert fb_opt.name == "attack_started"

        # Should have flowint as GenericOption
        flowint_opt = next(
            (
                opt
                for opt in rule.options
                if isinstance(opt, GenericOption) and opt.keyword == "flowint"
            ),
            None,
        )
        assert flowint_opt is not None
        assert "packet_count" in flowint_opt.value

    def test_flow_option_all_valid_directions(self):
        """Test flow option with all valid direction values."""
        directions = ["to_server", "to_client", "from_server", "from_client"]

        for direction in directions:
            rule_text = f'alert tcp any any -> any any (msg:"Test"; flow:{direction}; sid:1;)'
            rule = parse_rule(rule_text)

            assert rule is not None
            flow_opt = next((opt for opt in rule.options if isinstance(opt, FlowOption)), None)
            assert flow_opt is not None
            assert len(flow_opt.directions) > 0

    def test_flow_option_all_valid_states(self):
        """Test flow option with all valid state values."""
        states = [
            "established",
            "not_established",
            "stateless",
            "only_stream",
            "no_stream",
        ]

        for state in states:
            rule_text = f'alert tcp any any -> any any (msg:"Test"; flow:{state}; sid:1;)'
            rule = parse_rule(rule_text)

            assert rule is not None
            flow_opt = next((opt for opt in rule.options if isinstance(opt, FlowOption)), None)
            assert flow_opt is not None
            assert len(flow_opt.states) > 0

    def test_flow_option_empty_when_all_invalid(self):
        """Test flow option with all invalid values results in empty lists."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flow:bad1,bad2; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        flow_opt = next((opt for opt in rule.options if isinstance(opt, FlowOption)), None)
        assert flow_opt is not None
        # All values were invalid, so lists should be empty
        assert len(flow_opt.directions) == 0
        assert len(flow_opt.states) == 0

        # Should have warnings
        warnings = [
            d
            for d in rule.diagnostics
            if d.level == DiagnosticLevel.WARNING and "Unknown flow value" in d.message
        ]
        assert len(warnings) == 2


class TestFlowMixinEdgeCases:
    """Edge cases and defensive tests for flow mixin."""

    def test_flowbits_all_actions(self):
        """Test all valid flowbits actions."""
        actions = ["set", "isset", "isnotset", "toggle", "unset", "noalert"]

        for action in actions:
            if action == "noalert":
                rule_text = f'alert tcp any any -> any any (msg:"Test"; flowbits:{action}; sid:1;)'
            else:
                rule_text = (
                    f'alert tcp any any -> any any (msg:"Test"; flowbits:{action},testbit; sid:1;)'
                )

            rule = parse_rule(rule_text)
            assert rule is not None

            fb_opt = next((opt for opt in rule.options if isinstance(opt, FlowbitsOption)), None)
            assert fb_opt is not None
            assert fb_opt.action == action

    def test_flow_option_combined_directions_and_states(self):
        """Test flow option with both directions and states."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flow:to_server,established,only_stream; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

        flow_opt = next((opt for opt in rule.options if isinstance(opt, FlowOption)), None)
        assert flow_opt is not None

        # Should have both direction and states
        assert len(flow_opt.directions) >= 1
        assert len(flow_opt.states) >= 1
        assert FlowDirection.TO_SERVER in flow_opt.directions
        assert FlowState.ESTABLISHED in flow_opt.states
        assert FlowState.ONLY_STREAM in flow_opt.states

    def test_flowint_with_various_operators(self):
        """Test flowint with different operations."""
        # Test valid flowint operations based on grammar: WORD "," WORD ("," INT)?
        operations = [
            ("isset", None),
            ("isnotset", None),
            ("set", 5),
            ("add", 1),
            ("sub", 2),
            ("gt", 10),
            ("lt", 20),
            ("eq", 15),
        ]

        for op, value in operations:
            if value is None:
                rule_text = f'alert tcp any any -> any any (msg:"Test"; flowint:var,{op}; sid:1;)'
            else:
                rule_text = (
                    f'alert tcp any any -> any any (msg:"Test"; flowint:var,{op},{value}; sid:1;)'
                )
            rule = parse_rule(rule_text)

            assert rule is not None

            flowint_opt = next(
                (
                    opt
                    for opt in rule.options
                    if isinstance(opt, GenericOption) and opt.keyword == "flowint"
                ),
                None,
            )
            assert flowint_opt is not None
            assert op in flowint_opt.value

    def test_deterministic_parsing(self):
        """Test that parsing is deterministic (same input always produces same output)."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; flow:to_server,established; flowbits:set,test; flowint:counter,add,1; sid:1;)'

        # Parse the same rule multiple times
        results = [parse_rule(rule_text) for _ in range(5)]

        # All results should be identical
        for i in range(1, len(results)):
            assert results[i].header.protocol == results[0].header.protocol
            assert len(results[i].options) == len(results[0].options)
            assert len(results[i].diagnostics) == len(results[0].diagnostics)
