# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for AST pretty-printer.

Tests roundtrip conversion: text -> AST -> text -> AST
NO MOCKS - all tests use real parser and printer execution.
"""

import pytest
from lark import Lark

from surinort_ast.parsing.transformer import RuleTransformer
from surinort_ast.printer.formatter import FormatterOptions
from surinort_ast.printer.text_printer import TextPrinter, print_rule


class TestBasicPrinting:
    """Test basic rule printing."""

    def test_print_minimal_rule(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Print minimal rule."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        # Parse
        parse_tree = lark_parser.parse(rule_text)
        result = transformer.transform(parse_tree)
        rule = result[0]

        # Print
        printed = text_printer.print_rule(rule)

        # Should contain all essential parts
        assert "alert" in printed
        assert "tcp" in printed
        assert "any" in printed
        assert "->" in printed
        assert "80" in printed
        assert "msg:" in printed
        assert "sid:1" in printed

    def test_print_with_variables(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Print rule with address/port variables."""
        rule_text = 'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (msg:"Test"; sid:1;)'

        # Parse
        parse_tree = lark_parser.parse(rule_text)
        result = transformer.transform(parse_tree)
        rule = result[0]

        # Print
        printed = text_printer.print_rule(rule)

        # Variables should be preserved
        assert "$EXTERNAL_NET" in printed
        assert "$HOME_NET" in printed
        assert "$HTTP_PORTS" in printed


class TestRoundtripParsing:
    """Test roundtrip: parse -> print -> parse."""

    def test_roundtrip_simple_rule(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Roundtrip simple rule."""
        original_text = 'alert tcp any any -> any 80 (msg:"Test Rule"; sid:1000001; rev:1;)'

        # First parse
        parse_tree1 = lark_parser.parse(original_text)
        rule1 = transformer.transform(parse_tree1)[0]

        # Print
        printed_text = text_printer.print_rule(rule1)

        # Second parse
        parse_tree2 = lark_parser.parse(printed_text)
        rule2 = transformer.transform(parse_tree2)[0]

        # Compare key fields
        assert rule1.action == rule2.action
        assert rule1.header.protocol == rule2.header.protocol
        assert rule1.header.direction == rule2.header.direction
        assert rule1.header.dst_port.value == rule2.header.dst_port.value  # type: ignore

        # Options should match
        assert len(rule1.options) == len(rule2.options)

    def test_roundtrip_complex_rule(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Roundtrip complex rule with content and flow."""
        original_text = 'alert http any any -> any any (msg:"HTTP POST"; flow:established,to_server; http.method; content:"POST"; sid:2000001; rev:1;)'

        # First parse
        parse_tree1 = lark_parser.parse(original_text)
        rule1 = transformer.transform(parse_tree1)[0]

        # Print
        printed_text = text_printer.print_rule(rule1)

        # Second parse
        parse_tree2 = lark_parser.parse(printed_text)
        rule2 = transformer.transform(parse_tree2)[0]

        # Compare
        assert rule1.action == rule2.action
        assert rule1.header.protocol == rule2.header.protocol
        assert len(rule1.options) == len(rule2.options)

    @pytest.mark.parametrize(
        "rule_text",
        [
            'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
            'alert tcp 192.168.1.0/24 any -> any 80 (msg:"CIDR"; sid:2;)',
            'alert tcp any 1024:65535 -> any 80 (msg:"Port Range"; sid:3;)',
            'alert tcp any any <> any 80 (msg:"Bidirectional"; sid:4;)',
            'drop tcp any any -> any 22 (msg:"Drop SSH"; sid:5;)',
        ],
    )
    def test_roundtrip_various_rules(
        self,
        lark_parser: Lark,
        transformer: RuleTransformer,
        text_printer: TextPrinter,
        rule_text: str,
    ):
        """Roundtrip various rule patterns."""
        # Parse original
        parse_tree1 = lark_parser.parse(rule_text)
        rule1 = transformer.transform(parse_tree1)[0]

        # Print
        printed_text = text_printer.print_rule(rule1)

        # Parse printed
        parse_tree2 = lark_parser.parse(printed_text)
        rule2 = transformer.transform(parse_tree2)[0]

        # Basic structure should match
        assert rule1.action == rule2.action
        assert rule1.header.protocol == rule2.header.protocol
        assert rule1.header.direction == rule2.header.direction

    def test_roundtrip_fixture_rules(
        self,
        lark_parser: Lark,
        transformer: RuleTransformer,
        text_printer: TextPrinter,
        fixtures_dir,
    ):
        """Roundtrip all simple fixture rules."""
        simple_rules_file = fixtures_dir / "simple_rules.txt"

        with open(simple_rules_file, encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Parse original
                parse_tree1 = lark_parser.parse(line)
                rule1 = transformer.transform(parse_tree1)[0]

                # Print
                printed_text = text_printer.print_rule(rule1)

                # Parse printed
                try:
                    parse_tree2 = lark_parser.parse(printed_text)
                    rule2 = transformer.transform(parse_tree2)[0]

                    # Verify key fields match
                    assert rule1.action == rule2.action, f"Action mismatch at line {line_num}"
                    assert rule1.header.protocol == rule2.header.protocol, (
                        f"Protocol mismatch at line {line_num}"
                    )
                except Exception as e:
                    pytest.fail(
                        f"Roundtrip failed at line {line_num}\nOriginal: {line}\nPrinted: {printed_text}\nError: {e}"
                    )


class TestDeterministicOutput:
    """Test that printer produces deterministic output."""

    def test_print_twice_same_output(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Printing same rule twice produces identical output."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:1; classtype:misc-attack;)'

        # Parse
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Print twice
        output1 = text_printer.print_rule(rule)
        output2 = text_printer.print_rule(rule)

        # Should be identical
        assert output1 == output2

    def test_print_with_metadata_stable(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Printing rule with metadata is stable."""
        rule_text = (
            'alert tcp any any -> any 80 (msg:"Test"; metadata:key1 value1, key2 value2; sid:1;)'
        )

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Print multiple times
        outputs = [text_printer.print_rule(rule) for _ in range(5)]

        # All should be identical
        assert all(output == outputs[0] for output in outputs)


class TestFormattingOptions:
    """Test different formatting options."""

    def test_compact_formatting(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test compact formatting (no spaces)."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Compact format
        options = FormatterOptions(
            option_separator=" ",
            indent_size=0,
        )
        printer = TextPrinter(options=options)
        printed = printer.print_rule(rule)

        # Should be relatively compact
        assert "alert" in printed
        assert "tcp" in printed

    def test_standard_formatting(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test standard formatting."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Standard format
        options = FormatterOptions.standard()
        printer = TextPrinter(options=options)
        printed = printer.print_rule(rule)

        assert "alert tcp" in printed
        assert "msg:" in printed
        assert "sid:1" in printed


class TestContentPrinting:
    """Test printing content options."""

    def test_print_ascii_content(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Print content with ASCII pattern."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; content:"GET"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "content:" in printed
        assert "GET" in printed

    def test_print_hex_content(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Print content with hex pattern."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; content:|48 65 6c 6c 6f|; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        # Printed output should contain content (as hex or text)
        assert "content:" in printed


class TestMultipleRules:
    """Test printing multiple rules."""

    def test_print_multiple_rules(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Print multiple rules."""
        rules_text = [
            'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)',
            'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)',
            'alert udp any any -> any 53 (msg:"Rule 3"; sid:3;)',
        ]

        rules = []
        for rule_text in rules_text:
            parse_tree = lark_parser.parse(rule_text)
            rule = transformer.transform(parse_tree)[0]
            rules.append(rule)

        # Print all rules
        printed = text_printer.print_rules(rules)

        # Should contain all rules
        assert "Rule 1" in printed
        assert "Rule 2" in printed
        assert "Rule 3" in printed
        assert "sid:1" in printed
        assert "sid:2" in printed
        assert "sid:3" in printed


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_print_rule_function(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test print_rule convenience function."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Use convenience function
        printed = print_rule(rule)

        assert "alert" in printed
        assert "tcp" in printed
        assert "msg:" in printed
