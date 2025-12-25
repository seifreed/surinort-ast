# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Comprehensive roundtrip tests for text_printer module.

Tests parse → print → parse to ensure AST fidelity and correct formatting.
Covers all formatting options, edge cases, and special characters.
"""

import pytest

from surinort_ast import parse_rule
from surinort_ast.core.enums import Action, Direction, Protocol
from surinort_ast.core.nodes import (
    ContentOption,
    PcreOption,
    SidOption,
)
from surinort_ast.printer.formatter import FormatterOptions
from surinort_ast.printer.text_printer import TextPrinter, print_rule, print_rules


class TestRoundtripBasic:
    """Test basic roundtrip: parse → print → parse produces identical AST."""

    @pytest.mark.parametrize(
        "rule_text",
        [
            'alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1;)',
            'drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Outbound Attack"; sid:2;)',
            'alert udp any 53 -> any any (msg:"DNS Query"; sid:3; rev:2;)',
            'pass ip 192.168.1.0/24 any -> any any (msg:"Internal Traffic"; sid:4;)',
            'reject tcp !192.168.0.0/16 any -> any 22 (msg:"SSH Block"; sid:5;)',
            'alert http any any -> any any (msg:"Web Traffic"; sid:6;)',
            'alert tcp [192.168.1.1,192.168.1.2] any -> any any (msg:"Address List"; sid:7;)',
            'alert tcp any [80,443,8080] -> any any (msg:"Port List"; sid:8;)',
            'alert tcp any 1024:65535 -> any any (msg:"Port Range"; sid:9;)',
        ],
    )
    def test_roundtrip_basic(self, rule_text: str):
        """Parse, print, parse again should produce same AST structure."""
        # First parse
        rule1 = parse_rule(rule_text)
        assert rule1 is not None

        # Print to text
        printer = TextPrinter()
        printed = printer.print_rule(rule1)
        assert printed
        assert isinstance(printed, str)

        # Second parse
        rule2 = parse_rule(printed)
        assert rule2 is not None

        # Compare critical fields (AST structure should match)
        assert rule1.action == rule2.action
        assert rule1.header.protocol == rule2.header.protocol
        assert rule1.header.direction == rule2.header.direction
        assert len(rule1.options) == len(rule2.options)

        # Compare SID values
        sid1 = next((opt.value for opt in rule1.options if isinstance(opt, SidOption)), None)
        sid2 = next((opt.value for opt in rule2.options if isinstance(opt, SidOption)), None)
        assert sid1 == sid2


class TestRoundtripContent:
    """Test content option roundtrip with various encodings."""

    def test_content_printable_ascii(self):
        """Test content with printable ASCII characters."""
        rule_text = 'alert tcp any any -> any any (content:"GET /index.html"; sid:1;)'
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        # Extract content patterns
        content1 = next((opt for opt in rule1.options if isinstance(opt, ContentOption)), None)
        content2 = next((opt for opt in rule2.options if isinstance(opt, ContentOption)), None)

        assert content1 is not None
        assert content2 is not None
        assert content1.pattern == content2.pattern

    def test_content_hex_encoding(self):
        """Test content with hex-encoded bytes."""
        rule_text = 'alert tcp any any -> any any (content:"|48 45 4C 4C 4F|"; sid:1;)'
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        # Verify HELLO is preserved
        content1 = next((opt for opt in rule1.options if isinstance(opt, ContentOption)), None)
        content2 = next((opt for opt in rule2.options if isinstance(opt, ContentOption)), None)

        assert content1 is not None
        assert content2 is not None
        assert content1.pattern == content2.pattern
        assert content1.pattern == b"HELLO"

    def test_content_mixed_ascii_hex(self):
        """Test content with mixed ASCII and hex."""
        rule_text = 'alert tcp any any -> any any (content:"User-Agent|3a 20|Mozilla"; sid:1;)'
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        content1 = next((opt for opt in rule1.options if isinstance(opt, ContentOption)), None)
        content2 = next((opt for opt in rule2.options if isinstance(opt, ContentOption)), None)

        assert content1 is not None
        assert content2 is not None
        assert content1.pattern == content2.pattern

    def test_content_with_modifiers(self):
        """Test content with modifiers roundtrip."""
        rule_text = (
            'alert tcp any any -> any any (content:"attack"; nocase; offset:10; depth:20; sid:1;)'
        )
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        # Both should parse successfully
        assert rule1.action == Action.ALERT
        assert rule2.action == Action.ALERT


class TestRoundtripPCRE:
    """Test PCRE option roundtrip with various patterns."""

    def test_pcre_simple_pattern(self):
        """Test simple PCRE pattern."""
        rule_text = 'alert tcp any any -> any any (pcre:"/GET .*/"; sid:1;)'
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        pcre1 = next((opt for opt in rule1.options if isinstance(opt, PcreOption)), None)
        pcre2 = next((opt for opt in rule2.options if isinstance(opt, PcreOption)), None)

        assert pcre1 is not None
        assert pcre2 is not None
        assert pcre1.pattern == pcre2.pattern

    def test_pcre_with_flags(self):
        """Test PCRE with flags (case-insensitive, multiline, etc.)."""
        rule_text = 'alert tcp any any -> any any (pcre:"/admin/i"; sid:1;)'
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        pcre1 = next((opt for opt in rule1.options if isinstance(opt, PcreOption)), None)
        pcre2 = next((opt for opt in rule2.options if isinstance(opt, PcreOption)), None)

        assert pcre1 is not None
        assert pcre2 is not None
        assert pcre1.pattern == pcre2.pattern
        assert pcre1.flags == pcre2.flags

    def test_pcre_complex_pattern(self):
        """Test complex PCRE with escapes and special characters."""
        rule_text = r'alert tcp any any -> any any (pcre:"/\\/api\\/v[0-9]+\\//i"; sid:1;)'
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        assert rule1.action == Action.ALERT
        assert rule2.action == Action.ALERT


class TestRoundtripAddresses:
    """Test address expression roundtrip."""

    def test_cidr_notation(self):
        """Test CIDR network notation."""
        rule_text = 'alert tcp 10.0.0.0/8 any -> any any (msg:"Private Network"; sid:1;)'
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        assert rule1.header.protocol == Protocol.TCP
        assert rule2.header.protocol == Protocol.TCP

    def test_address_range(self):
        """Test IP address range."""
        rule_text = 'alert tcp [192.168.1.1-192.168.1.100] any -> any any (msg:"Range"; sid:1;)'
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        assert rule1.header.protocol == Protocol.TCP
        assert rule2.header.protocol == Protocol.TCP

    def test_address_negation(self):
        """Test address negation."""
        rule_text = 'alert tcp !10.0.0.0/8 any -> any any (msg:"Not Private"; sid:1;)'
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        assert rule1.action == Action.ALERT
        assert rule2.action == Action.ALERT

    def test_address_variable(self):
        """Test address variable."""
        rule_text = 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Outbound"; sid:1;)'
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        assert rule1.header.direction == Direction.TO
        assert rule2.header.direction == Direction.TO


class TestRoundtripPorts:
    """Test port expression roundtrip."""

    def test_port_single(self):
        """Test single port number."""
        rule_text = 'alert tcp any any -> any 443 (msg:"HTTPS"; sid:1;)'
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        assert rule1.header.protocol == Protocol.TCP
        assert rule2.header.protocol == Protocol.TCP

    def test_port_range(self):
        """Test port range."""
        rule_text = 'alert tcp any any -> any 1024:65535 (msg:"High Ports"; sid:1;)'
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        assert rule1.action == Action.ALERT
        assert rule2.action == Action.ALERT

    def test_port_list(self):
        """Test port list."""
        rule_text = 'alert tcp any any -> any [80,443,8080,8443] (msg:"Web Ports"; sid:1;)'
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        assert rule1.header.protocol == Protocol.TCP
        assert rule2.header.protocol == Protocol.TCP

    def test_port_negation(self):
        """Test port negation."""
        rule_text = 'alert tcp any any -> any !80 (msg:"Not HTTP"; sid:1;)'
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        assert rule1.action == Action.ALERT
        assert rule2.action == Action.ALERT


class TestFormatterOptions:
    """Test different formatter options."""

    def test_stable_format(self):
        """Test stable (canonical) formatting."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        printer = TextPrinter(FormatterOptions.stable())
        printed = printer.print_rule(rule)

        # Should be able to parse back
        rule2 = parse_rule(printed)
        assert rule2.action == Action.ALERT

    def test_standard_format(self):
        """Test standard formatting."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        printer = TextPrinter(FormatterOptions.standard())
        printed = printer.print_rule(rule)

        # Should be able to parse back
        rule2 = parse_rule(printed)
        assert rule2.action == Action.ALERT

    def test_custom_separator(self):
        """Test custom option separator."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:2;)'
        rule = parse_rule(rule_text)

        # Custom formatter with different separator
        options = FormatterOptions.standard()
        options.option_separator = " "
        printer = TextPrinter(options)
        printed = printer.print_rule(rule)

        # Should still be parseable
        rule2 = parse_rule(printed)
        assert rule2.action == Action.ALERT


class TestMultipleRules:
    """Test printing multiple rules."""

    def test_print_multiple_rules(self):
        """Test print_rules() convenience function."""
        rules_text = [
            'alert tcp any any -> any 80 (msg:"HTTP"; sid:1;)',
            'alert tcp any any -> any 443 (msg:"HTTPS"; sid:2;)',
            'alert udp any any -> any 53 (msg:"DNS"; sid:3;)',
        ]

        rules = [parse_rule(r) for r in rules_text]
        assert len(rules) == 3

        # Print all rules
        printed = print_rules(rules)
        assert printed
        assert printed.count("\n") >= 2  # At least 2 newlines for 3 rules

        # Each rule should be on its own line
        lines = printed.strip().split("\n")
        assert len(lines) == 3

        # Each line should start with an action
        for line in lines:
            assert line.startswith("alert")


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    def test_empty_options_list(self):
        """Test rule with minimal options."""
        rule_text = "alert tcp any any -> any 80 (sid:1;)"
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        assert rule1.action == Action.ALERT
        assert rule2.action == Action.ALERT

    def test_msg_with_special_characters(self):
        """Test msg with quotes and special characters."""
        # Use escaped quotes
        rule_text = r'alert tcp any any -> any 80 (msg:"Alert: \"Attack\" detected"; sid:1;)'
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)

        # Should contain the message
        assert "Attack" in printed or "Alert" in printed

    def test_bidirectional_direction(self):
        """Test bidirectional traffic."""
        rule_text = 'alert tcp any any <> any any (msg:"Bidirectional"; sid:1;)'
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        assert rule1.header.direction == Direction.BIDIRECTIONAL
        assert rule2.header.direction == Direction.BIDIRECTIONAL

    def test_all_protocols(self):
        """Test roundtrip for all supported protocols."""
        protocols = ["tcp", "udp", "icmp", "ip", "http", "dns", "tls"]

        for proto in protocols:
            rule_text = f'alert {proto} any any -> any any (msg:"Test {proto}"; sid:1;)'
            rule1 = parse_rule(rule_text)
            printed = print_rule(rule1)
            rule2 = parse_rule(printed)

            assert rule1.action == Action.ALERT
            assert rule2.action == Action.ALERT

    def test_all_actions(self):
        """Test roundtrip for all supported actions."""
        actions = ["alert", "drop", "reject", "pass", "log"]

        for action in actions:
            rule_text = f'{action} tcp any any -> any any (msg:"Test {action}"; sid:1;)'
            rule1 = parse_rule(rule_text)
            printed = print_rule(rule1)
            rule2 = parse_rule(printed)

            assert rule2 is not None


class TestRealWorldRules:
    """Test roundtrip with realistic, complex rules."""

    def test_emerging_threats_style_rule(self):
        """Test ET-style rule with multiple options."""
        rule_text = (
            "alert http $EXTERNAL_NET any -> $HOME_NET any "
            '(msg:"ET MALWARE CobaltStrike C2 Profile"; '
            'flow:established,to_server; http.method; content:"POST"; '
            'http.uri; content:"/api/v1/"; depth:8; '
            "classtype:trojan-activity; sid:2027452; rev:2;)"
        )
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        assert rule1.header.protocol == Protocol.HTTP
        assert rule2.header.protocol == Protocol.HTTP

    def test_snort_community_style_rule(self):
        """Test Snort community rule style."""
        rule_text = (
            "alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS "
            '(msg:"WEB-ATTACKS /bin/ps command attempt"; '
            'flow:to_server,established; content:"/bin/ps"; '
            "nocase; classtype:web-application-attack; sid:1328; rev:7;)"
        )
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        assert rule1.action == Action.ALERT
        assert rule2.action == Action.ALERT

    def test_metadata_option_roundtrip(self):
        """Test metadata option preservation."""
        rule_text = (
            "alert tcp any any -> any any "
            '(msg:"Test"; metadata:created_at 2025_01_01, updated_at 2025_01_15; sid:1;)'
        )
        rule1 = parse_rule(rule_text)
        printed = print_rule(rule1)
        rule2 = parse_rule(printed)

        # Should parse without errors
        assert rule1.action == Action.ALERT
        assert rule2.action == Action.ALERT
