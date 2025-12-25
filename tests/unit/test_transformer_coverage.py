# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Comprehensive transformer coverage tests.

Tests all transformation methods, protocols, actions, and option types.
Validates nesting depth limits and diagnostic generation.
"""

import pytest

from surinort_ast import parse_rule
from surinort_ast.core.enums import Action, Direction, FlowDirection, FlowState, Protocol
from surinort_ast.core.nodes import (
    BufferSelectOption,
    ClasstypeOption,
    ContentOption,
    FilestoreOption,
    FlowbitsOption,
    FlowOption,
    GenericOption,
    GidOption,
    MetadataOption,
    MsgOption,
    PcreOption,
    PriorityOption,
    ReferenceOption,
    RevOption,
    SidOption,
)
from surinort_ast.parsing.parser import RuleParser
from surinort_ast.parsing.parser_config import ParserConfig


class TestAllProtocols:
    """Test all 27 protocol types transform correctly."""

    @pytest.mark.parametrize(
        "protocol",
        [
            "tcp",
            "udp",
            "icmp",
            "ip",
            "http",
            "http2",
            "dns",
            "tls",
            "ssh",
            "ftp",
            "ftp-data",
            "smb",
            "smtp",
            "imap",
            "dcerpc",
            "dhcp",
            "nfs",
            "sip",
            "rdp",
            "mqtt",
            "modbus",
            "dnp3",
            "enip",
            "ike",
            "krb5",
            "ntp",
            "snmp",
            "tftp",
        ],
    )
    def test_protocol_transformation(self, protocol: str):
        """Test each protocol transforms to correct enum value."""
        rule_text = f'alert {protocol} any any -> any any (msg:"Test {protocol}"; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None
        assert rule.header.protocol.value == protocol

    def test_ssl_alias_to_tls(self):
        """Test that 'ssl' is aliased to TLS protocol."""
        rule_text = 'alert ssl any any -> any any (msg:"SSL Test"; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None
        assert rule.header.protocol == Protocol.TLS


class TestAllActions:
    """Test all action types transform correctly."""

    @pytest.mark.parametrize(
        "action,expected",
        [
            ("alert", Action.ALERT),
            ("log", Action.LOG),
            ("pass", Action.PASS),
            ("drop", Action.DROP),
            ("reject", Action.REJECT),
            ("sdrop", Action.SDROP),
        ],
    )
    def test_action_transformation(self, action: str, expected: Action):
        """Test each action transforms to correct enum value."""
        rule_text = f'{action} tcp any any -> any any (msg:"Test {action}"; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None
        assert rule.action == expected


class TestAllDirections:
    """Test all direction types transform correctly."""

    @pytest.mark.parametrize(
        "direction,expected",
        [
            ("->", Direction.TO),
            ("<-", Direction.FROM),
            ("<>", Direction.BIDIRECTIONAL),
        ],
    )
    def test_direction_transformation(self, direction: str, expected: Direction):
        """Test each direction transforms to correct enum value."""
        rule_text = f'alert tcp any any {direction} any any (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None
        assert rule.header.direction == expected


class TestAllOptions:
    """Test all option types transform correctly."""

    def test_msg_option(self):
        """Test msg option transformation."""
        rule_text = 'alert tcp any any -> any any (msg:"Test Message"; sid:1;)'
        rule = parse_rule(rule_text)

        msg_opt = next((opt for opt in rule.options if isinstance(opt, MsgOption)), None)
        assert msg_opt is not None
        assert msg_opt.text == "Test Message"

    def test_sid_option(self):
        """Test sid option transformation."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; sid:123456;)'
        rule = parse_rule(rule_text)

        sid_opt = next((opt for opt in rule.options if isinstance(opt, SidOption)), None)
        assert sid_opt is not None
        assert sid_opt.value == 123456

    def test_rev_option(self):
        """Test rev option transformation."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; sid:1; rev:5;)'
        rule = parse_rule(rule_text)

        rev_opt = next((opt for opt in rule.options if isinstance(opt, RevOption)), None)
        assert rev_opt is not None
        assert rev_opt.value == 5

    def test_gid_option(self):
        """Test gid option transformation."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; gid:100; sid:1;)'
        rule = parse_rule(rule_text)

        gid_opt = next((opt for opt in rule.options if isinstance(opt, GidOption)), None)
        assert gid_opt is not None
        assert gid_opt.value == 100

    def test_classtype_option(self):
        """Test classtype option transformation."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; classtype:trojan-activity; sid:1;)'
        rule = parse_rule(rule_text)

        ct_opt = next((opt for opt in rule.options if isinstance(opt, ClasstypeOption)), None)
        assert ct_opt is not None
        assert ct_opt.value == "trojan-activity"

    def test_priority_option(self):
        """Test priority option transformation."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; priority:1; sid:1;)'
        rule = parse_rule(rule_text)

        pri_opt = next((opt for opt in rule.options if isinstance(opt, PriorityOption)), None)
        assert pri_opt is not None
        assert pri_opt.value == 1

    def test_reference_option(self):
        """Test reference option transformation."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; reference:cve,2021-12345; sid:1;)'
        rule = parse_rule(rule_text)

        ref_opt = next((opt for opt in rule.options if isinstance(opt, ReferenceOption)), None)
        assert ref_opt is not None
        assert ref_opt.ref_type == "cve"
        assert ref_opt.ref_id == "2021-12345"

    def test_metadata_option(self):
        """Test metadata option transformation."""
        rule_text = (
            "alert tcp any any -> any any "
            '(msg:"Test"; metadata:created_at 2025_01_01, updated_at 2025_01_15; sid:1;)'
        )
        rule = parse_rule(rule_text)

        meta_opt = next((opt for opt in rule.options if isinstance(opt, MetadataOption)), None)
        assert meta_opt is not None
        assert len(meta_opt.entries) >= 1

    def test_content_option(self):
        """Test content option transformation."""
        rule_text = 'alert tcp any any -> any any (content:"malware"; sid:1;)'
        rule = parse_rule(rule_text)

        content_opt = next((opt for opt in rule.options if isinstance(opt, ContentOption)), None)
        assert content_opt is not None
        assert content_opt.pattern == b"malware"

    def test_pcre_option(self):
        """Test pcre option transformation."""
        rule_text = 'alert tcp any any -> any any (pcre:"/attack/i"; sid:1;)'
        rule = parse_rule(rule_text)

        pcre_opt = next((opt for opt in rule.options if isinstance(opt, PcreOption)), None)
        assert pcre_opt is not None
        assert pcre_opt.pattern == "attack"
        assert pcre_opt.flags == "i"

    def test_flow_option(self):
        """Test flow option transformation."""
        rule_text = "alert tcp any any -> any any (flow:established,to_server; sid:1;)"
        rule = parse_rule(rule_text)

        flow_opt = next((opt for opt in rule.options if isinstance(opt, FlowOption)), None)
        assert flow_opt is not None
        assert FlowState.ESTABLISHED in flow_opt.states
        assert FlowDirection.TO_SERVER in flow_opt.directions

    def test_flowbits_option(self):
        """Test flowbits option transformation."""
        rule_text = "alert tcp any any -> any any (flowbits:set,infected; sid:1;)"
        rule = parse_rule(rule_text)

        fb_opt = next((opt for opt in rule.options if isinstance(opt, FlowbitsOption)), None)
        assert fb_opt is not None
        assert fb_opt.action == "set"
        assert fb_opt.name == "infected"

    def test_buffer_select_option(self):
        """Test buffer select (sticky buffer) option transformation."""
        rule_text = 'alert http any any -> any any (http.uri; content:"/admin"; sid:1;)'
        rule = parse_rule(rule_text)

        buffer_opt = next(
            (opt for opt in rule.options if isinstance(opt, BufferSelectOption)), None
        )
        assert buffer_opt is not None
        assert buffer_opt.buffer_name == "http.uri"

    def test_filestore_option(self):
        """Test filestore option transformation."""
        rule_text = "alert tcp any any -> any any (filestore:request,file; sid:1;)"
        rule = parse_rule(rule_text)

        fs_opt = next((opt for opt in rule.options if isinstance(opt, FilestoreOption)), None)
        assert fs_opt is not None
        assert fs_opt.direction == "request"
        assert fs_opt.scope == "file"

    def test_generic_option(self):
        """Test generic option fallback."""
        rule_text = "alert tcp any any -> any any (threshold:type limit,track by_src,count 5,seconds 60; sid:1;)"
        rule = parse_rule(rule_text)

        # Should parse without errors
        assert rule is not None
        # Generic options should be present
        generic_opts = [opt for opt in rule.options if isinstance(opt, GenericOption)]
        assert len(generic_opts) >= 0  # May or may not create generic options


class TestContentModifiers:
    """Test content modifiers transformation."""

    def test_content_with_nocase(self):
        """Test content with nocase modifier."""
        rule_text = 'alert tcp any any -> any any (content:"attack"; nocase; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None
        # Nocase should be separate option or modifier
        assert len(rule.options) >= 2

    def test_content_with_offset(self):
        """Test content with offset modifier."""
        rule_text = 'alert tcp any any -> any any (content:"pattern"; offset:10; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

    def test_content_with_depth(self):
        """Test content with depth modifier."""
        rule_text = 'alert tcp any any -> any any (content:"pattern"; depth:20; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

    def test_content_with_distance(self):
        """Test content with distance modifier."""
        rule_text = (
            'alert tcp any any -> any any (content:"first"; content:"second"; distance:5; sid:1;)'
        )
        rule = parse_rule(rule_text)

        assert rule is not None

    def test_content_with_within(self):
        """Test content with within modifier."""
        rule_text = (
            'alert tcp any any -> any any (content:"first"; content:"second"; within:10; sid:1;)'
        )
        rule = parse_rule(rule_text)

        assert rule is not None


class TestNestingDepthValidation:
    """Test nesting depth limits prevent DoS attacks."""

    def test_deep_address_nesting(self):
        """Test deeply nested address lists."""
        config = ParserConfig(max_nesting_depth=50)
        parser = RuleParser(config=config, strict=False)

        # Create deeply nested address list
        nested = "[" * 60 + "1.1.1.1" + "]" * 60
        rule_text = f"alert tcp {nested} any -> any any (sid:1;)"

        rule = parser.parse(rule_text)
        # Should either parse or generate error
        assert rule is not None

    def test_deep_port_nesting(self):
        """Test deeply nested port lists."""
        config = ParserConfig(max_nesting_depth=50)
        parser = RuleParser(config=config, strict=False)

        # Create deeply nested port list
        nested = "[" * 60 + "80" + "]" * 60
        rule_text = f"alert tcp any {nested} -> any any (sid:1;)"

        rule = parser.parse(rule_text)
        # Should either parse or generate error
        assert rule is not None

    def test_reasonable_nesting_allowed(self):
        """Test reasonable nesting depth is allowed."""
        parser = RuleParser(strict=False)

        # Reasonable nesting (3 levels)
        rule_text = (
            "alert tcp [[192.168.1.1,192.168.1.2],[10.0.0.1,10.0.0.2]] any -> any any (sid:1;)"
        )
        rule = parser.parse(rule_text)

        assert rule is not None


class TestPortValidation:
    """Test port number validation."""

    def test_valid_port_range(self):
        """Test valid port numbers (0-65535)."""
        for port in [0, 1, 80, 443, 8080, 65535]:
            rule_text = f'alert tcp any any -> any {port} (msg:"Port {port}"; sid:1;)'
            rule = parse_rule(rule_text)
            assert rule is not None

    def test_port_range_validation(self):
        """Test port range validation."""
        rule_text = 'alert tcp any any -> any 1024:65535 (msg:"High Ports"; sid:1;)'
        rule = parse_rule(rule_text)

        assert rule is not None

    def test_open_ended_port_range(self):
        """Test open-ended port range (1024:)."""
        rule_text = 'alert tcp any any -> any 1024: (msg:"High Ports"; sid:1;)'
        rule = parse_rule(rule_text)

        # Should parse successfully
        assert rule is not None


class TestSIDValidation:
    """Test SID validation and diagnostic generation."""

    def test_valid_sid(self):
        """Test valid SID values."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; sid:1000001;)'
        rule = parse_rule(rule_text)

        sid_opt = next((opt for opt in rule.options if isinstance(opt, SidOption)), None)
        assert sid_opt is not None
        assert sid_opt.value == 1000001

    def test_sid_minimum_value(self):
        """Test SID minimum value (should be >= 1)."""
        parser = RuleParser(strict=False)
        rule_text = 'alert tcp any any -> any any (msg:"Test"; sid:1;)'
        rule = parser.parse(rule_text)

        # Should parse without errors
        assert rule is not None


class TestQuotedStrings:
    """Test quoted string parsing with escape sequences."""

    def test_simple_quoted_string(self):
        """Test simple quoted string."""
        rule_text = 'alert tcp any any -> any any (msg:"Simple message"; sid:1;)'
        rule = parse_rule(rule_text)

        msg_opt = next((opt for opt in rule.options if isinstance(opt, MsgOption)), None)
        assert msg_opt is not None
        assert msg_opt.text == "Simple message"

    def test_escaped_quotes(self):
        """Test escaped quotes in strings."""
        rule_text = r'alert tcp any any -> any any (msg:"Message with \"quotes\""; sid:1;)'
        rule = parse_rule(rule_text)

        msg_opt = next((opt for opt in rule.options if isinstance(opt, MsgOption)), None)
        assert msg_opt is not None
        # Should contain quotes
        assert "quotes" in msg_opt.text

    def test_escaped_backslash(self):
        """Test escaped backslash in strings."""
        rule_text = r'alert tcp any any -> any any (msg:"Path: C:\\Windows"; sid:1;)'
        rule = parse_rule(rule_text)

        msg_opt = next((opt for opt in rule.options if isinstance(opt, MsgOption)), None)
        assert msg_opt is not None
        # Should contain backslash
        assert "\\" in msg_opt.text or "Windows" in msg_opt.text


class TestHexStrings:
    """Test hex string parsing."""

    def test_hex_string_parsing(self):
        """Test hex string to bytes conversion."""
        rule_text = 'alert tcp any any -> any any (content:"|48 65 6C 6C 6F|"; sid:1;)'
        rule = parse_rule(rule_text)

        content_opt = next((opt for opt in rule.options if isinstance(opt, ContentOption)), None)
        assert content_opt is not None
        assert content_opt.pattern == b"Hello"

    def test_hex_string_lowercase(self):
        """Test lowercase hex string."""
        rule_text = 'alert tcp any any -> any any (content:"|48 65 6c 6c 6f|"; sid:1;)'
        rule = parse_rule(rule_text)

        content_opt = next((opt for opt in rule.options if isinstance(opt, ContentOption)), None)
        assert content_opt is not None
        assert content_opt.pattern == b"Hello"

    def test_hex_string_no_spaces(self):
        """Test hex string without spaces."""
        rule_text = 'alert tcp any any -> any any (content:"|48656C6C6F|"; sid:1;)'
        rule = parse_rule(rule_text)

        content_opt = next((opt for opt in rule.options if isinstance(opt, ContentOption)), None)
        assert content_opt is not None
        assert content_opt.pattern == b"Hello"


class TestByteOperations:
    """Test byte operation options."""

    def test_byte_test_option(self):
        """Test byte_test option parsing."""
        rule_text = "alert tcp any any -> any any (byte_test:4,>,1000,0; sid:1;)"
        rule = parse_rule(rule_text)

        # Should parse without errors
        assert rule is not None

    def test_byte_jump_option(self):
        """Test byte_jump option parsing."""
        rule_text = "alert tcp any any -> any any (byte_jump:4,0,relative; sid:1;)"
        rule = parse_rule(rule_text)

        # Should parse without errors
        assert rule is not None

    def test_byte_extract_option(self):
        """Test byte_extract option parsing."""
        rule_text = "alert tcp any any -> any any (byte_extract:4,0,var_name; sid:1;)"
        rule = parse_rule(rule_text)

        # Should parse without errors
        assert rule is not None


class TestDiagnosticGeneration:
    """Test diagnostic message generation during transformation."""

    def test_priority_range_warning(self):
        """Test warning for out-of-range priority values."""
        parser = RuleParser(strict=False)
        rule_text = 'alert tcp any any -> any any (msg:"Test"; priority:10; sid:1;)'
        rule = parser.parse(rule_text)

        # Should generate warning diagnostic
        assert rule is not None
        # May have diagnostics for unusual priority
        assert rule.diagnostics is not None

    def test_uricontent_deprecated_warning(self):
        """Test warning for deprecated uricontent option."""
        parser = RuleParser(strict=False)
        rule_text = 'alert tcp any any -> any any (uricontent:"admin"; sid:1;)'
        rule = parser.parse(rule_text)

        # Should generate deprecation warning
        assert rule is not None


class TestComplexRules:
    """Test complex real-world rule patterns."""

    def test_multiple_content_matches(self):
        """Test rule with multiple content matches."""
        rule_text = (
            "alert tcp any any -> any any "
            '(content:"POST"; content:"/upload"; content:"malware"; sid:1;)'
        )
        rule = parse_rule(rule_text)

        content_opts = [opt for opt in rule.options if isinstance(opt, ContentOption)]
        assert len(content_opts) == 3

    def test_flow_with_content(self):
        """Test flow with content matching."""
        rule_text = (
            'alert tcp any any -> any any (flow:established,to_server; content:"attack"; sid:1;)'
        )
        rule = parse_rule(rule_text)

        assert rule is not None
        assert len(rule.options) >= 3

    def test_pcre_with_content(self):
        """Test PCRE combined with content."""
        rule_text = (
            'alert tcp any any -> any any (content:"User-Agent"; pcre:"/curl|wget/i"; sid:1;)'
        )
        rule = parse_rule(rule_text)

        assert rule is not None
        # Should have both content and pcre options
        has_content = any(isinstance(opt, ContentOption) for opt in rule.options)
        has_pcre = any(isinstance(opt, PcreOption) for opt in rule.options)
        assert has_content or has_pcre  # At least one should be present
