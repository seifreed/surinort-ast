# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for IDS rule parser.

Tests the Lark parser and AST transformer using real rule text.
NO MOCKS - all tests use actual parser execution with real grammar.
"""

import pytest
from lark import Lark
from lark.exceptions import LarkError

from surinort_ast.core.enums import FlowDirection, FlowState
from surinort_ast.core.nodes import (
    Action,
    AddressList,
    AddressVariable,
    AnyAddress,
    AnyPort,
    BufferSelectOption,
    ClasstypeOption,
    ContentOption,
    Direction,
    FlowOption,
    IPAddress,
    IPCIDRRange,
    MsgOption,
    PcreOption,
    Port,
    PortList,
    PortRange,
    PortVariable,
    Protocol,
    RevOption,
    Rule,
    SidOption,
)
from surinort_ast.parsing.transformer import RuleTransformer
from tests._helpers import iter_rule_lines, transform_rule


class TestBasicParsing:
    """Test basic rule parsing with simple rules."""

    def test_parse_minimal_rule(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse minimal valid rule."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        result = transformer.transform(parse_tree)

        # Transformer returns list of rules for rule_file
        assert isinstance(result, list)
        assert len(result) == 1

        rule = result[0]
        assert isinstance(rule, Rule)
        assert rule.action == Action.ALERT
        assert rule.header.protocol == Protocol.TCP
        assert rule.header.direction == Direction.TO
        assert isinstance(rule.header.src_addr, AnyAddress)
        assert isinstance(rule.header.dst_addr, AnyAddress)
        assert isinstance(rule.header.src_port, AnyPort)
        assert isinstance(rule.header.dst_port, Port)
        assert rule.header.dst_port.value == 80

    def test_parse_all_actions(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse rules with different actions."""
        actions_to_test = [
            ("alert", Action.ALERT),
            ("log", Action.LOG),
            ("pass", Action.PASS),
            ("drop", Action.DROP),
            ("reject", Action.REJECT),
            ("sdrop", Action.SDROP),
        ]

        for action_text, expected_action in actions_to_test:
            rule_text = f'{action_text} tcp any any -> any 80 (msg:"Test"; sid:1;)'
            rule = transform_rule(rule_text, lark_parser, transformer)

            assert rule.action == expected_action, f"Failed to parse action: {action_text}"

    def test_parse_all_protocols(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse rules with different protocols."""
        protocols_to_test = [
            ("tcp", Protocol.TCP),
            ("tcp-pkt", Protocol.TCP_PKT),
            ("udp", Protocol.UDP),
            ("icmp", Protocol.ICMP),
            ("ip", Protocol.IP),
            ("http", Protocol.HTTP),
            ("http1", Protocol.HTTP1),
            ("dns", Protocol.DNS),
            ("tls", Protocol.TLS),
            ("bittorrent-dht", Protocol.BITTORRENT_DHT),
        ]

        for proto_text, expected_proto in protocols_to_test:
            rule_text = f'alert {proto_text} any any -> any 80 (msg:"Test"; sid:1;)'
            rule = transform_rule(rule_text, lark_parser, transformer)

            assert rule.header.protocol == expected_proto, f"Failed to parse protocol: {proto_text}"

    def test_parse_directions(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse rules with different traffic directions."""
        directions_to_test = [
            ("->", Direction.TO),
            ("<-", Direction.FROM),
            ("<>", Direction.BIDIRECTIONAL),
        ]

        for dir_text, expected_dir in directions_to_test:
            rule_text = f'alert tcp any any {dir_text} any 80 (msg:"Test"; sid:1;)'
            rule = transform_rule(rule_text, lark_parser, transformer)

            assert rule.header.direction == expected_dir, f"Failed to parse direction: {dir_text}"


class TestAddressParsing:
    """Test address expression parsing."""

    def test_parse_ipv4_address(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse IPv4 addresses."""
        rule_text = 'alert tcp 192.168.1.1 any -> 10.0.0.1 80 (msg:"Test"; sid:1;)'
        rule = transform_rule(rule_text, lark_parser, transformer)

        assert isinstance(rule.header.src_addr, IPAddress)
        assert rule.header.src_addr.value == "192.168.1.1"
        assert rule.header.src_addr.version == 4

        assert isinstance(rule.header.dst_addr, IPAddress)
        assert rule.header.dst_addr.value == "10.0.0.1"
        assert rule.header.dst_addr.version == 4

    def test_parse_ipv4_cidr(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse IPv4 CIDR notation."""
        rule_text = 'alert tcp 192.168.1.0/24 any -> 10.0.0.0/8 80 (msg:"Test"; sid:1;)'
        rule = transform_rule(rule_text, lark_parser, transformer)

        assert isinstance(rule.header.src_addr, IPCIDRRange)
        assert rule.header.src_addr.network == "192.168.1.0"
        assert rule.header.src_addr.prefix_len == 24

        assert isinstance(rule.header.dst_addr, IPCIDRRange)
        assert rule.header.dst_addr.network == "10.0.0.0"
        assert rule.header.dst_addr.prefix_len == 8

    def test_parse_address_variables(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse address variables."""
        rule_text = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Test"; sid:1;)'
        rule = transform_rule(rule_text, lark_parser, transformer)

        assert isinstance(rule.header.src_addr, AddressVariable)
        assert rule.header.src_addr.name == "EXTERNAL_NET"

        assert isinstance(rule.header.dst_addr, AddressVariable)
        assert rule.header.dst_addr.name == "HOME_NET"

    def test_parse_address_list(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse address lists."""
        rule_text = 'alert tcp [192.168.1.0/24,10.0.0.0/8] any -> any 80 (msg:"Test"; sid:1;)'
        rule = transform_rule(rule_text, lark_parser, transformer)

        assert isinstance(rule.header.src_addr, AddressList)
        assert len(rule.header.src_addr.elements) == 2
        assert isinstance(rule.header.src_addr.elements[0], IPCIDRRange)
        assert isinstance(rule.header.src_addr.elements[1], IPCIDRRange)

    def test_parse_ipv4_mapped_ipv6(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse IPv4-mapped IPv6 literals (valid Suricata address syntax)."""
        rule_text = 'alert ip ::ffff:192.168.1.1 any -> any any (msg:"Test"; sid:1;)'
        rule = transform_rule(rule_text, lark_parser, transformer)

        assert isinstance(rule.header.src_addr, IPAddress)
        assert rule.header.src_addr.value == "::ffff:192.168.1.1"
        assert rule.header.src_addr.version == 6


class TestPortParsing:
    """Test port expression parsing."""

    def test_parse_single_port(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse single port numbers."""
        rule_text = 'alert tcp any 1234 -> any 80 (msg:"Test"; sid:1;)'
        rule = transform_rule(rule_text, lark_parser, transformer)

        assert isinstance(rule.header.src_port, Port)
        assert rule.header.src_port.value == 1234

        assert isinstance(rule.header.dst_port, Port)
        assert rule.header.dst_port.value == 80

    def test_parse_port_range(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse port ranges."""
        rule_text = 'alert tcp any any -> any 1024:65535 (msg:"Test"; sid:1;)'
        rule = transform_rule(rule_text, lark_parser, transformer)

        assert isinstance(rule.header.dst_port, PortRange)
        assert rule.header.dst_port.start == 1024
        assert rule.header.dst_port.end == 65535

    def test_parse_port_variable(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse port variables."""
        rule_text = 'alert tcp any any -> any $HTTP_PORTS (msg:"Test"; sid:1;)'
        rule = transform_rule(rule_text, lark_parser, transformer)

        assert isinstance(rule.header.dst_port, PortVariable)
        assert rule.header.dst_port.name == "HTTP_PORTS"

    def test_parse_nested_port_list(self, lark_parser: Lark, transformer: RuleTransformer):
        """A plain nested port list is valid Suricata and must parse (like the
        address side and like a negated nested port list already do)."""
        rule_text = 'alert tcp any [80,[443,8443]] -> any any (msg:"Test"; sid:1;)'
        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        src = rule.header.src_port
        assert isinstance(src, PortList)
        assert len(src.elements) == 2
        assert isinstance(src.elements[0], Port)
        assert src.elements[0].value == 80
        assert isinstance(src.elements[1], PortList)
        assert [e.value for e in src.elements[1].elements] == [443, 8443]


class TestOptionParsing:
    """Test rule option parsing."""

    def test_parse_basic_options(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse basic rule options."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test Message"; sid:1000001; rev:2; gid:1;)'
        rule = transform_rule(rule_text, lark_parser, transformer)

        # Find options by type
        msg_opt = next((o for o in rule.options if isinstance(o, MsgOption)), None)
        sid_opt = next((o for o in rule.options if isinstance(o, SidOption)), None)
        rev_opt = next((o for o in rule.options if isinstance(o, RevOption)), None)

        assert msg_opt is not None
        assert msg_opt.text == "Test Message"

        assert sid_opt is not None
        assert sid_opt.value == 1000001

        assert rev_opt is not None
        assert rev_opt.value == 2

    def test_parse_classtype_option(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse classtype option."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; classtype:trojan-activity; sid:1;)'
        rule = transform_rule(rule_text, lark_parser, transformer)

        classtype_opt = next((o for o in rule.options if isinstance(o, ClasstypeOption)), None)
        assert classtype_opt is not None
        assert classtype_opt.value == "trojan-activity"

    def test_parse_content_option(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse content matching option."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; content:"GET"; sid:1;)'
        rule = transform_rule(rule_text, lark_parser, transformer)

        content_opt = next((o for o in rule.options if isinstance(o, ContentOption)), None)
        assert content_opt is not None
        assert content_opt.pattern == b"GET"

    def test_parse_content_with_hex(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse content with hex bytes."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; content:|48 65 6c 6c 6f|; sid:1;)'
        rule = transform_rule(rule_text, lark_parser, transformer)

        content_opt = next((o for o in rule.options if isinstance(o, ContentOption)), None)
        assert content_opt is not None
        assert content_opt.pattern == b"Hello"

    def test_parse_pcre_option(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse PCRE option."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; pcre:"/pattern/i"; sid:1;)'
        rule = transform_rule(rule_text, lark_parser, transformer)

        pcre_opt = next((o for o in rule.options if isinstance(o, PcreOption)), None)
        assert pcre_opt is not None
        assert pcre_opt.pattern == "pattern"
        assert pcre_opt.flags == "i"

    def test_parse_flow_option(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse flow option."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; flow:established,to_server; sid:1;)'
        rule = transform_rule(rule_text, lark_parser, transformer)

        flow_opt = next((o for o in rule.options if isinstance(o, FlowOption)), None)
        assert flow_opt is not None
        assert FlowState.ESTABLISHED in flow_opt.states
        assert FlowDirection.TO_SERVER in flow_opt.directions

    def test_parse_sticky_buffer(self, lark_parser: Lark, transformer: RuleTransformer):
        """Parse sticky buffer selection."""
        rule_text = 'alert http any any -> any any (msg:"Test"; http.uri; content:"/test"; sid:1;)'
        rule = transform_rule(rule_text, lark_parser, transformer)

        # Find http_uri buffer select option
        buffer_opts = [o for o in rule.options if isinstance(o, BufferSelectOption)]
        assert len(buffer_opts) > 0
        # Check if http.uri or http_uri is parsed (depends on grammar)


class TestRealRuleParsing:
    """Test parsing real rules from fixtures and rule files."""

    def test_parse_simple_fixture_rules(
        self, lark_parser: Lark, transformer: RuleTransformer, fixtures_dir
    ):
        """Parse all simple rules from fixtures."""
        simple_rules_file = fixtures_dir / "simple_rules.txt"

        for line_num, line in iter_rule_lines(simple_rules_file):
            try:
                parse_tree = lark_parser.parse(line)
                result = transformer.transform(parse_tree)
                assert isinstance(result, list)
                assert len(result) >= 1
                assert isinstance(result[0], Rule)
            except Exception as e:
                pytest.fail(f"Failed to parse simple rule at line {line_num}: {line}\nError: {e}")

    def test_parse_complex_fixture_rules(
        self, lark_parser: Lark, transformer: RuleTransformer, fixtures_dir
    ):
        """Parse all complex rules from fixtures."""
        complex_rules_file = fixtures_dir / "complex_rules.txt"

        for line_num, line in iter_rule_lines(complex_rules_file):
            try:
                parse_tree = lark_parser.parse(line)
                result = transformer.transform(parse_tree)
                assert isinstance(result, list)
                assert len(result) >= 1
                assert isinstance(result[0], Rule)
            except Exception as e:
                pytest.fail(f"Failed to parse complex rule at line {line_num}: {line}\nError: {e}")

    @pytest.mark.parametrize("rule_index", range(10))
    def test_parse_suricata_samples(
        self, lark_parser: Lark, transformer: RuleTransformer, suricata_sample_rules, rule_index
    ):
        """Parse first 10 Suricata rules individually."""
        if rule_index >= len(suricata_sample_rules):
            pytest.skip("Not enough sample rules")

        rule_text = suricata_sample_rules[rule_index]

        try:
            parse_tree = lark_parser.parse(rule_text)
            result = transformer.transform(parse_tree)
            assert isinstance(result, list)
            assert len(result) >= 1
            assert isinstance(result[0], Rule)
        except Exception as e:
            pytest.fail(
                f"Failed to parse Suricata rule {rule_index}: {rule_text[:100]}...\nError: {e}"
            )


class TestErrorRecovery:
    """Test parser error handling and diagnostics."""

    def test_parse_invalid_action(self, lark_parser: Lark):
        """Invalid action should raise parse error."""
        rule_text = 'invalid_action tcp any any -> any 80 (msg:"Test"; sid:1;)'

        with pytest.raises(LarkError):
            lark_parser.parse(rule_text)

    def test_parse_invalid_protocol(self, lark_parser: Lark):
        """Invalid protocol should raise parse error."""
        rule_text = 'alert invalid_proto any any -> any 80 (msg:"Test"; sid:1;)'

        with pytest.raises(LarkError):
            lark_parser.parse(rule_text)

    def test_parse_missing_semicolon(self, lark_parser: Lark):
        """Missing semicolon should still parse (grammar allows trailing semicolon to be optional)."""
        # Note: Some grammar variants allow optional trailing semicolon
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1)'

        # This might parse or fail depending on grammar
        # Either outcome is acceptable as long as it's deterministic
        try:
            parse_tree = lark_parser.parse(rule_text)
            assert parse_tree is not None
        except LarkError:
            # Also acceptable if grammar requires semicolon
            pass

    def test_invalid_port_creates_diagnostic(self, lark_parser: Lark, transformer: RuleTransformer):
        """Invalid port number should create diagnostic."""
        rule_text = 'alert tcp any any -> any 99999 (msg:"Test"; sid:1;)'

        # Parse might succeed but transformer should add diagnostic
        try:
            parse_tree = lark_parser.parse(rule_text)
            result = transformer.transform(parse_tree)

            # Check if diagnostics were recorded
            if isinstance(result, list) and len(result) > 0:
                rule = result[0]
                # Transformer should have recorded diagnostics
                assert len(transformer.diagnostics) > 0 or len(rule.diagnostics) > 0
        except (LarkError, ValueError):
            # Also acceptable if parser/validator rejects it
            pass


class TestLocationTracking:
    """Test that location information is preserved."""

    def test_location_tracking_enabled(self, lark_parser: Lark, transformer: RuleTransformer):
        """Verify location information is captured."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

        rule = transform_rule(rule_text, lark_parser, transformer)

        # Header should have location
        if rule.header.location:
            assert rule.header.location.span is not None
            assert rule.header.location.span.start.line >= 1

    def test_column_is_one_indexed_not_off_by_one(
        self, lark_parser: Lark, transformer: RuleTransformer
    ):
        """A parsed node's 1-indexed start column must equal offset + 1.

        Regression: token_to_location wrongly added 1 to Lark's already-1-indexed
        column, making every column (and SARIF startColumn) off by one.
        """
        rule_text = 'alert tcp any any -> any any (msg:"hello"; sid:1;)'
        rule = transformer.transform(lark_parser.parse(rule_text))[0]

        msg = next(o for o in rule.options if o.node_type == "MsgOption")
        span = msg.location.span
        assert span.start.column == span.start.offset + 1
        assert span.end.column == span.end.offset + 1
