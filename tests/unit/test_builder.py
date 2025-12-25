"""
Unit tests for builder module.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

import pytest

from surinort_ast.builder import RuleBuilder
from surinort_ast.builder.rule_builder import BuilderError
from surinort_ast.core.enums import Action, Dialect, Direction, Protocol
from surinort_ast.core.nodes import (
    AddressList,
    AddressNegation,
    AddressVariable,
    AnyAddress,
    AnyPort,
    BufferSelectOption,
    ByteExtractOption,
    ByteJumpOption,
    ByteTestOption,
    ClasstypeOption,
    ContentOption,
    DetectionFilterOption,
    FastPatternOption,
    FilestoreOption,
    FlowbitsOption,
    FlowOption,
    GidOption,
    IPAddress,
    IPCIDRRange,
    IPRange,
    LuajitOption,
    LuaOption,
    MetadataOption,
    MsgOption,
    PcreOption,
    Port,
    PortList,
    PortNegation,
    PortRange,
    PortVariable,
    PriorityOption,
    ReferenceOption,
    RevOption,
    Rule,
    SidOption,
    TagOption,
    ThresholdOption,
)


class TestRuleBuilderBasics:
    """Test basic RuleBuilder functionality."""

    def test_minimal_rule(self) -> None:
        """Test building a minimal valid rule."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test rule")
            .sid(1)
            .build()
        )

        assert isinstance(rule, Rule)
        assert rule.action == Action.ALERT
        assert rule.header.protocol == Protocol.TCP
        assert isinstance(rule.header.src_addr, AnyAddress)
        assert isinstance(rule.header.src_port, AnyPort)
        assert isinstance(rule.header.dst_addr, AnyAddress)
        assert isinstance(rule.header.dst_port, Port)
        assert rule.header.dst_port.value == 80

        # Check options
        msg_opts = [o for o in rule.options if isinstance(o, MsgOption)]
        assert len(msg_opts) == 1
        assert msg_opts[0].text == "Test rule"

        sid_opts = [o for o in rule.options if isinstance(o, SidOption)]
        assert len(sid_opts) == 1
        assert sid_opts[0].value == 1

    def test_method_chaining(self) -> None:
        """Test that all methods return self for chaining."""
        builder = RuleBuilder()
        result = builder.alert()
        assert result is builder

    def test_build_without_action_fails(self) -> None:
        """Test that building without action raises error."""
        with pytest.raises(BuilderError, match="Action is required"):
            RuleBuilder().tcp().source_ip("any").source_port("any").dest_ip("any").dest_port(
                80
            ).build()

    def test_build_without_protocol_fails(self) -> None:
        """Test that building without protocol raises error."""
        with pytest.raises(BuilderError, match="Protocol is required"):
            RuleBuilder().alert().source_ip("any").source_port("any").dest_ip("any").dest_port(
                80
            ).build()

    def test_build_without_source_ip_fails(self) -> None:
        """Test that building without source IP raises error."""
        with pytest.raises(BuilderError, match="Source IP is required"):
            RuleBuilder().alert().tcp().source_port("any").dest_ip("any").dest_port(80).build()

    def test_build_without_source_port_fails(self) -> None:
        """Test that building without source port raises error."""
        with pytest.raises(BuilderError, match="Source port is required"):
            RuleBuilder().alert().tcp().source_ip("any").dest_ip("any").dest_port(80).build()

    def test_build_without_dest_ip_fails(self) -> None:
        """Test that building without destination IP raises error."""
        with pytest.raises(BuilderError, match="Destination IP is required"):
            RuleBuilder().alert().tcp().source_ip("any").source_port("any").dest_port(80).build()

    def test_build_without_dest_port_fails(self) -> None:
        """Test that building without destination port raises error."""
        with pytest.raises(BuilderError, match="Destination port is required"):
            RuleBuilder().alert().tcp().source_ip("any").source_port("any").dest_ip("any").build()


class TestActions:
    """Test action configuration methods."""

    def test_alert_action(self) -> None:
        """Test alert() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.action == Action.ALERT

    def test_drop_action(self) -> None:
        """Test drop() method."""
        rule = (
            RuleBuilder()
            .drop()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.action == Action.DROP

    def test_reject_action(self) -> None:
        """Test reject() method."""
        rule = (
            RuleBuilder()
            .reject()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.action == Action.REJECT

    def test_pass_action(self) -> None:
        """Test pass_() method."""
        rule = (
            RuleBuilder()
            .pass_()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.action == Action.PASS

    def test_log_action(self) -> None:
        """Test log() method."""
        rule = (
            RuleBuilder()
            .log()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.action == Action.LOG

    def test_sdrop_action(self) -> None:
        """Test sdrop() method."""
        rule = (
            RuleBuilder()
            .sdrop()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.action == Action.SDROP

    def test_action_with_string(self) -> None:
        """Test action() with string parameter."""
        rule = (
            RuleBuilder()
            .action("alert")
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.action == Action.ALERT


class TestProtocols:
    """Test protocol configuration methods."""

    def test_tcp_protocol(self) -> None:
        """Test tcp() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.header.protocol == Protocol.TCP

    def test_udp_protocol(self) -> None:
        """Test udp() method."""
        rule = (
            RuleBuilder()
            .alert()
            .udp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(53)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.header.protocol == Protocol.UDP

    def test_http_protocol(self) -> None:
        """Test http() method."""
        rule = (
            RuleBuilder()
            .alert()
            .http()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.header.protocol == Protocol.HTTP

    def test_dns_protocol(self) -> None:
        """Test dns() method."""
        rule = (
            RuleBuilder()
            .alert()
            .dns()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(53)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.header.protocol == Protocol.DNS

    def test_protocol_with_string(self) -> None:
        """Test protocol() with string parameter."""
        rule = (
            RuleBuilder()
            .alert()
            .protocol("tls")
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(443)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.header.protocol == Protocol.TLS


class TestAddressParsing:
    """Test address expression parsing."""

    def test_any_address(self) -> None:
        """Test 'any' address parsing."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert isinstance(rule.header.src_addr, AnyAddress)
        assert isinstance(rule.header.dst_addr, AnyAddress)

    def test_ipv4_address(self) -> None:
        """Test IPv4 address parsing."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("192.168.1.1")
            .source_port("any")
            .dest_ip("10.0.0.1")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert isinstance(rule.header.src_addr, IPAddress)
        assert rule.header.src_addr.value == "192.168.1.1"
        assert rule.header.src_addr.version == 4

        assert isinstance(rule.header.dst_addr, IPAddress)
        assert rule.header.dst_addr.value == "10.0.0.1"
        assert rule.header.dst_addr.version == 4

    def test_ipv6_address(self) -> None:
        """Test IPv6 address parsing."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("2001:db8::1")
            .source_port("any")
            .dest_ip("fe80::1")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert isinstance(rule.header.src_addr, IPAddress)
        assert rule.header.src_addr.value == "2001:db8::1"
        assert rule.header.src_addr.version == 6

        assert isinstance(rule.header.dst_addr, IPAddress)
        assert rule.header.dst_addr.value == "fe80::1"
        assert rule.header.dst_addr.version == 6

    def test_cidr_range(self) -> None:
        """Test CIDR range parsing."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("192.168.1.0/24")
            .source_port("any")
            .dest_ip("10.0.0.0/8")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert isinstance(rule.header.src_addr, IPCIDRRange)
        assert rule.header.src_addr.network == "192.168.1.0"
        assert rule.header.src_addr.prefix_len == 24

        assert isinstance(rule.header.dst_addr, IPCIDRRange)
        assert rule.header.dst_addr.network == "10.0.0.0"
        assert rule.header.dst_addr.prefix_len == 8

    def test_variable_address(self) -> None:
        """Test variable address parsing."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("$HOME_NET")
            .source_port("any")
            .dest_ip("$EXTERNAL_NET")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert isinstance(rule.header.src_addr, AddressVariable)
        assert rule.header.src_addr.name == "$HOME_NET"

        assert isinstance(rule.header.dst_addr, AddressVariable)
        assert rule.header.dst_addr.name == "$EXTERNAL_NET"

    def test_negated_address(self) -> None:
        """Test negated address parsing."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("!192.168.1.1")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert isinstance(rule.header.src_addr, AddressNegation)
        assert isinstance(rule.header.src_addr.expr, IPAddress)
        assert rule.header.src_addr.expr.value == "192.168.1.1"

    def test_address_list(self) -> None:
        """Test address list parsing."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("[192.168.1.0/24,10.0.0.0/8]")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert isinstance(rule.header.src_addr, AddressList)
        assert len(rule.header.src_addr.elements) == 2
        assert isinstance(rule.header.src_addr.elements[0], IPCIDRRange)
        assert isinstance(rule.header.src_addr.elements[1], IPCIDRRange)

    def test_ip_range(self) -> None:
        """Test IP range parsing."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("[10.0.0.1-10.0.0.255]")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert isinstance(rule.header.src_addr, IPRange)
        assert rule.header.src_addr.start == "10.0.0.1"
        assert rule.header.src_addr.end == "10.0.0.255"


class TestPortParsing:
    """Test port expression parsing."""

    def test_any_port(self) -> None:
        """Test 'any' port parsing."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port("any")
            .msg("Test")
            .sid(1)
            .build()
        )
        assert isinstance(rule.header.src_port, AnyPort)
        assert isinstance(rule.header.dst_port, AnyPort)

    def test_single_port_int(self) -> None:
        """Test single port (integer) parsing."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port(1024)
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert isinstance(rule.header.src_port, Port)
        assert rule.header.src_port.value == 1024

        assert isinstance(rule.header.dst_port, Port)
        assert rule.header.dst_port.value == 80

    def test_single_port_string(self) -> None:
        """Test single port (string) parsing."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("1024")
            .dest_ip("any")
            .dest_port("80")
            .msg("Test")
            .sid(1)
            .build()
        )
        assert isinstance(rule.header.src_port, Port)
        assert rule.header.src_port.value == 1024

        assert isinstance(rule.header.dst_port, Port)
        assert rule.header.dst_port.value == 80

    def test_port_range(self) -> None:
        """Test port range parsing."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("1024:65535")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert isinstance(rule.header.src_port, PortRange)
        assert rule.header.src_port.start == 1024
        assert rule.header.src_port.end == 65535

    def test_port_variable(self) -> None:
        """Test port variable parsing."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("$HTTP_PORTS")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert isinstance(rule.header.src_port, PortVariable)
        assert rule.header.src_port.name == "$HTTP_PORTS"

    def test_port_negation(self) -> None:
        """Test port negation parsing."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("!80")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert isinstance(rule.header.src_port, PortNegation)
        assert isinstance(rule.header.src_port.expr, Port)
        assert rule.header.src_port.expr.value == 80

    def test_port_list(self) -> None:
        """Test port list parsing."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("[80,443,8080:8090]")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert isinstance(rule.header.src_port, PortList)
        assert len(rule.header.src_port.elements) == 3
        assert isinstance(rule.header.src_port.elements[0], Port)
        assert isinstance(rule.header.src_port.elements[1], Port)
        assert isinstance(rule.header.src_port.elements[2], PortRange)


class TestDirections:
    """Test direction configuration."""

    def test_default_direction(self) -> None:
        """Test default direction is TO."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.header.direction == Direction.TO

    def test_to_direction(self) -> None:
        """Test to() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .to()
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.header.direction == Direction.TO

    def test_from_direction(self) -> None:
        """Test from_() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .from_()
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.header.direction == Direction.FROM

    def test_bidirectional_direction(self) -> None:
        """Test bidirectional() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .bidirectional()
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.header.direction == Direction.BIDIRECTIONAL


class TestCommonOptions:
    """Test common rule options."""

    def test_msg_option(self) -> None:
        """Test msg() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test message")
            .sid(1)
            .build()
        )
        msg_opts = [o for o in rule.options if isinstance(o, MsgOption)]
        assert len(msg_opts) == 1
        assert msg_opts[0].text == "Test message"

    def test_sid_option(self) -> None:
        """Test sid() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1000001)
            .build()
        )
        sid_opts = [o for o in rule.options if isinstance(o, SidOption)]
        assert len(sid_opts) == 1
        assert sid_opts[0].value == 1000001

    def test_rev_option(self) -> None:
        """Test rev() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .rev(2)
            .build()
        )
        rev_opts = [o for o in rule.options if isinstance(o, RevOption)]
        assert len(rev_opts) == 1
        assert rev_opts[0].value == 2

    def test_gid_option(self) -> None:
        """Test gid() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .gid(3)
            .build()
        )
        gid_opts = [o for o in rule.options if isinstance(o, GidOption)]
        assert len(gid_opts) == 1
        assert gid_opts[0].value == 3

    def test_classtype_option(self) -> None:
        """Test classtype() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .classtype("trojan-activity")
            .build()
        )
        ct_opts = [o for o in rule.options if isinstance(o, ClasstypeOption)]
        assert len(ct_opts) == 1
        assert ct_opts[0].value == "trojan-activity"

    def test_priority_option(self) -> None:
        """Test priority() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .priority(1)
            .build()
        )
        pri_opts = [o for o in rule.options if isinstance(o, PriorityOption)]
        assert len(pri_opts) == 1
        assert pri_opts[0].value == 1

    def test_reference_option(self) -> None:
        """Test reference() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .reference("cve", "2021-12345")
            .build()
        )
        ref_opts = [o for o in rule.options if isinstance(o, ReferenceOption)]
        assert len(ref_opts) == 1
        assert ref_opts[0].ref_type == "cve"
        assert ref_opts[0].ref_id == "2021-12345"

    def test_metadata_option(self) -> None:
        """Test metadata() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .metadata(("key1", "value1"), ("key2", "value2"))
            .build()
        )
        meta_opts = [o for o in rule.options if isinstance(o, MetadataOption)]
        assert len(meta_opts) == 1
        assert len(meta_opts[0].entries) == 2
        assert meta_opts[0].entries[0] == ("key1", "value1")
        assert meta_opts[0].entries[1] == ("key2", "value2")


class TestContentOptions:
    """Test content matching options."""

    def test_simple_content(self) -> None:
        """Test simple content() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .content(b"GET")
            .build()
        )
        content_opts = [o for o in rule.options if isinstance(o, ContentOption)]
        assert len(content_opts) == 1
        assert content_opts[0].pattern == b"GET"

    def test_pcre_option(self) -> None:
        """Test pcre() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .pcre(r"/admin/", flags="i")
            .build()
        )
        pcre_opts = [o for o in rule.options if isinstance(o, PcreOption)]
        assert len(pcre_opts) == 1
        assert pcre_opts[0].pattern == r"/admin/"
        assert pcre_opts[0].flags == "i"


class TestFlowOptions:
    """Test flow-related options."""

    def test_flowbits_option(self) -> None:
        """Test flowbits() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .flowbits("set", "test_bit")
            .build()
        )
        fb_opts = [o for o in rule.options if isinstance(o, FlowbitsOption)]
        assert len(fb_opts) == 1
        assert fb_opts[0].action == "set"
        assert fb_opts[0].name == "test_bit"


class TestThresholdOptions:
    """Test threshold options."""

    def test_detection_filter_option(self) -> None:
        """Test detection_filter() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(22)
            .msg("Test")
            .sid(1)
            .detection_filter("by_src", 5, 60)
            .build()
        )
        df_opts = [o for o in rule.options if isinstance(o, DetectionFilterOption)]
        assert len(df_opts) == 1
        assert df_opts[0].track == "by_src"
        assert df_opts[0].count == 5
        assert df_opts[0].seconds == 60


class TestAdvancedOptions:
    """Test advanced options."""

    def test_byte_test_option(self) -> None:
        """Test byte_test() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .byte_test(4, ">", 1000, 0)
            .build()
        )
        bt_opts = [o for o in rule.options if isinstance(o, ByteTestOption)]
        assert len(bt_opts) == 1
        assert bt_opts[0].bytes_to_extract == 4
        assert bt_opts[0].operator == ">"
        assert bt_opts[0].value == 1000
        assert bt_opts[0].offset == 0

    def test_byte_jump_option(self) -> None:
        """Test byte_jump() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .byte_jump(4, 0)
            .build()
        )
        bj_opts = [o for o in rule.options if isinstance(o, ByteJumpOption)]
        assert len(bj_opts) == 1
        assert bj_opts[0].bytes_to_extract == 4
        assert bj_opts[0].offset == 0

    def test_byte_extract_option(self) -> None:
        """Test byte_extract() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .byte_extract(4, 0, "my_var")
            .build()
        )
        be_opts = [o for o in rule.options if isinstance(o, ByteExtractOption)]
        assert len(be_opts) == 1
        assert be_opts[0].bytes_to_extract == 4
        assert be_opts[0].offset == 0
        assert be_opts[0].var_name == "my_var"

    def test_tag_option(self) -> None:
        """Test tag() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .tag("session", 10, "packets")
            .build()
        )
        tag_opts = [o for o in rule.options if isinstance(o, TagOption)]
        assert len(tag_opts) == 1
        assert tag_opts[0].tag_type == "session"
        assert tag_opts[0].count == 10
        assert tag_opts[0].metric == "packets"

    def test_filestore_option(self) -> None:
        """Test filestore() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .filestore()
            .build()
        )
        fs_opts = [o for o in rule.options if isinstance(o, FilestoreOption)]
        assert len(fs_opts) == 1

    def test_lua_option(self) -> None:
        """Test lua() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .lua("test.lua")
            .build()
        )
        lua_opts = [o for o in rule.options if isinstance(o, LuaOption)]
        assert len(lua_opts) == 1
        assert lua_opts[0].script_name == "test.lua"
        assert lua_opts[0].negated is False

    def test_luajit_option(self) -> None:
        """Test luajit() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .luajit("test.lua", negated=True)
            .build()
        )
        luajit_opts = [o for o in rule.options if isinstance(o, LuajitOption)]
        assert len(luajit_opts) == 1
        assert luajit_opts[0].script_name == "test.lua"
        assert luajit_opts[0].negated is True

    def test_buffer_select_option(self) -> None:
        """Test buffer_select() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .buffer_select("http_uri")
            .build()
        )
        bs_opts = [o for o in rule.options if isinstance(o, BufferSelectOption)]
        assert len(bs_opts) == 1
        assert bs_opts[0].buffer_name == "http_uri"

    def test_fast_pattern_option(self) -> None:
        """Test fast_pattern() method."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .fast_pattern(10, 20)
            .build()
        )
        fp_opts = [o for o in rule.options if isinstance(o, FastPatternOption)]
        assert len(fp_opts) == 1
        assert fp_opts[0].offset == 10
        assert fp_opts[0].length == 20


class TestContentBuilder:
    """Test ContentBuilder functionality."""

    def test_content_builder_basic(self) -> None:
        """Test basic ContentBuilder usage."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .content_builder()
            .pattern(b"GET")
            .done()
            .build()
        )
        content_opts = [o for o in rule.options if isinstance(o, ContentOption)]
        assert len(content_opts) == 1
        assert content_opts[0].pattern == b"GET"

    def test_content_builder_without_pattern_fails(self) -> None:
        """Test ContentBuilder without pattern raises error."""
        with pytest.raises(Exception, match="Content pattern must be set"):
            (
                RuleBuilder()
                .alert()
                .tcp()
                .source_ip("any")
                .source_port("any")
                .dest_ip("any")
                .dest_port(80)
                .msg("Test")
                .sid(1)
                .content_builder()
                .done()
            )

    def test_content_builder_with_buffer(self) -> None:
        """Test ContentBuilder with sticky buffer."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .content_builder()
            .pattern(b"GET")
            .http_uri()
            .done()
            .build()
        )
        content_opts = [o for o in rule.options if isinstance(o, ContentOption)]
        assert len(content_opts) == 1

        buffer_opts = [o for o in rule.options if isinstance(o, BufferSelectOption)]
        assert len(buffer_opts) == 1
        assert buffer_opts[0].buffer_name == "http_uri"


class TestFlowBuilder:
    """Test FlowBuilder functionality."""

    def test_flow_builder_basic(self) -> None:
        """Test basic FlowBuilder usage."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .flow_builder()
            .established()
            .to_server()
            .done()
            .build()
        )
        flow_opts = [o for o in rule.options if isinstance(o, FlowOption)]
        assert len(flow_opts) == 1
        assert len(flow_opts[0].states) == 1
        assert len(flow_opts[0].directions) == 1


class TestThresholdBuilder:
    """Test ThresholdBuilder functionality."""

    def test_threshold_builder_basic(self) -> None:
        """Test basic ThresholdBuilder usage."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(22)
            .msg("Test")
            .sid(1)
            .threshold_builder()
            .threshold_type("limit")
            .track("by_src")
            .count(5)
            .seconds(60)
            .done()
            .build()
        )
        thresh_opts = [o for o in rule.options if isinstance(o, ThresholdOption)]
        assert len(thresh_opts) == 1
        assert thresh_opts[0].threshold_type == "limit"
        assert thresh_opts[0].track == "by_src"
        assert thresh_opts[0].count == 5
        assert thresh_opts[0].seconds == 60

    def test_threshold_builder_incomplete_fails(self) -> None:
        """Test ThresholdBuilder without required fields fails."""
        with pytest.raises(Exception, match="Threshold type must be set"):
            (
                RuleBuilder()
                .alert()
                .tcp()
                .source_ip("any")
                .source_port("any")
                .dest_ip("any")
                .dest_port(22)
                .msg("Test")
                .sid(1)
                .threshold_builder()
                .done()
            )


class TestDialect:
    """Test dialect configuration."""

    def test_default_dialect(self) -> None:
        """Test default dialect is SURICATA."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .build()
        )
        assert rule.dialect == Dialect.SURICATA

    def test_snort2_dialect(self) -> None:
        """Test setting SNORT2 dialect."""
        rule = (
            RuleBuilder()
            .alert()
            .tcp()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(80)
            .msg("Test")
            .sid(1)
            .dialect("snort2")
            .build()
        )
        assert rule.dialect == Dialect.SNORT2


class TestComplexRules:
    """Test building complex realistic rules."""

    def test_http_rule(self) -> None:
        """Test building HTTP detection rule."""
        rule = (
            RuleBuilder()
            .alert()
            .http()
            .source_ip("$EXTERNAL_NET")
            .source_port("any")
            .dest_ip("$HOME_NET")
            .dest_port("$HTTP_PORTS")
            .msg("HTTP GET request to admin panel")
            .flow_builder()
            .established()
            .to_server()
            .done()
            .content_builder()
            .pattern(b"GET")
            .http_method()
            .done()
            .content_builder()
            .pattern(b"/admin")
            .http_uri()
            .done()
            .classtype("web-application-attack")
            .sid(1000001)
            .rev(1)
            .build()
        )

        assert rule.action == Action.ALERT
        assert rule.header.protocol == Protocol.HTTP

        # Verify options
        msg_opts = [o for o in rule.options if isinstance(o, MsgOption)]
        assert len(msg_opts) == 1

        flow_opts = [o for o in rule.options if isinstance(o, FlowOption)]
        assert len(flow_opts) == 1

        content_opts = [o for o in rule.options if isinstance(o, ContentOption)]
        assert len(content_opts) == 2

    def test_dns_rule_with_threshold(self) -> None:
        """Test building DNS rule with threshold."""
        rule = (
            RuleBuilder()
            .alert()
            .dns()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(53)
            .msg("DNS query flood")
            .content_builder()
            .pattern(b"evil.com")
            .dns_query()
            .done()
            .threshold_builder()
            .threshold_type("limit")
            .track("by_src")
            .count(10)
            .seconds(60)
            .done()
            .classtype("attempted-dos")
            .priority(1)
            .sid(1000002)
            .rev(1)
            .build()
        )

        assert rule.header.protocol == Protocol.DNS

        thresh_opts = [o for o in rule.options if isinstance(o, ThresholdOption)]
        assert len(thresh_opts) == 1
        assert thresh_opts[0].count == 10

    def test_tls_rule(self) -> None:
        """Test building TLS SNI detection rule."""
        rule = (
            RuleBuilder()
            .alert()
            .tls()
            .source_ip("any")
            .source_port("any")
            .dest_ip("any")
            .dest_port(443)
            .msg("Suspicious TLS SNI")
            .content_builder()
            .pattern(b"malicious.example.com")
            .tls_sni()
            .done()
            .reference("url", "https://example.com/threat-intel")
            .classtype("trojan-activity")
            .sid(1000003)
            .rev(1)
            .build()
        )

        assert rule.header.protocol == Protocol.TLS

        ref_opts = [o for o in rule.options if isinstance(o, ReferenceOption)]
        assert len(ref_opts) == 1
        assert ref_opts[0].ref_type == "url"
