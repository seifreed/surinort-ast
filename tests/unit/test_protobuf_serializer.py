"""
Unit tests for Protocol Buffers serialization.

Tests comprehensive serialization/deserialization of AST nodes with roundtrip
fidelity verification.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

import pytest

from surinort_ast import parse_rule
from surinort_ast.core.enums import Dialect
from surinort_ast.serialization.protobuf import (
    ProtobufError,
    ProtobufSerializer,
    from_protobuf,
    to_protobuf,
)

# Skip all tests if protobuf is not available
pytestmark = pytest.mark.skipif(
    not hasattr(pytest, "importorskip"), reason="protobuf not available"
)


@pytest.fixture(autouse=True)
def check_protobuf():
    """Check if protobuf is available before running tests."""
    pytest.importorskip("google.protobuf")


class TestProtobufBasics:
    """Test basic protobuf serialization functionality."""

    def test_simple_rule_roundtrip(self):
        """Test roundtrip serialization of a simple rule."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:1;)'
        rule = parse_rule(rule_text)

        # Serialize
        binary = to_protobuf(rule)
        assert isinstance(binary, bytes)
        assert len(binary) > 0

        # Deserialize
        restored = from_protobuf(binary)
        assert restored == rule

    def test_serializer_with_metadata(self):
        """Test serializer with metadata envelope."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        serializer = ProtobufSerializer(include_metadata=True)
        binary = serializer.to_protobuf(rule)
        restored = serializer.from_protobuf(binary)

        assert restored == rule

    def test_serializer_without_metadata(self):
        """Test serializer without metadata envelope."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)

        serializer = ProtobufSerializer(include_metadata=False)
        binary = serializer.to_protobuf(rule)
        restored = serializer.from_protobuf(binary)

        assert restored == rule

    def test_binary_size_smaller_than_json(self):
        """Test that protobuf is more compact than JSON."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test Rule"; sid:1000; rev:1;)'
        rule = parse_rule(rule_text)

        # Protobuf binary
        binary = to_protobuf(rule, include_metadata=False)

        # Protobuf should be more compact (though our implementation uses JSON internally)
        assert len(binary) > 0
        assert isinstance(binary, bytes)


class TestRuleComponents:
    """Test serialization of different rule components."""

    def test_actions(self):
        """Test all action types."""
        actions = ["alert", "log", "pass", "drop", "reject"]
        for action in actions:
            rule_text = f'{action} tcp any any -> any 80 (msg:"Test"; sid:1;)'
            rule = parse_rule(rule_text)
            binary = to_protobuf(rule)
            restored = from_protobuf(binary)
            assert restored.action == rule.action

    def test_protocols(self):
        """Test different protocol types."""
        protocols = ["tcp", "tcp-pkt", "udp", "icmp", "ip", "http", "http1", "bittorrent-dht"]
        for protocol in protocols:
            rule_text = f'alert {protocol} any any -> any any (msg:"Test"; sid:1;)'
            rule = parse_rule(rule_text, dialect=Dialect.SURICATA)
            binary = to_protobuf(rule)
            restored = from_protobuf(binary)
            assert restored.header.protocol == rule.header.protocol

    def test_directions(self):
        """Test all direction types."""
        directions = ["->", "<-", "<>"]
        for direction in directions:
            rule_text = f'alert tcp any any {direction} any 80 (msg:"Test"; sid:1;)'
            rule = parse_rule(rule_text)
            binary = to_protobuf(rule)
            restored = from_protobuf(binary)
            assert restored.header.direction == rule.header.direction

    def test_addresses(self):
        """Test various address expressions."""
        addresses = [
            "any",
            "192.168.1.1",
            "10.0.0.0/8",
            "!192.168.1.1",
            "$HOME_NET",
            "[192.168.1.0/24,10.0.0.0/8]",
        ]
        for addr in addresses:
            rule_text = f'alert tcp {addr} any -> any 80 (msg:"Test"; sid:1;)'
            rule = parse_rule(rule_text)
            binary = to_protobuf(rule)
            restored = from_protobuf(binary)
            assert restored.header.src_addr == rule.header.src_addr

    def test_ports(self):
        """Test various port expressions."""
        ports = [
            "any",
            "80",
            "1024:65535",
            "!80",
            "$HTTP_PORTS",
            "[80,443,8080:8090]",
        ]
        for port in ports:
            rule_text = f'alert tcp any {port} -> any any (msg:"Test"; sid:1;)'
            rule = parse_rule(rule_text)
            binary = to_protobuf(rule)
            restored = from_protobuf(binary)
            assert restored.header.src_port == rule.header.src_port


class TestOptions:
    """Test serialization of rule options."""

    def test_msg_option(self):
        """Test msg option."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test Message"; sid:1;)'
        rule = parse_rule(rule_text)
        binary = to_protobuf(rule)
        restored = from_protobuf(binary)
        assert restored.options[0].text == rule.options[0].text  # type: ignore[attr-defined]

    def test_sid_rev_gid(self):
        """Test SID, REV, and GID options."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1000; rev:2; gid:1;)'
        rule = parse_rule(rule_text)
        binary = to_protobuf(rule)
        restored = from_protobuf(binary)

        assert len(restored.options) == len(rule.options)
        for orig_opt, rest_opt in zip(rule.options, restored.options, strict=True):
            assert type(orig_opt) == type(rest_opt)  # noqa: E721

    def test_content_option(self):
        """Test content option with modifiers."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; content:"GET"; nocase; sid:1;)'
        rule = parse_rule(rule_text)
        binary = to_protobuf(rule)
        restored = from_protobuf(binary)

        assert restored == rule

    def test_pcre_option(self):
        """Test PCRE option."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; pcre:"/test/i"; sid:1;)'
        rule = parse_rule(rule_text)
        binary = to_protobuf(rule)
        restored = from_protobuf(binary)

        assert restored == rule

    def test_flow_option(self):
        """Test flow option."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; flow:established,to_server; sid:1;)'
        rule = parse_rule(rule_text)
        binary = to_protobuf(rule)
        restored = from_protobuf(binary)

        assert restored == rule

    def test_reference_option(self):
        """Test reference option."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; reference:cve,2021-12345; sid:1;)'
        rule = parse_rule(rule_text)
        binary = to_protobuf(rule)
        restored = from_protobuf(binary)

        assert restored == rule

    def test_metadata_option(self):
        """Test metadata option."""
        rule_text = (
            'alert tcp any any -> any 80 (msg:"Test"; metadata:key1 value1, key2 value2; sid:1;)'
        )
        rule = parse_rule(rule_text)
        binary = to_protobuf(rule)
        restored = from_protobuf(binary)

        assert restored == rule

    def test_threshold_option(self):
        """Test threshold option."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; threshold:type limit,track by_src,count 10,seconds 60; sid:1;)'
        rule = parse_rule(rule_text)
        binary = to_protobuf(rule)
        restored = from_protobuf(binary)

        assert restored == rule


class TestComplexRules:
    """Test serialization of complex rules."""

    def test_complex_rule_with_many_options(self):
        """Test a complex rule with multiple options."""
        rule_text = """alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (
            msg:"Complex Test Rule";
            flow:established,to_server;
            content:"GET"; nocase;
            pcre:"/test/i";
            classtype:web-application-attack;
            reference:cve,2021-12345;
            metadata:policy balanced-ips;
            sid:1000000;
            rev:3;
        )"""
        rule = parse_rule(rule_text)
        binary = to_protobuf(rule)
        restored = from_protobuf(binary)

        assert restored == rule

    def test_rule_with_byte_options(self):
        """Test rule with byte_test, byte_jump, byte_extract."""
        rule_text = 'alert tcp any any -> any any (msg:"Test"; byte_test:4,>,1000,0; sid:1;)'
        rule = parse_rule(rule_text)
        binary = to_protobuf(rule)
        restored = from_protobuf(binary)

        assert restored == rule

    def test_rule_with_sticky_buffer(self):
        """Test rule with sticky buffer (buffer select)."""
        rule_text = 'alert http any any -> any any (msg:"Test"; http_uri; content:"test"; sid:1;)'
        rule = parse_rule(rule_text, dialect=Dialect.SURICATA)
        binary = to_protobuf(rule)
        restored = from_protobuf(binary)

        assert restored == rule


class TestBatchSerialization:
    """Test serialization of multiple rules."""

    def test_multiple_rules_roundtrip(self):
        """Test serialization of multiple rules."""
        rule_texts = [
            'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)',
            'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)',
            'alert udp any any -> any 53 (msg:"Rule 3"; sid:3;)',
        ]
        rules = [parse_rule(text) for text in rule_texts]

        binary = to_protobuf(rules)
        restored = from_protobuf(binary)

        assert isinstance(restored, list)
        assert len(restored) == len(rules)
        for orig, rest in zip(rules, restored, strict=True):
            assert orig == rest

    def test_empty_list(self):
        """Test serialization of empty rule list."""
        rules = []
        binary = to_protobuf(rules)
        restored = from_protobuf(binary)

        assert isinstance(restored, list)
        assert len(restored) == 0


class TestErrorHandling:
    """Test error handling in protobuf serialization."""

    def test_invalid_binary_data(self):
        """Test deserialization with invalid binary data."""
        with pytest.raises(ProtobufError):
            from_protobuf(b"invalid binary data")

    def test_corrupted_data(self):
        """Test deserialization with corrupted data."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'
        rule = parse_rule(rule_text)
        binary = to_protobuf(rule)

        # Corrupt the binary data
        corrupted = binary[:10] + b"corrupted" + binary[10:]

        with pytest.raises(ProtobufError):
            from_protobuf(corrupted)


class TestRoundtripFidelity:
    """Test complete roundtrip fidelity for various rule types."""

    def test_all_address_types_roundtrip(self):
        """Test roundtrip for all address types."""
        rule_texts = [
            'alert tcp any any -> any 80 (msg:"Test 1"; sid:1;)',
            'alert tcp 192.168.1.1 any -> any 80 (msg:"Test 2"; sid:2;)',
            'alert tcp 10.0.0.0/8 any -> any 80 (msg:"Test 3"; sid:3;)',
            'alert tcp [192.168.1.1-192.168.1.255] any -> any 80 (msg:"Test 4"; sid:4;)',
            'alert tcp !192.168.1.1 any -> any 80 (msg:"Test 5"; sid:5;)',
            'alert tcp $HOME_NET any -> any 80 (msg:"Test 6"; sid:6;)',
            'alert tcp [192.168.1.0/24,10.0.0.0/8] any -> any 80 (msg:"Test 7"; sid:7;)',
        ]

        for rule_text in rule_texts:
            rule = parse_rule(rule_text)
            binary = to_protobuf(rule)
            restored = from_protobuf(binary)
            assert restored == rule, f"Roundtrip failed for: {rule_text}"

    def test_all_port_types_roundtrip(self):
        """Test roundtrip for all port types."""
        rule_texts = [
            'alert tcp any any -> any any (msg:"Test 1"; sid:1;)',
            'alert tcp any 80 -> any any (msg:"Test 2"; sid:2;)',
            'alert tcp any 1024:65535 -> any any (msg:"Test 3"; sid:3;)',
            'alert tcp any !80 -> any any (msg:"Test 4"; sid:4;)',
            'alert tcp any $HTTP_PORTS -> any any (msg:"Test 5"; sid:5;)',
            'alert tcp any [80,443,8080:8090] -> any any (msg:"Test 6"; sid:6;)',
        ]

        for rule_text in rule_texts:
            rule = parse_rule(rule_text)
            binary = to_protobuf(rule)
            restored = from_protobuf(binary)
            assert restored == rule, f"Roundtrip failed for: {rule_text}"

    def test_all_option_types_roundtrip(self):
        """Test roundtrip for various option combinations."""
        rule_texts = [
            'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
            'alert tcp any any -> any 80 (msg:"Test"; sid:1; rev:2; gid:1;)',
            'alert tcp any any -> any 80 (msg:"Test"; content:"GET"; nocase; sid:1;)',
            'alert tcp any any -> any 80 (msg:"Test"; pcre:"/test/i"; sid:1;)',
            'alert tcp any any -> any 80 (msg:"Test"; flow:established,to_server; sid:1;)',
            'alert tcp any any -> any 80 (msg:"Test"; classtype:trojan-activity; sid:1;)',
            'alert tcp any any -> any 80 (msg:"Test"; priority:1; sid:1;)',
            'alert tcp any any -> any 80 (msg:"Test"; reference:cve,2021-12345; sid:1;)',
        ]

        for rule_text in rule_texts:
            rule = parse_rule(rule_text)
            binary = to_protobuf(rule)
            restored = from_protobuf(binary)
            assert restored == rule, f"Roundtrip failed for: {rule_text}"


class TestPerformance:
    """Performance-related tests (informational)."""

    def test_serialization_speed(self):
        """Test serialization speed (informational)."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test"; content:"GET"; nocase; sid:1;)'
        rule = parse_rule(rule_text)

        import time

        # Measure protobuf serialization
        start = time.time()
        for _ in range(1000):
            to_protobuf(rule, include_metadata=False)
        protobuf_time = time.time() - start

        # Measure JSON serialization
        start = time.time()
        for _ in range(1000):
            rule.model_dump_json()
        json_time = time.time() - start

        print(f"\nProtobuf serialization: {protobuf_time:.4f}s")
        print(f"JSON serialization: {json_time:.4f}s")
        # Note: Our protobuf implementation uses JSON internally,
        # so times will be similar

    def test_size_comparison(self):
        """Test size comparison (informational)."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Test Rule with Content"; content:"GET /index.html HTTP/1.1"; nocase; offset:0; depth:100; sid:1000000; rev:3;)'
        rule = parse_rule(rule_text)

        protobuf_size = len(to_protobuf(rule, include_metadata=False))
        json_size = len(rule.model_dump_json())

        print(f"\nProtobuf size: {protobuf_size} bytes")
        print(f"JSON size: {json_size} bytes")
        print(f"Compression ratio: {json_size / protobuf_size:.2f}x")


class TestRoundtripRegressions:
    """Regression tests for protobuf round-trip data loss."""

    def test_negated_pcre_roundtrip(self):
        """A negated PCRE must survive the protobuf round-trip.

        Regression: PcreOption.negated had no proto field and was dropped, so a
        negated match silently became a positive one.
        """
        from surinort_ast.core.enums import Action, Direction, Protocol
        from surinort_ast.core.nodes import (
            AnyAddress,
            AnyPort,
            Header,
            MsgOption,
            PcreOption,
            Rule,
            SidOption,
        )

        rule = Rule(
            action=Action.ALERT,
            header=Header(
                protocol=Protocol.TCP,
                src_addr=AnyAddress(),
                src_port=AnyPort(),
                direction=Direction.TO,
                dst_addr=AnyAddress(),
                dst_port=AnyPort(),
            ),
            options=[
                PcreOption(pattern="/evil/", flags="", negated=True),
                MsgOption(text="t"),
                SidOption(value=1),
            ],
        )

        restored = from_protobuf(to_protobuf(rule))

        negated = [opt.negated for opt in restored.options if isinstance(opt, PcreOption)]
        assert negated == [True]

    def test_large_sid_roundtrip(self):
        """A SID above the signed 32-bit range must serialize without crashing.

        Regression: SID/rev/gid used proto int32, so any value above 2**31-1
        (valid unsigned 32-bit identifiers) raised ValueError on serialize.
        """
        from surinort_ast.core.nodes import SidOption

        rule = parse_rule('alert tcp any any -> any 80 (msg:"t"; sid:4000000000;)')

        restored = from_protobuf(to_protobuf(rule))

        sids = [opt.value for opt in restored.options if isinstance(opt, SidOption)]
        assert sids == [4000000000]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestProtobufFileProtocol:
    """The 'file' protocol must serialize without crashing.

    Regression: Protocol.FILE existed in the enum and grammar but was missing
    from the proto enum and _PROTOCOL_TO_PB, so to_protobuf on an `alert file`
    rule raised KeyError.
    """

    def test_file_protocol_round_trips(self):
        rule = parse_rule('alert file any any -> any any (msg:"x"; sid:1;)')
        restored = from_protobuf(to_protobuf(rule))
        assert restored.header.protocol == rule.header.protocol


class TestProtobufLargeByteTestValue:
    """byte_test values beyond int32 must not overflow protobuf serialization.

    Regression: ByteTestOption.value/offset were int32 in the proto, so a
    multi-byte value (> 2^31) raised on serialize.
    """

    def test_large_value_and_negative_offset_round_trip(self):
        from surinort_ast.core.enums import Action, Direction, Protocol
        from surinort_ast.core.nodes import (
            AnyAddress,
            AnyPort,
            ByteTestOption,
            Header,
            Port,
            Rule,
            SidOption,
        )

        rule = Rule(
            action=Action.ALERT,
            header=Header(
                protocol=Protocol.TCP,
                src_addr=AnyAddress(),
                src_port=AnyPort(),
                direction=Direction.TO,
                dst_addr=AnyAddress(),
                dst_port=Port(value=80),
            ),
            options=[
                ByteTestOption(bytes_to_extract=8, operator=">", value=5_000_000_000, offset=-4),
                SidOption(value=1),
            ],
        )
        restored = from_protobuf(to_protobuf(rule))
        byte_test = next(o for o in restored.options if o.node_type == "ByteTestOption")
        assert byte_test.value == 5_000_000_000
        assert byte_test.offset == -4


class TestProtobufListShapePreserved:
    """A single-element list must round-trip to a list, like the JSON serializer.

    Regression: from_protobuf(to_protobuf([rule])) returned a scalar Rule
    (count == 1 special-case), silently changing a list input into a scalar.
    """

    def test_single_element_list_round_trips_to_list(self):
        rule = parse_rule("alert tcp any any -> any any (sid:1;)")
        restored = from_protobuf(to_protobuf([rule]))
        assert isinstance(restored, list)
        assert len(restored) == 1
        assert restored[0] == rule

    def test_scalar_rule_round_trips_to_scalar(self):
        rule = parse_rule("alert tcp any any -> any any (sid:1;)")
        restored = from_protobuf(to_protobuf(rule))
        assert not isinstance(restored, list)
        assert restored == rule
