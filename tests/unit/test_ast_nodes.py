# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for AST node definitions and Pydantic validation.

Tests node creation, validation, immutability, and serialization.
NO MOCKS - tests use real Pydantic validation and model behavior.
"""

import json

import pytest
from pydantic import ValidationError

from surinort_ast.core.enums import ContentModifierType
from surinort_ast.core.location import Location, Position, Span
from surinort_ast.core.nodes import (
    Action,
    AddressList,
    AddressVariable,
    AnyAddress,
    AnyPort,
    ContentModifier,
    ContentOption,
    Dialect,
    Direction,
    FlowDirection,
    FlowOption,
    FlowState,
    Header,
    IPAddress,
    IPCIDRRange,
    MetadataOption,
    MsgOption,
    Port,
    PortRange,
    Protocol,
    ReferenceOption,
    RevOption,
    Rule,
    SidOption,
)
from tests.unit._helpers import any_header


class TestNodeCreation:
    """Test AST node creation and validation."""

    def test_create_minimal_rule(self):
        """Create minimal valid rule."""
        header = any_header(dst_port=Port(value=80))

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Test"),
                SidOption(value=1),
            ],
        )

        assert rule.action == Action.ALERT
        assert rule.header.protocol == Protocol.TCP
        assert len(rule.options) == 2
        assert rule.dialect == Dialect.SURICATA  # Default

    def test_node_immutability(self):
        """Nodes should be immutable (frozen)."""
        port = Port(value=80)

        # Assign through a non-literal attribute name: the frozen model must
        # reject it at runtime (the static read-only check is not the point).
        field = "value"
        with pytest.raises((ValidationError, AttributeError)):
            setattr(port, field, 443)

    def test_port_validation(self):
        """Port numbers must be valid."""
        # Valid ports
        Port(value=0)
        Port(value=80)
        Port(value=65535)

        # Invalid ports
        with pytest.raises(ValidationError):
            Port(value=-1)

        with pytest.raises(ValidationError):
            Port(value=99999)

    def test_sid_rev_gid_bounded_to_uint32(self):
        """sid/rev/gid are uint32 in Suricata; the model rejects out-of-range
        values so JSON, protobuf and the model agree instead of crashing the
        protobuf serializer."""
        from surinort_ast.core.nodes import GidOption, RevOption

        # uint32 boundaries are valid.
        SidOption(value=4294967295)
        RevOption(value=4294967295)
        GidOption(value=4294967295)

        # Above uint32 max is rejected.
        for cls in (SidOption, RevOption, GidOption):
            with pytest.raises(ValidationError):
                cls(value=4294967296)

    def test_port_range_validation(self):
        """Port range start must be <= end."""
        # Valid range
        PortRange(start=1024, end=65535)

        # Invalid: end < start
        with pytest.raises(ValidationError):
            PortRange(start=8080, end=80)

    def test_ipv4_cidr_validation(self):
        """IPv4 CIDR can be created with valid prefix."""
        # Valid CIDR
        cidr = IPCIDRRange(network="192.168.1.0", prefix_len=24)
        assert cidr.network == "192.168.1.0"
        assert cidr.prefix_len == 24

    def test_ipv4_cidr_prefix_above_32_rejected(self):
        """An IPv4 network cannot carry a prefix above /32."""
        IPCIDRRange(network="10.0.0.0", prefix_len=32)  # boundary is valid
        with pytest.raises(ValidationError, match="out of range for IPv4"):
            IPCIDRRange(network="10.0.0.0", prefix_len=64)

    def test_ipv6_cidr_validation(self):
        """IPv6 CIDR prefix must be 0-128."""
        # Valid CIDR
        IPCIDRRange(network="2001:db8::", prefix_len=32)

        # Invalid prefix
        with pytest.raises(ValidationError):
            IPCIDRRange(network="2001:db8::", prefix_len=129)

    def test_ip_address_version_must_match_value(self):
        """The version field must agree with the address value."""
        IPAddress(value="192.168.1.1", version=4)
        IPAddress(value="2001:db8::1", version=6)
        IPAddress(value="::ffff:192.168.1.1", version=6)
        with pytest.raises(ValidationError, match="inconsistent"):
            IPAddress(value="192.168.1.1", version=6)
        with pytest.raises(ValidationError, match="inconsistent"):
            IPAddress(value="2001:db8::1", version=4)

    def test_sid_validation(self):
        """SID must be positive integer."""
        # Valid SID
        SidOption(value=1)
        SidOption(value=1000001)

        # Invalid: zero
        with pytest.raises(ValidationError):
            SidOption(value=0)

        # Invalid: negative
        with pytest.raises(ValidationError):
            SidOption(value=-1)

    def test_rev_validation(self):
        """Rev must be positive integer."""
        # Valid rev
        RevOption(value=1)
        RevOption(value=999)

        # Invalid: zero
        with pytest.raises(ValidationError):
            RevOption(value=0)


class TestNodeSerialization:
    """Test Pydantic serialization to dict/JSON."""

    def test_serialize_simple_rule(self):
        """Serialize simple rule to dict."""
        header = any_header(dst_port=Port(value=80))

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Test"),
                SidOption(value=1),
            ],
        )

        # Serialize to dict
        rule_dict = rule.model_dump(mode="json")

        assert rule_dict["action"] == "alert"
        assert rule_dict["header"]["protocol"] == "tcp"
        # Verify dst_port exists (discriminated union serialization may vary)
        assert "dst_port" in rule_dict["header"]
        assert len(rule_dict["options"]) == 2

    def test_json_roundtrip(self):
        """Serialize to JSON and back."""
        header = Header(
            protocol=Protocol.HTTP,
            src_addr=AddressVariable(name="EXTERNAL_NET"),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AddressVariable(name="HOME_NET"),
            dst_port=Port(value=80),
        )

        original_rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="HTTP Attack"),
                SidOption(value=1000001),
                RevOption(value=1),
            ],
        )

        # Serialize to JSON
        json_str = original_rule.model_dump_json()

        # Parse JSON
        parsed_dict = json.loads(json_str)

        # Deserialize
        restored_rule = Rule.model_validate(parsed_dict)

        # Verify equality (field by field since nodes are immutable)
        assert restored_rule.action == original_rule.action
        assert restored_rule.header.protocol == original_rule.header.protocol
        assert len(restored_rule.options) == len(original_rule.options)


class TestContentOption:
    """Test content option with bytes pattern."""

    def test_content_with_ascii(self):
        """Content with ASCII pattern."""
        content = ContentOption(pattern=b"GET")

        assert content.pattern == b"GET"
        assert len(content.modifiers) == 0

    def test_content_with_hex_bytes(self):
        """Content with hex bytes."""
        content = ContentOption(pattern=b"\x48\x65\x6c\x6c\x6f")  # "Hello"

        assert content.pattern == b"Hello"

    def test_content_with_modifiers(self):
        """Content with multiple modifiers."""
        content = ContentOption(
            pattern=b"GET",
            modifiers=[
                ContentModifier(name=ContentModifierType.NOCASE),
                ContentModifier(name=ContentModifierType.DEPTH, value=10),
                ContentModifier(name=ContentModifierType.OFFSET, value=0),
            ],
        )

        assert len(content.modifiers) == 3
        assert content.modifiers[0].name == ContentModifierType.NOCASE
        assert content.modifiers[1].value == 10

    def test_modifier_known_name_string_coerced_to_enum(self):
        """A known-modifier string converges on the enum (the documented
        invariant), so builder/JSON callers match the parser instead of
        serializing the modifier as a custom one."""
        assert ContentModifier(name="nocase").name is ContentModifierType.NOCASE
        assert ContentModifier(name="depth", value=10).name is ContentModifierType.DEPTH

    def test_modifier_unknown_name_stays_string(self):
        """An unrecognized inline modifier keeps its literal name."""
        mod = ContentModifier(name="custom_kw")
        assert mod.name == "custom_kw"
        assert not isinstance(mod.name, ContentModifierType)

    def test_custom_modifier_value_rejects_separators(self):
        """A custom modifier prints as ',<name> <value>', so a comma/semicolon in
        its value would re-split/terminate the option on reparse (no escape)."""
        for bad in ("a,b", "a;b"):
            with pytest.raises(ValidationError):
                ContentModifier(name="custommod", value=bad)

    def test_known_modifier_value_allows_comma(self):
        """fast_pattern:3,7 is faithfully printed, so commas in a known-modifier
        value must stay legal."""
        assert ContentModifier(name="fast_pattern", value="3,7").value == "3,7"

    def test_content_serialization(self):
        """Content option can be created with bytes pattern."""
        content = ContentOption(pattern=b"\x00\x01\x02\xff")

        # Verify the pattern is stored correctly
        assert content.pattern == b"\x00\x01\x02\xff"
        assert len(content.pattern) == 4


class TestUnrepresentableOptionValues:
    """Values that the rule text format cannot represent must be rejected at the
    model boundary, so a builder/JSON-built node cannot print to corrupting text.

    Regression: the printer emitted these structural separators raw, so the
    printed rule re-parsed to a different AST (split metadata entries, truncated
    reference, spilled GenericOption) or failed to parse.
    """

    def test_reference_id_rejects_semicolon(self):
        with pytest.raises(ValidationError):
            ReferenceOption(ref_type="url", ref_id="ex.com/a;b")

    def test_reference_id_allows_comma(self):
        # The id is read to the terminator, so commas (e.g. in URLs) round-trip.
        assert ReferenceOption(ref_type="url", ref_id="ex.com/a,b").ref_id == "ex.com/a,b"

    def test_reference_type_rejects_comma_and_semicolon(self):
        for bad in ("a,b", "a;b"):
            with pytest.raises(ValidationError):
                ReferenceOption(ref_type=bad, ref_id="id")

    def test_metadata_value_rejects_comma_and_semicolon(self):
        for bad in ("Major, Critical", "a;b"):
            with pytest.raises(ValidationError):
                MetadataOption(entries=(("sev", bad),))

    def test_metadata_value_allows_space(self):
        assert MetadataOption(entries=(("k", "a b c"),)).entries[0][1] == "a b c"

    def test_metadata_key_rejects_whitespace_and_separators(self):
        for bad in ("a b", "a,b", "a;b"):
            with pytest.raises(ValidationError):
                MetadataOption(entries=((bad, "v"),))


class TestFlowOption:
    """Test flow option with directions and states."""

    def test_flow_with_directions(self):
        """Flow with direction."""
        flow = FlowOption(
            directions=[FlowDirection.TO_SERVER],
            states=[FlowState.ESTABLISHED],
        )

        assert len(flow.directions) == 1
        assert FlowDirection.TO_SERVER in flow.directions
        assert len(flow.states) == 1
        assert FlowState.ESTABLISHED in flow.states

    def test_flow_multiple_values(self):
        """Flow with multiple directions and states."""
        flow = FlowOption(
            directions=[FlowDirection.TO_SERVER, FlowDirection.TO_CLIENT],
            states=[FlowState.ESTABLISHED, FlowState.NOT_ESTABLISHED],
        )

        assert len(flow.directions) == 2
        assert len(flow.states) == 2


class TestAddressList:
    """Test address list composition."""

    def test_address_list_with_cidr(self):
        """Address list with multiple CIDR blocks."""
        addr_list = AddressList(
            elements=[
                IPCIDRRange(network="192.168.1.0", prefix_len=24),
                IPCIDRRange(network="10.0.0.0", prefix_len=8),
            ]
        )

        assert len(addr_list.elements) == 2
        assert isinstance(addr_list.elements[0], IPCIDRRange)
        assert addr_list.elements[0].network == "192.168.1.0"

    def test_address_list_mixed_types(self):
        """Address list with mixed address types."""
        addr_list = AddressList(
            elements=[
                IPAddress(value="192.168.1.1", version=4),
                IPCIDRRange(network="10.0.0.0", prefix_len=8),
                AddressVariable(name="HOME_NET"),
            ]
        )

        assert len(addr_list.elements) == 3
        assert isinstance(addr_list.elements[0], IPAddress)
        assert isinstance(addr_list.elements[1], IPCIDRRange)
        assert isinstance(addr_list.elements[2], AddressVariable)


class TestLocation:
    """Test location tracking."""

    def test_create_location(self):
        """Create location with span."""
        start = Position(line=1, column=1, offset=0)
        end = Position(line=1, column=50, offset=49)
        span = Span(start=start, end=end)
        location = Location(span=span, file_path="/path/to/rules.rules")

        assert location.span.start.line == 1
        assert location.span.end.column == 50
        assert location.file_path == "/path/to/rules.rules"

    def test_node_with_location(self):
        """Node can have location."""
        start = Position(line=1, column=1, offset=0)
        end = Position(line=1, column=10, offset=9)
        span = Span(start=start, end=end)
        location = Location(span=span)

        port = Port(value=80, location=location)

        assert port.location is not None
        assert port.location.span.start.line == 1


class TestNodeProperties:
    """Test node properties and methods."""

    def test_node_type_property(self):
        """All nodes have node_type property."""
        port = Port(value=80)
        assert port.node_type == "Port"

        addr = AnyAddress()
        assert addr.node_type == "AnyAddress"

        msg = MsgOption(text="Test")
        assert msg.node_type == "MsgOption"

    def test_comments_field(self):
        """Nodes can store comments."""
        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=Port(value=80),
            comments=["This is a comment", "Another comment"],
        )

        assert len(header.comments) == 2
        assert "This is a comment" in header.comments


class TestModelCopy:
    """Test Pydantic model_copy for creating modified nodes."""

    def test_modify_port_value(self):
        """Create new node with modified value."""
        original = Port(value=80)
        modified = original.model_copy(update={"value": 443})

        # Original unchanged
        assert original.value == 80

        # Modified has new value
        assert modified.value == 443

    def test_modify_rule_action(self):
        """Modify rule action."""
        header = any_header(dst_port=Port(value=80))

        original = Rule(
            action=Action.ALERT,
            header=header,
            options=[],
        )

        modified = original.model_copy(update={"action": Action.DROP})

        assert original.action == Action.ALERT
        assert modified.action == Action.DROP


class TestStrictValidation:
    """Test strict validation (extra fields forbidden)."""

    def test_extra_fields_forbidden(self):
        """Extra fields should be rejected."""
        with pytest.raises(ValidationError):
            Port(value=80, extra_field="not allowed")  # type: ignore

    def test_wrong_field_type(self):
        """Wrong field types should be rejected."""
        with pytest.raises(ValidationError):
            Port(value="not_a_number")


class TestNodeImmutabilityAndHashing:
    """Frozen AST nodes must be hashable and reject in-place sequence mutation."""

    def _rule(self):
        from surinort_ast import parse_rule

        return parse_rule(
            "alert tcp [1.1.1.1,2.2.2.2] any -> any 80 "
            '(content:"x"; nocase; flowbits:set,a; sid:1;)'
        )

    def test_leaf_node_hashable(self):
        from surinort_ast.core.nodes import SidOption

        assert len({SidOption(value=1), SidOption(value=1)}) == 1

    def test_full_rule_hashable_and_equal_rules_share_hash(self):
        a = self._rule()
        b = self._rule()
        assert a == b
        assert hash(a) == hash(b)
        assert len({a, b}) == 1

    def test_sequence_fields_are_tuples(self):
        rule = self._rule()
        assert isinstance(rule.options, tuple)
        assert isinstance(rule.diagnostics, tuple)
        assert isinstance(rule.header.src_addr.elements, tuple)

    def test_sequence_fields_reject_in_place_mutation(self):
        from surinort_ast.core.nodes import AnyAddress

        node = AnyAddress()
        with pytest.raises(AttributeError):
            node.comments.append("x")
