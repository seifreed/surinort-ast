# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Comprehensive unit tests for transformer.py to achieve 100% coverage.

Tests all helper functions, protocol transformers, option transformers,
content modifiers, and edge cases using real code execution.
NO MOCKS - all tests use actual transformer execution with real parse trees.
"""

from lark import Token, Tree

from surinort_ast.core.diagnostics import DiagnosticLevel
from surinort_ast.core.enums import (
    ContentModifierType,
    FlowDirection,
    FlowState,
    Protocol,
)
from surinort_ast.core.location import Location, Position, Span
from surinort_ast.core.nodes import (
    AddressVariable,
    ContentModifier,
    ContentOption,
    FastPatternOption,
    FilestoreOption,
    FlowOption,
    GenericOption,
    IPAddress,
    IPCIDRRange,
    IPRange,
    Port,
    PortRange,
    PortVariable,
    PriorityOption,
    RawbytesOption,
    RevOption,
    SidOption,
)
from surinort_ast.parsing.transformer import (
    RuleTransformer,
    parse_hex_string,
    parse_pcre_pattern,
    parse_quoted_string,
    token_to_location,
)


def make_token(type_: str, value: str, line: int = 1, column: int = 0) -> Token:
    """Helper to create a complete Token with all required attributes."""
    token = Token(
        type_, value, line=line, column=column, start_pos=column, end_pos=column + len(str(value))
    )
    token.end_line = line
    token.end_column = column + len(str(value))
    return token


class TestHelperFunctions:
    """Test all helper functions with real data."""

    def test_token_to_location_basic(self):
        """Test token_to_location with basic token."""
        token = Token("WORD", "test", line=1, column=0, start_pos=0, end_pos=4)
        token.end_line = 1
        token.end_column = 4

        location = token_to_location(token, file_path="/test/file.rules")

        assert location.file_path == "/test/file.rules"
        assert location.span.start.line == 1
        assert location.span.start.column == 1  # 0-indexed to 1-indexed
        assert location.span.start.offset == 0
        assert location.span.end.line == 1
        assert location.span.end.column == 5  # 0-indexed to 1-indexed
        assert location.span.end.offset == 4

    def test_token_to_location_multiline(self):
        """Test token_to_location with multi-line token."""
        token = Token("STRING", "test\nvalue", line=2, column=5, start_pos=10, end_pos=20)
        token.end_line = 3
        token.end_column = 5

        location = token_to_location(token)

        assert location.span.start.line == 2
        assert location.span.start.column == 6  # column+1
        assert location.span.end.line == 3
        assert location.span.end.column == 6  # end_column+1

    def test_parse_quoted_string_double_quotes(self):
        """Test parse_quoted_string with double quotes."""
        result = parse_quoted_string('"Hello World"')
        assert result == "Hello World"

    def test_parse_quoted_string_single_quotes(self):
        """Test parse_quoted_string with single quotes."""
        result = parse_quoted_string("'Hello World'")
        assert result == "Hello World"

    def test_parse_quoted_string_with_escapes(self):
        """Test parse_quoted_string with escape sequences."""
        result = parse_quoted_string('"Hello \\"World\\" \\n\\r\\t\\\\ test"')
        assert result == 'Hello "World" \n\r\t\\ test'

    def test_parse_quoted_string_empty(self):
        """Test parse_quoted_string with empty string."""
        result = parse_quoted_string('""')
        assert result == ""

    def test_parse_quoted_string_short(self):
        """Test parse_quoted_string with string too short."""
        result = parse_quoted_string('"')
        assert result == '"'

    def test_parse_quoted_string_no_quotes(self):
        """Test parse_quoted_string with unquoted string."""
        result = parse_quoted_string("Hello")
        assert result == "Hello"

    def test_parse_hex_string_valid(self):
        """Test parse_hex_string with valid hex."""
        result = parse_hex_string("|48 65 6c 6c 6f|")
        assert result == b"Hello"

    def test_parse_hex_string_no_spaces(self):
        """Test parse_hex_string without spaces."""
        result = parse_hex_string("|48656c6c6f|")
        assert result == b"Hello"

    def test_parse_hex_string_with_whitespace(self):
        """Test parse_hex_string with newlines and tabs."""
        result = parse_hex_string("|48 65\n6c\r6c\t6f|")
        assert result == b"Hello"

    def test_parse_hex_string_invalid(self):
        """Test parse_hex_string with invalid hex characters."""
        result = parse_hex_string("|ZZ|")
        assert result == b""

    def test_parse_hex_string_empty(self):
        """Test parse_hex_string with empty content."""
        result = parse_hex_string("||")
        assert result == b""

    def test_parse_pcre_pattern_with_flags(self):
        """Test parse_pcre_pattern with pattern and flags."""
        pattern, flags = parse_pcre_pattern("/test.*pattern/ims")
        assert pattern == "test.*pattern"
        assert flags == "ims"

    def test_parse_pcre_pattern_no_flags(self):
        """Test parse_pcre_pattern without flags."""
        pattern, flags = parse_pcre_pattern("/test.*pattern/")
        assert pattern == "test.*pattern"
        assert flags == ""

    def test_parse_pcre_pattern_all_flags(self):
        """Test parse_pcre_pattern with all possible flags."""
        pattern, flags = parse_pcre_pattern("/pattern/imsxAEGRUB")
        assert pattern == "pattern"
        assert flags == "imsxAEGRUB"

    def test_parse_pcre_pattern_no_delimiters(self):
        """Test parse_pcre_pattern without delimiters (fallback)."""
        pattern, flags = parse_pcre_pattern("plain_pattern")
        assert pattern == "plain_pattern"
        assert flags == ""


class TestAllProtocolTransformers:
    """Test all protocol transformer methods."""

    def test_http2_protocol(self):
        """Test http2 protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.http2([])
        assert result == Protocol.HTTP2

    def test_ftp_data_protocol(self):
        """Test ftp_data protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.ftp_data([])
        assert result == Protocol.FTP_DATA

    def test_smb_protocol(self):
        """Test smb protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.smb([])
        assert result == Protocol.SMB

    def test_smtp_protocol(self):
        """Test smtp protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.smtp([])
        assert result == Protocol.SMTP

    def test_imap_protocol(self):
        """Test imap protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.imap([])
        assert result == Protocol.IMAP

    def test_dcerpc_protocol(self):
        """Test dcerpc protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.dcerpc([])
        assert result == Protocol.DCERPC

    def test_dhcp_protocol(self):
        """Test dhcp protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.dhcp([])
        assert result == Protocol.DHCP

    def test_nfs_protocol(self):
        """Test nfs protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.nfs([])
        assert result == Protocol.NFS

    def test_sip_protocol(self):
        """Test sip protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.sip([])
        assert result == Protocol.SIP

    def test_rdp_protocol(self):
        """Test rdp protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.rdp([])
        assert result == Protocol.RDP

    def test_mqtt_protocol(self):
        """Test mqtt protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.mqtt([])
        assert result == Protocol.MQTT

    def test_modbus_protocol(self):
        """Test modbus protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.modbus([])
        assert result == Protocol.MODBUS

    def test_dnp3_protocol(self):
        """Test dnp3 protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.dnp3([])
        assert result == Protocol.DNP3

    def test_enip_protocol(self):
        """Test enip protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.enip([])
        assert result == Protocol.ENIP

    def test_ike_protocol(self):
        """Test ike protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.ike([])
        assert result == Protocol.IKE

    def test_krb5_protocol(self):
        """Test krb5 protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.krb5([])
        assert result == Protocol.KRB5

    def test_ntp_protocol(self):
        """Test ntp protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.ntp([])
        assert result == Protocol.NTP

    def test_snmp_protocol(self):
        """Test snmp protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.snmp([])
        assert result == Protocol.SNMP

    def test_tftp_protocol(self):
        """Test tftp protocol transformer."""
        transformer = RuleTransformer()
        result = transformer.tftp([])
        assert result == Protocol.TFTP


class TestAddressTransformers:
    """Test address transformation methods."""

    def test_address_var_with_dollar(self):
        """Test address_var transformer with $ prefix."""
        transformer = RuleTransformer(file_path="/test/rules")
        token = make_token("VAR", "$HOME_NET")

        result = transformer.address_var(token)

        assert isinstance(result, AddressVariable)
        assert result.name == "HOME_NET"

    def test_ipv4_cidr_valid_range(self):
        """Test ipv4_cidr with valid prefix length."""
        transformer = RuleTransformer()
        ip_token = make_token("IPV4", "192.168.1.0")
        prefix_token = make_token("INT", "24", column=12)

        result = transformer.ipv4_cidr(ip_token, prefix_token)

        assert isinstance(result, IPCIDRRange)
        assert result.prefix_len == 24
        assert result.network == "192.168.1.0"

    def test_ipv6_cidr_valid_range(self):
        """Test ipv6_cidr with valid prefix length."""
        transformer = RuleTransformer()
        ip_token = make_token("IPV6", "2001:db8::")
        prefix_token = make_token("INT", "64", column=12)

        result = transformer.ipv6_cidr(ip_token, prefix_token)

        assert isinstance(result, IPCIDRRange)
        assert result.prefix_len == 64
        assert result.network == "2001:db8::"

    def test_address_range_with_ip_addresses(self):
        """Test address_range with IPAddress objects."""
        transformer = RuleTransformer()
        start = IPAddress(value="192.168.1.1", version=4)
        end = IPAddress(value="192.168.1.254", version=4)

        result = transformer.address_range(start, end)

        assert isinstance(result, IPRange)
        assert result.start == "192.168.1.1"
        assert result.end == "192.168.1.254"

    def test_address_range_with_tokens(self):
        """Test address_range with raw tokens."""
        transformer = RuleTransformer()
        start = "10.0.0.1"
        end = "10.0.0.255"

        result = transformer.address_range(start, end)

        assert isinstance(result, IPRange)
        assert result.start == "10.0.0.1"
        assert result.end == "10.0.0.255"


class TestPortTransformers:
    """Test port transformation methods."""

    def test_port_var_with_dollar(self):
        """Test port_var transformer with $ prefix."""
        transformer = RuleTransformer(file_path="/test/rules")
        token = make_token("VAR", "$HTTP_PORTS")

        result = transformer.port_var(token)

        assert isinstance(result, PortVariable)
        assert result.name == "HTTP_PORTS"

    def test_port_range_open_ended(self):
        """Test port_range with open-ended range (e.g., 1024:)."""
        transformer = RuleTransformer()
        start_token = make_token("INT", "1024")

        result = transformer.port_range([start_token])

        assert isinstance(result, PortRange)
        assert result.start == 1024
        assert result.end == 65535  # Default max port

    def test_port_range_with_both_ends(self):
        """Test port_range with both start and end."""
        transformer = RuleTransformer()
        start_token = make_token("INT", "80")
        end_token = make_token("INT", "443")

        result = transformer.port_range([start_token, end_token])

        assert isinstance(result, PortRange)
        assert result.start == 80
        assert result.end == 443

    def test_port_range_valid(self):
        """Test port_range with valid range."""
        transformer = RuleTransformer()
        start_token = make_token("INT", "8000")
        end_token = make_token("INT", "9000")

        result = transformer.port_range([start_token, end_token])

        assert isinstance(result, PortRange)
        assert result.start == 8000
        assert result.end == 9000

    def test_port_single_valid(self):
        """Test port_single with valid port."""
        transformer = RuleTransformer()
        port_token = make_token("INT", "443")

        result = transformer.port_single(port_token)

        assert isinstance(result, Port)
        assert result.value == 443

    def test_port_elem(self):
        """Test port_elem passthrough."""
        transformer = RuleTransformer()
        port = Port(value=80)

        result = transformer.port_elem([port])

        assert result is port

    def test_port_elem_empty(self):
        """Test port_elem with empty list."""
        transformer = RuleTransformer()

        result = transformer.port_elem([])

        assert result is None


class TestOptionTransformers:
    """Test option transformation methods."""

    def test_sid_option_valid(self):
        """Test sid_option with valid SID."""
        transformer = RuleTransformer()
        sid_token = make_token("INT", "1000001")

        result = transformer.sid_option(sid_token)

        assert isinstance(result, SidOption)
        assert result.value == 1000001

    def test_rev_option_valid(self):
        """Test rev_option with valid rev."""
        transformer = RuleTransformer()
        rev_token = make_token("INT", "3")

        result = transformer.rev_option(rev_token)

        assert isinstance(result, RevOption)
        assert result.value == 3

    def test_priority_option_valid(self):
        """Test priority_option with valid priority."""
        transformer = RuleTransformer()
        priority_token = make_token("INT", "2")

        result = transformer.priority_option(priority_token)

        assert isinstance(result, PriorityOption)
        assert result.value == 2

    def test_reference_id(self):
        """Test reference_id extraction."""
        transformer = RuleTransformer()
        token = Token("WORD", "CVE-2021-12345")

        result = transformer.reference_id([token])

        assert result == "CVE-2021-12345"

    def test_reference_id_empty(self):
        """Test reference_id with empty list."""
        transformer = RuleTransformer()

        result = transformer.reference_id([])

        assert result == ""

    def test_metadata_entry_empty(self):
        """Test metadata_entry with no items."""
        transformer = RuleTransformer()

        result = transformer.metadata_entry([])

        assert result == ("", "")

    def test_metadata_entry_with_tree(self):
        """Test metadata_entry with Tree objects."""
        transformer = RuleTransformer()
        token = Token("WORD", "value1")
        tree = Tree("metadata_word", [token])
        key_token = Token("WORD", "key")

        result = transformer.metadata_entry([key_token, tree])

        assert result == ("key", "value1")

    def test_metadata_entry_no_values(self):
        """Test metadata_entry when values extraction fails."""
        transformer = RuleTransformer()
        tree_without_children = Tree("metadata_word", [])

        result = transformer.metadata_entry([tree_without_children])

        assert result == ("", "")

    def test_uricontent_option(self):
        """Test uricontent_option generates deprecation warning."""
        transformer = RuleTransformer()
        Token("QUOTED_STRING", '"test"')
        content_value = b"test"

        result = transformer.uricontent_option(content_value)

        assert isinstance(result, ContentOption)
        assert result.pattern == b"test"
        assert len(transformer.diagnostics) == 1
        assert "deprecated" in transformer.diagnostics[0].message

    def test_flow_option_valid_values(self):
        """Test flow_option with valid flow values."""
        transformer = RuleTransformer()
        token1 = make_token("WORD", "established")
        token2 = make_token("WORD", "to_server")

        result = transformer.flow_option([token1, token2])

        assert isinstance(result, FlowOption)
        assert FlowState.ESTABLISHED in result.states
        assert FlowDirection.TO_SERVER in result.directions

    def test_flow_value(self):
        """Test flow_value extraction."""
        transformer = RuleTransformer()
        token = Token("WORD", "established")

        result = transformer.flow_value([token])

        assert result is token

    def test_flow_value_empty(self):
        """Test flow_value with empty list."""
        transformer = RuleTransformer()

        result = transformer.flow_value([])

        assert isinstance(result, Token)
        assert result.value == ""

    def test_flowbits_action(self):
        """Test flowbits_action passthrough."""
        transformer = RuleTransformer()
        tokens = [Token("WORD", "set"), Token("WORD", "flag")]

        result = transformer.flowbits_action(tokens)

        assert result is tokens


class TestContentModifiers:
    """Test content modifier transformers."""

    def test_cm_depth(self):
        """Test cm_depth content modifier."""
        transformer = RuleTransformer()
        kw = Token("WORD", "depth")
        val = Token("INT", "10")

        result = transformer.cm_depth([kw, val])

        assert isinstance(result, ContentModifier)
        assert result.name == ContentModifierType.DEPTH
        assert result.value == 10

    def test_cm_offset(self):
        """Test cm_offset content modifier."""
        transformer = RuleTransformer()
        kw = Token("WORD", "offset")
        val = Token("INT", "5")

        result = transformer.cm_offset([kw, val])

        assert isinstance(result, ContentModifier)
        assert result.name == ContentModifierType.OFFSET
        assert result.value == 5

    def test_cm_distance_positive(self):
        """Test cm_distance with positive value."""
        transformer = RuleTransformer()
        kw = Token("WORD", "distance")
        val = Token("INT", "3")

        result = transformer.cm_distance([kw, val])

        assert isinstance(result, ContentModifier)
        assert result.name == ContentModifierType.DISTANCE
        assert result.value == 3

    def test_cm_distance_negative(self):
        """Test cm_distance with negative value."""
        transformer = RuleTransformer()
        kw = Token("WORD", "distance")
        minus = Token("MINUS", "-")
        val = Token("INT", "5")

        result = transformer.cm_distance([kw, minus, val])

        assert isinstance(result, ContentModifier)
        assert result.name == ContentModifierType.DISTANCE
        assert result.value == -5

    def test_cm_within(self):
        """Test cm_within content modifier."""
        transformer = RuleTransformer()
        kw = Token("WORD", "within")
        val = Token("INT", "20")

        result = transformer.cm_within([kw, val])

        assert isinstance(result, ContentModifier)
        assert result.name == ContentModifierType.WITHIN
        assert result.value == 20

    def test_cm_nocase(self):
        """Test cm_nocase content modifier."""
        transformer = RuleTransformer()
        kw = Token("WORD", "nocase")

        result = transformer.cm_nocase([kw])

        assert isinstance(result, ContentModifier)
        assert result.name == ContentModifierType.NOCASE
        assert result.value is None

    def test_cm_rawbytes(self):
        """Test cm_rawbytes content modifier."""
        transformer = RuleTransformer()
        kw = Token("WORD", "rawbytes")

        result = transformer.cm_rawbytes([kw])

        assert isinstance(result, ContentModifier)
        assert result.name == ContentModifierType.RAWBYTES
        assert result.value is None

    def test_cm_startswith(self):
        """Test cm_startswith content modifier."""
        transformer = RuleTransformer()
        kw = Token("WORD", "startswith")

        result = transformer.cm_startswith([kw])

        assert isinstance(result, ContentModifier)
        assert result.name == ContentModifierType.STARTSWITH
        assert result.value is None

    def test_cm_endswith(self):
        """Test cm_endswith content modifier."""
        transformer = RuleTransformer()
        kw = Token("WORD", "endswith")

        result = transformer.cm_endswith([kw])

        assert isinstance(result, ContentModifier)
        assert result.name == ContentModifierType.ENDSWITH
        assert result.value is None

    def test_cm_fast_pattern(self):
        """Test cm_fast_pattern content modifier."""
        transformer = RuleTransformer()
        kw = Token("WORD", "fast_pattern")

        result = transformer.cm_fast_pattern([kw])

        assert isinstance(result, ContentModifier)
        assert result.name == ContentModifierType.FAST_PATTERN
        assert result.value is None

    def test_cm_generic_name_only(self):
        """Test cm_generic with name only."""
        transformer = RuleTransformer()
        name = Token("WORD", "unknown")

        result = transformer.cm_generic([name])

        assert isinstance(result, ContentModifier)
        assert result.name == ContentModifierType.NOCASE  # Default fallback
        assert result.value is None

    def test_cm_generic_with_value(self):
        """Test cm_generic with name and value."""
        transformer = RuleTransformer()
        name = Token("WORD", "custom")
        val = Token("INT", "42")

        result = transformer.cm_generic([name, val])

        assert isinstance(result, ContentModifier)
        assert result.name == ContentModifierType.NOCASE  # Default fallback
        assert result.value == 42


class TestByteOperations:
    """Test byte operation transformers."""

    def test_threshold_params(self):
        """Test threshold_params passthrough."""
        transformer = RuleTransformer()
        params = [Token("WORD", "type"), Token("WORD", "limit")]

        result = transformer.threshold_params(params)

        assert result is params

    def test_threshold_param(self):
        """Test threshold_param extraction."""
        transformer = RuleTransformer()
        key = Token("WORD", "type")
        value = Token("WORD", "threshold")

        result = transformer.threshold_param([key, value])

        assert result == ("type", "threshold")

    def test_threshold_param_no_value(self):
        """Test threshold_param with only key."""
        transformer = RuleTransformer()
        key = Token("WORD", "type")

        result = transformer.threshold_param([key])

        assert result == ("type", "")

    def test_threshold_param_empty(self):
        """Test threshold_param with empty list."""
        transformer = RuleTransformer()

        result = transformer.threshold_param([])

        assert result == ("", "")

    def test_detection_params(self):
        """Test detection_params passthrough."""
        transformer = RuleTransformer()
        params = [Token("WORD", "track")]

        result = transformer.detection_params(params)

        assert result is params

    def test_detection_param(self):
        """Test detection_param extraction."""
        transformer = RuleTransformer()
        key = Token("WORD", "track")
        value = Token("INT", "5")

        result = transformer.detection_param([key, value])

        assert result == ("track", "5")

    def test_detection_param_incomplete(self):
        """Test detection_param with insufficient items."""
        transformer = RuleTransformer()

        result = transformer.detection_param([])

        assert result == ("", "")

    def test_fast_pattern_option_with_params(self):
        """Test fast_pattern_option with offset and length."""
        transformer = RuleTransformer()
        offset_token = Token("INT", "10")
        length_token = Token("INT", "20")

        result = transformer.fast_pattern_option([offset_token, length_token])

        assert isinstance(result, FastPatternOption)
        assert result.offset == 10
        assert result.length == 20

    def test_fast_pattern_option_no_params(self):
        """Test fast_pattern_option without parameters."""
        transformer = RuleTransformer()

        result = transformer.fast_pattern_option([])

        assert isinstance(result, FastPatternOption)
        assert result.offset is None
        assert result.length is None

    def test_rawbytes_option(self):
        """Test rawbytes_option."""
        transformer = RuleTransformer()

        result = transformer.rawbytes_option([])

        assert isinstance(result, RawbytesOption)

    def test_byte_test_params(self):
        """Test byte_test_params passthrough."""
        transformer = RuleTransformer()
        params = [Token("INT", "4"), Token("WORD", ">=")]

        result = transformer.byte_test_params(params)

        assert result is params

    def test_byte_jump_params(self):
        """Test byte_jump_params passthrough."""
        transformer = RuleTransformer()
        params = [Token("INT", "2"), Token("INT", "0")]

        result = transformer.byte_jump_params(params)

        assert result is params

    def test_byte_extract_params(self):
        """Test byte_extract_params passthrough."""
        transformer = RuleTransformer()
        params = [Token("INT", "4"), Token("INT", "0")]

        result = transformer.byte_extract_params(params)

        assert result is params

    def test_byte_math_params(self):
        """Test byte_math_params passthrough."""
        transformer = RuleTransformer()
        params = [Token("WORD", "bytes"), Token("INT", "2")]

        result = transformer.byte_math_params(params)

        assert result is params


class TestFileAndTagOptions:
    """Test file and tag option transformers."""

    def test_tag_params(self):
        """Test tag_params passthrough."""
        transformer = RuleTransformer()
        params = [Token("WORD", "session"), Token("INT", "5")]

        result = transformer.tag_params(params)

        assert result is params

    def test_filestore_option_with_direction_and_scope(self):
        """Test filestore_option with both parameters."""
        transformer = RuleTransformer()
        dir_token = Token("WORD", "request")
        scope_token = Token("WORD", "file")

        result = transformer.filestore_option([[dir_token, scope_token]])

        assert isinstance(result, FilestoreOption)
        assert result.direction == "request"
        assert result.scope == "file"

    def test_filestore_option_with_direction_only(self):
        """Test filestore_option with direction only."""
        transformer = RuleTransformer()
        dir_token = Token("WORD", "response")

        result = transformer.filestore_option([[dir_token]])

        assert isinstance(result, FilestoreOption)
        assert result.direction == "response"
        assert result.scope is None

    def test_filestore_option_empty(self):
        """Test filestore_option with no parameters."""
        transformer = RuleTransformer()

        result = transformer.filestore_option([])

        assert isinstance(result, FilestoreOption)
        assert result.direction is None
        assert result.scope is None

    def test_filestore_params(self):
        """Test filestore_params passthrough."""
        transformer = RuleTransformer()
        params = [Token("WORD", "request")]

        result = transformer.filestore_params(params)

        assert result is params


class TestGenericOptions:
    """Test generic option transformers."""

    def test_option_value(self):
        """Test option_value extraction."""
        transformer = RuleTransformer()
        token = Token("WORD", "value123")

        result = transformer.option_value([token])

        assert result == "value123"

    def test_option_value_quoted(self):
        """Test option_value with quoted string."""
        transformer = RuleTransformer()
        token = Token("QUOTED_STRING", '"quoted value"')

        result = transformer.option_value([token])

        assert result == "quoted value"

    def test_option_value_empty(self):
        """Test option_value with empty list."""
        transformer = RuleTransformer()

        result = transformer.option_value([])

        assert result == ""

    def test_generic_option_keyword_only(self):
        """Test generic_option with keyword only."""
        transformer = RuleTransformer()
        kw_token = Token("WORD", "established")

        result = transformer.generic_option([kw_token])

        assert isinstance(result, GenericOption)
        assert result.keyword == "established"
        assert result.value is None
        assert result.raw == "established"

    def test_generic_option_with_quoted_value(self):
        """Test generic_option with quoted value."""
        transformer = RuleTransformer()
        kw_token = Token("WORD", "msg")
        val_token = Token("QUOTED_STRING", '"test message"')

        result = transformer.generic_option([kw_token, val_token])

        assert isinstance(result, GenericOption)
        assert result.keyword == "msg"
        assert result.value == "test message"

    def test_generic_option_skip_tuples(self):
        """Test generic_option skips tuple items."""
        transformer = RuleTransformer()
        kw_token = Token("WORD", "test")
        val_token = Token("WORD", "value")
        tuple_item = ("skip", "this")

        result = transformer.generic_option([kw_token, val_token, tuple_item])

        assert isinstance(result, GenericOption)
        assert result.keyword == "test"
        assert result.value == "value"


class TestIgnoredElements:
    """Test ignored element transformers."""

    def test_comment(self):
        """Test comment returns None."""
        transformer = RuleTransformer()

        result = transformer.comment([])

        assert result is None

    def test_newline(self):
        """Test NEWLINE returns None."""
        transformer = RuleTransformer()
        token = Token("NEWLINE", "\n")

        result = transformer.NEWLINE(token)

        assert result is None


class TestDiagnostics:
    """Test diagnostic generation."""

    def test_add_diagnostic(self):
        """Test add_diagnostic creates diagnostic."""
        transformer = RuleTransformer(file_path="/test/rules")
        location = Location(
            span=Span(
                start=Position(line=1, column=1, offset=0),
                end=Position(line=1, column=5, offset=4),
            ),
            file_path="/test/rules",
        )

        transformer.add_diagnostic(
            level=DiagnosticLevel.ERROR,
            message="Test error",
            location=location,
            code="E001",
            hint="Fix this",
        )

        assert len(transformer.diagnostics) == 1
        diag = transformer.diagnostics[0]
        assert diag.level == DiagnosticLevel.ERROR
        assert diag.message == "Test error"
        assert diag.code == "E001"
        assert diag.hint == "Fix this"
        assert diag.location is location
