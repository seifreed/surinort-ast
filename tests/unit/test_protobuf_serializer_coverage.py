# Copyright (c) 2026 Marc Rivero Lopez
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.
"""
Coverage-completion tests for the protobuf serializer.

Each test class targets a specific cluster of uncovered lines/branches
identified by running coverage against the existing test suite.  All tests
exercise real production code paths: no mocks, no stubs, no skips.
"""

from typing import Literal

import pytest

from surinort_ast import parse_rule
from surinort_ast.core.diagnostics import Diagnostic, DiagnosticLevel
from surinort_ast.core.enums import (
    Action,
    ContentModifierType,
    Dialect,
    Direction,
    FlowDirection,
    FlowState,
    Protocol,
)
from surinort_ast.core.location import Location, Position, Span
from surinort_ast.core.nodes import (
    AddressExpr,
    AddressList,
    AnyAddress,
    AnyPort,
    BufferSelectOption,
    ByteExtractOption,
    ByteJumpOption,
    ByteTestOption,
    ContentModifier,
    ContentOption,
    DepthOption,
    DistanceOption,
    EndswithOption,
    FastPatternOption,
    FilestoreOption,
    FlowOption,
    GenericOption,
    GidOption,
    Header,
    IPAddress,
    LuajitOption,
    LuaOption,
    MsgOption,
    NocaseOption,
    OffsetOption,
    Port,
    PortExpr,
    PortList,
    PortNegation,
    PortRange,
    PortVariable,
    PriorityOption,
    RawbytesOption,
    ReferenceOption,
    RevOption,
    Rule,
    SidOption,
    SourceOrigin,
    StartswithOption,
    TagOption,
    ThresholdOption,
    WithinOption,
)
from surinort_ast.serialization.protobuf import (
    ProtobufError,
    ProtobufSerializer,
    from_protobuf,
    to_protobuf,
)
from tests.unit._helpers import any_header

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.skipif(
    not hasattr(pytest, "importorskip"), reason="protobuf not available"
)


@pytest.fixture(autouse=True)
def _require_protobuf() -> None:
    pytest.importorskip("google.protobuf")


def _make_loc(file_path: str | None = None) -> Location:
    """Return a minimal Location object, optionally with a file_path."""
    span = Span(
        start=Position(line=1, column=1, offset=0),
        end=Position(line=1, column=10, offset=9),
    )
    return Location(span=span, file_path=file_path)


def _minimal_header() -> Header:
    """Return a minimal TCP->any header with AnyAddress/AnyPort."""
    return any_header()


def _wrap(options: list) -> Rule:
    """Build a Rule that uses the supplied option list."""
    return Rule(
        action=Action.ALERT,
        header=_minimal_header(),
        options=options,
    )


# ---------------------------------------------------------------------------
# Lines 268 / 277 - _serialize_location with file_path set
# ---------------------------------------------------------------------------


class TestSerializeLocationWithFilePath:
    """Lines 276-277: serialize a Location that carries a file_path."""

    def test_location_file_path_survives_roundtrip(self) -> None:
        loc = _make_loc(file_path="/rules/local.rules")
        rule = Rule(
            action=Action.ALERT,
            header=Header(
                protocol=Protocol.TCP,
                src_addr=AnyAddress(),
                src_port=AnyPort(),
                direction=Direction.TO,
                dst_addr=AnyAddress(),
                dst_port=AnyPort(),
                location=loc,
            ),
            options=[SidOption(value=1)],
            location=loc,
        )
        restored = from_protobuf(to_protobuf(rule))
        assert restored.location is not None
        assert restored.location.file_path == "/rules/local.rules"
        assert restored.header.location is not None
        assert restored.header.location.file_path == "/rules/local.rules"


# ---------------------------------------------------------------------------
# Line 287 / 306->309 / 319 / 334->337 - address/port with location+comments
# ---------------------------------------------------------------------------


class TestAddressExprWithLocationAndComments:
    """Lines 284-287: address node that carries both location and comments."""

    def test_ip_address_with_location_and_comments(self) -> None:
        rule = parse_rule("alert tcp 192.168.1.1 any -> any 80 (sid:1;)")
        src = rule.header.src_addr
        # Attach location and comments via model_copy on the rule's header
        patched_addr = src.model_copy(update={"location": _make_loc(), "comments": ("# note",)})
        patched_header = rule.header.model_copy(update={"src_addr": patched_addr})
        patched_rule = rule.model_copy(update={"header": patched_header})
        restored = from_protobuf(to_protobuf(patched_rule))
        assert restored.header.src_addr.location is not None
        assert list(restored.header.src_addr.comments) == ["# note"]

    def test_any_address_with_location(self) -> None:
        """AnyAddress branch with a location."""
        rule = _wrap([SidOption(value=1)])
        patched_addr = AnyAddress(location=_make_loc(), comments=("# any",))
        patched_header = rule.header.model_copy(update={"src_addr": patched_addr})
        patched_rule = rule.model_copy(update={"header": patched_header})
        restored = from_protobuf(to_protobuf(patched_rule))
        assert isinstance(restored.header.src_addr, AnyAddress)
        assert list(restored.header.src_addr.comments) == ["# any"]

    def test_address_list_with_comments(self) -> None:
        """AddressList node with comments."""
        addr_list = AddressList(
            elements=(IPAddress(value="192.168.1.1", version=4),),
            comments=("# list",),
        )
        patched_header = _minimal_header().model_copy(update={"src_addr": addr_list})
        rule = Rule(
            action=Action.ALERT,
            header=patched_header,
            options=[SidOption(value=1)],
        )
        restored = from_protobuf(to_protobuf(rule))
        assert isinstance(restored.header.src_addr, AddressList)
        assert list(restored.header.src_addr.comments) == ["# list"]


class TestPortExprWithLocationAndComments:
    """Lines 316-319, 334->337: port nodes that carry location and comments."""

    def test_port_with_location_and_comments(self) -> None:
        port = Port(value=443, location=_make_loc(), comments=("# https",))
        patched_header = _minimal_header().model_copy(update={"src_port": port})
        rule = Rule(action=Action.ALERT, header=patched_header, options=[SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert restored.header.src_port.location is not None
        assert list(restored.header.src_port.comments) == ["# https"]

    def test_any_port_with_location_and_comments(self) -> None:
        port = AnyPort(location=_make_loc(), comments=("# anyport",))
        patched_header = _minimal_header().model_copy(update={"dst_port": port})
        rule = Rule(action=Action.ALERT, header=patched_header, options=[SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert isinstance(restored.header.dst_port, AnyPort)
        assert list(restored.header.dst_port.comments) == ["# anyport"]

    def test_port_list_with_comments(self) -> None:
        port_list = PortList(
            elements=(Port(value=80), Port(value=443)),
            comments=("# web",),
        )
        patched_header = _minimal_header().model_copy(update={"dst_port": port_list})
        rule = Rule(action=Action.ALERT, header=patched_header, options=[SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert isinstance(restored.header.dst_port, PortList)
        assert list(restored.header.dst_port.comments) == ["# web"]

    def test_port_negation_with_location(self) -> None:
        port_neg = PortNegation(expr=Port(value=80), location=_make_loc())
        patched_header = _minimal_header().model_copy(update={"src_port": port_neg})
        rule = Rule(action=Action.ALERT, header=patched_header, options=[SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert isinstance(restored.header.src_port, PortNegation)
        assert restored.header.src_port.location is not None

    def test_port_variable_with_location(self) -> None:
        pv = PortVariable(name="$HTTP_PORTS", location=_make_loc())
        patched_header = _minimal_header().model_copy(update={"dst_port": pv})
        rule = Rule(action=Action.ALERT, header=patched_header, options=[SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert isinstance(restored.header.dst_port, PortVariable)
        assert restored.header.dst_port.location is not None

    def test_port_range_with_location(self) -> None:
        pr = PortRange(start=1024, end=65535, location=_make_loc())
        patched_header = _minimal_header().model_copy(update={"src_port": pr})
        rule = Rule(action=Action.ALERT, header=patched_header, options=[SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert isinstance(restored.header.src_port, PortRange)
        assert restored.header.src_port.location is not None


# ---------------------------------------------------------------------------
# Lines 345-349 - ContentModifier with int and str values (known enum name)
# ---------------------------------------------------------------------------


class TestContentModifierStringValue:
    """Lines 345-349: known ContentModifierType with int and string values."""

    def test_content_modifier_enum_with_int_value_roundtrip(self) -> None:
        # OFFSET carries an integer value.
        mod = ContentModifier(name=ContentModifierType.OFFSET, value=10)
        opt = ContentOption(pattern=b"GET", modifiers=(mod,))
        rule = _wrap([opt, SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        content_opts = [o for o in restored.options if isinstance(o, ContentOption)]
        assert content_opts[0].modifiers[0].value == 10

    def test_content_modifier_enum_with_string_value_roundtrip(self) -> None:
        # FAST_PATTERN carries an "offset,length" string in some contexts.
        mod = ContentModifier(name=ContentModifierType.FAST_PATTERN, value="10,20")
        opt = ContentOption(pattern=b"GET", modifiers=(mod,))
        rule = _wrap([opt, SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        content_opts = [o for o in restored.options if isinstance(o, ContentOption)]
        assert content_opts[0].modifiers[0].value == "10,20"


# ---------------------------------------------------------------------------
# Lines 370 - option base with comments (lines 366-370)
# ---------------------------------------------------------------------------


class TestOptionBaseWithComments:
    """Line 370: _serialize_option_base writes comments to protobuf."""

    def test_option_with_comments_roundtrip(self) -> None:
        opt = SidOption(value=42, comments=("# important",))
        rule = _wrap([opt])
        restored = from_protobuf(to_protobuf(rule))
        assert list(restored.options[0].comments) == ["# important"]

    def test_option_with_location_roundtrip(self) -> None:
        opt = MsgOption(text="hello", location=_make_loc(file_path="/rules/test.rules"))
        rule = _wrap([opt, SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert restored.options[0].location is not None
        assert restored.options[0].location.file_path == "/rules/test.rules"


# ---------------------------------------------------------------------------
# Lines 382-384 - singledispatch fallback for unknown Option subclass
# ---------------------------------------------------------------------------


class TestSerializeOptionFallback:
    """Lines 382-384: singledispatch base case for an unregistered Option type."""

    def test_unknown_option_subclass_uses_fallback(self) -> None:
        # Create a custom Option subclass that is NOT registered with
        # @_serialize_option.register.  The singledispatch base function is
        # invoked and returns a bare pb.Option().
        from surinort_ast.core.nodes import Option
        from surinort_ast.serialization.protobuf import serializer as _ser

        class _UnknownOpt(Option):
            type: Literal["_UnknownOpt"] = "_UnknownOpt"

        unknown = _UnknownOpt()
        # The fallback returns a pb.Option with no option_type oneof set.
        result = _ser._serialize_option(unknown)
        # WhichOneof returns None when no field in the oneof is set.
        assert result.WhichOneof("option_type") is None


# ---------------------------------------------------------------------------
# Lines 487-491, 507-512 - FlowbitsOption, DetectionFilterOption
# ---------------------------------------------------------------------------


class TestFlowbitsAndDetectionFilter:
    """Lines 487-491, 507-512: FlowbitsOption and DetectionFilterOption roundtrip."""

    def test_flowbits_roundtrip(self) -> None:
        rule = parse_rule(
            'alert tcp any any -> any any (msg:"t"; flowbits:set,scanner.http; sid:1;)'
        )
        assert from_protobuf(to_protobuf(rule)) == rule

    def test_detection_filter_roundtrip(self) -> None:
        rule = parse_rule(
            "alert tcp any any -> any any "
            '(msg:"t"; detection_filter:track by_src,count 5,seconds 30; sid:1;)'
        )
        assert from_protobuf(to_protobuf(rule)) == rule


# ---------------------------------------------------------------------------
# Lines 537-542, 547-553 - ByteJumpOption, ByteExtractOption
# ---------------------------------------------------------------------------


class TestByteJumpAndByteExtract:
    """Lines 537-542, 547-553: ByteJumpOption and ByteExtractOption roundtrip."""

    def test_byte_jump_roundtrip(self) -> None:
        rule = _wrap(
            [ByteJumpOption(bytes_to_extract=4, offset=0, flags=("relative",)), SidOption(value=1)]
        )
        restored = from_protobuf(to_protobuf(rule))
        bj = next(o for o in restored.options if isinstance(o, ByteJumpOption))
        assert bj.bytes_to_extract == 4
        assert list(bj.flags) == ["relative"]

    def test_byte_extract_roundtrip(self) -> None:
        rule = _wrap(
            [
                ByteExtractOption(
                    bytes_to_extract=4, offset=0, var_name="myvar", flags=("little",)
                ),
                SidOption(value=1),
            ]
        )
        restored = from_protobuf(to_protobuf(rule))
        be = next(o for o in restored.options if isinstance(o, ByteExtractOption))
        assert be.var_name == "myvar"
        assert list(be.flags) == ["little"]


# ---------------------------------------------------------------------------
# Lines 573-578, 589, 591 - TagOption, FilestoreOption (with direction/scope)
# ---------------------------------------------------------------------------


class TestTagAndFilestore:
    """Lines 573-578, 589, 591: TagOption and FilestoreOption branches."""

    def test_tag_option_roundtrip(self) -> None:
        rule = _wrap(
            [TagOption(tag_type="session", count=10, metric="packets"), SidOption(value=1)]
        )
        restored = from_protobuf(to_protobuf(rule))
        tag = next(o for o in restored.options if isinstance(o, TagOption))
        assert tag.tag_type == "session"
        assert tag.count == 10
        assert tag.metric == "packets"

    def test_filestore_with_direction_roundtrip(self) -> None:
        rule = _wrap([FilestoreOption(direction="request"), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        fs = next(o for o in restored.options if isinstance(o, FilestoreOption))
        assert fs.direction == "request"
        assert fs.scope is None

    def test_filestore_with_scope_roundtrip(self) -> None:
        rule = _wrap([FilestoreOption(scope="file"), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        fs = next(o for o in restored.options if isinstance(o, FilestoreOption))
        assert fs.scope == "file"

    def test_filestore_with_direction_and_scope_roundtrip(self) -> None:
        rule = _wrap([FilestoreOption(direction="response", scope="stream"), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        fs = next(o for o in restored.options if isinstance(o, FilestoreOption))
        assert fs.direction == "response"
        assert fs.scope == "stream"


# ---------------------------------------------------------------------------
# Lines 597-601, 606-610 - LuaOption, LuajitOption
# ---------------------------------------------------------------------------


class TestLuaAndLuajit:
    """Lines 597-601, 606-610: LuaOption and LuajitOption roundtrip."""

    def test_lua_option_roundtrip(self) -> None:
        rule = _wrap([LuaOption(script_name="detect.lua", negated=False), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        lua = next(o for o in restored.options if isinstance(o, LuaOption))
        assert lua.script_name == "detect.lua"
        assert lua.negated is False

    def test_lua_negated_roundtrip(self) -> None:
        rule = _wrap([LuaOption(script_name="detect.lua", negated=True), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        lua = next(o for o in restored.options if isinstance(o, LuaOption))
        assert lua.negated is True

    def test_luajit_option_roundtrip(self) -> None:
        rule = _wrap(
            [LuajitOption(script_name="jit_detect.lua", negated=False), SidOption(value=1)]
        )
        restored = from_protobuf(to_protobuf(rule))
        lj = next(o for o in restored.options if isinstance(o, LuajitOption))
        assert lj.script_name == "jit_detect.lua"
        assert lj.negated is False

    def test_luajit_negated_roundtrip(self) -> None:
        rule = _wrap([LuajitOption(script_name="jit.lua", negated=True), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        lj = next(o for o in restored.options if isinstance(o, LuajitOption))
        assert lj.negated is True


# ---------------------------------------------------------------------------
# Lines 620, 631, 637-643, 648-654 - DepthOption, OffsetOption,
# DistanceOption, WithinOption - string variant
# ---------------------------------------------------------------------------


class TestStringValuedModifierOptions:
    """Lines 620, 631, 637-643, 648-654: depth/offset/distance/within with str value."""

    def test_depth_int_roundtrip(self) -> None:
        rule = _wrap([DepthOption(value=100), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert next(o for o in restored.options if isinstance(o, DepthOption)).value == 100

    def test_depth_string_roundtrip(self) -> None:
        rule = _wrap([DepthOption(value="myvar"), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert next(o for o in restored.options if isinstance(o, DepthOption)).value == "myvar"

    def test_offset_int_roundtrip(self) -> None:
        rule = _wrap([OffsetOption(value=0), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert next(o for o in restored.options if isinstance(o, OffsetOption)).value == 0

    def test_offset_string_roundtrip(self) -> None:
        rule = _wrap([OffsetOption(value="extractedvar"), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert (
            next(o for o in restored.options if isinstance(o, OffsetOption)).value == "extractedvar"
        )

    def test_distance_int_roundtrip(self) -> None:
        rule = _wrap([DistanceOption(value=5), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert next(o for o in restored.options if isinstance(o, DistanceOption)).value == 5

    def test_distance_string_roundtrip(self) -> None:
        rule = _wrap([DistanceOption(value="distvar"), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert next(o for o in restored.options if isinstance(o, DistanceOption)).value == "distvar"

    def test_within_int_roundtrip(self) -> None:
        rule = _wrap([WithinOption(value=50), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert next(o for o in restored.options if isinstance(o, WithinOption)).value == 50

    def test_within_string_roundtrip(self) -> None:
        rule = _wrap([WithinOption(value="winvar"), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert next(o for o in restored.options if isinstance(o, WithinOption)).value == "winvar"


# ---------------------------------------------------------------------------
# Lines 667-670, 675-678, 683-686 - NocaseOption, RawbytesOption,
# StartswithOption, EndswithOption
# ---------------------------------------------------------------------------


class TestBareOptions:
    """Lines 667-670, 675-678, 683-686: parameter-less option variants."""

    def test_nocase_roundtrip(self) -> None:
        rule = _wrap([NocaseOption(), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert any(isinstance(o, NocaseOption) for o in restored.options)

    def test_rawbytes_roundtrip(self) -> None:
        rule = _wrap([RawbytesOption(), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert any(isinstance(o, RawbytesOption) for o in restored.options)

    def test_startswith_roundtrip(self) -> None:
        rule = _wrap([StartswithOption(), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert any(isinstance(o, StartswithOption) for o in restored.options)

    def test_endswith_roundtrip(self) -> None:
        rule = _wrap([EndswithOption(), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert any(isinstance(o, EndswithOption) for o in restored.options)


# ---------------------------------------------------------------------------
# Lines 694->696, 712, 714 - GenericOption with and without value
# ---------------------------------------------------------------------------


class TestGenericOption:
    """Lines 694->696, 712, 714: GenericOption with None value and with value."""

    def test_generic_with_value_roundtrip(self) -> None:
        opt = GenericOption(keyword="custom_kw", value="some_val", raw="custom_kw:some_val")
        rule = _wrap([opt, SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        gen = next(o for o in restored.options if isinstance(o, GenericOption))
        assert gen.keyword == "custom_kw"
        assert gen.value == "some_val"

    def test_generic_without_value_roundtrip(self) -> None:
        opt = GenericOption(keyword="bare_kw", value=None, raw="bare_kw")
        rule = _wrap([opt, SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        gen = next(o for o in restored.options if isinstance(o, GenericOption))
        assert gen.keyword == "bare_kw"
        assert gen.value is None


# ---------------------------------------------------------------------------
# Lines 712, 714 - header with location and comments
# ---------------------------------------------------------------------------


class TestHeaderWithLocationAndComments:
    """Lines 711-714: header that carries both location and comments."""

    def test_header_location_roundtrip(self) -> None:
        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
            location=_make_loc(file_path="/rules/test.rules"),
            comments=("# header comment",),
        )
        rule = Rule(action=Action.ALERT, header=header, options=[SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        assert restored.header.location is not None
        assert restored.header.location.file_path == "/rules/test.rules"
        assert list(restored.header.comments) == ["# header comment"]


# ---------------------------------------------------------------------------
# Lines 729, 741-752 - _serialize_diagnostic with code, hint and location
# ---------------------------------------------------------------------------


class TestDiagnosticSerialization:
    """Lines 728-734: diagnostic with code, hint, and location set."""

    def test_diagnostic_with_code_and_hint_roundtrip(self) -> None:
        diag = Diagnostic(
            level=DiagnosticLevel.ERROR,
            message="parse error",
            code="E001",
            hint="check the rule",
        )
        rule = parse_rule("alert tcp any any -> any any (sid:1;)").model_copy(
            update={"diagnostics": (diag,)}
        )
        restored = from_protobuf(to_protobuf(rule))
        assert restored.diagnostics[0].code == "E001"
        assert restored.diagnostics[0].hint == "check the rule"

    def test_diagnostic_with_location_roundtrip(self) -> None:
        diag = Diagnostic(
            level=DiagnosticLevel.WARNING,
            message="suspicious",
            location=_make_loc(file_path="/rules/x.rules"),
        )
        rule = parse_rule("alert tcp any any -> any any (sid:1;)").model_copy(
            update={"diagnostics": (diag,)}
        )
        restored = from_protobuf(to_protobuf(rule))
        assert restored.diagnostics[0].location is not None
        assert restored.diagnostics[0].location.file_path == "/rules/x.rules"

    def test_diagnostic_info_level_roundtrip(self) -> None:
        diag = Diagnostic(level=DiagnosticLevel.INFO, message="informational note")
        rule = parse_rule("alert tcp any any -> any any (sid:1;)").model_copy(
            update={"diagnostics": (diag,)}
        )
        restored = from_protobuf(to_protobuf(rule))
        assert restored.diagnostics[0].level == DiagnosticLevel.INFO


# ---------------------------------------------------------------------------
# Lines 741-752 - _serialize_source_origin branches (file_path, line_number,
# rule_id all set or unset)
# ---------------------------------------------------------------------------


class TestSourceOriginSerialization:
    """Lines 741-752: SourceOrigin with all optional fields set."""

    def test_source_origin_fully_populated(self) -> None:
        origin = SourceOrigin(file_path="/rules/local.rules", line_number=42, rule_id="sid:1")
        rule = parse_rule("alert tcp any any -> any any (sid:1;)").model_copy(
            update={"origin": origin}
        )
        restored = from_protobuf(to_protobuf(rule))
        assert restored.origin is not None
        assert restored.origin.file_path == "/rules/local.rules"
        assert restored.origin.line_number == 42
        assert restored.origin.rule_id == "sid:1"

    def test_source_origin_none_fields(self) -> None:
        """SourceOrigin with all optional fields unset (empty proto message)."""
        origin = SourceOrigin(file_path=None, line_number=None, rule_id=None)
        rule = parse_rule("alert tcp any any -> any any (sid:1;)").model_copy(
            update={"origin": origin}
        )
        restored = from_protobuf(to_protobuf(rule))
        # When no optional fields are set, origin may round-trip to None or
        # an empty SourceOrigin; either is acceptable.
        if restored.origin is not None:
            assert restored.origin.file_path is None
            assert restored.origin.line_number is None
            assert restored.origin.rule_id is None

    def test_source_origin_file_path_only(self) -> None:
        origin = SourceOrigin(file_path="/tmp/test.rules")
        rule = parse_rule("alert tcp any any -> any any (sid:1;)").model_copy(
            update={"origin": origin}
        )
        restored = from_protobuf(to_protobuf(rule))
        assert restored.origin is not None
        assert restored.origin.file_path == "/tmp/test.rules"

    def test_source_origin_rule_id_only(self) -> None:
        origin = SourceOrigin(rule_id="1001")
        rule = parse_rule("alert tcp any any -> any any (sid:1;)").model_copy(
            update={"origin": origin}
        )
        restored = from_protobuf(to_protobuf(rule))
        assert restored.origin is not None
        assert restored.origin.rule_id == "1001"


# ---------------------------------------------------------------------------
# Lines 766-768, 775, 777, 790 - _serialize_rule optional fields
# (origin None path, raw_text, location, comments)
# ---------------------------------------------------------------------------


class TestRuleOptionalFields:
    """Lines 765-778, 790: rule with raw_text, location, comments and origin."""

    def test_rule_with_raw_text_roundtrip(self) -> None:
        rule = parse_rule("alert tcp any any -> any any (sid:1;)").model_copy(
            update={"raw_text": "alert tcp any any -> any any (sid:1;)"}
        )
        restored = from_protobuf(to_protobuf(rule))
        assert restored.raw_text == "alert tcp any any -> any any (sid:1;)"

    def test_rule_with_location_roundtrip(self) -> None:
        rule = parse_rule("alert tcp any any -> any any (sid:1;)").model_copy(
            update={"location": _make_loc(file_path="/rules/l.rules")}
        )
        restored = from_protobuf(to_protobuf(rule))
        assert restored.location is not None
        assert restored.location.file_path == "/rules/l.rules"

    def test_rule_with_comments_roundtrip(self) -> None:
        rule = parse_rule("alert tcp any any -> any any (sid:1;)").model_copy(
            update={"comments": ("# top-level comment",)}
        )
        restored = from_protobuf(to_protobuf(rule))
        assert "# top-level comment" in restored.comments

    def test_rule_origin_none_serializes_cleanly(self) -> None:
        rule = parse_rule("alert tcp any any -> any any (sid:1;)")
        assert rule.origin is None
        restored = from_protobuf(to_protobuf(rule))
        assert restored.origin is None


# ---------------------------------------------------------------------------
# Line 856 - _deserialize_address_expr raises ProtobufError for unknown type
# ---------------------------------------------------------------------------


class TestDeserializeAddressExprUnknownType:
    """Line 856: ProtobufError raised for an unknown address_type oneof value."""

    def test_unknown_address_type_raises(self) -> None:
        from surinort_ast.serialization.protobuf import ast_pb2 as pb
        from surinort_ast.serialization.protobuf.serializer import _deserialize_address_expr

        pb_addr = pb.AddressExpr()
        # Leave all address_type oneof fields unset; WhichOneof returns None.
        with pytest.raises(ProtobufError, match="Unknown address type"):
            _deserialize_address_expr(pb_addr)


# ---------------------------------------------------------------------------
# Line 892 - _deserialize_port_expr raises ProtobufError for unknown type
# ---------------------------------------------------------------------------


class TestDeserializePortExprUnknownType:
    """Line 892: ProtobufError raised for an unknown port_type oneof value."""

    def test_unknown_port_type_raises(self) -> None:
        from surinort_ast.serialization.protobuf import ast_pb2 as pb
        from surinort_ast.serialization.protobuf.serializer import _deserialize_port_expr

        pb_port = pb.PortExpr()
        # Leave port_type unset; WhichOneof returns None.
        with pytest.raises(ProtobufError, match="Unknown port type"):
            _deserialize_port_expr(pb_port)


# ---------------------------------------------------------------------------
# Line 909 - _deserialize_content_modifier CONTENT_MODIFIER_UNSPECIFIED path
# ---------------------------------------------------------------------------


class TestDeserializeContentModifierUnspecified:
    """Line 909: CONTENT_MODIFIER_UNSPECIFIED with int and string values."""

    def test_unspecified_modifier_string_value(self) -> None:
        rule = parse_rule('alert tcp any any -> any any (content:"x",customkw foo; sid:1;)')
        restored = from_protobuf(to_protobuf(rule))
        assert restored == rule

    def test_unspecified_modifier_int_value(self) -> None:
        rule = parse_rule('alert tcp any any -> any any (content:"x",customkw 42; sid:1;)')
        restored = from_protobuf(to_protobuf(rule))
        assert restored == rule

    def test_unspecified_modifier_no_value(self) -> None:
        rule = parse_rule('alert tcp any any -> any any (content:"x",customkw; sid:1;)')
        restored = from_protobuf(to_protobuf(rule))
        assert restored == rule


# ---------------------------------------------------------------------------
# Lines 1007, 1033, 1072, 1085, 1110, 1133, 1145 - deserializer functions
# invoked via the dispatch table
# ---------------------------------------------------------------------------


class TestDeserializerDispatchTable:
    """Lines 1007-1133: deserializer functions not explicitly covered elsewhere."""

    def test_gid_option_roundtrip(self) -> None:
        rule = _wrap([GidOption(value=1), SidOption(value=99)])
        restored = from_protobuf(to_protobuf(rule))
        gid = next(o for o in restored.options if isinstance(o, GidOption))
        assert gid.value == 1

    def test_priority_option_roundtrip(self) -> None:
        rule = _wrap([PriorityOption(value=2), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        pri = next(o for o in restored.options if isinstance(o, PriorityOption))
        assert pri.value == 2

    def test_reference_option_roundtrip(self) -> None:
        rule = _wrap([ReferenceOption(ref_type="cve", ref_id="2024-1234"), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        ref = next(o for o in restored.options if isinstance(o, ReferenceOption))
        assert ref.ref_type == "cve"
        assert ref.ref_id == "2024-1234"

    def test_rev_option_roundtrip(self) -> None:
        rule = _wrap([RevOption(value=7), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        rev = next(o for o in restored.options if isinstance(o, RevOption))
        assert rev.value == 7

    def test_buffer_select_roundtrip(self) -> None:
        rule = _wrap([BufferSelectOption(buffer_name="http_uri"), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        bs = next(o for o in restored.options if isinstance(o, BufferSelectOption))
        assert bs.buffer_name == "http_uri"

    def test_flow_with_all_variants(self) -> None:
        rule = _wrap(
            [
                FlowOption(
                    directions=(FlowDirection.FROM_CLIENT, FlowDirection.TO_SERVER),
                    states=(FlowState.ESTABLISHED, FlowState.ONLY_STREAM),
                ),
                SidOption(value=1),
            ]
        )
        restored = from_protobuf(to_protobuf(rule))
        flow = next(o for o in restored.options if isinstance(o, FlowOption))
        assert FlowDirection.FROM_CLIENT in flow.directions
        assert FlowState.ONLY_STREAM in flow.states

    def test_byte_test_roundtrip(self) -> None:
        rule = _wrap(
            [
                ByteTestOption(
                    bytes_to_extract=4, operator=">", value=100, offset=0, flags=("big",)
                ),
                SidOption(value=1),
            ]
        )
        restored = from_protobuf(to_protobuf(rule))
        bt = next(o for o in restored.options if isinstance(o, ByteTestOption))
        assert bt.operator == ">"
        assert list(bt.flags) == ["big"]

    def test_fast_pattern_only_roundtrip(self) -> None:
        rule = _wrap([FastPatternOption(only=True), SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        fp = next(o for o in restored.options if isinstance(o, FastPatternOption))
        assert fp.only is True

    def test_threshold_roundtrip(self) -> None:
        rule = _wrap(
            [
                ThresholdOption(threshold_type="limit", track="by_src", count=10, seconds=60),
                SidOption(value=1),
            ]
        )
        restored = from_protobuf(to_protobuf(rule))
        th = next(o for o in restored.options if isinstance(o, ThresholdOption))
        assert th.threshold_type == "limit"


# ---------------------------------------------------------------------------
# Lines 1155-1159, 1166-1170, 1177-1181, 1188-1192 - deserialize depth/offset/
# distance/within string_value branch
# ---------------------------------------------------------------------------


class TestDeserializeStringValuedOptions:
    """
    Lines 1155-1159, 1166-1170, 1177-1181, 1188-1192:
    string_value branch of depth/offset/distance/within deserialization.
    """

    def test_depth_string_value_branch(self) -> None:
        from surinort_ast.serialization.protobuf import ast_pb2 as pb
        from surinort_ast.serialization.protobuf.serializer import _deserialize_option

        pb_opt = pb.Option()
        pb_opt.depth.string_value = "myvar"
        result = _deserialize_option(pb_opt)
        assert result.value == "myvar"

    def test_offset_string_value_branch(self) -> None:
        from surinort_ast.serialization.protobuf import ast_pb2 as pb
        from surinort_ast.serialization.protobuf.serializer import _deserialize_option

        pb_opt = pb.Option()
        pb_opt.offset.string_value = "ovar"
        result = _deserialize_option(pb_opt)
        assert result.value == "ovar"

    def test_distance_string_value_branch(self) -> None:
        from surinort_ast.serialization.protobuf import ast_pb2 as pb
        from surinort_ast.serialization.protobuf.serializer import _deserialize_option

        pb_opt = pb.Option()
        pb_opt.distance.string_value = "dvar"
        result = _deserialize_option(pb_opt)
        assert result.value == "dvar"

    def test_within_string_value_branch(self) -> None:
        from surinort_ast.serialization.protobuf import ast_pb2 as pb
        from surinort_ast.serialization.protobuf.serializer import _deserialize_option

        pb_opt = pb.Option()
        pb_opt.within.string_value = "wvar"
        result = _deserialize_option(pb_opt)
        assert result.value == "wvar"


# ---------------------------------------------------------------------------
# Lines 1206, 1213, 1220 - deserialize nocase/rawbytes/startswith/endswith
# ---------------------------------------------------------------------------


class TestDeserializeBareOptions:
    """Lines 1206, 1213, 1220: nocase, rawbytes, startswith, endswith deserialization."""

    def test_nocase_deserialization(self) -> None:
        from surinort_ast.serialization.protobuf import ast_pb2 as pb
        from surinort_ast.serialization.protobuf.serializer import _deserialize_option

        pb_opt = pb.Option()
        pb_opt.nocase.SetInParent()
        result = _deserialize_option(pb_opt)
        assert isinstance(result, NocaseOption)

    def test_rawbytes_deserialization(self) -> None:
        from surinort_ast.serialization.protobuf import ast_pb2 as pb
        from surinort_ast.serialization.protobuf.serializer import _deserialize_option

        pb_opt = pb.Option()
        pb_opt.rawbytes.SetInParent()
        result = _deserialize_option(pb_opt)
        assert isinstance(result, RawbytesOption)

    def test_startswith_deserialization(self) -> None:
        from surinort_ast.serialization.protobuf import ast_pb2 as pb
        from surinort_ast.serialization.protobuf.serializer import _deserialize_option

        pb_opt = pb.Option()
        pb_opt.startswith.SetInParent()
        result = _deserialize_option(pb_opt)
        assert isinstance(result, StartswithOption)

    def test_endswith_deserialization(self) -> None:
        from surinort_ast.serialization.protobuf import ast_pb2 as pb
        from surinort_ast.serialization.protobuf.serializer import _deserialize_option

        pb_opt = pb.Option()
        pb_opt.endswith.SetInParent()
        result = _deserialize_option(pb_opt)
        assert isinstance(result, EndswithOption)


# ---------------------------------------------------------------------------
# Line 1289 - _deserialize_option raises ProtobufError for None option_type
# ---------------------------------------------------------------------------


class TestDeserializeOptionUnknownType:
    """Line 1289: ProtobufError raised for None/unknown option_type in dispatch."""

    def test_none_option_type_raises(self) -> None:
        from surinort_ast.serialization.protobuf import ast_pb2 as pb
        from surinort_ast.serialization.protobuf.serializer import _deserialize_option

        pb_opt = pb.Option()
        # No option_type oneof field is set; WhichOneof returns None.
        with pytest.raises(ProtobufError, match="Unknown option type"):
            _deserialize_option(pb_opt)


# ---------------------------------------------------------------------------
# Lines 1323-1326 - _deserialize_source_origin with None input
# ---------------------------------------------------------------------------


class TestDeserializeSourceOriginNone:
    """Lines 1323-1324: _deserialize_source_origin returns None when passed None."""

    def test_none_input_returns_none(self) -> None:
        from surinort_ast.serialization.protobuf.serializer import _deserialize_source_origin

        assert _deserialize_source_origin(None) is None


# ---------------------------------------------------------------------------
# Lines 1409-1415 - to_protobuf wraps non-ProtobufError exceptions
# ---------------------------------------------------------------------------


class TestToProtobufExceptionWrapping:
    """Lines 1409-1415: non-ProtobufError raised inside to_protobuf is wrapped."""

    def test_generic_exception_becomes_protobuf_error(self) -> None:
        """
        Trigger the except-Exception branch by monkeypatching _serialize_rule
        to raise a plain ValueError.  No mock framework is used; the real
        serializer module is mutated and restored in a try/finally block.
        """
        import surinort_ast.serialization.protobuf.serializer as _ser

        real_serialize_rule = _ser._serialize_rule

        def _bad_serialize(rule: Rule) -> None:
            raise ValueError("injected error for coverage")

        rule = parse_rule("alert tcp any any -> any any (sid:1;)")
        serializer = ProtobufSerializer()

        _ser._serialize_rule = _bad_serialize
        try:
            with pytest.raises(ProtobufError, match="Failed to serialize"):
                serializer.to_protobuf(rule)
        finally:
            _ser._serialize_rule = real_serialize_rule


# ---------------------------------------------------------------------------
# Lines 1488-1490 - to_protobuf_stream yields chunks
# ---------------------------------------------------------------------------


class TestToProtobufStream:
    """Lines 1488-1490: to_protobuf_stream yields serialized chunks."""

    def test_stream_single_chunk(self) -> None:
        rules = [
            parse_rule(f'alert tcp any any -> any any (msg:"r{i}"; sid:{i + 1};)') for i in range(3)
        ]
        serializer = ProtobufSerializer()
        chunks = list(serializer.to_protobuf_stream(rules, chunk_size=10))
        assert len(chunks) == 1
        assert isinstance(chunks[0], bytes)

    def test_stream_multiple_chunks(self) -> None:
        rules = [
            parse_rule(f'alert tcp any any -> any any (msg:"r{i}"; sid:{i + 1};)') for i in range(5)
        ]
        serializer = ProtobufSerializer()
        chunks = list(serializer.to_protobuf_stream(rules, chunk_size=2))
        assert len(chunks) == 3  # ceil(5/2) = 3

        # Deserialise each chunk to verify integrity.
        total: list[Rule] = []
        for chunk in chunks:
            result = serializer.from_protobuf(chunk)
            if isinstance(result, Rule):
                total.append(result)
            else:
                total.extend(result)
        assert len(total) == 5

    def test_stream_empty_list(self) -> None:
        serializer = ProtobufSerializer()
        chunks = list(serializer.to_protobuf_stream([], chunk_size=10))
        assert chunks == []


# ---------------------------------------------------------------------------
# Dialect coverage (SNORT2 and SNORT3)
# ---------------------------------------------------------------------------


class TestDialectSerialization:
    """All three Dialect values must round-trip through protobuf."""

    def test_snort2_dialect_roundtrip(self) -> None:
        rule = parse_rule('alert tcp any any -> any 80 (msg:"t"; sid:1;)', dialect=Dialect.SNORT2)
        restored = from_protobuf(to_protobuf(rule))
        assert restored.dialect == Dialect.SNORT2

    def test_snort3_dialect_roundtrip(self) -> None:
        rule = parse_rule('alert tcp any any -> any 80 (msg:"t"; sid:1;)', dialect=Dialect.SNORT3)
        restored = from_protobuf(to_protobuf(rule))
        assert restored.dialect == Dialect.SNORT3


# ---------------------------------------------------------------------------
# from_protobuf: shape detection paths
# ---------------------------------------------------------------------------


class TestFromProtobufBatchShapeDetection:
    """
    Lines 1461-1463: batch with count==1 and is_collection=False returns
    a scalar Rule; ensure the is_collection=False / count==1 branch is hit.
    """

    def test_single_rule_no_metadata_returns_scalar(self) -> None:
        rule = parse_rule("alert tcp any any -> any any (sid:1;)")
        # include_metadata=False -> bare Rule wire format (no RuleBatch)
        binary = to_protobuf(rule, include_metadata=False)
        restored = from_protobuf(binary)
        assert not isinstance(restored, list)
        assert restored == rule

    def test_batch_count_one_not_collection_returns_scalar(self) -> None:
        """Serialise a single Rule with metadata (count=1, is_collection=False)."""
        rule = parse_rule("alert tcp any any -> any any (sid:1;)")
        binary = to_protobuf(rule, include_metadata=True)
        restored = from_protobuf(binary)
        assert not isinstance(restored, list)
        assert restored == rule

    def test_is_collection_true_single_element_returns_list(self) -> None:
        """Serialise a single-element list; is_collection=True returns a list."""
        rule = parse_rule("alert tcp any any -> any any (sid:1;)")
        binary = to_protobuf([rule])
        restored = from_protobuf(binary)
        assert isinstance(restored, list)
        assert restored[0] == rule


# ---------------------------------------------------------------------------
# IPRange address roundtrip
# ---------------------------------------------------------------------------


class TestIPRangeSerialization:
    """Covers the ip_range branch in _serialize/_deserialize_address_expr."""

    def test_ip_range_roundtrip(self) -> None:
        rule = parse_rule("alert tcp [192.168.1.1-192.168.1.255] any -> any 80 (sid:1;)")
        restored = from_protobuf(to_protobuf(rule))
        assert restored.header.src_addr == rule.header.src_addr


# ---------------------------------------------------------------------------
# Additional Protocol coverage
# ---------------------------------------------------------------------------


class TestAdditionalProtocols:
    """Exercise protocol variants not covered by the existing suite."""

    @pytest.mark.parametrize(
        "proto",
        [
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
    def test_protocol_roundtrip(self, proto: str) -> None:
        rule = parse_rule(
            f'alert {proto} any any -> any any (msg:"t"; sid:1;)', dialect=Dialect.SURICATA
        )
        restored = from_protobuf(to_protobuf(rule))
        assert restored.header.protocol == rule.header.protocol


# ---------------------------------------------------------------------------
# Additional Action coverage (sdrop)
# ---------------------------------------------------------------------------


class TestSdropAction:
    """sdrop action must round-trip (Action.SDROP entry in _ACTION_TO_PB)."""

    def test_sdrop_roundtrip(self) -> None:
        rule = parse_rule('sdrop tcp any any -> any 80 (msg:"t"; sid:1;)')
        restored = from_protobuf(to_protobuf(rule))
        assert restored.action == rule.action


# ---------------------------------------------------------------------------
# FlowState / FlowDirection additional variants
# ---------------------------------------------------------------------------


class TestFlowStateAndDirectionVariants:
    """Cover FlowState/FlowDirection values not exercised by the existing suite."""

    def test_flow_not_established_no_stream(self) -> None:
        rule = _wrap(
            [
                FlowOption(
                    states=(FlowState.NOT_ESTABLISHED, FlowState.NO_STREAM),
                    directions=(FlowDirection.FROM_SERVER,),
                ),
                SidOption(value=1),
            ]
        )
        restored = from_protobuf(to_protobuf(rule))
        flow = next(o for o in restored.options if isinstance(o, FlowOption))
        assert FlowState.NOT_ESTABLISHED in flow.states
        assert FlowState.NO_STREAM in flow.states
        assert FlowDirection.FROM_SERVER in flow.directions

    def test_flow_stateless_to_client(self) -> None:
        rule = _wrap(
            [
                FlowOption(
                    states=(FlowState.STATELESS,),
                    directions=(FlowDirection.TO_CLIENT,),
                ),
                SidOption(value=1),
            ]
        )
        restored = from_protobuf(to_protobuf(rule))
        flow = next(o for o in restored.options if isinstance(o, FlowOption))
        assert FlowState.STATELESS in flow.states
        assert FlowDirection.TO_CLIENT in flow.directions

    def test_flow_only_frag_no_frag(self) -> None:
        rule = _wrap(
            [
                FlowOption(
                    states=(FlowState.ONLY_FRAG, FlowState.NO_FRAG),
                    directions=(FlowDirection.TO_SERVER,),
                ),
                SidOption(value=1),
            ]
        )
        restored = from_protobuf(to_protobuf(rule))
        flow = next(o for o in restored.options if isinstance(o, FlowOption))
        assert FlowState.ONLY_FRAG in flow.states
        assert FlowState.NO_FRAG in flow.states


# ---------------------------------------------------------------------------
# Line 268 - _serialize_location called with loc=None
# ---------------------------------------------------------------------------


class TestSerializeLocationNone:
    """Line 268: calling _serialize_location(None, ...) returns immediately."""

    def test_none_location_is_noop(self) -> None:
        from surinort_ast.serialization.protobuf import ast_pb2 as pb
        from surinort_ast.serialization.protobuf.serializer import _serialize_location

        pb_loc = pb.Location()
        # Should not raise and should leave pb_loc unchanged.
        _serialize_location(None, pb_loc)
        assert not pb_loc.HasField("span")


# ---------------------------------------------------------------------------
# Line 306->309 - _serialize_address_expr fallthrough when no isinstance match
# ---------------------------------------------------------------------------


class TestSerializeAddressExprFallthrough:
    """Line 306->309: fallthrough when none of the isinstance checks match."""

    def test_unrecognised_address_subclass_returns_empty_proto(self) -> None:
        from surinort_ast.serialization.protobuf.serializer import _serialize_address_expr

        class _Dummy(AddressExpr):
            type: Literal["_Dummy"] = "_Dummy"

        result = _serialize_address_expr(_Dummy())
        # No address_type oneof is set.
        assert result.WhichOneof("address_type") is None


# ---------------------------------------------------------------------------
# Line 334->337 - _serialize_port_expr fallthrough (no isinstance match)
# ---------------------------------------------------------------------------


class TestSerializePortExprFallthrough:
    """Line 334->337: fallthrough when none of the isinstance checks match."""

    def test_unrecognised_port_subclass_returns_empty_proto(self) -> None:
        from surinort_ast.serialization.protobuf.serializer import _serialize_port_expr

        class _DummyPort(PortExpr):
            type: Literal["_DummyPort"] = "_DummyPort"

        result = _serialize_port_expr(_DummyPort())
        assert result.WhichOneof("port_type") is None


# ---------------------------------------------------------------------------
# Lines 347, 348->362 - ContentModifier with None value
# ---------------------------------------------------------------------------


class TestContentModifierNoneValue:
    """Lines 347, 348->362: ContentModifier.value is None (no int_value or string_value)."""

    def test_known_enum_modifier_with_none_value_roundtrip(self) -> None:
        # ContentModifierType.NOCASE has no value; value stays None.
        mod = ContentModifier(name=ContentModifierType.NOCASE, value=None)
        opt = ContentOption(pattern=b"test", modifiers=(mod,))
        rule = _wrap([opt, SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        content_opts = [o for o in restored.options if isinstance(o, ContentOption)]
        assert content_opts[0].modifiers[0].value is None

    def test_custom_name_modifier_with_none_value_roundtrip(self) -> None:
        # Custom modifier with no value.
        mod = ContentModifier(name="customkw", value=None)
        opt = ContentOption(pattern=b"test", modifiers=(mod,))
        rule = _wrap([opt, SidOption(value=1)])
        restored = from_protobuf(to_protobuf(rule))
        content_opts = [o for o in restored.options if isinstance(o, ContentOption)]
        assert content_opts[0].modifiers[0].value is None


# ---------------------------------------------------------------------------
# Line 742 - _serialize_source_origin returns None for None input
# ---------------------------------------------------------------------------


class TestSerializeSourceOriginNone:
    """Line 742: _serialize_source_origin(None) returns None directly."""

    def test_none_origin_returns_none(self) -> None:
        from surinort_ast.serialization.protobuf.serializer import _serialize_source_origin

        assert _serialize_source_origin(None) is None


# ---------------------------------------------------------------------------
# Lines 767->769 - the `if origin:` False branch in _serialize_rule
# ---------------------------------------------------------------------------


class TestSerializeRuleOriginFalsyBranch:
    """Lines 767->769: `if origin:` evaluates to False inside _serialize_rule."""

    def test_origin_falsy_branch(self) -> None:
        import surinort_ast.serialization.protobuf.serializer as _ser

        real_fn = _ser._serialize_source_origin

        def _return_none(origin: object) -> None:
            return None

        rule = parse_rule("alert tcp any any -> any any (sid:1;)").model_copy(
            update={"origin": SourceOrigin(file_path="/x")}
        )
        _ser._serialize_source_origin = _return_none
        try:
            # Should serialize without crashing; the origin field is simply skipped.
            pb_rule = _ser._serialize_rule(rule)
            assert not pb_rule.HasField("origin")
        finally:
            _ser._serialize_source_origin = real_fn


# ---------------------------------------------------------------------------
# Line 790 - _deserialize_location returns None when span is not set
# ---------------------------------------------------------------------------


class TestDeserializeLocationNoSpan:
    """Line 790: _deserialize_location returns None when pb_loc has no span."""

    def test_no_span_returns_none(self) -> None:
        from surinort_ast.serialization.protobuf import ast_pb2 as pb
        from surinort_ast.serialization.protobuf.serializer import _deserialize_location

        pb_loc = pb.Location()
        assert _deserialize_location(pb_loc) is None


# ---------------------------------------------------------------------------
# Line 1410 - to_protobuf re-raises ProtobufError unchanged
# ---------------------------------------------------------------------------


class TestToProtobufReRaisesProtobufError:
    """Line 1410: ProtobufError inside to_protobuf is re-raised as-is (not wrapped)."""

    def test_protobuf_error_is_reraise_not_wrapped(self) -> None:
        import surinort_ast.serialization.protobuf.serializer as _ser

        real_serialize_rule = _ser._serialize_rule

        def _raise_pb_error(rule: Rule) -> None:
            raise ProtobufError("inner error")

        rule = parse_rule("alert tcp any any -> any any (sid:1;)")
        serializer = ProtobufSerializer()

        _ser._serialize_rule = _raise_pb_error
        try:
            with pytest.raises(ProtobufError, match="inner error"):
                serializer.to_protobuf(rule)
        finally:
            _ser._serialize_rule = real_serialize_rule
