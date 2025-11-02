# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for text_printer.py to achieve 100% coverage.

This test file targets all missing lines from the previous coverage run:
- Lines 293-300: ThresholdOption printing (threshold:type <type>, track <track>, count <N>, seconds <N>;)
- Lines 303-309: DetectionFilterOption printing (detection_filter:track <track>, count <N>, seconds <N>;)
- Lines 315-324: ByteTestOption printing with flags
- Lines 327-331: ByteJumpOption printing with flags
- Lines 334-342: ByteExtractOption printing with flags
- Line 346: FastPatternOption with offset and length
- Lines 412-414: ContentOption modifiers printing
- Lines 469-471: ContentModifier without value (just name)
"""

from surinort_ast.core.nodes import (
    Action,
    AnyAddress,
    AnyPort,
    BufferSelectOption,
    ByteExtractOption,
    ByteJumpOption,
    ByteTestOption,
    ClasstypeOption,
    ContentModifier,
    ContentModifierType,
    ContentOption,
    DetectionFilterOption,
    Direction,
    FastPatternOption,
    FlowDirection,
    FlowOption,
    FlowState,
    Header,
    MetadataOption,
    MsgOption,
    PriorityOption,
    Protocol,
    ReferenceOption,
    RevOption,
    Rule,
    SidOption,
    ThresholdOption,
)
from surinort_ast.printer.text_printer import TextPrinter, print_rule, print_rules


class TestThresholdOption:
    """Test ThresholdOption printing (lines 293-300)."""

    def test_threshold_option_type_threshold(self) -> None:
        """Test printing threshold option with type:threshold."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        threshold = ThresholdOption(
            threshold_type="threshold",
            track="by_src",
            count=5,
            seconds=60,
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Threshold Test"),
                threshold,
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        # Lines 293-300: threshold option formatting
        assert "threshold:" in printed
        assert "type threshold" in printed
        assert "track by_src" in printed
        assert "count 5" in printed
        assert "seconds 60" in printed

    def test_threshold_option_type_limit(self) -> None:
        """Test printing threshold option with type:limit."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        threshold = ThresholdOption(
            threshold_type="limit",
            track="by_dst",
            count=10,
            seconds=120,
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Limit Test"),
                threshold,
                SidOption(value=2),
            ],
        )

        printed = text_printer.print_rule(rule)

        # Verify threshold option with limit type
        assert "threshold:" in printed
        assert "type limit" in printed
        assert "track by_dst" in printed
        assert "count 10" in printed
        assert "seconds 120" in printed


class TestDetectionFilterOption:
    """Test DetectionFilterOption printing (lines 303-309)."""

    def test_detection_filter_by_src(self) -> None:
        """Test printing detection_filter with track:by_src."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        detection_filter = DetectionFilterOption(
            track="by_src",
            count=3,
            seconds=30,
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Detection Filter Test"),
                detection_filter,
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        # Lines 303-309: detection_filter option formatting
        assert "detection_filter:" in printed
        assert "track by_src" in printed
        assert "count 3" in printed
        assert "seconds 30" in printed

    def test_detection_filter_by_dst(self) -> None:
        """Test printing detection_filter with track:by_dst."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        detection_filter = DetectionFilterOption(
            track="by_dst",
            count=5,
            seconds=60,
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Detection Filter by dst"),
                detection_filter,
                SidOption(value=2),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "detection_filter:" in printed
        assert "track by_dst" in printed
        assert "count 5" in printed
        assert "seconds 60" in printed


class TestByteTestOption:
    """Test ByteTestOption printing with flags (lines 315-324)."""

    def test_byte_test_with_flags_relative(self) -> None:
        """Test printing byte_test with flags=['relative']."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        byte_test = ByteTestOption(
            bytes_to_extract=4,
            operator=">",
            value=1024,
            offset=0,
            flags=["relative"],
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Byte Test with Flags"),
                ContentOption(pattern=b"test", modifiers=[]),
                byte_test,
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        # Lines 315-324: byte_test with flags
        assert "byte_test:" in printed
        assert "4" in printed
        assert ">" in printed
        assert "1024" in printed
        assert "0" in printed
        assert "relative" in printed

    def test_byte_test_with_multiple_flags(self) -> None:
        """Test printing byte_test with multiple flags."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        byte_test = ByteTestOption(
            bytes_to_extract=2,
            operator="<",
            value=100,
            offset=5,
            flags=["big", "string", "dec"],
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Byte Test Multiple Flags"),
                ContentOption(pattern=b"test", modifiers=[]),
                byte_test,
                SidOption(value=2),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "byte_test:" in printed
        assert "2" in printed
        assert "<" in printed
        assert "100" in printed
        assert "5" in printed
        assert "big" in printed
        assert "string" in printed
        assert "dec" in printed


class TestByteJumpOption:
    """Test ByteJumpOption printing with flags (lines 327-331)."""

    def test_byte_jump_with_flags_relative(self) -> None:
        """Test printing byte_jump with flags=['relative']."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        byte_jump = ByteJumpOption(
            bytes_to_extract=4,
            offset=0,
            flags=["relative"],
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Byte Jump with Flags"),
                ContentOption(pattern=b"test", modifiers=[]),
                byte_jump,
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        # Lines 327-331: byte_jump with flags
        assert "byte_jump:" in printed
        assert "4" in printed
        assert "0" in printed
        assert "relative" in printed

    def test_byte_jump_with_multiple_flags(self) -> None:
        """Test printing byte_jump with multiple flags."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        byte_jump = ByteJumpOption(
            bytes_to_extract=2,
            offset=10,
            flags=["big", "string"],
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Byte Jump Multiple Flags"),
                ContentOption(pattern=b"test", modifiers=[]),
                byte_jump,
                SidOption(value=2),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "byte_jump:" in printed
        assert "2" in printed
        assert "10" in printed
        assert "big" in printed
        assert "string" in printed


class TestByteExtractOption:
    """Test ByteExtractOption printing with flags (lines 334-342)."""

    def test_byte_extract_with_flags_relative(self) -> None:
        """Test printing byte_extract with flags=['relative']."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        byte_extract = ByteExtractOption(
            bytes_to_extract=4,
            offset=0,
            var_name="myvar",
            flags=["relative"],
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Byte Extract with Flags"),
                ContentOption(pattern=b"test", modifiers=[]),
                byte_extract,
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        # Lines 334-342: byte_extract with flags
        assert "byte_extract:" in printed
        assert "4" in printed
        assert "0" in printed
        assert "myvar" in printed
        assert "relative" in printed

    def test_byte_extract_with_multiple_flags(self) -> None:
        """Test printing byte_extract with multiple flags."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        byte_extract = ByteExtractOption(
            bytes_to_extract=2,
            offset=5,
            var_name="var2",
            flags=["big", "string"],
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Byte Extract Multiple Flags"),
                ContentOption(pattern=b"test", modifiers=[]),
                byte_extract,
                SidOption(value=2),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "byte_extract:" in printed
        assert "2" in printed
        assert "5" in printed
        assert "var2" in printed
        assert "big" in printed
        assert "string" in printed


class TestFastPatternOption:
    """Test FastPatternOption printing (line 346)."""

    def test_fast_pattern_with_offset_and_length(self) -> None:
        """Test printing fast_pattern with offset and length (line 346)."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        fast_pattern = FastPatternOption(offset=0, length=10)

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Fast Pattern with Offset Length"),
                ContentOption(pattern=b"test", modifiers=[]),
                fast_pattern,
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        # Line 346: fast_pattern with offset and length
        assert "fast_pattern:" in printed
        assert "0" in printed
        assert "10" in printed

    def test_fast_pattern_with_different_offset_length(self) -> None:
        """Test printing fast_pattern with different offset/length values."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        fast_pattern = FastPatternOption(offset=10, length=20)

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Fast Pattern Offset Length"),
                ContentOption(pattern=b"test", modifiers=[]),
                fast_pattern,
                SidOption(value=2),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "fast_pattern:" in printed
        assert "10" in printed
        assert "20" in printed


class TestContentWithModifiers:
    """Test ContentOption with modifiers printing (lines 412-414)."""

    def test_content_with_single_modifier(self) -> None:
        """Test printing content with single modifier."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        # Create content with nocase modifier
        content = ContentOption(
            pattern=b"test",
            modifiers=[
                ContentModifier(
                    name=ContentModifierType.NOCASE,
                    value=None,
                )
            ],
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Content with Modifier"),
                content,
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        # Lines 412-414: content with modifiers
        assert "content:" in printed
        assert "test" in printed
        assert "nocase;" in printed

    def test_content_with_multiple_modifiers(self) -> None:
        """Test printing content with multiple modifiers."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        # Create content with multiple modifiers
        content = ContentOption(
            pattern=b"test",
            modifiers=[
                ContentModifier(
                    name=ContentModifierType.NOCASE,
                    value=None,
                ),
                ContentModifier(
                    name=ContentModifierType.DEPTH,
                    value=100,
                ),
                ContentModifier(
                    name=ContentModifierType.OFFSET,
                    value=10,
                ),
            ],
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Content with Multiple Modifiers"),
                content,
                SidOption(value=2),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "content:" in printed
        assert "test" in printed
        assert "nocase;" in printed
        assert "depth:100" in printed
        assert "offset:10" in printed

    def test_content_with_distance_within(self) -> None:
        """Test printing content with distance and within modifiers."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        # First content
        content1 = ContentOption(
            pattern=b"first",
            modifiers=[],
        )

        # Second content with distance and within
        content2 = ContentOption(
            pattern=b"second",
            modifiers=[
                ContentModifier(
                    name=ContentModifierType.DISTANCE,
                    value=5,
                ),
                ContentModifier(
                    name=ContentModifierType.WITHIN,
                    value=20,
                ),
            ],
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Content Distance Within"),
                content1,
                content2,
                SidOption(value=3),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "content:" in printed
        assert "first" in printed
        assert "second" in printed
        assert "distance:5" in printed
        assert "within:20" in printed


class TestContentModifierNoValue:
    """Test ContentModifier without value (lines 469-471)."""

    def test_content_modifier_nocase(self) -> None:
        """Test printing content modifier without value (nocase)."""
        text_printer = TextPrinter()

        # Create nocase modifier directly
        modifier = ContentModifier(
            name=ContentModifierType.NOCASE,
            value=None,
        )

        # Call _print_content_modifier directly to test line 469-470
        result = text_printer._print_content_modifier(modifier)

        # Lines 469-470: modifier without value
        assert "nocase;" in result

    def test_content_modifier_rawbytes(self) -> None:
        """Test printing content modifier without value (rawbytes)."""
        text_printer = TextPrinter()

        # Create rawbytes modifier directly
        modifier = ContentModifier(
            name=ContentModifierType.RAWBYTES,
            value=None,
        )

        result = text_printer._print_content_modifier(modifier)

        assert "rawbytes;" in result

    def test_content_modifier_startswith(self) -> None:
        """Test printing content modifier without value (startswith)."""
        text_printer = TextPrinter()

        # Create startswith modifier directly
        modifier = ContentModifier(
            name=ContentModifierType.STARTSWITH,
            value=None,
        )

        result = text_printer._print_content_modifier(modifier)

        assert "startswith;" in result

    def test_content_modifier_endswith(self) -> None:
        """Test printing content modifier without value (endswith)."""
        text_printer = TextPrinter()

        # Create endswith modifier directly
        modifier = ContentModifier(
            name=ContentModifierType.ENDSWITH,
            value=None,
        )

        result = text_printer._print_content_modifier(modifier)

        assert "endswith;" in result

    def test_content_modifier_with_value(self) -> None:
        """Test printing content modifier with value (line 471)."""
        text_printer = TextPrinter()

        # Create depth modifier with value
        modifier = ContentModifier(
            name=ContentModifierType.DEPTH,
            value=100,
        )

        # Call _print_content_modifier to test line 471
        result = text_printer._print_content_modifier(modifier)

        # Lines 471: modifier with value
        assert "depth:100;" in result

    def test_content_modifier_offset(self) -> None:
        """Test printing content modifier offset with value."""
        text_printer = TextPrinter()

        # Create offset modifier with value
        modifier = ContentModifier(
            name=ContentModifierType.OFFSET,
            value=50,
        )

        result = text_printer._print_content_modifier(modifier)

        assert "offset:50;" in result


class TestMissingOptionTypes:
    """Test missing option types (lines 254, 260, 263, 266, 269-271, 282-287, 312)."""

    def test_rev_option(self) -> None:
        """Test printing RevOption (line 254)."""

        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Rev Option Test"),
                RevOption(value=2),
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "rev:2" in printed

    def test_classtype_option(self) -> None:
        """Test printing ClasstypeOption (line 260)."""

        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Classtype Test"),
                ClasstypeOption(value="trojan-activity"),
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "classtype:trojan-activity" in printed

    def test_priority_option(self) -> None:
        """Test printing PriorityOption (line 263)."""

        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Priority Test"),
                PriorityOption(value=1),
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "priority:1" in printed

    def test_reference_option(self) -> None:
        """Test printing ReferenceOption (line 266)."""

        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Reference Test"),
                ReferenceOption(ref_type="url", ref_id="https://example.com"),
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "reference:url,https://example.com" in printed

    def test_metadata_option(self) -> None:
        """Test printing MetadataOption (lines 269-271)."""

        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Metadata Test"),
                MetadataOption(entries=[("key1", "value1"), ("key2", "value2")]),
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "metadata:" in printed
        assert "key1 value1" in printed
        assert "key2 value2" in printed

    def test_flow_option(self) -> None:
        """Test printing FlowOption (lines 282-287)."""

        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Flow Test"),
                FlowOption(
                    directions=[FlowDirection.TO_SERVER],
                    states=[FlowState.ESTABLISHED],
                ),
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "flow:" in printed
        assert "established" in printed
        assert "to_server" in printed

    def test_buffer_select_option(self) -> None:
        """Test printing BufferSelectOption (line 312)."""

        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Buffer Select Test"),
                BufferSelectOption(buffer_name="http.uri"),
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "http.uri;" in printed


class TestConvenienceFunctions:
    """Test convenience functions (lines 485-486, 500-501)."""

    def test_print_rule_function(self) -> None:
        """Test print_rule convenience function (lines 485-486)."""
        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Convenience Function Test"),
                SidOption(value=1),
            ],
        )

        # Use the module-level print_rule function
        printed = print_rule(rule)

        assert "alert tcp any any -> any any" in printed
        assert "msg:" in printed
        assert "Convenience Function Test" in printed
        assert "sid:1" in printed

    def test_print_rule_function_with_options(self) -> None:
        """Test print_rule with FormatterOptions."""
        from surinort_ast.printer.formatter import FormatterOptions

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Test with Options"),
                SidOption(value=2),
            ],
        )

        # Use print_rule with custom formatter options
        options = FormatterOptions.standard()
        printed = print_rule(rule, options)

        assert "msg:" in printed
        assert "sid:2" in printed

    def test_print_rules_function(self) -> None:
        """Test print_rules convenience function (lines 500-501)."""
        header1 = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        rule1 = Rule(
            action=Action.ALERT,
            header=header1,
            options=[
                MsgOption(text="First Rule"),
                SidOption(value=1),
            ],
        )

        header2 = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        rule2 = Rule(
            action=Action.ALERT,
            header=header2,
            options=[
                MsgOption(text="Second Rule"),
                SidOption(value=2),
            ],
        )

        # Use the module-level print_rules function
        printed = print_rules([rule1, rule2])

        assert "First Rule" in printed
        assert "Second Rule" in printed
        assert "sid:1" in printed
        assert "sid:2" in printed


class TestByteTestWithoutFlags:
    """Test byte options without flags (branch coverage)."""

    def test_byte_test_without_flags(self) -> None:
        """Test byte_test without flags - branch coverage for line 322->324."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        byte_test = ByteTestOption(
            bytes_to_extract=4,
            operator=">",
            value=1024,
            offset=0,
            flags=[],  # Empty flags - condition is falsy
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Byte Test No Flags"),
                ContentOption(pattern=b"test", modifiers=[]),
                byte_test,
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        # Should have byte_test without flags
        assert "byte_test:" in printed
        assert "4" in printed
        assert ">" in printed
        assert "1024" in printed
        assert "0" in printed

    def test_byte_jump_without_flags(self) -> None:
        """Test byte_jump without flags - branch coverage for line 329->331."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        byte_jump = ByteJumpOption(
            bytes_to_extract=4,
            offset=0,
            flags=[],  # Empty flags - condition is falsy
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Byte Jump No Flags"),
                ContentOption(pattern=b"test", modifiers=[]),
                byte_jump,
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        # Should have byte_jump without flags
        assert "byte_jump:" in printed
        assert "4" in printed
        assert "0" in printed

    def test_byte_extract_without_flags(self) -> None:
        """Test byte_extract without flags - branch coverage for line 340->342."""
        text_printer = TextPrinter()

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        byte_extract = ByteExtractOption(
            bytes_to_extract=4,
            offset=0,
            var_name="myvar",
            flags=[],  # Empty flags - condition is falsy
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Byte Extract No Flags"),
                ContentOption(pattern=b"test", modifiers=[]),
                byte_extract,
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        # Should have byte_extract without flags
        assert "byte_extract:" in printed
        assert "4" in printed
        assert "0" in printed
        assert "myvar" in printed
