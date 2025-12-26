# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Comprehensive coverage tests for text_printer.py.

This test file targets all missing lines to achieve 100% coverage:
- Lines 116, 193, 220 (fallback returns)
- Lines 293-300 (ThresholdOption)
- Lines 303-309 (DetectionFilterOption)
- Lines 315-324 (ByteTestOption)
- Lines 327-331 (ByteJumpOption)
- Lines 334-342 (ByteExtractOption)
- Lines 346, 350 (FastPatternOption, TagOption)
- Lines 390 (fallback for unknown options)
- Lines 412-414 (content modifiers)
- Lines 469-471 (content modifier with value)
"""

from lark import Lark

from surinort_ast.parsing.transformer import RuleTransformer
from surinort_ast.printer.formatter import FormatterOptions
from surinort_ast.printer.text_printer import TextPrinter, print_rules


class TestAddressFallback:
    """Test address printing fallback."""

    def test_print_rule_without_options(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing rule without options (line 116)."""
        # This requires constructing a rule AST directly since parser always adds options
        from surinort_ast.core.nodes import (
            Action,
            AnyAddress,
            AnyPort,
            Direction,
            Header,
            Protocol,
            Rule,
        )

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,  # Use Direction.TO instead of UNIDIRECTIONAL
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[],  # Empty options
        )

        printed = text_printer.print_rule(rule)

        # Should not contain parentheses for options
        assert "(" not in printed
        assert ")" not in printed
        assert printed == "alert tcp any any -> any any"


class TestPortFallback:
    """Test port expression fallback (line 220)."""

    def test_invalid_port_expr_fallback(self, text_printer: TextPrinter):
        """Test fallback for unknown port expression type."""
        from surinort_ast.core.nodes import ASTNode

        # Create a mock port expression that doesn't match any known type
        class UnknownPortExpr(ASTNode):
            """Unknown port expression for testing."""

            pass

        unknown_port = UnknownPortExpr()
        result = text_printer._print_port(unknown_port)  # type: ignore

        assert result == "any"

    def test_print_port_range(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing PortRange (line 210)."""
        rule_text = 'alert tcp any 1024:65535 -> any 80 (msg:"Port Range"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "1024:65535" in printed

    def test_print_port_variable(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing PortVariable (line 212)."""
        rule_text = 'alert tcp any any -> any $HTTP_PORTS (msg:"Port Variable"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "$HTTP_PORTS" in printed

    def test_print_port_negation(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing PortNegation (line 214-215)."""
        rule_text = 'alert tcp any any -> any !80 (msg:"Port Negation"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "!80" in printed

    def test_print_port_list(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing PortList (line 217-219)."""
        rule_text = 'alert tcp any any -> any [80, 443, 8080] (msg:"Port List"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "80" in printed
        assert "443" in printed
        assert "8080" in printed


class TestAddressListFallback:
    """Test address list fallback (line 193)."""

    def test_invalid_address_expr_fallback(self, text_printer: TextPrinter):
        """Test fallback for unknown address expression type."""
        from surinort_ast.core.nodes import ASTNode

        # Create a mock address expression that doesn't match any known type
        class UnknownAddressExpr(ASTNode):
            """Unknown address expression for testing."""

            pass

        unknown_addr = UnknownAddressExpr()
        result = text_printer._print_address(unknown_addr)  # type: ignore

        assert result == "any"

    def test_print_ip_address(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing IPAddress (line 179)."""
        rule_text = 'alert tcp 192.168.1.1 any -> any 80 (msg:"IP Address"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "192.168.1.1" in printed

    def test_print_ip_cidr_range(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing IPCIDRRange (line 181)."""
        rule_text = 'alert tcp 10.0.0.0/8 any -> any 80 (msg:"CIDR Range"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "10.0.0.0/8" in printed

    def test_print_ip_range(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing IPRange (line 183)."""
        rule_text = 'alert tcp [192.168.1.1-192.168.1.10] any -> any 80 (msg:"IP Range"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "[192.168.1.1-192.168.1.10]" in printed

    def test_print_address_variable(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing AddressVariable (line 185)."""
        rule_text = 'alert tcp $HOME_NET any -> any 80 (msg:"Address Variable"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "$HOME_NET" in printed

    def test_print_address_negation(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing AddressNegation (line 187-188)."""
        rule_text = 'alert tcp !192.168.1.1 any -> any 80 (msg:"Address Negation"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "!192.168.1.1" in printed

    def test_print_address_list(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing AddressList (line 190-192)."""
        rule_text = 'alert tcp [192.168.1.1, 10.0.0.1] any -> any 80 (msg:"Address List"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "192.168.1.1" in printed
        assert "10.0.0.1" in printed


class TestAdditionalOptions:
    """Test additional option types."""

    def test_print_gid_option(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing GidOption (line 257)."""
        rule_text = 'alert tcp any any -> any 80 (msg:"GID Test"; gid:1; sid:100;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "gid:1" in printed

    def test_print_pcre_option(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing PcreOption (line 277-279)."""
        rule_text = 'alert tcp any any -> any 80 (msg:"PCRE Test"; pcre:"/test/i"; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "pcre:" in printed
        assert "/test/i" in printed

    def test_print_flowbits_option(self, text_printer: TextPrinter):
        """Test printing FlowbitsOption (line 290)."""
        from surinort_ast.core.nodes import (
            Action,
            AnyAddress,
            AnyPort,
            Direction,
            FlowbitsOption,
            Header,
            MsgOption,
            Protocol,
            Rule,
            SidOption,
        )

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        flowbits = FlowbitsOption(action="set", name="test.bit")

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Flowbits Test"),
                flowbits,
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "flowbits:set,test.bit" in printed or "flowbits:set, test.bit" in printed


class TestThresholdOption:
    """Test ThresholdOption printing (lines 293-300)."""

    def test_print_threshold_option(self, text_printer: TextPrinter):
        """Test printing threshold option."""
        from surinort_ast.core.nodes import (
            Action,
            AnyAddress,
            AnyPort,
            Direction,
            Header,
            MsgOption,
            Protocol,
            Rule,
            SidOption,
            ThresholdOption,
        )

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

        assert "threshold:" in printed
        assert "type threshold" in printed
        assert "track by_src" in printed
        assert "count 5" in printed
        assert "seconds 60" in printed

    def test_print_threshold_limit(self, text_printer: TextPrinter):
        """Test printing threshold with type limit."""
        from surinort_ast.core.nodes import (
            Action,
            AnyAddress,
            AnyPort,
            Direction,
            Header,
            MsgOption,
            Protocol,
            Rule,
            SidOption,
            ThresholdOption,
        )

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

        assert "threshold:" in printed
        assert "type limit" in printed
        assert "track by_dst" in printed


class TestDetectionFilterOption:
    """Test DetectionFilterOption printing (lines 303-309)."""

    def test_print_detection_filter(self, text_printer: TextPrinter):
        """Test printing detection_filter option."""
        from surinort_ast.core.nodes import (
            Action,
            AnyAddress,
            AnyPort,
            DetectionFilterOption,
            Direction,
            Header,
            MsgOption,
            Protocol,
            Rule,
            SidOption,
        )

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

        assert "detection_filter:" in printed
        assert "track by_src" in printed
        assert "count 3" in printed
        assert "seconds 30" in printed

    def test_print_detection_filter_by_dst(self, text_printer: TextPrinter):
        """Test printing detection_filter with by_dst."""
        from surinort_ast.core.nodes import (
            Action,
            AnyAddress,
            AnyPort,
            DetectionFilterOption,
            Direction,
            Header,
            MsgOption,
            Protocol,
            Rule,
            SidOption,
        )

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
                MsgOption(text="Filter by dst"),
                detection_filter,
                SidOption(value=2),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "detection_filter:" in printed
        assert "track by_dst" in printed


class TestByteTestOption:
    """Test ByteTestOption printing (lines 315-324)."""

    def test_print_byte_test_basic(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing byte_test without flags."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Byte Test"; content:"test"; byte_test:4, >, 1024, 0; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "byte_test:" in printed
        assert "4" in printed
        assert ">" in printed
        assert "1024" in printed

    def test_print_byte_test_with_flags(self, text_printer: TextPrinter):
        """Test printing byte_test with flags (line 322-323)."""
        from surinort_ast.core.nodes import (
            Action,
            AnyAddress,
            AnyPort,
            ByteTestOption,
            ContentOption,
            Direction,
            Header,
            MsgOption,
            Protocol,
            Rule,
            SidOption,
        )

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
            flags=["big", "string", "dec"],  # Non-empty flags
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Byte Test Flags"),
                ContentOption(pattern=b"test", modifiers=[]),
                byte_test,
                SidOption(value=2),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "byte_test:" in printed
        assert "big" in printed
        assert "string" in printed
        assert "dec" in printed


class TestByteJumpOption:
    """Test ByteJumpOption printing (lines 327-331)."""

    def test_print_byte_jump_basic(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing byte_jump without flags."""
        rule_text = (
            'alert tcp any any -> any 80 (msg:"Byte Jump"; content:"test"; byte_jump:4, 0; sid:1;)'
        )

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "byte_jump:" in printed
        assert "4" in printed

    def test_print_byte_jump_with_flags(self, text_printer: TextPrinter):
        """Test printing byte_jump with flags (line 329-330)."""
        from surinort_ast.core.nodes import (
            Action,
            AnyAddress,
            AnyPort,
            ByteJumpOption,
            ContentOption,
            Direction,
            Header,
            MsgOption,
            Protocol,
            Rule,
            SidOption,
        )

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
            flags=["big", "string"],  # Non-empty flags
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Byte Jump Flags"),
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
    """Test ByteExtractOption printing (lines 334-342)."""

    def test_print_byte_extract_basic(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing byte_extract without flags."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Byte Extract"; content:"test"; byte_extract:4, 0, myvar; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "byte_extract:" in printed
        assert "4" in printed
        assert "0" in printed
        assert "myvar" in printed

    def test_print_byte_extract_with_flags(self, text_printer: TextPrinter):
        """Test printing byte_extract with flags (line 340-341)."""
        from surinort_ast.core.nodes import (
            Action,
            AnyAddress,
            AnyPort,
            ByteExtractOption,
            ContentOption,
            Direction,
            Header,
            MsgOption,
            Protocol,
            Rule,
            SidOption,
        )

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
            flags=["big", "string"],  # Non-empty flags
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Byte Extract Flags"),
                ContentOption(pattern=b"test", modifiers=[]),
                byte_extract,
                SidOption(value=2),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "byte_extract:" in printed
        assert "var2" in printed
        assert "big" in printed
        assert "string" in printed


class TestFastPatternOption:
    """Test FastPatternOption printing (lines 344-347)."""

    def test_print_fast_pattern_simple(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing fast_pattern without offset/length (line 347)."""
        rule_text = (
            'alert tcp any any -> any 80 (msg:"Fast Pattern"; content:"test"; fast_pattern; sid:1;)'
        )

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "fast_pattern;" in printed

    def test_print_fast_pattern_with_offset_length(self, text_printer: TextPrinter):
        """Test printing fast_pattern with offset and length (line 346)."""
        from surinort_ast.core.nodes import (
            Action,
            AnyAddress,
            AnyPort,
            ContentOption,
            Direction,
            FastPatternOption,
            Header,
            MsgOption,
            Protocol,
            Rule,
            SidOption,
        )

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
                MsgOption(text="Fast Pattern Offset"),
                ContentOption(pattern=b"test", modifiers=[]),
                fast_pattern,
                SidOption(value=2),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "fast_pattern:" in printed
        assert "10" in printed
        assert "20" in printed


class TestTagOption:
    """Test TagOption printing (line 350)."""

    def test_print_tag_option(self, text_printer: TextPrinter):
        """Test printing tag option."""
        from surinort_ast.core.nodes import (
            Action,
            AnyAddress,
            AnyPort,
            Direction,
            Header,
            MsgOption,
            Protocol,
            Rule,
            SidOption,
            TagOption,
        )

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        tag = TagOption(tag_type="host", count=10, metric="seconds")

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Tag Test"),
                tag,
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "tag:" in printed
        assert "host" in printed
        assert "10" in printed
        assert "seconds" in printed

    def test_print_tag_session(self, text_printer: TextPrinter):
        """Test printing tag with session type."""
        from surinort_ast.core.nodes import (
            Action,
            AnyAddress,
            AnyPort,
            Direction,
            Header,
            MsgOption,
            Protocol,
            Rule,
            SidOption,
            TagOption,
        )

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        tag = TagOption(tag_type="session", count=5, metric="packets")

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Tag Session"),
                tag,
                SidOption(value=2),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "tag:" in printed
        assert "session" in printed


class TestFilestoreOption:
    """Test FilestoreOption printing (lines 352-357)."""

    def test_print_filestore_simple(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing filestore without direction/scope."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Filestore Test"; filestore; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "filestore;" in printed

    def test_print_filestore_with_direction(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing filestore with direction only."""
        rule_text = (
            'alert tcp any any -> any 80 (msg:"Filestore Direction"; filestore:request; sid:2;)'
        )

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "filestore:request" in printed

    def test_print_filestore_with_direction_and_scope(
        self, lark_parser: Lark, transformer: RuleTransformer, text_printer: TextPrinter
    ):
        """Test printing filestore with direction and scope."""
        rule_text = (
            'alert tcp any any -> any 80 (msg:"Filestore Full"; filestore:response, file; sid:3;)'
        )

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        printed = text_printer.print_rule(rule)

        assert "filestore:response,file" in printed or "filestore:response, file" in printed


class TestGenericOption:
    """Test GenericOption and fallback printing (line 384-390)."""

    def test_print_generic_option_with_semicolon(self, text_printer: TextPrinter):
        """Test printing generic option that already has semicolon."""
        from surinort_ast.core.nodes import GenericOption

        option = GenericOption(keyword="custom_option", value="value", raw="custom_option:value;")
        result = text_printer._print_option(option)

        assert result == "custom_option:value;"

    def test_print_generic_option_without_semicolon(self, text_printer: TextPrinter):
        """Test printing generic option - printer adds semicolon if not present."""
        from surinort_ast.core.nodes import GenericOption

        option = GenericOption(keyword="another_option", value=None, raw="another_option")
        result = text_printer._print_option(option)

        # Printer adds semicolon if raw text doesn't have one (for roundtrip compatibility)
        assert result == "another_option;"

    def test_print_unknown_option_fallback(self, text_printer: TextPrinter):
        """Test fallback for completely unknown option type (line 390)."""
        from surinort_ast.core.nodes import Option

        # Create a minimal option subclass
        class UnknownOption(Option):
            """Unknown option for testing fallback."""

            pass

        option = UnknownOption()
        result = text_printer._print_option(option)

        # Should use node_type.lower() + semicolon
        assert result == "unknownoption;"


class TestPrintRulesConvenience:
    """Test print_rules convenience function."""

    def test_print_rules_function(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test print_rules convenience function."""
        rules_text = [
            'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)',
            'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)',
        ]

        rules = []
        for rule_text in rules_text:
            parse_tree = lark_parser.parse(rule_text)
            rule = transformer.transform(parse_tree)[0]
            rules.append(rule)

        # Use convenience function
        printed = print_rules(rules)

        assert "Rule 1" in printed
        assert "Rule 2" in printed
        assert "sid:1" in printed
        assert "sid:2" in printed

    def test_print_rules_with_custom_options(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test print_rules with custom formatter options."""
        rules_text = [
            'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)',
        ]

        parse_tree = lark_parser.parse(rules_text[0])
        rule = transformer.transform(parse_tree)[0]

        options = FormatterOptions(
            option_separator=" ",
            quote_style="single",
        )

        printed = print_rules([rule], options)

        assert "alert" in printed
        assert "msg:" in printed


class TestEdgeCases:
    """Test edge cases and special formatting."""

    def test_print_rule_with_comments(self, text_printer: TextPrinter):
        """Test printing rule with comments (line 110-111)."""
        from surinort_ast.core.nodes import (
            Action,
            AnyAddress,
            AnyPort,
            Direction,
            Header,
            MsgOption,
            Protocol,
            Rule,
            SidOption,
        )

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,  # Use Direction.TO
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Test"),
                SidOption(value=1),
            ],
            comments=["This is a comment", "Another comment"],
        )

        # Use printer with preserve_comments enabled
        options = FormatterOptions(preserve_comments=True)
        printer = TextPrinter(options)

        printed = printer.print_rule(rule)

        assert "# This is a comment" in printed
        assert "# Another comment" in printed

    def test_print_hex_content_uppercase(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test printing hex content with uppercase option."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Hex Test"; content:|48 65 6C 6C 6F|; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Use uppercase hex
        options = FormatterOptions(hex_uppercase=True)
        printer = TextPrinter(options)

        printed = printer.print_rule(rule)

        assert "content:" in printed

    def test_print_hex_content_lowercase(self, lark_parser: Lark, transformer: RuleTransformer):
        """Test printing hex content with lowercase option (line 453)."""
        rule_text = 'alert tcp any any -> any 80 (msg:"Hex Test"; content:|48 65 6c 6c 6f|; sid:1;)'

        parse_tree = lark_parser.parse(rule_text)
        rule = transformer.transform(parse_tree)[0]

        # Use lowercase hex
        options = FormatterOptions(hex_uppercase=False)
        printer = TextPrinter(options)

        printed = printer.print_rule(rule)

        assert "content:" in printed

    def test_content_modifier_without_value(self, text_printer: TextPrinter):
        """Test printing content modifier without value (line 470)."""
        from surinort_ast.core.nodes import ContentModifier, ContentModifierType

        modifier = ContentModifier(name=ContentModifierType.NOCASE, value=None)
        result = text_printer._print_content_modifier(modifier)

        assert result == "nocase;"

    def test_content_modifier_with_value(self, text_printer: TextPrinter):
        """Test printing content modifier with value (line 471)."""
        from surinort_ast.core.nodes import ContentModifier, ContentModifierType

        modifier = ContentModifier(name=ContentModifierType.DEPTH, value=100)
        result = text_printer._print_content_modifier(modifier)

        assert result == "depth:100;"

    def test_print_content_with_inline_modifiers(self, text_printer: TextPrinter):
        """Test printing content with inline modifiers (lines 412-414)."""
        from surinort_ast.core.nodes import (
            Action,
            AnyAddress,
            AnyPort,
            ContentModifier,
            ContentModifierType,
            ContentOption,
            Direction,
            Header,
            MsgOption,
            Protocol,
            Rule,
            SidOption,
        )

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        # Content with inline modifiers
        content = ContentOption(
            pattern=b"test",
            modifiers=[
                ContentModifier(name=ContentModifierType.NOCASE, value=None),
                ContentModifier(name=ContentModifierType.DEPTH, value=50),
            ],
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Content with modifiers"),
                content,
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "content:" in printed
        assert "test" in printed
        assert "nocase;" in printed
        assert "depth:50" in printed

    def test_print_content_with_special_chars(self, text_printer: TextPrinter):
        """Test printing content with special characters needing hex (lines 453-455)."""
        from surinort_ast.core.nodes import (
            Action,
            AnyAddress,
            AnyPort,
            ContentOption,
            Direction,
            Header,
            MsgOption,
            Protocol,
            Rule,
            SidOption,
        )

        header = Header(
            protocol=Protocol.TCP,
            src_addr=AnyAddress(),
            src_port=AnyPort(),
            direction=Direction.TO,
            dst_addr=AnyAddress(),
            dst_port=AnyPort(),
        )

        # Content with special bytes that need hex encoding
        content = ContentOption(
            pattern=b"\x00\x01\xff",  # Non-printable bytes
            modifiers=[],
        )

        rule = Rule(
            action=Action.ALERT,
            header=header,
            options=[
                MsgOption(text="Special chars"),
                content,
                SidOption(value=1),
            ],
        )

        printed = text_printer.print_rule(rule)

        assert "content:" in printed
        # Should have hex representation
        assert "|" in printed
