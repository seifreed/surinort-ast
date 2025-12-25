"""
Test parser interface and dependency injection.

This module tests the IParser protocol interface and dependency injection patterns.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from pathlib import Path

import pytest

from surinort_ast.core.enums import Action, Dialect, Protocol
from surinort_ast.core.nodes import Rule
from surinort_ast.parsing import IParser, LarkRuleParser, ParserConfig, ParserFactory
from surinort_ast.parsing.interfaces import IParser as IParserProtocol


class MockParser:
    """Mock parser for testing dependency injection."""

    def __init__(
        self,
        dialect: Dialect = Dialect.SURICATA,
        strict: bool = False,
        error_recovery: bool = True,
        config: ParserConfig | None = None,
    ):
        self.dialect = dialect
        self.strict = strict
        self.config = config or ParserConfig.default()
        self.parse_called = False
        self.parse_file_called = False

    def parse(self, text: str, file_path: str | None = None, line_offset: int = 0) -> Rule:
        """Mock parse implementation that returns a simple rule."""
        self.parse_called = True
        from surinort_ast.core.enums import Direction
        from surinort_ast.core.nodes import AnyAddress, AnyPort, Header

        return Rule(
            action=Action.ALERT,
            header=Header(
                protocol=Protocol.TCP,
                src_addr=AnyAddress(),
                src_port=AnyPort(),
                direction=Direction.TO,
                dst_addr=AnyAddress(),
                dst_port=AnyPort(),
            ),
            options=[],
            raw_text=text,
            dialect=self.dialect,
        )

    def parse_file(
        self, path: str | Path, encoding: str = "utf-8", skip_errors: bool = True
    ) -> list[Rule]:
        """Mock parse_file implementation."""
        self.parse_file_called = True
        # Return a simple rule list
        return [self.parse("alert tcp any any -> any 80 (sid:1;)")]


class TestIParserProtocol:
    """Test the IParser protocol interface."""

    def test_lark_parser_implements_iparser(self):
        """Test that LarkRuleParser implements IParser protocol."""
        parser = LarkRuleParser()
        assert isinstance(parser, IParserProtocol)

    def test_mock_parser_implements_iparser(self):
        """Test that MockParser implements IParser protocol."""
        parser = MockParser()
        assert isinstance(parser, IParserProtocol)

    def test_iparser_has_required_methods(self):
        """Test that IParser protocol requires parse and parse_file methods."""
        # This is a compile-time check, but we can verify the protocol has the methods
        assert hasattr(IParserProtocol, "parse")
        assert hasattr(IParserProtocol, "parse_file")


class TestLarkRuleParser:
    """Test LarkRuleParser implementation."""

    def test_lark_parser_initialization(self):
        """Test LarkRuleParser initialization with default parameters."""
        parser = LarkRuleParser()
        assert parser.dialect == Dialect.SURICATA
        assert parser.strict is False
        assert parser.error_recovery is True
        assert isinstance(parser.config, ParserConfig)

    def test_lark_parser_custom_config(self):
        """Test LarkRuleParser with custom configuration."""
        config = ParserConfig.strict()
        parser = LarkRuleParser(
            dialect=Dialect.SNORT3,
            strict=True,
            error_recovery=False,
            config=config,
        )
        assert parser.dialect == Dialect.SNORT3
        assert parser.strict is True
        assert parser.error_recovery is False
        assert parser.config == config

    def test_lark_parser_parse_simple_rule(self):
        """Test parsing a simple rule with LarkRuleParser."""
        parser = LarkRuleParser()
        rule = parser.parse('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        assert rule.action == Action.ALERT
        assert rule.header.protocol == Protocol.TCP
        assert rule.raw_text == 'alert tcp any any -> any 80 (msg:"Test"; sid:1;)'

    def test_lark_parser_parse_with_file_path(self):
        """Test parsing with file path metadata."""
        parser = LarkRuleParser()
        rule = parser.parse(
            'alert tcp any any -> any 80 (msg:"Test"; sid:1;)',
            file_path="/test/rules.rules",
            line_offset=10,
        )

        assert rule.action == Action.ALERT
        assert rule.origin is not None
        assert rule.origin.file_path == "/test/rules.rules"

    def test_lark_parser_parse_file(self, tmp_path):
        """Test parsing rules from a file."""
        rules_file = tmp_path / "test.rules"
        rules_file.write_text(
            'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)\n'
            'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)\n'
        )

        parser = LarkRuleParser()
        rules = parser.parse_file(rules_file)

        assert len(rules) == 2
        assert rules[0].action == Action.ALERT
        assert rules[1].action == Action.ALERT


class TestParserFactory:
    """Test ParserFactory for creating parser instances."""

    def test_factory_create_default(self):
        """Test factory creates default LarkRuleParser."""
        parser = ParserFactory.create()
        assert isinstance(parser, LarkRuleParser)
        assert parser.dialect == Dialect.SURICATA

    def test_factory_create_with_dialect(self):
        """Test factory creates parser with specified dialect."""
        parser = ParserFactory.create(dialect=Dialect.SNORT3)
        assert isinstance(parser, LarkRuleParser)
        assert parser.dialect == Dialect.SNORT3

    def test_factory_create_with_config(self):
        """Test factory creates parser with custom configuration."""
        config = ParserConfig.permissive()
        parser = ParserFactory.create(config=config)
        assert parser.config == config

    def test_factory_register_custom_parser(self):
        """Test registering a custom parser as default."""
        # Register MockParser as default
        ParserFactory.register_default(MockParser)

        # Create parser should now return MockParser
        parser = ParserFactory.create()
        assert isinstance(parser, MockParser)
        assert not isinstance(parser, LarkRuleParser)

        # Reset to default
        ParserFactory.reset_default()
        parser = ParserFactory.create()
        assert isinstance(parser, LarkRuleParser)

    def test_factory_reset_default(self):
        """Test resetting factory to default parser."""
        # Register custom parser
        ParserFactory.register_default(MockParser)
        parser = ParserFactory.create()
        assert isinstance(parser, MockParser)

        # Reset
        ParserFactory.reset_default()
        parser = ParserFactory.create()
        assert isinstance(parser, LarkRuleParser)

    def test_factory_create_lark_parser_directly(self):
        """Test creating LarkRuleParser directly via factory."""
        # Register custom parser
        ParserFactory.register_default(MockParser)

        # create_lark_parser should still create LarkRuleParser
        parser = ParserFactory.create_lark_parser(dialect=Dialect.SNORT3)
        assert isinstance(parser, LarkRuleParser)
        assert parser.dialect == Dialect.SNORT3

        # Reset
        ParserFactory.reset_default()

    def test_factory_register_invalid_parser(self):
        """Test that registering invalid parser raises TypeError."""

        class InvalidParser:
            """Parser without required methods."""

            pass

        with pytest.raises(TypeError, match="must implement IParser protocol"):
            ParserFactory.register_default(InvalidParser)


class TestDependencyInjection:
    """Test dependency injection patterns with parsers."""

    def test_parse_rule_with_custom_parser(self):
        """Test using custom parser via dependency injection."""
        from surinort_ast.api.parsing import parse_rule

        mock_parser = MockParser()
        rule = parse_rule("alert tcp any any -> any 80 (sid:1;)", parser=mock_parser)

        assert mock_parser.parse_called
        assert rule.action == Action.ALERT

    def test_parse_rule_with_factory_parser(self):
        """Test using factory-created parser via dependency injection."""
        from surinort_ast.api.parsing import parse_rule

        custom_parser = ParserFactory.create(dialect=Dialect.SNORT3, strict=True)
        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)', parser=custom_parser)

        assert rule.action == Action.ALERT
        assert rule.dialect == Dialect.SNORT3

    def test_parse_rule_without_custom_parser(self):
        """Test that parse_rule works without custom parser (default behavior)."""
        from surinort_ast.api.parsing import parse_rule

        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        assert rule.action == Action.ALERT
        assert rule.header.protocol == Protocol.TCP

    def test_function_accepts_iparser_type(self):
        """Test that functions can accept IParser type annotation."""

        def process_with_parser(parser: IParser, text: str) -> Rule:
            """Function that accepts any IParser implementation."""
            return parser.parse(text)

        # Test with LarkRuleParser
        lark_parser = LarkRuleParser()
        rule = process_with_parser(lark_parser, "alert tcp any any -> any 80 (sid:1;)")
        assert rule.action == Action.ALERT

        # Test with MockParser
        mock_parser = MockParser()
        rule = process_with_parser(mock_parser, "alert tcp any any -> any 80 (sid:1;)")
        assert rule.action == Action.ALERT


class TestBackwardCompatibility:
    """Test backward compatibility with existing RuleParser."""

    def test_rule_parser_still_works(self):
        """Test that old RuleParser API still works."""
        from surinort_ast.parsing import RuleParser

        parser = RuleParser()
        rule = parser.parse('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')

        assert rule.action == Action.ALERT
        assert rule.header.protocol == Protocol.TCP

    def test_rule_parser_delegates_to_lark_parser(self):
        """Test that RuleParser delegates to LarkRuleParser."""
        from surinort_ast.parsing import RuleParser

        parser = RuleParser(dialect=Dialect.SNORT3)
        # Access internal parser (implementation detail)
        assert hasattr(parser, "_parser")
        assert isinstance(parser._parser, LarkRuleParser)
        assert parser._parser.dialect == Dialect.SNORT3

    def test_convenience_functions_still_work(self):
        """Test that convenience functions still work."""
        from surinort_ast.parsing import parse_rule

        rule = parse_rule('alert tcp any any -> any 80 (msg:"Test"; sid:1;)')
        assert rule.action == Action.ALERT

    def test_parse_file_still_works(self, tmp_path):
        """Test that parse_file still works."""
        from surinort_ast.parsing import RuleParser

        rules_file = tmp_path / "test.rules"
        rules_file.write_text(
            'alert tcp any any -> any 80 (msg:"Rule 1"; sid:1;)\n'
            'alert tcp any any -> any 443 (msg:"Rule 2"; sid:2;)\n'
        )

        parser = RuleParser()
        rules = parser.parse_file(rules_file)

        assert len(rules) == 2
        assert rules[0].action == Action.ALERT
