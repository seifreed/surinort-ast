"""
Unit tests for PatternMatchingOptionsMixin coverage.

Tests pattern matching transformation methods to achieve 100% coverage:
- pcre_option with empty items (edge case - line 80)
- pcre_option with valid patterns and flags
- pcre_option with negation
- pcre_option with various PCRE flags

This test file specifically targets the uncovered line 80 in pattern_mixin.py
where pcre_option handles empty items list.

Licensed under GNU General Public License v3.0
Author: Marc Rivero | @seifreed | mriverolopez@gmail.com
"""

from __future__ import annotations

from lark import Token

from surinort_ast import parse_rule
from surinort_ast.core.nodes import PcreOption
from surinort_ast.parsing.mixins.options.pattern_mixin import (
    PatternMatchingOptionsMixin,
)


class MockPatternTransformer(PatternMatchingOptionsMixin):
    """Mock transformer for testing PatternMatchingOptionsMixin in isolation."""

    def __init__(self, file_path: str | None = None):
        """Initialize mock transformer with optional file path."""
        self.file_path = file_path


class TestPcreOptionEmptyItems:
    """Test pcre_option with empty items list (line 80 coverage)."""

    def test_pcre_option_empty_items(self):
        """
        Test pcre_option returns empty PcreOption when items list is empty.

        This test covers line 80:
            if not items:
                return PcreOption(pattern="", flags="")

        This edge case occurs when the parser encounters malformed PCRE syntax
        or an incomplete pcre option declaration.
        """
        # Arrange
        transformer = MockPatternTransformer()
        empty_items: list[Token] = []

        # Act
        result = transformer.pcre_option(empty_items)

        # Assert
        assert isinstance(result, PcreOption)
        assert result.pattern == ""
        assert result.flags == ""
        assert result.location is None

    def test_pcre_option_empty_items_with_file_path(self):
        """
        Test pcre_option with empty items when file_path is set.

        Validates that even with file_path context, empty items
        produces a valid empty PcreOption without location.
        """
        # Arrange
        transformer = MockPatternTransformer(file_path="/tmp/test.rules")
        empty_items: list[Token] = []

        # Act
        result = transformer.pcre_option(empty_items)

        # Assert
        assert isinstance(result, PcreOption)
        assert result.pattern == ""
        assert result.flags == ""
        assert result.location is None


class TestPcreOptionValidPatterns:
    """Test pcre_option with valid patterns and flags."""

    def test_pcre_option_simple_pattern(self):
        """
        Test pcre_option with simple pattern without flags.

        Rule: pcre:"/test/";
        Expected: pattern="test", flags=""
        """
        # Arrange
        rule_text = 'alert tcp any any -> any any (msg:"Test"; pcre:"/test/"; sid:1;)'

        # Act
        rule = parse_rule(rule_text)

        # Assert
        pcre_opts = [opt for opt in rule.options if isinstance(opt, PcreOption)]
        assert len(pcre_opts) == 1
        pcre_opt = pcre_opts[0]
        assert pcre_opt.pattern == "test"
        assert pcre_opt.flags == ""

    def test_pcre_option_with_single_flag(self):
        """
        Test pcre_option with pattern and single flag.

        Rule: pcre:"/test/i";
        Expected: pattern="test", flags="i"
        """
        # Arrange
        rule_text = 'alert tcp any any -> any any (msg:"Test"; pcre:"/test/i"; sid:1;)'

        # Act
        rule = parse_rule(rule_text)

        # Assert
        pcre_opts = [opt for opt in rule.options if isinstance(opt, PcreOption)]
        assert len(pcre_opts) == 1
        pcre_opt = pcre_opts[0]
        assert pcre_opt.pattern == "test"
        assert pcre_opt.flags == "i"

    def test_pcre_option_with_multiple_flags(self):
        """
        Test pcre_option with pattern and multiple flags.

        Rule: pcre:"/test/imsxAEGRUB";
        Expected: pattern="test", flags="imsxAEGRUB"

        PCRE Flags tested:
        - i: Case insensitive
        - m: Multiline
        - s: Dot matches newline
        - x: Extended
        - A: Anchor at start
        - E: Dollar matches newline at end
        - G: Dollar matches newline anywhere
        - R: Relative to previous match
        - U: Ungreedy
        - B: Match in HTTP response body
        """
        # Arrange
        rule_text = 'alert tcp any any -> any any (msg:"Test"; pcre:"/test/imsxAEGRUB"; sid:1;)'

        # Act
        rule = parse_rule(rule_text)

        # Assert
        pcre_opts = [opt for opt in rule.options if isinstance(opt, PcreOption)]
        assert len(pcre_opts) == 1
        pcre_opt = pcre_opts[0]
        assert pcre_opt.pattern == "test"
        assert pcre_opt.flags == "imsxAEGRUB"

    def test_pcre_option_complex_pattern(self):
        """
        Test pcre_option with complex regex pattern.

        Rule: pcre:"/^GET\\s+\\/admin/i";
        Expected: pattern matches HTTP GET request to /admin
        """
        # Arrange
        rule_text = r'alert tcp any any -> any any (msg:"Test"; pcre:"/^GET\\s+\\/admin/i"; sid:1;)'

        # Act
        rule = parse_rule(rule_text)

        # Assert
        pcre_opts = [opt for opt in rule.options if isinstance(opt, PcreOption)]
        assert len(pcre_opts) == 1
        pcre_opt = pcre_opts[0]
        # Check that key components are present
        assert "GET" in pcre_opt.pattern
        assert "admin" in pcre_opt.pattern
        assert pcre_opt.flags == "i"

    def test_pcre_option_with_special_chars(self):
        """
        Test pcre_option with special regex characters.

        Rule: pcre:"/[a-zA-Z0-9]{8,}/";
        Expected: pattern matches 8+ alphanumeric characters
        """
        # Arrange
        rule_text = 'alert tcp any any -> any any (msg:"Test"; pcre:"/[a-zA-Z0-9]{8,}/"; sid:1;)'

        # Act
        rule = parse_rule(rule_text)

        # Assert
        pcre_opts = [opt for opt in rule.options if isinstance(opt, PcreOption)]
        assert len(pcre_opts) == 1
        pcre_opt = pcre_opts[0]
        assert pcre_opt.pattern == "[a-zA-Z0-9]{8,}"
        assert pcre_opt.flags == ""


class TestPcreOptionNegation:
    """Test pcre_option with negation prefix."""

    def test_pcre_option_with_negation(self):
        """
        Test pcre_option with negation (!) prefix.

        Rule: pcre:!"/malware/i";
        Expected: Alert if pattern does NOT match
        """
        # Arrange
        rule_text = 'alert tcp any any -> any any (msg:"Test"; pcre:!"/malware/i"; sid:1;)'

        # Act
        rule = parse_rule(rule_text)

        # Assert
        pcre_opts = [opt for opt in rule.options if isinstance(opt, PcreOption)]
        assert len(pcre_opts) == 1
        pcre_opt = pcre_opts[0]
        # Note: Negation is handled at grammar level, transformer receives the pattern
        assert pcre_opt.pattern == "malware"
        assert pcre_opt.flags == "i"


class TestPcreOptionLocationTracking:
    """Test pcre_option location tracking functionality."""

    def test_pcre_option_has_location(self):
        """
        Test that pcre_option includes location information when parsed.

        Location should track line, column, and file_path for diagnostics.
        """
        # Arrange
        rule_text = 'alert tcp any any -> any any (msg:"Test"; pcre:"/test/i"; sid:1;)'

        # Act
        rule = parse_rule(rule_text)

        # Assert
        pcre_opts = [opt for opt in rule.options if isinstance(opt, PcreOption)]
        assert len(pcre_opts) == 1
        pcre_opt = pcre_opts[0]

        # Location should be present from parsing
        assert pcre_opt.location is not None
        assert pcre_opt.location.span.start.line >= 1
        assert pcre_opt.location.span.start.column >= 1


class TestPcreOptionDirectTransformerCall:
    """Test pcre_option by calling transformer methods directly."""

    def test_pcre_option_with_file_path_tracking(self):
        """
        Test pcre_option includes file_path in location when transformer has file_path.

        This validates that location tracking properly includes source file context.
        """
        # Arrange
        transformer = MockPatternTransformer(file_path="/tmp/test.rules")
        pattern_token = Token("QUOTED_STRING", '"/test/i"')
        # Add position metadata to token for location tracking
        pattern_token.line = 1
        pattern_token.column = 45
        pattern_token.start_pos = 45
        pattern_token.end_line = 1
        pattern_token.end_column = 54
        pattern_token.end_pos = 54

        # Act
        result = transformer.pcre_option([pattern_token])

        # Assert
        assert isinstance(result, PcreOption)
        assert result.pattern == "test"
        assert result.flags == "i"
        assert result.location is not None
        assert result.location.file_path == "/tmp/test.rules"
        assert result.location.span.start.line == 1
        assert (
            result.location.span.start.column == 46
        )  # column is 0-indexed in token, 1-indexed in Position


class TestPcreOptionEdgeCases:
    """Test pcre_option edge cases and boundary conditions."""

    def test_pcre_option_empty_pattern(self):
        """
        Test pcre_option with empty pattern string.

        Rule: pcre:"//";
        Expected: pattern="", flags=""
        """
        # Arrange
        rule_text = 'alert tcp any any -> any any (msg:"Test"; pcre:"//"; sid:1;)'

        # Act
        rule = parse_rule(rule_text)

        # Assert
        pcre_opts = [opt for opt in rule.options if isinstance(opt, PcreOption)]
        assert len(pcre_opts) == 1
        pcre_opt = pcre_opts[0]
        assert pcre_opt.pattern == ""
        assert pcre_opt.flags == ""

    def test_pcre_option_pattern_with_escaped_quotes(self):
        """
        Test pcre_option with escaped quotes in pattern.

        Rule: pcre:"/\"quoted\"/";
        Expected: pattern contains escaped quote characters
        """
        # Arrange
        rule_text = r'alert tcp any any -> any any (msg:"Test"; pcre:"/\"test\"/"; sid:1;)'

        # Act
        rule = parse_rule(rule_text)

        # Assert
        pcre_opts = [opt for opt in rule.options if isinstance(opt, PcreOption)]
        assert len(pcre_opts) == 1
        pcre_opt = pcre_opts[0]
        # Pattern should preserve the escaped quotes
        assert "test" in pcre_opt.pattern

    def test_pcre_option_multiple_in_rule(self):
        """
        Test rule with multiple pcre options.

        Rule: pcre:"/first/i"; pcre:"/second/m";
        Expected: Both PCRE options captured correctly
        """
        # Arrange
        rule_text = (
            'alert tcp any any -> any any (msg:"Test"; pcre:"/first/i"; pcre:"/second/m"; sid:1;)'
        )

        # Act
        rule = parse_rule(rule_text)

        # Assert
        pcre_opts = [opt for opt in rule.options if isinstance(opt, PcreOption)]
        assert len(pcre_opts) == 2

        # First PCRE option
        assert pcre_opts[0].pattern == "first"
        assert pcre_opts[0].flags == "i"

        # Second PCRE option
        assert pcre_opts[1].pattern == "second"
        assert pcre_opts[1].flags == "m"


class TestPcreOptionRealWorldPatterns:
    """Test pcre_option with real-world IDS rule patterns."""

    def test_pcre_option_sql_injection_pattern(self):
        """
        Test PCRE pattern for SQL injection detection.

        Pattern detects common SQL injection payloads.
        """
        # Arrange
        rule_text = r'alert tcp any any -> any any (msg:"SQL Injection"; pcre:"/(\%27)|(\')|(\-\-)|(\%23)|(#)/i"; sid:1000;)'

        # Act
        rule = parse_rule(rule_text)

        # Assert
        pcre_opts = [opt for opt in rule.options if isinstance(opt, PcreOption)]
        assert len(pcre_opts) == 1
        pcre_opt = pcre_opts[0]
        # Check for key SQL injection indicators in the pattern
        assert "%27" in pcre_opt.pattern or "\\%27" in pcre_opt.pattern
        assert "#" in pcre_opt.pattern
        assert pcre_opt.flags == "i"

    def test_pcre_option_xss_pattern(self):
        """
        Test PCRE pattern for XSS (Cross-Site Scripting) detection.

        Pattern detects script tag injections.
        """
        # Arrange
        rule_text = r'alert tcp any any -> any any (msg:"XSS Attempt"; pcre:"/<script[^>]*>.*?<\/script>/is"; sid:2000;)'

        # Act
        rule = parse_rule(rule_text)

        # Assert
        pcre_opts = [opt for opt in rule.options if isinstance(opt, PcreOption)]
        assert len(pcre_opts) == 1
        pcre_opt = pcre_opts[0]
        assert "script" in pcre_opt.pattern
        assert pcre_opt.flags == "is"

    def test_pcre_option_http_method_pattern(self):
        """
        Test PCRE pattern for HTTP method validation.

        Pattern matches HTTP request methods.
        """
        # Arrange
        rule_text = r'alert tcp any any -> any any (msg:"HTTP Method"; pcre:"/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s/"; sid:3000;)'

        # Act
        rule = parse_rule(rule_text)

        # Assert
        pcre_opts = [opt for opt in rule.options if isinstance(opt, PcreOption)]
        assert len(pcre_opts) == 1
        pcre_opt = pcre_opts[0]
        assert "GET" in pcre_opt.pattern
        assert "POST" in pcre_opt.pattern
        assert pcre_opt.flags == ""
